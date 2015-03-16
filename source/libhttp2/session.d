/**
 * Session
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.session;

import libhttp2.constants;
import libhttp2.types;
import libhttp2.frame;
import libhttp2.stream;
import libhttp2.connector;
import libhttp2.deflater;
import libhttp2.inflater;
import libhttp2.buffers;
import libhttp2.priority_queue;
import libhttp2.helpers;
import libhttp2.huffman;
import core.exception : RangeError;

import memutils.circularbuffer;
import memutils.vector;
import memutils.hashmap;

import std.algorithm : min, max;

enum OptionsMask {
	NONE = 0,
    NO_AUTO_WINDOW_UPDATE = 1 << 0,
    RECV_CLIENT_PREFACE = 1 << 1,
    NO_HTTP_MESSAGING = 1 << 2,
}

enum OutboundState {
    POP_ITEM,
    SEND_DATA
}

struct ActiveOutboundItem {
    OutboundItem item;
    Buffers framebufs;
	OutboundState state = OutboundState.POP_ITEM;

	void reset() {
		LOGF("send: reset http2_active_outbound_item");
		LOGF("send: aob.item = %s", item);
		if(item) {
			item.free();
			Mem.free(item);
			item = null;
		}
		framebufs.reset();
		state = OutboundState.POP_ITEM;
	}
}

/// Internal state when receiving incoming frame
enum InboundState : ubyte {
    /* Receiving frame header */
    READ_CLIENT_PREFACE,
    READ_FIRST_SETTINGS,
    READ_HEAD,
    READ_NBYTE,
    READ_HEADER_BLOCK,
    IGN_HEADER_BLOCK,
    IGN_PAYLOAD,
    FRAME_SIZE_ERROR,
    READ_SETTINGS,
    READ_GOAWAY_DEBUG,
    EXPECT_CONTINUATION,
    IGN_CONTINUATION,
    READ_PAD_DATA,
    READ_DATA,
    IGN_DATA,
    IGN_ALL,
}

struct InboundFrame {
    Frame frame;

    /* The received SETTINGS entry. The protocol says that we only cares
	   about the defined settings ID. If unknown ID is received, it is
	   ignored.  We use last entry to hold minimum header table size if
	   same settings are seen multiple times. */
    Setting[INBOUND_NUM_IV] iva;

    /// buffer pointers to small buffer, raw_sbuf 
    Buffer sbuf;

    /// buffer pointers to large buffer, raw_lbuf
    Buffer lbuf;

    /// Large buffer, malloced on demand
    ubyte[] raw_lbuf;

    /* The number of entry filled in |iva| */
    size_t niv;

    /* How many bytes we still need to receive for current frame */
    size_t payloadleft;

    /* padding length for the current frame */
    size_t padlen;

    InboundState state;

    /* Small buffer.  Currently the largest contiguous chunk to buffer
     is frame header.  We buffer part of payload, but they are smaller
     than frame header. */
    ubyte[FRAME_HDLEN] raw_sbuf;

	/// Returns the amount of bytes that are required by this frame
	size_t readLength(const ubyte* input, const ubyte* last)
	{
		return min(cast(size_t)(last - input), payloadleft);
	}
	
	/*
	 * Resets iframe.sbuf and advance its mark pointer by |left| bytes.
	 */
	void setMark(size_t left)
	{
		sbuf.reset;
		sbuf.mark += left;
	}
	
	size_t read(in ubyte* input, in ubyte* last) 
	{
		import std.c.string : memcpy;

		size_t readlen;
		
		readlen = min(last - input, sbuf.markAvailable);

		memcpy(sbuf.last, input, readlen);
		sbuf.last += readlen;

		return readlen;
	}
	
	/*
	 * Unpacks SETTINGS entry in iframe.sbuf.
	 */
	void unpackSetting() 
	{
		Setting _iv;
		_iv.unpack(sbuf.pos);

		size_t i;
			
		with(Setting) switch (_iv.id) {
			case HEADER_TABLE_SIZE:
			case ENABLE_PUSH:
			case MAX_CONCURRENT_STREAMS:
			case INITIAL_WINDOW_SIZE:
			case MAX_FRAME_SIZE:
			case MAX_HEADER_LIST_SIZE:
				break;
			default:
				LOGF("recv: ignore unknown settings id=0x%02x", _iv.id);
				return;
		}
		
		for(i = 0; i < niv; i++) {
			if (iva[i].id == _iv.id) {
				iva[i] = _iv;
				break;
			}
		}
		
		if (i == niv) {
			iva[niv++] = _iv;
		}
		
		if (_iv.id == Setting.HEADER_TABLE_SIZE && _iv.value < iva[INBOUND_NUM_IV - 1].value) 
		{			
			iva[INBOUND_NUM_IV - 1] = _iv;
		}
	}
private:
	/*
	 * Checks PADDED flags and set iframe.sbuf to read them accordingly.
	 * If padding is set, this function returns 1.  If no padding is set,
	 * this function returns 0.  On error, returns -1.
	 */
	int handlePad()
	{
		if (frame.hd.flags & FrameFlags.PADDED) {
			if (frame.hd.length < 1) {
				return -1;
			}
			setMark(1);
			return 1;
		}
		LOGF("recv: no padding in payload");
		return ErrorCode.OK;
	}
	
	/*
	 * Computes number of padding based on flags. This function returns
	 * padlen if it succeeds, or -1.
	 */
	int computePad() 
	{
		/* 1 for Pad Length field */
		int _padlen = sbuf.pos[0] + 1;
		
		LOGF("recv: padlen=%d", padlen);

		/* We cannot use iframe.frame.hd.length because of CONTINUATION */
		if (_padlen - 1 > payloadleft) {
			return -1;
		}

		padlen = _padlen;

		return _padlen;
	}
	
	/*
	 * This function returns the effective payload length in the data of
	 * length |readlen| when the remaning payload is |payloadleft|. The
	 * |payloadleft| does not include |readlen|. If padding was started
	 * strictly before this data chunk, this function returns -1.
	 */
	int effectiveReadLength(size_t _payloadleft, size_t readlen) 
	{
		size_t trail_padlen = frame.trailPadlen(padlen);

		if (trail_padlen > _payloadleft) {
			size_t padlen;
			padlen = trail_padlen - _payloadleft;
			if (readlen < padlen) {
				return -1;
			} else {
				return cast(int)(readlen - padlen);
			}
		}
		return cast(int)readlen;
	}

	void reset()
	{
		/* A bit risky code, since if this function is called from Session(), we rely on the fact that
     	   frame.hd.type is 0, so that no free is performed. */
		with (FrameType) switch (frame.hd.type) {
			case HEADERS:
				frame.headers.free();
				break;
			case PRIORITY:
				frame.priority.free();
				break;
			case RST_STREAM:
				frame.rst_stream.free();
				break;
			case SETTINGS:
				frame.settings.free();
				break;
			case PUSH_PROMISE:
				frame.push_promise.free();
				break;
			case PING:
				frame.ping.free();
				break;
			case GOAWAY:
				frame.goaway.free();
				break;
			case WINDOW_UPDATE:
				frame.window_update.free();
				break;
			default: break;
		}
		
		destroy(frame);
		
		state = InboundState.READ_HEAD;
		
		sbuf = Buffer(raw_sbuf.ptr[0 .. raw_sbuf.sizeof]);
		sbuf.mark += FRAME_HDLEN;
		
		lbuf.free();
		lbuf = Buffer();
		destroy(iva);
		payloadleft = 0;
		padlen = 0;
		iva[INBOUND_NUM_IV - 1].id = Setting.HEADER_TABLE_SIZE;
		iva[INBOUND_NUM_IV - 1].value = uint.max;
	}
}

struct SettingsStorage {
	uint header_table_size = HD_DEFAULT_MAX_BUFFER_SIZE;
	uint enable_push = 1;
	uint max_concurrent_streams = INITIAL_MAX_CONCURRENT_STREAMS;
	uint initial_window_size = INITIAL_WINDOW_SIZE;
	uint max_frame_size = MAX_FRAME_SIZE_MIN;
	uint max_header_list_size = uint.max;
}

enum GoAwayFlags {
    NONE = 0,
    /* Flag means that connection should be terminated after sending GOAWAY. */
    TERM_ON_SEND = 0x1,
    /* Flag means GOAWAY to terminate session has been sent */
    TERM_SENT = 0x2,
    /* Flag means GOAWAY was sent */
    SENT = 0x4,
    /* Flag means GOAWAY was received */
    RECV = 0x8,
}

enum {
	CLIENT = false,
	SERVER = true
}

class Session {

	this(bool server, Connector callbacks, in Options options = Options.init)
	{
		if (server) {
			is_server = true;
			next_stream_id = 2; // server IDs always pair
		}
		else
			next_stream_id = 1; // client IDs always impair

		roots = Mem.alloc!StreamRoots();
		scope(failure) Mem.free(roots);

		hd_inflater = Inflater(true);
		scope(failure) hd_inflater.free();

		hd_deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
		scope(failure) hd_deflater.free();

		ob_pq = PriorityQueue(128);
		scope(failure) ob_pq.free();

		ob_ss_pq = PriorityQueue(128);
		scope(failure) ob_ss_pq.free();

		ob_da_pq = PriorityQueue(128);
		scope(failure) ob_da_pq.free();

		/* 1 for Pad Field. */
		aob.framebufs = Mem.alloc!Buffers(FRAMEBUF_CHUNKLEN, FRAMEBUF_MAX_NUM, 1, FRAME_HDLEN + 1);
		scope(failure) { aob.framebufs.free(); Mem.free(aob.framebufs); }

		aob.reset();
		
		if (options != Options.init) {
			if ((options.opt_set_mask & OptionFlags.NO_AUTO_WINDOW_UPDATE) && options.no_auto_window_update) 
			{
				opt_flags |= OptionsMask.NO_AUTO_WINDOW_UPDATE;
			}
			
			if (options.opt_set_mask & OptionFlags.PEER_MAX_CONCURRENT_STREAMS) 
			{
				remote_settings.max_concurrent_streams = options.peer_max_concurrent_streams;
			}
			
			if ((options.opt_set_mask & OptionFlags.RECV_CLIENT_PREFACE) && options.recv_client_preface) 
			{
				opt_flags |= OptionsMask.RECV_CLIENT_PREFACE;
			}
			
			if ((options.opt_set_mask & OptionFlags.NO_HTTP_MESSAGING) && options.no_http_messaging)
			{
				opt_flags |= OptionsMask.NO_HTTP_MESSAGING;
			}
		}
		
		connector = callbacks;

		iframe.reset();
		
		if (is_server && opt_flags & OptionsMask.RECV_CLIENT_PREFACE) 
		{
			iframe.state = InboundState.READ_CLIENT_PREFACE;
			iframe.payloadleft = CLIENT_CONNECTION_PREFACE.length;
		} else static if (ENABLE_FIRST_SETTING_CHECK)
		{			
			iframe.state = InboundState.READ_FIRST_SETTINGS;
		}
	}

	/**
	 * Frees any resources allocated for $(D Session).  If $(D Session) is
	 * `null`, this function does nothing.
	 */
	void free() {		
		if (inflight_iva) 
			Mem.free(inflight_iva);
		roots.free();
		Mem.free(roots);
		freeAllStreams();
		aob.reset();
		iframe.reset();
		ob_pq.free();
		ob_ss_pq.free();
		ob_da_pq.free();
		hd_deflater.free();
		hd_inflater.free();
		aob.framebufs.free();
		if (aob.framebufs)
			Mem.free(aob.framebufs);
	}

	/**
	 * Sends pending frames to the remote peer.
	 *
	 * This function retrieves the highest prioritized frame from the
	 * outbound queue and sends it to the remote peer.  It does this as
	 * many as possible until the user callback $(D Connector.write) returns
	 * $(D ErrorCode.WOULDBLOCK) or the outbound queue becomes empty.
	 * 
	 * This function calls several $(D Connector) functions which are passed
	 * when initializing the $(D Session).  Here is the simple time chart
	 * which tells when each callback is invoked:
	 *
	 * 1. Get the next frame to be sent from a priority sorted outbound queue.
	 *
	 * 2. Prepare transmission of the frame.
	 *
	 * 3. $(D Connector.onFrameFailure) may be invoked if the control frame cannot 
	 * 	  be sent because some preconditions are not met (e.g., request HEADERS 
	 * 	  cannot be sent after GOAWAY). This then aborts the following steps.
	 *
	 * 4. $(D Connector.selectPaddingLength) is invoked if the frame is HEADERS, 
	 *    PUSH_PROMISE or DATA.
	 *
	 * 5. If the frame is request HEADERS, the stream is opened here.
	 *
	 * 6. $(D Connector.onFrameReady) is invoked.
	 *
	 * 7. $(D Connector.write) is invoked one or more times to send the frame.
	 *
	 * 8. $(D Connector.onFrameSent) is invoked after all data is transmitted.
	 *
	 * 9. $(D Connector.onStreamExit) may be invoked if the transmission of the frame 
	 *    triggers closure of the stream, it is destroyed afterwards.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * 
	 * $(D ErrorCode.CALLBACK_FAILURE)
	 *     The callback function failed.
	 */
	ErrorCode send() {
		ErrorCode rv;
		ubyte[] data;
		int sentlen;
		Buffers framebufs = aob.framebufs;
		
		for (;;) {
			logDebug(framebufs.length);
			rv = memSendInternal(data, false);
			if (rv < 0)
				return rv;
			else if (data.length == 0)
				return ErrorCode.OK;
			sentlen = connector.write(data);
			logDebug("write: ", data.length, " buf state: ", aob.state, " Sent: ", sentlen);
			
			if (sentlen < 0) {
				if (cast(ErrorCode) sentlen == ErrorCode.WOULDBLOCK) {
					/* Transmission canceled. Rewind the offset */
					framebufs.cur.buf.pos -= data.length;					
					return ErrorCode.OK;
				}
				
				return ErrorCode.CALLBACK_FAILURE;
			}
			
			/* Rewind the offset to the amount of unsent bytes */
			framebufs.cur.buf.pos -= (data.length - sentlen);
		}

		assert(false);
	}

	/**
	 * @function
	 *
	 * Returns the serialized data to send.
	 *
	 * This function behaves like `send()` except that it
	 * does not use $(D Connector.write) to transmit data.
	 * Instead, it assigns the serialized data to the given $(D ubyte[])
	 * |data_arr|.  The other callbacks are called in the same way as they are
	 * in `send()`.
	 *
	 * This function may not return all serialized data in one invocation.
	 * To get all data, call this function repeatedly until it returns an
	 * array of 0 length or one of negative error codes.
	 *
	 * The assigned |data_ar| is valid until the next call of
	 * `memSend()` or `send()`.
	 *
	 * The caller must send all data before sending the next chunk of
	 * data.
	 *
	 * This function returns an error code on failure or 0 on success
	 */
	ErrorCode memSend(ref ubyte[] data_arr) 
	{
		ErrorCode rv;
		
		rv = memSendInternal(data_arr, true);
		if (rv < 0) {
			return rv;
		}
		
		/* We have to call afterFrameSent here to handle stream
	       closure upon transmission of frames.  Otherwise, END_STREAM may
	       be reached to client before we call memSend
	       again and we may get exceeding number of incoming streams. */
		rv = afterFrameSent();
		if (rv < 0) {
			/* FATAL */
			assert(isFatal(rv));
			return rv;
		}
		
		return ErrorCode.OK;
	}

	/**
	 * Receives frames from the remote peer.
	 *
	 * This function receives as many frames as possible until the user
	 * callback $(D Connector.read) returns $(D ErrorCode.WOULDBLOCK).  
	 * This function calls several $(D Connector) functions which are passed 
	 * when initializing the $(D Session).  
	 * 
	 * Here is the simple time chart which tells when each callback is invoked:
	 *
	 * 1. $(D Connector.read) is invoked one or more times to receive the frame header.
	 *
	 * 2. $(D Connector.onFrameHeader) is invoked after the frame header is received.
	 *
	 * 3. If the frame is DATA frame:
	 *
	 *    1. $(D Connector.read) is invoked one or more times to receive the DATA payload. 
	 * 
	 * 	  2. $(D Connector.onDataChunk) is invoked alternatively with $(D Connector.read) 
	 *       for each chunk of data.
	 *
	 *    2. $(D Connector.onFrame) may be invoked if one DATA frame is completely received.
	 * 
	 * 	  3. $(D Connector.onStreamExit) may be invoked if the reception of the frame triggers 
	 *  	 closure of the stream.
	 *
	 * 4. If the frame is the control frame:
	 *
	 *    1. $(D Connector.read) is invoked one or more times to receive the whole frame.
	 *
	 *    2. If the received frame is valid, then following actions are
	 *       taken.  
	 * 		- If the frame is either HEADERS or PUSH_PROMISE:
	 *      	- $(D Connector.onHeaders) is invoked first.
	 * 			- $(D Connector.onHeaderField) is invoked for each header fields.
	 * 			- $(D Connector.onFrame) is invoked after all header fields.
	 * 		- For other frames:
	 *       	- $(D Connector.onFrame) is invoked.  
	 *          - $(D Connector.onStreamExit) may be invoked if the reception of the frame 
	 * 			  triggers the closure of the stream.
	 *
	 *    3. $(D Connector.onInvalidFrame) may be invoked if the received frame is unpacked 
	 * 		 but is interpreted as invalid.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.EOF)
	 *     The remote peer did shutdown on the connection.
	 * $(D ErrorCode.CALLBACK_FAILURE)
	 *     The callback function failed.
	 * $(D ErrorCode.BAD_PREFACE)
	 *     Invalid client preface was detected.  This error only returns
	 *     when $(D Session) was configured as server and
	 *     `setRecvClientPreface()` is used.
	 */
	ErrorCode recv() {
		ubyte[INBOUND_BUFFER_LENGTH] buf;
		while (1) {
			int readlen;
			readlen = callRead(buf.ptr[0 .. buf.sizeof]);
			if (readlen > 0) {
				// process the received data
				int proclen = memRecv(buf[0 .. readlen]);
				if (proclen < 0) {
					return cast(ErrorCode)proclen;
				}
				assert(proclen == readlen);
			} else if (readlen == 0 || readlen == ErrorCode.WOULDBLOCK) {
				return ErrorCode.OK;
			} else if (readlen == ErrorCode.EOF) {
				return ErrorCode.EOF;
			} else if (readlen < 0) {
				return ErrorCode.CALLBACK_FAILURE;
			}
		}
	}

	/**
	 * Processes data |input| as an input from the remote endpoint.  The
	 * |inlen| indicates the number of bytes in the |in|.
	 *
	 * This function behaves like $(D Session.recv) except that it
	 * does not use $(D Connector.read) to receive data; the
	 * |input| is the only data for the invocation of this function.  If all
	 * bytes are processed, this function returns.  The other connector
	 * are called in the same way as they are in $(D Session.recv).
	 *
	 * In the current implementation, this function always tries to
	 * process all input data unless either an error occurs or
	 * $(D ErrorCode.PAUSE) is returned from $(D Connector.onHeaderField) or
	 * $(D Connector.onDataChunk).  If $(D ErrorCode.PAUSE) is used, 
	 * the return value includes the number of bytes which was used to 
	 * produce the data or frame for the callback.
	 *
	 * This function returns the number of processed bytes, or one of the
	 * following negative error codes:
	 *
	 * $(D ErrorCode.CALLBACK_FAILURE)
	 *     The callback function failed.
	 * $(D ErrorCode.BAD_PREFACE)
	 *     Invalid client preface was detected.  This error only returns
	 *     when $(D Session) was configured as server and
	 *     `setRecvClientPreface()` is used.
	 */
	int memRecv(in ubyte[] input) 
	{
		const(ubyte)* pos = input.ptr;
		const ubyte* first = input.ptr;
		const ubyte* last = input.ptr + input.length;
		size_t readlen;
		int padlen;
		ErrorCode rv;
		bool busy;
		FrameHeader cont_hd;
		Stream stream;
		size_t pri_fieldlen;
		
		LOGF("recv: connection recv_window_size=%d, local_window=%d", recv_window_size, local_window_size);
		
		for (;;) {
			with(InboundState) final switch (iframe.state) {
				case READ_CLIENT_PREFACE:
					readlen = min(input.length, iframe.payloadleft);
					
					if (CLIENT_CONNECTION_PREFACE[$ - iframe.payloadleft .. readlen] != pos[0 .. readlen])
					{
						return ErrorCode.BAD_PREFACE;
					}
					
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					if (iframe.payloadleft == 0) {
						iframe.reset();
						iframe.state = READ_FIRST_SETTINGS;
					}
					
					break;
				case READ_FIRST_SETTINGS:
					LOGF("recv: [READ_FIRST_SETTINGS]");
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					
					if (iframe.sbuf.markAvailable) {
						return cast(int)(pos - first);
					}
					
					if (iframe.sbuf.pos[3] != FrameType.SETTINGS || (iframe.sbuf.pos[4] & FrameFlags.ACK))
					{
						
						iframe.state = IGN_ALL;
						
						rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "SETTINGS expected");
						
						if (isFatal(rv)) {
							return rv;
						}
						
						return cast(int)input.length;
					}
					
					iframe.state = READ_HEAD;
					
					goto case READ_HEAD;
				case READ_HEAD: {
					bool on_frame_header_called;
					
					LOGF("recv: [READ_HEAD]");
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					
					if (iframe.sbuf.markAvailable) {
						return cast(int)(pos - first);
					}
					
					iframe.frame.hd.unpack(iframe.sbuf[]);
					iframe.payloadleft = iframe.frame.hd.length;
					
					LOGF("recv: payloadlen=%d, type=%u, flags=0x%02x, stream_id=%d",
						iframe.frame.hd.length, iframe.frame.hd.type, iframe.frame.hd.flags, iframe.frame.hd.stream_id);
					
					if (iframe.frame.hd.length > local_settings.max_frame_size) {
						LOGF("recv: length is too large %d > %u", iframe.frame.hd.length, local_settings.max_frame_size);
						
						busy = true;
						
						iframe.state = IGN_PAYLOAD;
						
						rv = terminateSessionWithReason(FrameError.FRAME_SIZE_ERROR, "too large frame size");
						
						if (isFatal(rv)) {
							return rv;
						}
						
						break;
					}
					
					switch (iframe.frame.hd.type) {
						case FrameType.DATA: {
							LOGF("recv: DATA");
							
							iframe.frame.hd.flags &= (FrameFlags.END_STREAM | FrameFlags.PADDED);
							/* Check stream is open. If it is not open or closing, ignore payload. */
							busy = true;
							
							rv = onDataFailFast();
							if (rv == ErrorCode.IGN_PAYLOAD) {
								LOGF("recv: DATA not allowed stream_id=%d", iframe.frame.hd.stream_id);
								iframe.state = IGN_DATA;
								break;
							}
							
							if (isFatal(rv)) {
								return rv;
							}
							
							rv = cast(ErrorCode)iframe.handlePad();
							if (rv < 0) {
								iframe.state = IGN_DATA;
								rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "DATA: insufficient padding space");
								
								if (isFatal(rv)) {
									return rv;
								}
								break;
							}
							
							if (rv == 1) {
								iframe.state = READ_PAD_DATA;
								break;
							}
							
							iframe.state = READ_DATA;
							break;
						}
						case FrameType.HEADERS:
							
							LOGF("recv: HEADERS");
							
							iframe.frame.hd.flags &= (FrameFlags.END_STREAM | FrameFlags.END_HEADERS | FrameFlags.PADDED | FrameFlags.PRIORITY);
							
							rv = cast(ErrorCode)iframe.handlePad();
							if (rv < 0) {
								busy = true;
								
								iframe.state = IGN_PAYLOAD;
								
								rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "HEADERS: insufficient padding space");
								if (isFatal(rv)) {
									return rv;
								}
								break;
							}
							
							if (rv == 1) {
								iframe.state = READ_NBYTE;
								break;
							}
							
							pri_fieldlen = priorityLength(iframe.frame.hd.flags);
							
							if (pri_fieldlen > 0) {
								if (iframe.payloadleft < pri_fieldlen) {
									busy = true;
									iframe.state = FRAME_SIZE_ERROR;
									break;
								}
								
								iframe.state = READ_NBYTE;
								
								iframe.setMark(pri_fieldlen);
								break;
							}
							
							/* Call onFrameHeader here because processHeadersFrame() may call onHeaders callback */
							bool ok = callOnFrameHeader(iframe.frame.hd);
							
							if (!ok) {
								return ErrorCode.CALLBACK_FAILURE;
							}
							
							on_frame_header_called = true;
							
							rv = processHeadersFrame();
							if (isFatal(rv)) {
								return rv;
							}
							
							busy = true;
							
							if (rv == ErrorCode.IGN_HEADER_BLOCK) {
								iframe.state = IGN_HEADER_BLOCK;
								break;
							}
							
							iframe.state = READ_HEADER_BLOCK;
							
							break;
						case FrameType.PRIORITY:
							LOGF("recv: PRIORITY");
							
							iframe.frame.hd.flags = FrameFlags.NONE;
							
							if (iframe.payloadleft != PRIORITY_SPECLEN) {
								busy = true;
								
								iframe.state = FRAME_SIZE_ERROR;
								
								break;
							}
							
							iframe.state = READ_NBYTE;
							
							iframe.setMark(PRIORITY_SPECLEN);
							
							break;
						case FrameType.RST_STREAM:
						case FrameType.WINDOW_UPDATE:
							static if (DEBUG) {
								switch (iframe.frame.hd.type) {
									case FrameType.RST_STREAM:
										LOGF("recv: RST_STREAM");
										break;
									case FrameType.WINDOW_UPDATE:
										LOGF("recv: WINDOW_UPDATE");
										break;
									default: break;
								}
							}
							
							iframe.frame.hd.flags = FrameFlags.NONE;
							
							if (iframe.payloadleft != 4) {
								busy = true;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							
							iframe.setMark(4);
							
							break;
						case FrameType.SETTINGS:
							LOGF("recv: SETTINGS");
							
							iframe.frame.hd.flags &= FrameFlags.ACK;
							
							if ((iframe.frame.hd.length % FRAME_SETTINGS_ENTRY_LENGTH) ||
								((iframe.frame.hd.flags & FrameFlags.ACK) && iframe.payloadleft > 0)) {
								busy = true;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_SETTINGS;
							
							if (iframe.payloadleft) {
								iframe.setMark(FRAME_SETTINGS_ENTRY_LENGTH);
								break;
							}
							
							busy = true;
							
							iframe.setMark(0);
							
							break;
						case FrameType.PUSH_PROMISE:
							LOGF("recv: PUSH_PROMISE");
							
							iframe.frame.hd.flags &= (FrameFlags.END_HEADERS | FrameFlags.PADDED);
							
							rv = cast(ErrorCode)iframe.handlePad();
							if (rv < 0) {
								busy = true;
								iframe.state = IGN_PAYLOAD;
								rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: insufficient padding space");
								if (isFatal(rv)) {
									return rv;
								}
								break;
							}
							
							if (rv == 1) {
								iframe.state = READ_NBYTE;
								break;
							}
							
							if (iframe.payloadleft < 4) {
								busy = true;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							
							iframe.setMark(4);
							
							break;
						case FrameType.PING:
							LOGF("recv: PING");
							
							iframe.frame.hd.flags &= FrameFlags.ACK;
							
							if (iframe.payloadleft != 8) {
								busy = true;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							iframe.setMark(8);
							
							break;
						case FrameType.GOAWAY:
							LOGF("recv: GOAWAY");
							
							iframe.frame.hd.flags = FrameFlags.NONE;
							
							if (iframe.payloadleft < 8) {
								busy = true;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							iframe.setMark(8);
							
							break;
						case FrameType.CONTINUATION:
							LOGF("recv: unexpected CONTINUATION");
							
							/* Receiving CONTINUATION in this state are subject to connection error of type PROTOCOL_ERROR */
							rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "CONTINUATION: unexpected");
							if (isFatal(rv))
							{
								return rv;
							}
							
							busy = true;
							
							iframe.state = IGN_PAYLOAD;
							
							break;
						default:
							LOGF("recv: unknown frame");
							
							/* Silently ignore unknown frame type. */
							
							busy = true;
							
							iframe.state = IGN_PAYLOAD;
							
							break;
					}
					
					if (!on_frame_header_called) {
						switch (iframe.state) {
							case IGN_HEADER_BLOCK:
							case IGN_PAYLOAD:
							case FRAME_SIZE_ERROR:
							case IGN_DATA:
								break;
							default:
								bool ok = callOnFrameHeader(iframe.frame.hd);
								
								if (!ok) {
									return ErrorCode.CALLBACK_FAILURE;
								}
						}
					}
					
					break;
				}
				case READ_NBYTE:
					LOGF("recv: [READ_NBYTE]");
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					iframe.payloadleft -= readlen;
					
					LOGF("recv: readlen=%d, payloadleft=%d, left=%d, type=%s", readlen, iframe.payloadleft, iframe.sbuf.markAvailable, iframe.frame.hd.type);
					
					if (iframe.sbuf.markAvailable) {
						return cast(int)(pos - first);
					}
					
					switch (iframe.frame.hd.type) {
						case FrameType.HEADERS:
							if (iframe.padlen == 0 && (iframe.frame.hd.flags & FrameFlags.PADDED)) {
								padlen = iframe.computePad();
								if (padlen < 0) {
									busy = true;
									rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "HEADERS: invalid padding");
									if (isFatal(rv)) {
										return rv;
									}
									iframe.state = IGN_PAYLOAD;
									break;
								}
								iframe.frame.headers.padlen = padlen;
								
								pri_fieldlen = priorityLength(iframe.frame.hd.flags);
								if (pri_fieldlen > 0) {
									if (iframe.payloadleft < pri_fieldlen) {
										busy = true;
										iframe.state = FRAME_SIZE_ERROR;
										break;
									}
									iframe.state = READ_NBYTE;
									iframe.setMark(pri_fieldlen);
									break;
								} else {
									/* Truncate buffers used for padding spec */
									iframe.setMark(0);
								}
							}
							
							rv = processHeadersFrame();
							if (isFatal(rv)) {
								return rv;
							}
							
							busy = true;
							
							if (rv == ErrorCode.IGN_HEADER_BLOCK) {
								iframe.state = IGN_HEADER_BLOCK;
								break;
							}
							
							iframe.state = READ_HEADER_BLOCK;
							
							break;
						case FrameType.PRIORITY:
							rv = processPriorityFrame();
							if (isFatal(rv)) {
								return rv;
							}
							
							iframe.reset();
							
							break;
						case FrameType.RST_STREAM:
							rv = processRstStreamFrame();
							if (isFatal(rv)) {
								return rv;
							}
							
							iframe.reset();
							
							break;
						case FrameType.PUSH_PROMISE:
							if (iframe.padlen == 0 && (iframe.frame.hd.flags & FrameFlags.PADDED)) {
								padlen = iframe.computePad();
								if (padlen < 0) {
									busy = true;
									rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: invalid padding");
									if (isFatal(rv)) {
										return rv;
									}
									iframe.state = IGN_PAYLOAD;
									break;
								}
								
								iframe.frame.push_promise.padlen = padlen;
								
								if (iframe.payloadleft < 4) {
									busy = true;
									iframe.state = FRAME_SIZE_ERROR;
									break;
								}
								
								iframe.state = READ_NBYTE;
								
								iframe.setMark(4);
								
								break;
							}
							
							rv = processPushPromiseFrame();
							if (isFatal(rv)) {
								return rv;
							}
							
							busy = true;
							
							if (rv == ErrorCode.IGN_HEADER_BLOCK) {
								iframe.state = IGN_HEADER_BLOCK;
								break;
							}
							
							iframe.state = READ_HEADER_BLOCK;
							
							break;
						case FrameType.PING:
							rv = processPingFrame();
							if (isFatal(rv)) {
								return rv;
							}
							
							iframe.reset();
							
							break;
						case FrameType.GOAWAY: {
							size_t debuglen;
							
							/* 8 is Last-stream-ID + Error Code */
							debuglen = iframe.frame.hd.length - 8;
							
							if (debuglen > 0) {
								iframe.raw_lbuf = Mem.alloc!(ubyte[])(debuglen);
								iframe.lbuf = Buffer(iframe.raw_lbuf);
							}
							
							busy = true;
							
							iframe.state = READ_GOAWAY_DEBUG;
							
							break;
						}
						case FrameType.WINDOW_UPDATE:
							rv = processWindowUpdateFrame();
							if (isFatal(rv)) {
								return rv;
							}
							
							iframe.reset();
							
							break;
						default:
							/* This is unknown frame */
							iframe.reset();
							
							break;
					}
					break;
				case READ_HEADER_BLOCK:
				case IGN_HEADER_BLOCK: {
					int data_readlen;
					static if (DEBUG) {
						if (iframe.state == READ_HEADER_BLOCK) {
							LOGF("recv: [READ_HEADER_BLOCK]");
						} else {
							LOGF("recv: [IGN_HEADER_BLOCK]");
						}
					}
					
					readlen = iframe.readLength(pos, last);
					
					LOGF("recv: readlen=%d, payloadleft=%d", readlen, iframe.payloadleft - readlen);
					
					data_readlen = iframe.effectiveReadLength(iframe.payloadleft - readlen, readlen);
					
					if (data_readlen >= 0) {
						size_t trail_padlen;
						size_t hd_proclen = 0;
						trail_padlen = iframe.frame.trailPadlen(iframe.padlen);
						LOGF("recv: block final=%d", (iframe.frame.hd.flags & FrameFlags.END_HEADERS) && iframe.payloadleft - data_readlen == trail_padlen);
						
						rv = inflateHeaderBlock(iframe.frame, hd_proclen, cast(ubyte[])pos[0 .. data_readlen], 
												(iframe.frame.hd.flags & FrameFlags.END_HEADERS) && iframe.payloadleft - data_readlen == trail_padlen,
												iframe.state == READ_HEADER_BLOCK);
						
						if (isFatal(rv)) {
							return rv;
						}
						
						if (rv == ErrorCode.PAUSE) {
							pos += hd_proclen;
							iframe.payloadleft -= hd_proclen;
							
							return cast(int)(pos - first);
						}
						
						if (rv == ErrorCode.TEMPORAL_CALLBACK_FAILURE) {
							/* The application says no more headers. We decompress the
				             rest of the header block but not invoke on_header_callback
				             and on_frame_recv_callback. */
							pos += hd_proclen;
							iframe.payloadleft -= hd_proclen;
							
							addRstStream(iframe.frame.hd.stream_id, FrameError.INTERNAL_ERROR);
							busy = true;
							iframe.state = IGN_HEADER_BLOCK;
							break;
						}
						
						pos += readlen;
						iframe.payloadleft -= readlen;
						
						if (rv == ErrorCode.HEADER_COMP) {
							/* GOAWAY is already issued */
							if (iframe.payloadleft == 0) {
								iframe.reset();
							} else {
								busy = true;
								iframe.state = IGN_PAYLOAD;
							}
							break;
						}
					} else {
						pos += readlen;
						iframe.payloadleft -= readlen;
					}
					
					if (iframe.payloadleft) {
						break;
					}
					
					if ((iframe.frame.hd.flags & FrameFlags.END_HEADERS) == 0) {
						
						iframe.setMark(FRAME_HDLEN);
						
						iframe.padlen = 0;
						
						if (iframe.state == READ_HEADER_BLOCK)
							iframe.state = EXPECT_CONTINUATION;
						else 
							iframe.state = IGN_CONTINUATION;
						
					} else {
						if (iframe.state == READ_HEADER_BLOCK) {
							rv = afterHeaderBlockReceived();
							if (isFatal(rv)) {
								return rv;
							}
						}
						iframe.reset();
					}
					break;
				}
				case IGN_PAYLOAD:
					LOGF("recv: [IGN_PAYLOAD]");
					
					readlen = iframe.readLength(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					LOGF("recv: readlen=%d, payloadleft=%d", readlen, iframe.payloadleft);
					
					if (iframe.payloadleft) {
						break;
					}
					
					switch (iframe.frame.hd.type) {
						case FrameType.HEADERS:
						case FrameType.PUSH_PROMISE:
						case FrameType.CONTINUATION:
							/* Mark inflater bad so that we won't perform further decoding */
							hd_inflater.ctx.bad = 1;
							break;
						default:
							break;
					}
					
					iframe.reset();
					
					break;
				case FRAME_SIZE_ERROR:
					LOGF("recv: [FRAME_SIZE_ERROR]");
					 
					rv = terminateSession(FrameError.FRAME_SIZE_ERROR);
					if (isFatal(rv)) {
						return rv;
					}
					
					busy = true;
					
					iframe.state = IGN_PAYLOAD;
					
					break;
				case READ_SETTINGS:
					LOGF("recv: [READ_SETTINGS]");
					
					readlen = iframe.read(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					LOGF("recv: readlen=%d, payloadleft=%d", readlen, iframe.payloadleft);
					
					if (iframe.sbuf.markAvailable) {
						break;
					}

					if (readlen > 0) 
						iframe.unpackSetting();
					
					if (iframe.payloadleft) {
						iframe.setMark(FRAME_SETTINGS_ENTRY_LENGTH);
						break;
					}
					
					rv = processSettingsFrame();
					
					if (isFatal(rv)) {
						return rv;
					}
					
					iframe.reset();
					
					break;
				case READ_GOAWAY_DEBUG:
					LOGF("recv: [READ_GOAWAY_DEBUG]");
					
					readlen = iframe.readLength(pos, last);

					iframe.lbuf.last[0 .. readlen] = pos[0 .. readlen];
					iframe.lbuf.last += readlen;
					
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					LOGF("recv: readlen=%d, payloadleft=%d", readlen, iframe.payloadleft);
					
					if (iframe.payloadleft) {
						assert(iframe.lbuf.available > 0);
						
						break;
					}
					
					rv = processGoAwayFrame();
					
					if (isFatal(rv)) {
						return rv;
					}
					
					iframe.reset();
					
					break;
				case EXPECT_CONTINUATION:
				case IGN_CONTINUATION:
					static if (DEBUG) {
						if (iframe.state == EXPECT_CONTINUATION) {
							LOGF("recv: [EXPECT_CONTINUATION]");
						} else {
							LOGF("recv: [IGN_CONTINUATION]");
						}
					}
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					
					if (iframe.sbuf.markAvailable) {
						return cast(int)(pos - first);
					}
					
					cont_hd.unpack(iframe.sbuf.pos);
					iframe.payloadleft = cont_hd.length;

					LOGF("recv: payloadlen=%d, type=%u, flags=0x%02x, stream_id=%d", cont_hd.length, cont_hd.type, cont_hd.flags, cont_hd.stream_id);
					
					if (cont_hd.type != FrameType.CONTINUATION ||
						cont_hd.stream_id != iframe.frame.hd.stream_id) {
						LOGF("recv: expected stream_id=%d, type=%d, but got stream_id=%d, type=%d", 
							iframe.frame.hd.stream_id, FrameType.CONTINUATION, cont_hd.stream_id, cont_hd.type);
						rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "unexpected non-CONTINUATION frame or stream_id is invalid");
						if (isFatal(rv)) {
							return rv;
						}
						
						busy = true;
						
						iframe.state = IGN_PAYLOAD;
						
						break;
					}
					
					/* CONTINUATION won't bear FrameFlags.PADDED flag */                
					iframe.frame.hd.flags |= cont_hd.flags & FrameFlags.END_HEADERS;
					iframe.frame.hd.length += cont_hd.length;
					
					busy = true;
					
					if (iframe.state == EXPECT_CONTINUATION) {
						iframe.state = READ_HEADER_BLOCK;

						bool ok = callOnFrameHeader(cont_hd);

						if (!ok) {
							return ErrorCode.CALLBACK_FAILURE;
						}
					} else {
						iframe.state = IGN_HEADER_BLOCK;
					}
					
					break;
				case READ_PAD_DATA:
					LOGF("recv: [READ_PAD_DATA]");
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					iframe.payloadleft -= readlen;

					LOGF("recv: readlen=%d, payloadleft=%d, left=%d", readlen, iframe.payloadleft, iframe.sbuf.markAvailable);
					
					if (iframe.sbuf.markAvailable) {
						return cast(int)(pos - first);
					}
					
					/* Pad Length field is subject to flow control */
					rv = updateRecvConnectionWindowSize(readlen);
					if (isFatal(rv)) {
						return rv;
					}
					
					/* Pad Length field is consumed immediately */
					rv = consume(iframe.frame.hd.stream_id, readlen);
					
					if (isFatal(rv)) {
						return rv;
					}
					
					stream = getStream(iframe.frame.hd.stream_id);
					if (stream) 
						updateRecvStreamWindowSize(stream, readlen, iframe.payloadleft || (iframe.frame.hd.flags & FrameFlags.END_STREAM) == 0);

					busy = true;
					
					padlen = iframe.computePad();
					if (padlen < 0) {
						rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "DATA: invalid padding");
						if (isFatal(rv)) {
							return rv;
						}
						iframe.state = IGN_DATA;
						break;
					}
					
					iframe.frame.data.padlen = padlen;
					
					iframe.state = READ_DATA;
					
					break;
				case READ_DATA:
					LOGF("recv: [READ_DATA]");
					
					readlen = iframe.readLength(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					LOGF("recv: readlen=%d, payloadleft=%d", readlen, iframe.payloadleft);
					
					if (readlen > 0) {
						int data_readlen;
						
						rv = updateRecvConnectionWindowSize(readlen);
						if (isFatal(rv)) {
							return rv;
						}
						
						stream = getStream(iframe.frame.hd.stream_id);
						if (stream)
							updateRecvStreamWindowSize(stream, readlen, iframe.payloadleft || (iframe.frame.hd.flags & FrameFlags.END_STREAM) == 0);

						data_readlen = iframe.effectiveReadLength(iframe.payloadleft, readlen);
						
						padlen = cast(int)(readlen - data_readlen);
						
						if (padlen > 0) {
							/* Padding is considered as "consumed" immediately */
							rv = consume(iframe.frame.hd.stream_id, padlen);
							
							if (isFatal(rv)) {
								return rv;
							}
						}
						
						LOGF("recv: data_readlen=%d", data_readlen);
						
						if (stream && data_readlen > 0) {
							if (isHTTPMessagingEnabled()) {
								if (!stream.onDataChunk(data_readlen)) {
									addRstStream(iframe.frame.hd.stream_id, FrameError.PROTOCOL_ERROR);
									busy = true;
									iframe.state = IGN_DATA;
									break;
								}
							}

							ubyte[] data_nopad =  cast(ubyte[])(pos - readlen)[0 .. data_readlen];
							FrameFlags flags = iframe.frame.hd.flags;
							int stream_id = iframe.frame.hd.stream_id;
							bool pause;
							bool ok = connector.onDataChunk(flags, stream_id, data_nopad, pause);

							if (pause) {
								return cast(int)(pos - first);
							}
							
							if (!ok) {
								return ErrorCode.CALLBACK_FAILURE;
							}

						}
					}
					
					if (iframe.payloadleft) {
						break;
					}
					
					rv = processDataFrame();
					if (isFatal(rv)) {
						return rv;
					}
					
					iframe.reset();
					
					break;
				case IGN_DATA:
					LOGF("recv: [IGN_DATA]");
					
					readlen = iframe.readLength(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					LOGF("recv: readlen=%d, payloadleft=%d", readlen, iframe.payloadleft);
					
					if (readlen > 0) {
						/* Update connection-level flow control window for ignored DATA frame too */
						rv = updateRecvConnectionWindowSize(readlen);
						if (isFatal(rv)) {
							return rv;
						}
						
						if (opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE) {
							
							/* Ignored DATA is considered as "consumed" immediately. */
							rv = updateConnectionConsumedSize(readlen);
							
							if (isFatal(rv)) {
								return rv;
							}
						}
					}
					
					if (iframe.payloadleft) {
						break;
					}
					
					iframe.reset();
					
					break;
				case IGN_ALL:
					return cast(int)input.length;
			}
			
			if (!busy && pos == last) {
				break;
			}
			
			busy = false;
		}
		
		assert(pos == last);
		
		return cast(int)(pos - first);
	}

	/**
	 * Puts back previously deferred DATA frame in the stream |stream_id|
	 * to the outbound queue.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The stream does not exist; or no deferred data exist.
	 */
	ErrorCode resumeData(int stream_id)
	{
		Stream stream = getStream(stream_id);
		
		if (!stream || !stream.isItemDeferred()) 
			return ErrorCode.INVALID_ARGUMENT;
		
		stream.resumeDeferredItem(StreamFlags.DEFERRED_USER, this);
		return ErrorCode.OK;
	}

	/**
	 * Returns true value if $(D Session) wants to receive data from the
	 * remote peer.
	 *
	 * If both `wantRead()` and `wantWrite()` return false, the application should
	 * drop the connection.
	 */
	bool wantRead() 
	{
		size_t num_active_streams;
		
		/* If this flag is set, we don't want to read. The application should drop the connection. */
		if (goaway_flags & GoAwayFlags.TERM_SENT) {
			return false;
		}
		
		num_active_streams = getNumActiveStreams();
		
		/* Unless termination GOAWAY is sent or received, we always want to read incoming frames. */
		if (num_active_streams > 0) {
			return true;
		}

		/* If there is no active streams and GOAWAY has been sent or received, we are done with this session. */
		return (goaway_flags & (GoAwayFlags.SENT | GoAwayFlags.RECV)) == 0;
	}

	/**
	 * Returns true value if $(D Session) wants to send data to the remote
	 * peer.
	 *
	 * If both `wantRead()` and `wantWrite()` return false, the application should
	 * drop the connection.
	 */
	bool wantWrite()
	{
		size_t num_active_streams;
		
		/* If these flag is set, we don't want to write any data. The application should drop the connection. */
		if (goaway_flags & GoAwayFlags.TERM_SENT)
		{
			return false;
		}
		
		num_active_streams = getNumActiveStreams();
		
		/*
		 * Unless termination GOAWAY is sent or received, we want to write
		 * frames if there is pending ones. If pending frame is request/push
		 * response HEADERS and concurrent stream limit is reached, we don't
		 * want to write them.
		 */
		
		if (!aob.item && ob_pq.empty &&
			(ob_da_pq.empty || remote_window_size == 0) &&
			(ob_ss_pq.empty || isOutgoingConcurrentStreamsMax())) 
		{
			return false;
		}
		
		if (num_active_streams > 0)
		{
			return true;
		}
		
		/* If there is no active streams and GOAWAY has been sent or received, we are done with this session. */
		return (goaway_flags & (GoAwayFlags.SENT | GoAwayFlags.RECV)) == 0;
	}

	/**
	 * Returns stream_user_data for the stream |stream_id|.  The
	 * stream_user_data is provided by `submitRequest()`,
	 * `submitHeaders()` or  `setStreamUserData()`. 
	 * Unless it is set using `setStreamUserData()`, if the stream is
	 * initiated by the remote endpoint, stream_user_data is always
	 * `null`.  If the stream does not exist, this function returns
	 * `null`.
	 */
	void* getStreamUserData(int stream_id) {
		Stream stream = getStream(stream_id);
		if (stream) {
			return stream.userData;
		} else {
			return null;
		}
	}

	/**
	 * Sets the |stream_user_data| to the stream denoted by the
	 * |stream_id|.  If a stream user data is already set to the stream,
	 * it is replaced with the |stream_user_data|.  It is valid to specify
	 * `null` in the |stream_user_data|, which nullifies the associated
	 * data pointer.
	 *
	 * It is valid to set the |stream_user_data| to the stream reserved by
	 * PUSH_PROMISE frame.
	 *
	 * This function returns 0 if it succeeds, or one of following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The stream does not exist
	 */
	ErrorCode setStreamUserData(int stream_id, void* stream_user_data){
		Stream stream = getStream(stream_id);
		if (!stream)
			return ErrorCode.INVALID_ARGUMENT;
		stream.userData = stream_user_data;
		return ErrorCode.OK;
	}

package:
	/**
	 * Returns the number of frames in the outbound queue.  This does not
	 * include the deferred DATA frames.
	 */
	size_t getOutboundQueueSize() {
		return ob_pq.length + ob_ss_pq.length + ob_da_pq.length;
	}

	/**
	 * Returns the number of DATA payload in bytes received without
	 * WINDOW_UPDATE transmission for the stream |stream_id|.  The local
	 * (receive) window size can be adjusted by
	 * $(D submitWindowUpdate).  This function takes into account
	 * that and returns effective data length.  In particular, if the
	 * local window size is reduced by submitting negative
	 * window_size_increment with $(D submitWindowUpdate), this
	 * function returns the number of bytes less than actually received.
	 *
	 * This function returns -1 if it fails.
	 */
	int getStreamEffectiveRecvDataLength(int stream_id) 
	{
		Stream stream = getStream(stream_id);
		if (!stream)
			return -1;
		return stream.recvWindowSize < 0 ? 0 : stream.recvWindowSize;
	}

	/**
	 * Returns the local (receive) window size for the stream |stream_id|.
	 * The local window size can be adjusted by
	 * $(D submitWindowUpdate).  This function takes into account
	 * that and returns effective window size.
	 *
	 * This function returns -1 if it fails.
	 */	
	int getStreamEffectiveLocalWindowSize(int stream_id)
	{
		Stream stream = getStream(stream_id);
		if (!stream)
			return -1;
		return stream.localWindowSize;
	}

	/**
	 * Returns the number of DATA payload in bytes received without
	 * WINDOW_UPDATE transmission for a connection.  The local (receive)
	 * window size can be adjusted by $(D submitWindowUpdate).
	 * This function takes into account that and returns effective data
	 * length.  In particular, if the local window size is reduced by
	 * submitting negative window_size_increment with
	 * $(D submitWindowUpdate), this function returns the number
	 * of bytes less than actually received.
	 *
	 * This function returns -1 if it fails.
	 */
	int getEffectiveRecvDataLength()
	{
		return recv_window_size < 0 ? 0 : recv_window_size;
	}

	/**
	 * Returns the local (receive) window size for a connection.  The
	 * local window size can be adjusted by
	 * $(D submitWindowUpdate).  This function takes into account
	 * that and returns effective window size.
	 *
	 * This function returns -1 if it fails.
	 */
	int getEffectiveLocalWindowSize() 
	{
		return local_window_size;
	}

	/**
	 * Returns the remote window size for a given stream |stream_id|.
	 *
	 * This is the amount of flow-controlled payload (e.g., DATA) that the
	 * local endpoint can send without stream level WINDOW_UPDATE.  There
	 * is also connection level flow control, so the effective size of
	 * payload that the local endpoint can actually send is
	 * min(getStreamRemoteWindowSize(), getRemoteWindowSize()).
	 *
	 * This function returns -1 if it fails.
	 */
	int getStreamRemoteWindowSize(int stream_id) 
	{
		Stream stream = getStream(stream_id);
		if (!stream)
			return -1;

		/* stream.remoteWindowSize can be negative when Setting.INITIAL_WINDOW_SIZE is changed. */
		return max(0, stream.remoteWindowSize);
	}

	/**
	 * Returns the remote window size for a connection.
	 *
	 * This function always succeeds.
	 */
	int getRemoteWindowSize() {
		return remote_window_size;
	}

	/**
	 * Returns 1 if local peer half closed the given stream |stream_id|.
	 * Returns 0 if it did not.  Returns -1 if no such stream exists.
	 */
	int getStreamLocalClose(int stream_id)
	{
		Stream stream = getStream(stream_id);
		
		if (!stream)
			return -1;
		
		return (stream.shutFlags & ShutdownFlag.WR) != 0;
	}

	/**
	 * Returns 1 if remote peer half closed the given stream |stream_id|.
	 * Returns 0 if it did not.  Returns -1 if no such stream exists.
	 */
	int getStreamRemoteClose(int stream_id) 
	{
		Stream stream = getStream(stream_id);
		
		if (!stream)
			return -1;
		
		return (stream.shutFlags & ShutdownFlag.RD) != 0;
	}

	/**
	 * Signals the session so that the connection should be terminated.
	 *
	 * The last stream ID is the minimum value between the stream ID of a
	 * stream for which $(D Connector.onFrame) was called
	 * most recently and the last stream ID we have sent to the peer
	 * previously.
	 *
	 * The |error_code| is the error code of this GOAWAY frame.  The
	 * pre-defined error code is one of $(D FrameError).
	 *
	 * After the transmission, both `wantRead()` and
	 * `wantWrite()` return 0.
	 *
	 * This function should be called when the connection should be
	 * terminated after sending GOAWAY.  If the remaining streams should
	 * be processed after GOAWAY, use `submitGoAway()` instead.
	 */
	ErrorCode terminateSession(FrameError error_code)
	{
		return terminateSession(last_proc_stream_id, error_code, null);
	}


	/**
	 * Signals the session so that the connection should be terminated.
	 *
	 * This function behaves like $(D Session.terminateSession),
	 * but the last stream ID can be specified by the application for fine
	 * grained control of stream.  The HTTP/2 specification does not allow
	 * last_stream_id to be increased.  So the actual value sent as
	 * last_stream_id is the minimum value between the given
	 * |last_stream_id| and the last_stream_id we have previously sent to
	 * the peer.
	 *
	 * The |last_stream_id| is peer's stream ID or 0.  So if $(D Session) is
	 * initialized as client, |last_stream_id| must be even or 0.  If
	 * $(D Session) is initialized as server, |last_stream_id| must be odd or
	 * 0.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The |last_stream_id| is invalid.
	 */
	ErrorCode terminateSession(int last_stream_id, FrameError error_code) {
		return terminateSession(last_stream_id, error_code, null);
	}

	/**
	 * Returns the value of SETTINGS |id| notified by a remote endpoint.
	 * The |id| must be one of values defined in $(D SettingsID).
	 */
	uint getRemoteSettings(SettingsID id) {
		switch (id) {
			case Setting.HEADER_TABLE_SIZE:
				return remote_settings.header_table_size;
			case Setting.ENABLE_PUSH:
				return remote_settings.enable_push;
			case Setting.MAX_CONCURRENT_STREAMS:
				return remote_settings.max_concurrent_streams;
			case Setting.INITIAL_WINDOW_SIZE:
				return remote_settings.initial_window_size;
			case Setting.MAX_FRAME_SIZE:
				return remote_settings.max_frame_size;
			case Setting.MAX_HEADER_LIST_SIZE:
				return remote_settings.max_header_list_size;
			default: return -1;
		}
	}

	/**
	 * Tells the $(D Session) that next stream ID is |next_stream_id|.  The
	 * |next_stream_id| must be equal or greater than the value returned
	 * by `getNextStreamID()`.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The |next_stream_id| is strictly less than the value
	 *     `getNextStreamID()` returns.
	 */
	ErrorCode setNextStreamID(int _next_stream_id)
	{
		if (_next_stream_id < 0 || next_stream_id > cast(uint)next_stream_id) {
			return ErrorCode.INVALID_ARGUMENT;
		}
		
		next_stream_id = _next_stream_id;

		return ErrorCode.OK;
	}

	/**
	 * Returns the next outgoing stream ID.  Notice that return type is
	 * uint.  If we run out of stream ID for this session, this
	 * function returns 1 << 31.
	 */
	uint getNextStreamID() 
	{
		return next_stream_id;
	}

	/**
	 * Tells the $(D Session) that |size| bytes for a stream denoted by
	 * |stream_id| were consumed by application and are ready to
	 * WINDOW_UPDATE.  This function is intended to be used without
	 * automatic window update (see
	 * $(D Options.setNoAutoWindowUpdate).
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The |stream_id| is 0.
	 * $(D ErrorCode.INVALID_STATE)
	 *     Automatic WINDOW_UPDATE is not disabled.
	 */
	ErrorCode consume(int stream_id, size_t size) {
		ErrorCode rv;
		Stream stream;
		
		if (stream_id == 0) {
			return ErrorCode.INVALID_ARGUMENT;
		}
		
		if (!(opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE)) {
			return ErrorCode.INVALID_STATE;
		}
		
		rv = updateConnectionConsumedSize(size);
		
		if (isFatal(rv)) {
			return rv;
		}
		
		stream = getStream(stream_id);
		
		if (stream) {
			rv = updateStreamConsumedSize(stream, size);
			
			if (isFatal(rv)) {
				return rv;
			}
		}
		
		return ErrorCode.OK;
	}

	/**
	 * Performs post-process of HTTP Upgrade request.  This function can
	 * be called from both client and server, but the behavior is very
	 * different in each other.
	 *
	 * If called from client side, the |settings_payload| must be the
	 * value sent in `HTTP2-Settings` header field and must be decoded
	 * by base64url decoder.  The |settings_payloadlen| is the length of
	 * |settings_payload|.  The |settings_payload| is unpacked and its
	 * setting values will be submitted using $(D submitSettings).
	 * This means that the client application code does not need to submit
	 * SETTINGS by itself.  The stream with stream ID=1 is opened and the
	 * |stream_user_data| is used for its stream_user_data.  The opened
	 * stream becomes half-closed (local) state.
	 *
	 * If called from server side, the |settings_payload| must be the
	 * value received in `HTTP2-Settings` header field and must be
	 * decoded by base64url decoder.  The |settings_payloadlen| is the
	 * length of |settings_payload|.  It is treated as if the SETTINGS
	 * frame with that payload is received.  Thus, callback functions for
	 * the reception of SETTINGS frame will be invoked.  The stream with
	 * stream ID=1 is opened.  The |stream_user_data| is ignored.  The
	 * opened stream becomes half-closed (remote).
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The |settings_payload| is badly formed.
	 * $(D ErrorCode.PROTO)
	 *     The stream ID 1 is already used or closed; or is not available.
	 */
	ErrorCode upgrade(in ubyte[] settings_payload, void* stream_user_data = null) 
	{
		Stream stream;
		Frame frame;
		Setting[] iva;
		ErrorCode rv;
		PrioritySpec pri_spec;
		
		if ((!is_server && next_stream_id != 1) ||
			(is_server && last_recv_stream_id >= 1)) {
			return ErrorCode.PROTO;
		}
		
		if (settings_payload.length % FRAME_SETTINGS_ENTRY_LENGTH) {
			return ErrorCode.INVALID_ARGUMENT;
		}
		
		Settings.unpack(iva, settings_payload);
		
		if (is_server) {
			frame.hd = FrameHeader(cast(uint)settings_payload.length, FrameType.SETTINGS, FrameFlags.NONE, 0);
			frame.settings.iva = iva;
			rv = onSettings(frame, 1 /* No ACK */);
		} else {
			rv = submitSettings(this, iva);
		}
		
		Mem.free(iva);
		
		stream = openStream(1, StreamFlags.NONE, pri_spec, StreamState.OPENING, is_server ? null : stream_user_data);
		
		if (is_server)
		{
			stream.shutdown(ShutdownFlag.RD);
			last_recv_stream_id = 1;
			last_proc_stream_id = 1;
		} else {
			stream.shutdown(ShutdownFlag.WR);
			next_stream_id += 2;
		}

		return ErrorCode.OK;
	}

	/*
	 * Returns true if |stream_id| is initiated by local endpoint.
	 */	
	bool isMyStreamId(int stream_id)
	{
		int rem;
		if (stream_id == 0) {
			return false;
		}
		rem = stream_id & 0x1;
		if  (is_server) {
			return rem == 0;
		}
		return rem == 1;
	}

	/*
	 * Adds |item| to the outbound queue in $(D Session).  When this function
	 * succeeds, it takes ownership of |item|. So caller must not free it
	 * on success.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.STREAM_CLOSED
	 *     Stream already closed (DATA frame only)
	 * 
	 * ErrorCode.DATA_EXIST
	 */
	ErrorCode addItem(OutboundItem item) 
	{
		/* TODO: Return error if stream is not found for the frame requiring stream presence. */
		Stream stream = getStream(item.frame.hd.stream_id);
		Frame* frame = &item.frame;
		
		if (frame.hd.type != FrameType.DATA) {        
			switch (frame.hd.type) {
				case FrameType.RST_STREAM:
					if (stream)
						stream.state = StreamState.CLOSING;
					break;
				case FrameType.SETTINGS:
					item.weight = OB_SETTINGS_WEIGHT;                
					break;
				case FrameType.PING:
					/* Ping has highest priority. */
					item.weight = OB_PING_WEIGHT;                
					break;
				default:
					break;
			}
			
			if (frame.hd.type == FrameType.HEADERS) {
				/* We push request HEADERS and push response HEADERS to
		         dedicated queue because their transmission is affected by
		         Setting.MAX_CONCURRENT_STREAMS */
				/* TODO: If 2 HEADERS are submitted for reserved stream, then
		         both of them are queued into ob_ss_pq, which is not
		         desirable. */
				if (frame.headers.cat == HeadersCategory.REQUEST) {
					ob_ss_pq.push(item);
					item.queued = 1;
				} else if (stream && (stream.state == StreamState.RESERVED || item.aux_data.headers.attach_stream)) {
					item.weight = stream.effectiveWeight;
					item.cycle = last_cycle;
					stream.attachItem(item, this);
				} else {
					ob_pq.push(item);
					item.queued = 1;
				}
			} else {
				ob_pq.push(item);
				item.queued = 1;
			}
			
			return ErrorCode.OK;
		}
		
		if (!stream) {
			return ErrorCode.STREAM_CLOSED;
		}
		
		if (stream.item) {
			return ErrorCode.DATA_EXIST;
		}
		
		item.weight = stream.effectiveWeight;
		item.cycle = last_cycle;
		
		stream.attachItem(item, this);

		return ErrorCode.OK;
	}

	/*
	 * Adds RST_STREAM frame for the stream |stream_id| with the error
	 * code |error_code|. This is a convenient function built on top of
	 * $(D Session.addFrame) to add RST_STREAM easily.
	 *
	 * This function simply returns without adding RST_STREAM frame if
	 * given stream is in StreamState.CLOSING state, because multiple
	 * RST_STREAM for a stream is redundant.
	 */
	void addRstStream(int stream_id, FrameError error_code) 
	{
		ErrorCode rv;
		OutboundItem item;
		Frame* frame;
		Stream stream;
		
		stream = getStream(stream_id);
		if (stream && stream.state == StreamState.CLOSING) 
			return;		
		
		/* Cancel pending request HEADERS in ob_ss_pq if this RST_STREAM refers to that stream. */
		if (!is_server && isMyStreamId(stream_id) && ob_ss_pq.top)
		{
			OutboundItem top;
			Frame* headers_frame;
			
			top = ob_ss_pq.top;
			headers_frame = &top.frame;
			
			assert(headers_frame.hd.type == FrameType.HEADERS);
			
			if (headers_frame.hd.stream_id <= stream_id && cast(uint)stream_id < next_stream_id) 
			{
				foreach (OutboundItem item; ob_ss_pq) {
					
					HeadersAuxData* aux_data = &item.aux_data.headers;
					
					if (item.frame.hd.stream_id != stream_id || aux_data.canceled) 
					{
						continue;
					}
					
					aux_data.error_code = error_code;
					aux_data.canceled = 1;				
					return;
				}
			}
		}
		
		item = Mem.alloc!OutboundItem(this);    
		frame = &item.frame;
		
		frame.rst_stream = RstStream(stream_id, error_code);
		addItem(item);
	}

	/*
	 * Adds PING frame. This is a convenient functin built on top of
	 * $(D Session.addFrame) to add PING easily.
	 *
	 * If the |opaque_data| is not null, it must point to 8 bytes memory
	 * region of data. The data pointed by |opaque_data| is copied. It can
	 * be null. In this case, 8 bytes null is used.
	 *
	 */
	void addPing(FrameFlags flags, in ubyte[] opaque_data) 
	{
		ErrorCode rv;
		OutboundItem item;
		Frame* frame;

		item = Mem.alloc!OutboundItem(this);
		
		frame = &item.frame;
		
		frame.ping = Ping(flags, opaque_data);
		
		addItem(item);
	}

	/*
	 * Adds GOAWAY frame with the last-stream-ID |last_stream_id| and the
	 * error code |error_code|. This is a convenient function built on top
	 * of $(D Session.addFrame) to add GOAWAY easily.  The
	 * |aux_flags| are bitwise-OR of one or more of
	 * GoAwayAuxFlags.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * 
	 * ErrorCode.INVALID_ARGUMENT
	 *     The |opaque_data_len| is too large.
	 */
	ErrorCode addGoAway(int last_stream_id, FrameError error_code, in string opaque_data, GoAwayAuxFlags aux_flags) {
		ErrorCode rv;
		OutboundItem item;
		Frame* frame;
		string opaque_data_copy;
		GoAwayAuxData* aux_data;
		
		if (isMyStreamId(last_stream_id)) {
			return ErrorCode.INVALID_ARGUMENT;
		}
		
		if (opaque_data) {
			if (opaque_data.length + 8 > MAX_PAYLOADLEN) {
				return ErrorCode.INVALID_ARGUMENT;
			}
			opaque_data_copy = cast(string)Mem.copy(opaque_data);
		}
		
		item = Mem.alloc!OutboundItem(this);
		
		frame = &item.frame;
		
		/* last_stream_id must not be increased from the value previously sent */
		last_stream_id = min(last_stream_id, local_last_stream_id);
		
		frame.goaway = GoAway(last_stream_id, error_code, opaque_data_copy);
		
		aux_data = &item.aux_data.goaway;
		aux_data.flags = aux_flags;
		
		addItem(item);
		return ErrorCode.OK;
	}
	/*
	 * Adds WINDOW_UPDATE frame with stream ID |stream_id| and
	 * window-size-increment |window_size_increment|. This is a convenient
	 * function built on top of $(D Session.addFrame) to add
	 * WINDOW_UPDATE easily.
	 */
	void addWindowUpdate(FrameFlags flags, int stream_id, int window_size_increment) {
		ErrorCode rv;
		OutboundItem item;
		Frame* frame;

		item = Mem.alloc!OutboundItem(this);    
		frame = &item.frame;
		
		frame.window_update = WindowUpdate(flags, stream_id, window_size_increment);
		
		addItem(item);
	}

	/*
	 * Adds SETTINGS frame.
	 */
	ErrorCode addSettings(FrameFlags flags, in Setting[] iva) 
	{
		OutboundItem item;
		Frame* frame;
		Setting[] iva_copy;
		size_t i;
		
		if (flags & FrameFlags.ACK) {
			if (iva.length != 0) {
				return ErrorCode.INVALID_ARGUMENT;
			}
		}
		else if (inflight_iva.length != 0) 
			return ErrorCode.TOO_MANY_INFLIGHT_SETTINGS;
		
		if (!iva.check())
			return ErrorCode.INVALID_ARGUMENT;
		
		item = Mem.alloc!OutboundItem(this);
		scope(failure) Mem.free(item);
		
		if (iva.length > 0)
			iva_copy = iva.copy();
		else
			iva_copy = null;
		
		scope(failure) if(iva_copy) Mem.free(iva_copy);
		
		if ((flags & FrameFlags.ACK) == 0) {
			if (iva.length > 0)
				inflight_iva = iva.copy();
			else
				inflight_iva = null;     
			
		}
		
		frame = &item.frame;
		
		frame.settings = Settings(flags, iva_copy);
		
		addItem(item);
		
		/* Extract Setting.MAX_CONCURRENT_STREAMS here and use it to refuse the incoming streams with RST_STREAM. */
		foreach_reverse(ref iv; iva)
		{
			if (iv.id == Setting.MAX_CONCURRENT_STREAMS) {
				pending_local_max_concurrent_stream = iv.value;
				break;
			}
			
		}

		return ErrorCode.OK;
	}

	/**
	 * Creates new stream in $(D Session) with stream ID |stream_id|,
	 * priority |pri_spec| and flags |flags|.  The |flags| is bitwise OR
	 * of StreamFlags.  Since this function is called when initial
	 * HEADERS is sent or received, these flags are taken from it.  The
	 * state of stream is set to |initial_state|. The |stream_user_data|
	 * is a pointer to the arbitrary user supplied data to be associated
	 * to this stream.
	 *
	 * If |initial_state| is StreamState.RESERVED, this function sets the
	 * StreamFlags.PUSH flag.
	 *
	 * This function returns a pointer to created new stream object.
	 */
	Stream openStream(int stream_id, StreamFlags flags, PrioritySpec pri_spec_in, StreamState initial_state, void *stream_user_data = null)
	{
		logDebug("Open stream: ", stream_id, " Pri_spec: ", pri_spec_in, " initial_state: ", initial_state);
		ErrorCode rv;
		Stream stream;
		Stream dep_stream = null;
		Stream root_stream;
		bool stream_alloc;
		PrioritySpec pri_spec_default;
		PrioritySpec pri_spec = pri_spec_in;
		
		stream = getStreamRaw(stream_id);
		
		if (stream) {
			assert(stream.state == StreamState.IDLE);
			assert(stream.inDepTree());
			detachIdleStream(stream);
			stream.remove();
		} else {
			if (is_server && initial_state != StreamState.IDLE && !isMyStreamId(stream_id))				
				adjustClosedStream(1);
			stream_alloc = true;
		}
		
		if (pri_spec.stream_id != 0) {
			logDebug("pri_spec stream_id != 0");
			dep_stream = getStreamRaw(pri_spec.stream_id);
			logDebug("dep_stream: ", &dep_stream);
			logDebug("in dep tree: ", dep_stream.inDepTree);
			if  (is_server && !dep_stream && idleStreamDetect(pri_spec.stream_id)) 
			{
				logDebug("pri_spec idle stream");
				/* Depends on idle stream, which does not exist in memory. Assign default priority for it. */            
				dep_stream = openStream(pri_spec.stream_id, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
			} else if (!dep_stream || !dep_stream.inDepTree()) {
				/* If dep_stream is not part of dependency tree, stream will get default priority. */
				pri_spec = pri_spec_default;
			}
		}
		
		if (initial_state == StreamState.RESERVED)
			flags |= StreamFlags.PUSH;

		if (stream_alloc) 
			stream = Mem.alloc!Stream(stream_id, flags, initial_state, pri_spec.weight, roots, 
									  remote_settings.initial_window_size, local_settings.initial_window_size, stream_user_data);
		scope(failure) if (stream_alloc) Mem.free(stream);

		if (stream_alloc)
			streams[stream_id] = stream;
		scope(failure) if (stream_alloc) streams.remove(stream_id);
		
		switch (initial_state) {
			case StreamState.RESERVED:
				if (isMyStreamId(stream_id)) {
					/* half closed (remote) */
					stream.shutdown(ShutdownFlag.RD);
				} else {
					/* half closed (local) */
					stream.shutdown(ShutdownFlag.WR);
				}
				/* Reserved stream does not count in the concurrent streams limit. That is one of the DOS vector. */
				break;
			case StreamState.IDLE:
				/* Idle stream does not count toward the concurrent streams limit. This is used as anchor node in dependency tree. */
				assert(is_server);
				keepIdleStream(stream);
				break;
			default:
				if (isMyStreamId(stream_id)) {
					++num_outgoing_streams;
				} else {
					++num_incoming_streams;
				}
		}
		
		/* We don't have to track dependency of received reserved stream */
		if (stream.shutFlags & ShutdownFlag.WR)
			return stream;
		
		if (pri_spec.stream_id == 0)
		{
			logDebug("Has no dep stream");
			
			++roots.num_streams;
			
			if (pri_spec.exclusive && roots.num_streams <= MAX_DEP_TREE_LENGTH)
				stream.makeTopmostRoot(this);
			else
				roots.add(stream);
			
			return stream;
		}


		/* TODO Client does not have to track dependencies of streams except
	     for those which have upload data.  Currently, we just track
	     everything. */    
		assert(dep_stream);
		
		root_stream = dep_stream.getRoot();
		
		if (root_stream.subStreams < MAX_DEP_TREE_LENGTH) {
			if (pri_spec.exclusive) {
				dep_stream.insert(stream);
			} else {
				dep_stream.add(stream);
			}
		} else {
			stream.weight = DEFAULT_WEIGHT;        
			roots.add(stream);
		}
		
		return stream;
	}

	/*
	 * Closes stream whose stream ID is |stream_id|. The reason of closure
	 * is indicated by the |error_code|. When closing the stream,
	 * on_stream_close_callback will be called.
	 *
	 * If the session is initialized as server and |stream| is incoming
	 * stream, stream is just marked closed and this function calls
	 * keepClosedStream() with |stream|.  Otherwise,
	 * |stream| will be deleted from memory.
	 *
	 * This function returns 0 if it succeeds, or one the following
	 * negative error codes:
	 *
	 * ErrorCode.INVALID_ARGUMENT
	 *     The specified stream does not exist.
	 * ErrorCode.CALLBACK_FAILURE
	 *     The callback function failed.
	 */
	ErrorCode closeStream(int stream_id, FrameError error_code)
	{
		Stream stream = getStream(stream_id);
			
		if (!stream) {
			return ErrorCode.INVALID_ARGUMENT;
		}
	
		LOGF("stream: stream(%s=%d close", stream, stream.id);
			
		if (stream.item) {
			OutboundItem item = stream.item;
			
			stream.detachItem(this);
							
			/* If item is queued, it will be deleted when it is popped
		       (prepareFrame() will fail).  If aob.item
		       points to this item, let active_outbound_item_reset()
		       free the item. */
			if (!item.queued && item != aob.item) {
				item.free();
				Mem.free(item);
			}
		}
		
		/* We call on_stream_close_callback even if stream.state is
		     StreamState.INITIAL. This will happen while sending request
		     HEADERS, a local endpoint receives RST_STREAM for that stream. It
		     may be PROTOCOL_ERROR, but without notifying stream closure will
		     hang the stream in a local endpoint.
		*/    
		if (!connector.onStreamExit(stream_id, error_code))
			return ErrorCode.CALLBACK_FAILURE;
		
		/* pushed streams which is not opened yet is not counted toward max concurrent limits */
		if ((stream.flags & StreamFlags.PUSH) == 0) {
			if (isMyStreamId(stream_id)) {
				--num_outgoing_streams;
			} else {
				--num_incoming_streams;
			}
		}

		/* Closes both directions just in case they are not closed yet */
		stream.flags = cast(StreamFlags)(stream.flags | StreamFlags.CLOSED);
		
		if  (is_server && stream.inDepTree())
		{
			/* On server side, retain stream at most MAX_CONCURRENT_STREAMS
		       combined with the current active incoming streams to make
		       dependency tree work better. */
			keepClosedStream(stream);
		} else {
			destroyStream(stream);
		}
		return ErrorCode.OK;
	}

	/*
	 * Deletes |stream| from memory.  After this function returns, stream
	 * cannot be accessed.
	 *
	 */
	void destroyStream(Stream stream)
	{
		LOGF("stream: destroy closed stream(%s=%d", stream, stream.id);
		
		stream.remove();
		
		streams.remove(stream.id);
		stream.free();
		Mem.free(stream);
	}

	/*
	 * Tries to keep incoming closed stream |stream|.  Due to the
	 * limitation of maximum number of streams in memory, |stream| is not
	 * closed and just deleted from memory (see destroyStream).
	 */
	void keepClosedStream(Stream stream)
	{
		LOGF("stream: keep closed stream(%s=%d, state=%d", stream, stream.id, stream.state);
		
		if (closed_stream_tail) {
			closed_stream_tail.closedNext = stream;
			stream.closedPrev = closed_stream_tail;
		} else {
			closed_stream_head = stream;
		}
		closed_stream_tail = stream;
		
		++num_closed_streams;
		
		adjustClosedStream(0);
	}

	/*
	 * Appends |stream| to linked list |session.idle_stream_head|.  We
	 * apply fixed limit for list size.  To fit into that limit, one or
	 * more oldest streams are removed from list as necessary.
	 */
	void keepIdleStream(Stream stream)
	{
		LOGF("stream: keep idle stream(%s=%d, state=%d", stream, stream.id, stream.state);
		
		if (idle_stream_tail) {
			idle_stream_tail.closedNext = stream;
			stream.closedPrev = idle_stream_tail;
		} else {
			idle_stream_head = stream;
		}
		idle_stream_tail = stream;
		
		++num_idle_streams;
		
		adjustIdleStream();
	}

	/*
	 * Detaches |stream| from idle streams linked list.
	 */

	void detachIdleStream(Stream stream) 
	{
		Stream prev_stream;
		Stream next_stream;
		
		LOGF("stream: detach idle stream(%s=%d, state=%d", stream, stream.id, stream.state);
		
		prev_stream = stream.closedPrev;
		next_stream = stream.closedNext;
		
		if (prev_stream) {
			prev_stream.closedNext = next_stream;
		} else {
			idle_stream_head = next_stream;
		}
		
		if (next_stream) {
			next_stream.closedPrev = prev_stream;
		} else {
			idle_stream_tail = prev_stream;
		}
		
		stream.closedPrev = null;
		stream.closedNext = null;
		
		--num_idle_streams;
	}

	/*
	 * Deletes closed stream to ensure that number of incoming streams
	 * including active and closed is in the maximum number of allowed
	 * stream.  If |offset| is nonzero, it is decreased from the maximum
	 * number of allowed stream when comparing number of active and closed
	 * stream and the maximum number.
	 */
	void adjustClosedStream(int offset) 
	{
		size_t num_stream_max;
		
		num_stream_max = min(local_settings.max_concurrent_streams, pending_local_max_concurrent_stream);
		
		LOGF("stream: adjusting kept closed streams  num_closed_streams=%d, num_incoming_streams=%d, max_concurrent_streams=%d",
				num_closed_streams, num_incoming_streams, num_stream_max);

		while (num_closed_streams > 0 && num_closed_streams + num_incoming_streams + offset > num_stream_max)
		{
			Stream head_stream;
			
			head_stream = closed_stream_head;
			
			assert(head_stream);
			
			closed_stream_head = head_stream.closedNext;
			
			if (closed_stream_head) 
				closed_stream_head.closedPrev = null;
			else
				closed_stream_tail = null;
			
			destroyStream(head_stream);
			/* head_stream is now freed */
			--num_closed_streams;
		}
	}

	/*
	 * Deletes idle stream to ensure that number of idle streams is in
	 * certain limit.
	 */
	void adjustIdleStream() 
	{
		size_t _max;
		
		/* Make minimum number of idle streams 2 so that allocating 2
	     streams at once is easy.  This happens when PRIORITY frame to
	     idle stream, which depends on idle stream which does not
	     exist. */
		_max = max(2, min(local_settings.max_concurrent_streams, pending_local_max_concurrent_stream));
		
		LOGF("stream: adjusting kept idle streams num_idle_streams=%d, max=%d", num_idle_streams, _max);
		
		while (num_idle_streams > _max) {
			Stream head;
			
			head = idle_stream_head;
			assert(head);
			
			idle_stream_head = head.closedNext;
			
			if (idle_stream_head) {
				idle_stream_head.closedPrev = null;
			} else {
				idle_stream_tail = null;
			}
			
			destroyStream(head);
			/* head is now destroyed */
			--num_idle_streams;
		}
	}

	/*
	 * Closes stream with stream ID |stream_id| if both transmission and
	 * reception of the stream were disallowed. The |error_code| indicates
	 * the reason of the closure.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.INVALID_ARGUMENT
	 *   The stream is not found.
	 * ErrorCode.CALLBACK_FAILURE
	 *   The callback function failed.
	 */
	ErrorCode closeStreamIfShutRdWr(Stream stream)
	{
		if ((stream.shutFlags & ShutdownFlag.RDWR) == ShutdownFlag.RDWR)
			return closeStream(stream.id, FrameError.NO_ERROR);
		return ErrorCode.OK;
	}

	void endRequestHeadersReceived(Frame frame, Stream stream)
	{
		if (frame.hd.flags & FrameFlags.END_STREAM) {
			stream.shutdown(ShutdownFlag.RD);
		}
		/* Here we assume that stream is not shutdown in ShutdownFlag.WR */
	}

	ErrorCode endResponseHeadersReceived(Frame frame, Stream stream) 
	{
		if (frame.hd.flags & FrameFlags.END_STREAM) {
			/* This is the last frame of this stream, so disallow further receptions. */
			stream.shutdown(ShutdownFlag.RD);
			return closeStreamIfShutRdWr(stream);
		}

		return ErrorCode.OK;
	}

	ErrorCode endHeadersReceived(Frame frame, Stream stream)
	{
		if (frame.hd.flags & FrameFlags.END_STREAM) {
			stream.shutdown(ShutdownFlag.RD);
			return closeStreamIfShutRdWr(stream);
		}
		return ErrorCode.OK;
	}


	ErrorCode onRequestHeaders(Frame frame) 
	{
		ErrorCode rv;
		Stream stream;
		if (frame.hd.stream_id == 0) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "request HEADERS: stream_id == 0");
		}
		
		/* If client recieves idle stream from server, it is invalid
	     regardless stream ID is even or odd.  This is because client is
	     not expected to receive request from server. */
		if (!is_server) {
			if (idleStreamDetect(frame.hd.stream_id)) {
				return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "request HEADERS: client received request");
			}
			
			return ErrorCode.IGN_HEADER_BLOCK;
		}
		
		if (!isNewPeerStreamId(frame.hd.stream_id)) 
		{
			/* The spec says if an endpoint receives a HEADERS with invalid
		       stream ID, it MUST issue connection error with error code
		       PROTOCOL_ERROR.  But we could get trailer HEADERS after we have
		       sent RST_STREAM to this stream and peer have not received it.
		       Then connection error is too harsh.  It means that we only use
		       connection error if stream ID refers idle stream.  OTherwise we
		       just ignore HEADERS for now. */
			if (idleStreamDetect(frame.hd.stream_id)) {
				return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "request HEADERS: invalid stream_id");
			}
			
			return ErrorCode.IGN_HEADER_BLOCK;
		}

		last_recv_stream_id = frame.hd.stream_id;
		
		if (goaway_flags & GoAwayFlags.SENT) {
			/* We just ignore stream after GOAWAY was queued */
			return ErrorCode.IGN_HEADER_BLOCK;
		}
		
		if (isIncomingConcurrentStreamsMax()) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "request HEADERS: max concurrent streams exceeded");
		}
		
		if (frame.headers.pri_spec.stream_id == frame.hd.stream_id) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "request HEADERS: depend on itself");
		}
		
		if (isIncomingConcurrentStreamsPendingMax()) {
			return handleInflateInvalidStream(frame, FrameError.REFUSED_STREAM);
		}

		stream = openStream(frame.hd.stream_id, StreamFlags.NONE, frame.headers.pri_spec, StreamState.OPENING, null);
		last_proc_stream_id = last_recv_stream_id;

		if (!callOnHeaders(frame))
			return ErrorCode.CALLBACK_FAILURE;

		return ErrorCode.OK;
	}
	
	ErrorCode onResponseHeaders(Frame frame, Stream stream) 
	{
		ErrorCode rv;
		/* This function is only called if stream.state == StreamState.OPENING and stream_id is local side initiated. */
		assert(stream.state == StreamState.OPENING && isMyStreamId(frame.hd.stream_id));
		if (frame.hd.stream_id == 0) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "response HEADERS: stream_id == 0");
		}
		if (stream.shutFlags & ShutdownFlag.RD) {
			/* half closed (remote): from the spec:

	           If an endpoint receives additional frames for a stream that is
	           in this state it MUST respond with a stream error (Section
	           5.4.2) of type STREAM_CLOSED.
	        */
			return handleInflateInvalidStream(frame, FrameError.STREAM_CLOSED);
		}
		stream.state = StreamState.OPENED;
		if (!callOnHeaders(frame))
			return ErrorCode.CALLBACK_FAILURE;
		return ErrorCode.OK;
	}

	ErrorCode onPushResponseHeaders(Frame frame, Stream stream) 
	{
		ErrorCode rv;
		assert(stream.state == StreamState.RESERVED);
		if (frame.hd.stream_id == 0) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "push response HEADERS: stream_id == 0");
		}
		if (goaway_flags) {
			/* We don't accept new stream after GOAWAY is sent or received. */
			return ErrorCode.IGN_HEADER_BLOCK;
		}
		
		if (isIncomingConcurrentStreamsMax()) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "push response HEADERS: max concurrent streams exceeded");
		}
		if (isIncomingConcurrentStreamsPendingMax()) {
			return handleInflateInvalidStream(frame, FrameError.REFUSED_STREAM);
		}
		
		stream.promiseFulfilled();
		++num_incoming_streams;
		if (!callOnHeaders(frame))
			return ErrorCode.CALLBACK_FAILURE;
		return ErrorCode.OK;
	}

	/*
	 * Called when HEADERS is received, assuming |frame| is properly
	 * initialized.  This function will first validate received frame and
	 * then open stream sending it through callback functions.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.IGN_HEADER_BLOCK
	 *     Frame was rejected and header block must be decoded but
	 *     result must be ignored.
	 * ErrorCode.CALLBACK_FAILURE
	 *     The read_callback failed
	 */
	ErrorCode onHeaders(Frame frame, Stream stream) 
	{
		ErrorCode rv;
		if (frame.hd.stream_id == 0) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "HEADERS: stream_id == 0");
		}
		if (stream.state == StreamState.RESERVED) 
		{
			/* reserved. The valid push response HEADERS is processed by
		       onPushResponseHeaders(). This
		       generic HEADERS is called invalid cases for HEADERS against
		       reserved state. */
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "HEADERS: stream in reserved");
		}
		if ((stream.shutFlags & ShutdownFlag.RD)) {
			/* half closed (remote): from the spec:

		       If an endpoint receives additional frames for a stream that is
		       in this state it MUST respond with a stream error (Section
		       5.4.2) of type STREAM_CLOSED.
		    */
			return handleInflateInvalidStream(frame, FrameError.STREAM_CLOSED);
		}
		if (isMyStreamId(frame.hd.stream_id)) {
			if (stream.state == StreamState.OPENED) {
				if (!callOnHeaders(frame))
					return ErrorCode.CALLBACK_FAILURE;
				return ErrorCode.OK;
			} else if (stream.state == StreamState.CLOSING) {
				/* This is race condition. StreamState.CLOSING indicates
		         that we queued RST_STREAM but it has not been sent. It will
		         eventually sent, so we just ignore this frame. */
				return ErrorCode.IGN_HEADER_BLOCK;
			} else {
				return handleInflateInvalidStream(frame, FrameError.PROTOCOL_ERROR);
			}
		}
		/* If this is remote peer initiated stream, it is OK unless it
		   has sent END_STREAM frame already. But if stream is in
		   StreamState.CLOSING, we discard the frame. This is a race
		   condition. */
		if (stream.state != StreamState.CLOSING) 
		{
			if (!callOnHeaders(frame))
				return ErrorCode.CALLBACK_FAILURE;
			return ErrorCode.OK;
		}
		return ErrorCode.IGN_HEADER_BLOCK;
	}

	/*
	 * Called when PRIORITY is received, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *     The read_callback failed
	 */
	ErrorCode onPriority(Frame frame) 
	{
		ErrorCode rv;
		Stream stream;
		
		if (frame.hd.stream_id == 0) {
			return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PRIORITY: stream_id == 0");
		}
		
		if (!is_server) {
			/* Re-prioritization works only in server */	
			bool ok = callOnFrame(frame);
			if (!ok)
				return ErrorCode.CALLBACK_FAILURE;
			return ErrorCode.OK;
		}
		
		stream = getStreamRaw(frame.hd.stream_id);
		
		if (!stream) {
			/* PRIORITY against idle stream can create anchor node in dependency tree. */
			if (!idleStreamDetect(frame.hd.stream_id)) {
				return ErrorCode.OK;
			}
			
			stream = openStream(frame.hd.stream_id, StreamFlags.NONE, frame.priority.pri_spec, StreamState.IDLE, null);
		} else
			reprioritizeStream(stream, frame.priority.pri_spec);
		
		bool ok = callOnFrame(frame);
		if (!ok)
			return ErrorCode.CALLBACK_FAILURE;
		return ErrorCode.OK;
	}

	/*
	 * Called when RST_STREAM is received, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one the following
	 * negative error codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *     The read_callback failed
	 */
	ErrorCode onRstStream(Frame frame) 
	{
		ErrorCode rv;
		Stream stream;
		if (frame.hd.stream_id == 0) {
			return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "RST_STREAM: stream_id == 0");
		}
		stream = getStream(frame.hd.stream_id);
		if (!stream) {
			if (idleStreamDetect(frame.hd.stream_id)) {
				return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "RST_STREAM: stream in idle");
			}
		}
		
		bool ok = callOnFrame(frame);
		if (!ok)
			return ErrorCode.CALLBACK_FAILURE;
		
		rv = closeStream(frame.hd.stream_id, frame.rst_stream.error_code);
		if (isFatal(rv)) {
			return rv;
		}
		return ErrorCode.OK;
	}

	/*
	 * Called when SETTINGS is received, assuming |frame| is properly
	 * initialized. If |noack| is non-zero, SETTINGS with ACK will not be
	 * submitted. If |frame| has NGFrameFlags.ACK flag set, no SETTINGS
	 * with ACK will not be submitted regardless of |noack|.
	 *
	 * This function returns 0 if it succeeds, or one the following
	 * negative error codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *     The read_callback failed
	 */

	ErrorCode onSettings(Frame frame, bool noack) 
	{
		ErrorCode rv;
		size_t i;
		
		if (frame.hd.stream_id != 0) {
			return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "SETTINGS: stream_id != 0");
		}
		if (frame.hd.flags & FrameFlags.ACK) {
			if (frame.settings.iva.length != 0) {
				return handleInvalidConnection(frame, FrameError.FRAME_SIZE_ERROR, "SETTINGS: ACK and payload != 0");
			}
			if (!inflight_iva) {
				return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "SETTINGS: unexpected ACK");
			}
			rv = updateLocalSettings(inflight_iva);
			Mem.free(inflight_iva);
			inflight_iva = null;
			if (rv != ErrorCode.OK) {
				FrameError error_code = FrameError.INTERNAL_ERROR;
				if (isFatal(rv)) {
					return rv;
				}
				if (rv == ErrorCode.HEADER_COMP) {
					error_code = FrameError.COMPRESSION_ERROR;
				}
				return handleInvalidConnection(frame, error_code, null);
			}
			bool ok = callOnFrame(frame);
			if (!ok)
				return ErrorCode.CALLBACK_FAILURE;
			return ErrorCode.OK;
		}
		
		for (i = 0; i < frame.settings.iva.length; ++i) {
			Setting entry = frame.settings.iva[i];
			
			with(Setting) switch (entry.id) {
				case HEADER_TABLE_SIZE:
					
					if (entry.value > MAX_HEADER_TABLE_SIZE) {
						return handleInvalidConnection(frame, FrameError.COMPRESSION_ERROR, "SETTINGS: too large Setting.HEADER_TABLE_SIZE");
					}
					
					hd_deflater.changeTableSize(entry.value);
					
					remote_settings.header_table_size = entry.value;
					
					break;
				case ENABLE_PUSH:
					
					if (entry.value != 0 && entry.value != 1) {
						return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "SETTINGS: invalid Setting.ENABLE_PUSH");
					}
					
					if (!is_server && entry.value != 0) {
						return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "SETTINGS: server attempted to enable push");
					}
					
					remote_settings.enable_push = entry.value;
					
					break;
				case MAX_CONCURRENT_STREAMS:
					
					remote_settings.max_concurrent_streams = entry.value;
					
					break;
				case INITIAL_WINDOW_SIZE:                
					/* Update the initial window size of the all active streams */
					/* Check that initial_window_size < (1u << 31) */
					if (entry.value > MAX_WINDOW_SIZE) {
						return handleInvalidConnection(frame, FrameError.FLOW_CONTROL_ERROR, "SETTINGS: too large Setting.INITIAL_WINDOW_SIZE");
					}
					
					rv = updateRemoteInitialWindowSize(entry.value);
					
					if (isFatal(rv)) {
						return rv;
					}
					
					if (rv != ErrorCode.OK) {
						return handleInvalidConnection(frame, FrameError.FLOW_CONTROL_ERROR, null);
					}
					
					remote_settings.initial_window_size = entry.value;
					
					break;
				case MAX_FRAME_SIZE:
					
					if (entry.value < MAX_FRAME_SIZE_MIN ||
						entry.value > MAX_FRAME_SIZE_MAX) {
						return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "SETTINGS: invalid Setting.MAX_FRAME_SIZE");
					}
					
					remote_settings.max_frame_size = entry.value;
					
					break;
				case MAX_HEADER_LIST_SIZE:
					
					remote_settings.max_header_list_size = entry.value;
					
					break;
				default: break;
			}
		}
		
		if (!noack && !isClosing()) {
			rv = addSettings(FrameFlags.ACK, null);
			
			if (rv != ErrorCode.OK) {
				if (isFatal(rv)) {
					return rv;
				}
				
				return handleInvalidConnection(frame, FrameError.INTERNAL_ERROR, null);
			}
		}
		bool ok = callOnFrame(frame);
		if (!ok)
			return ErrorCode.CALLBACK_FAILURE;
		return ErrorCode.OK;
	}
	/*
	 * Called when PUSH_PROMISE is received, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.IGN_HEADER_BLOCK
	 *     Frame was rejected and header block must be decoded but
	 *     result must be ignored.
	 * ErrorCode.CALLBACK_FAILURE
	 *     The read_callback failed
	 */

	ErrorCode onPushPromise(Frame frame) 
	{
		ErrorCode rv;
		Stream stream;
		Stream promised_stream;
		PrioritySpec pri_spec;
		
		if (frame.hd.stream_id == 0) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: stream_id == 0");
		}
		if (is_server || local_settings.enable_push == 0) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: push disabled");
		}
		if (goaway_flags) {
			/* We just dicard PUSH_PROMISE after GOAWAY is sent or received. */
			return ErrorCode.IGN_HEADER_BLOCK;
		}
		
		if (!isMyStreamId(frame.hd.stream_id)) {
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: invalid stream_id");
		}
		
		if (!isNewPeerStreamId(frame.push_promise.promised_stream_id)) {
			/* The spec says if an endpoint receives a PUSH_PROMISE with
		       illegal stream ID is subject to a connection error of type
		       PROTOCOL_ERROR. */
			return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: invalid promised_stream_id");
		}
		last_recv_stream_id = frame.push_promise.promised_stream_id;
		stream = getStream(frame.hd.stream_id);
		if (!stream || stream.state == StreamState.CLOSING) {
			if (!stream) {
				if (idleStreamDetect(frame.hd.stream_id)) {
					return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: stream in idle");
				}
			}
			addRstStream(frame.push_promise.promised_stream_id, FrameError.REFUSED_STREAM);
			return ErrorCode.IGN_HEADER_BLOCK;
		}
		if (stream.shutFlags & ShutdownFlag.RD) {
			if (!connector.onInvalidFrame(frame, FrameError.PROTOCOL_ERROR)) 
				return ErrorCode.CALLBACK_FAILURE;

			addRstStream(frame.push_promise.promised_stream_id, FrameError.PROTOCOL_ERROR);
			return ErrorCode.IGN_HEADER_BLOCK;
		}
		
		/* TODO: It is unclear reserved stream depends on associated stream with or without exclusive flag set */
		pri_spec = PrioritySpec(stream.id, DEFAULT_WEIGHT, 0);
		
		promised_stream = openStream(frame.push_promise.promised_stream_id, StreamFlags.NONE, pri_spec, StreamState.RESERVED, null);
		
		last_proc_stream_id = last_recv_stream_id;
		if (!callOnHeaders(frame))
			return ErrorCode.CALLBACK_FAILURE;
		return ErrorCode.OK;
	}

	/*
	 * Called when PING is received, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *   The callback function failed.
	 */
	ErrorCode onPing(Frame frame) 
	{
		int rv = 0;
		if (frame.hd.stream_id != 0) {
			return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PING: stream_id != 0");
		}
		if ((frame.hd.flags & FrameFlags.ACK) == 0 && !isClosing()) 
		{
			/* Peer sent ping, so ping it back */
			addPing(FrameFlags.ACK, frame.ping.opaque_data);
		}
		bool ok = callOnFrame(frame);
		if (!ok)
			return ErrorCode.CALLBACK_FAILURE;
		return ErrorCode.OK;
	}

	/*
	 * Called when GOAWAY is received, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *   The callback function failed.
	 */
	ErrorCode onGoAway(Frame frame) 
	{		
		if (frame.hd.stream_id != 0) 
		{
			return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "GOAWAY: stream_id != 0");
		}

		/* Spec says Endpoints MUST NOT increase the value they send in the last stream identifier. */
		if ((frame.goaway.last_stream_id > 0 && !isMyStreamId(frame.goaway.last_stream_id)) ||
			 remote_last_stream_id < frame.goaway.last_stream_id) 
		{
			return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "GOAWAY: invalid last_stream_id");
		}
		
		goaway_flags |= GoAwayFlags.RECV;
		
		remote_last_stream_id = frame.goaway.last_stream_id;

		bool ok = callOnFrame(frame);
		if (!ok)
			return ErrorCode.CALLBACK_FAILURE;
		
		return closeStreamOnGoAway(frame.goaway.last_stream_id, 0);
	}

	/*
	 * Called when WINDOW_UPDATE is recieved, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * ErrorCode.CALLBACK_FAILURE
	 *   The callback function failed.
	 */
	ErrorCode onWindowUpdate(Frame frame) 
	{
		if (frame.hd.stream_id == 0)
		{
			/* Handle connection-level flow control */
			if (frame.window_update.window_size_increment == 0)		
				return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, null);
			
			if (MAX_WINDOW_SIZE - frame.window_update.window_size_increment < remote_window_size)
				return handleInvalidConnection(frame, FrameError.FLOW_CONTROL_ERROR, null);
			
			remote_window_size += frame.window_update.window_size_increment;
			
		} else {
			/* handle stream window update */
			Stream stream = getStream(frame.hd.stream_id);
			
			if (!stream) {
				if (idleStreamDetect(frame.hd.stream_id))
					return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "WINDOW_UPDATE to idle stream");
				return ErrorCode.OK;
			}
			
			if (isReservedRemote(stream)) 
				return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "WINDOW_UPADATE to reserved stream");
			
			if (frame.window_update.window_size_increment == 0) 
				return handleInvalidStream(frame, FrameError.PROTOCOL_ERROR);
			
			if (MAX_WINDOW_SIZE - frame.window_update.window_size_increment < stream.remoteWindowSize)
				return handleInvalidStream(frame, FrameError.FLOW_CONTROL_ERROR);
			
			stream.remoteWindowSize = stream.remoteWindowSize + frame.window_update.window_size_increment;
			
			if (stream.remoteWindowSize > 0 && stream.isDeferredByFlowControl())        
				stream.resumeDeferredItem(StreamFlags.DEFERRED_FLOW_CONTROL, this);
		}
		
		bool ok = callOnFrame(frame);

		if (!ok)
			return ErrorCode.CALLBACK_FAILURE;
		
		return ErrorCode.OK;
	}

	/*
	 * Called when DATA is received, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * ErrorCode.CALLBACK_FAILURE
	 *   The callback function failed.
	 */
	ErrorCode onData(Frame frame) 
	{
		ErrorCode rv;
		bool call_cb = true;
		Stream stream = getStream(frame.hd.stream_id);
		
		/* We don't call on_frame_recv_callback if stream has been closed already or being closed. */
		if (!stream || stream.state == StreamState.CLOSING) {
			/* This should be treated as stream error, but it results in lots
		       of RST_STREAM. So just ignore frame against nonexistent stream
		       for now. */
			return ErrorCode.OK;
		}
		
		if (isHTTPMessagingEnabled() && (frame.hd.flags & FrameFlags.END_STREAM)) 
		{
			if (!stream.validateRemoteEndStream()) {
				call_cb = false;
				addRstStream(stream.id, FrameError.PROTOCOL_ERROR);
			}
		}
		
		if (call_cb) {
			bool ok = callOnFrame(frame);
			if (!ok) {
				return ErrorCode.CALLBACK_FAILURE;
			}
		}
		
		if (frame.hd.flags & FrameFlags.END_STREAM)
		{
			stream.shutdown(ShutdownFlag.RD);
			rv = closeStreamIfShutRdWr(stream);
			if (isFatal(rv)) {
				return rv;
			}
		}
		return ErrorCode.OK;
	}

	/*
	 * Packs DATA frame |frame| in wire frame format and stores it in
	 * |bufs|.  Payload will be read using |aux_data.data_prd|.  The
	 * length of payload is at most |datamax| bytes.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.DEFERRED
	 *     The DATA frame is postponed.
	 * ErrorCode.TEMPORAL_CALLBACK_FAILURE
	 *     The read_callback failed (stream error).
	 * ErrorCode.CALLBACK_FAILURE
	 *     The read_callback failed (session error).
	 */
	ErrorCode packData(Buffers bufs, int datamax, Frame frame, ref DataAuxData aux_data) {
		ErrorCode rv;
		DataFlags data_flags;
		int payloadlen;
		int padded_payloadlen;
		Buffer* buf;
		size_t max_payloadlen;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.cur.buf;
		
		Stream stream;
			
		stream = getStream(frame.hd.stream_id);

		if (!stream)
			return ErrorCode.INVALID_ARGUMENT;
		
		payloadlen = connector.maxFrameSize(frame.hd.type, stream.id, remote_window_size, stream.remoteWindowSize, remote_settings.max_frame_size);
		
		LOGF("send: read_length_callback=%d", payloadlen);
		
		payloadlen = enforceFlowControlLimits(stream, payloadlen);
		
		LOGF("send: read_length_callback after flow control=%d", payloadlen);
		
		if (payloadlen <= 0) {
			return ErrorCode.CALLBACK_FAILURE;
		}
		
		if (payloadlen > buf.available) {
			import core.exception : OutOfMemoryError;
			/* Resize the current buffer(s).  The reason why we do +1 for buffer size is for possible padding field. */
			try {
				aob.framebufs.realloc(FRAME_HDLEN + 1 + payloadlen);
				assert(aob.framebufs == bufs);
				buf = &bufs.cur.buf;
			} catch (OutOfMemoryError oom) {
				LOGF("send: realloc buffer failed rv=%d", rv);
				/* If reallocation failed, old buffers are still in tact.  So use safe limit. */
				payloadlen = datamax;
				
				LOGF("send: use safe limit payloadlen=%d", payloadlen);
			}

		}

		datamax = payloadlen;
		
		/* Current max DATA length is less then buffer chunk size */
		assert(buf.available >= datamax);
		
		data_flags = DataFlags.NONE;

		// TODO: Deferred and all
		payloadlen = aux_data.data_prd.read_callback(frame.hd.stream_id, buf.pos[0 .. datamax], data_flags, aux_data.data_prd.source);
		
		if (payloadlen == ErrorCode.DEFERRED ||
			payloadlen == ErrorCode.TEMPORAL_CALLBACK_FAILURE)
		{
			import libhttp2.helpers : toString;
			LOGF("send: DATA postponed due to %s", toString(cast(ErrorCode)payloadlen));
			
			return cast(ErrorCode)payloadlen;
		}
		
		if (payloadlen < 0 || datamax < cast(size_t)payloadlen) 
		{
			/* This is the error code when callback is failed. */
			return ErrorCode.CALLBACK_FAILURE;
		}
		
		buf.last = buf.pos + payloadlen;
		buf.pos -= FRAME_HDLEN;
		
		/* Clear flags, because this may contain previous flags of previous DATA */
		frame.hd.flags = FrameFlags.NONE;
		
		if (data_flags & DataFlags.EOF) {
			aux_data.eof = true;
			if (aux_data.flags & FrameFlags.END_STREAM)
				frame.hd.flags |= FrameFlags.END_STREAM;
		}
		
		frame.hd.length = payloadlen;
		frame.data.padlen = 0;
		
		max_payloadlen = min(datamax, frame.hd.length + MAX_PADLEN);
		
		padded_payloadlen = callSelectPadding(frame, max_payloadlen);
		
		if (isFatal(cast(int)padded_payloadlen)) {
			return cast(ErrorCode)padded_payloadlen;
		}
		
		frame.data.padlen = padded_payloadlen - payloadlen;
		
		frame.hd.pack((*buf)[]);
		
		frame.hd.addPad(bufs, frame.data.padlen);
		
		return ErrorCode.OK;
	}
	/*
	 * This function is called when HTTP header field |hf| in |frame| is
	 * received for |stream|.  This function will validate |hf| against
	 * the current state of stream.  This function returns true if it
	 * succeeds, or false.
	 */
	bool validateHeaderField(Stream stream, in Frame frame, HeaderField hf, bool trailer)
	{
		if (!hf.validateName() || !hf.validateValue())
			return false;
		
		if (is_server || frame.hd.type == FrameType.PUSH_PROMISE)
			return hf.validateRequestHeader(stream, trailer);

		return hf.validateResponseHeader(stream, trailer);
	}

	/*
	 * Pops and returns next item to send. If there is no such item,
	 * returns null.  This function takes into account max concurrent
	 * streams. That means if session.ob_pq is empty but
	 * session.ob_ss_pq has item and max concurrent streams is reached,
	 * then this function returns null.
	 */
	OutboundItem popNextOutboundItem() {
		OutboundItem item;
		OutboundItem headers_item;
		
		if (ob_pq.empty) {
			if (ob_ss_pq.empty) {
				if (remote_window_size == 0 || ob_da_pq.empty)
					return null;
				item = ob_da_pq.top;
				ob_da_pq.pop(); 
				item.queued = 0;
				return item;
			}
			
			/* Pop item only when concurrent connection limit is not reached */
			if (isOutgoingConcurrentStreamsMax()) {
				if (remote_window_size == 0 || ob_da_pq.empty)
					return null;
				
				item = ob_da_pq.top;
				ob_da_pq.pop();
				item.queued = 0;
				return item;
			}
			
			item = ob_ss_pq.top;
			ob_ss_pq.pop();			
			item.queued = 0;			
			return item;
		}
		
		if (ob_ss_pq.empty) {
			item = ob_pq.top;
			ob_pq.pop();			
			item.queued = 0;			
			return item;
		}
		
		item = ob_pq.top;
		headers_item = ob_ss_pq.top;
		
		if (isOutgoingConcurrentStreamsMax() ||
			item.weight > headers_item.weight ||
			(item.weight == headers_item.weight && item.seq < headers_item.seq)) 
		{
			ob_pq.pop();			
			item.queued = 0;
			return item;
		}
		
		ob_ss_pq.pop();		
		headers_item.queued = 0;		
		return headers_item;
	}
	
	/*
	 * Returns next item to send. If there is no such item, this function
	 * returns null.  This function takes into account max concurrent
	 * streams. That means if session.ob_pq is empty but
	 * session.ob_ss_pq has item and max concurrent streams is reached,
	 * then this function returns null.
	 */
	OutboundItem getNextOutboundItem() {
		OutboundItem item;
		OutboundItem headers_item;
		
		if (ob_pq.empty) {
			if (ob_ss_pq.empty) {
				if (remote_window_size == 0 || ob_da_pq.empty)
					return null;				
				
				return ob_da_pq.top;
			}
			
			/* Return item only when concurrent connection limit is not reached */
			if (isOutgoingConcurrentStreamsMax()) {
				if (remote_window_size == 0 || ob_da_pq.empty)
					return null;				
				
				return ob_da_pq.top;
			}
			
			return ob_ss_pq.top;
		}
		
		if (ob_ss_pq.empty) {
			return ob_pq.top;
		}
		
		item = ob_pq.top;
		headers_item = ob_ss_pq.top;
		
		if (isOutgoingConcurrentStreamsMax() || item.weight > headers_item.weight ||
		   (item.weight == headers_item.weight && item.seq < headers_item.seq))
		{
			return item;
		}
		
		return headers_item;
	}
	
	/*
	 * Updates local settings with the |iva|. The number of elements in the
	 * array pointed by the |iva| is given by the |iva.length|.  This function
	 * assumes that the all settings_id member in |iva| are in range 1 to
	 * Setting.MAX_HEADER_LIST_SIZE, inclusive.
	 *
	 * While updating individual stream's local window size, if the window
	 * size becomes strictly larger than max_WINDOW_SIZE,
	 * RST_STREAM is issued against such a stream.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.HEADER_COMP
	 *     The header table size is out of range
	 */
	ErrorCode updateLocalSettings(Setting[] iva) 
	{
		ErrorCode rv;
		size_t i;
		int new_initial_window_size = -1;
		int header_table_size = -1;
		bool header_table_size_seen;
		/* Use the value last seen. */
		foreach(iv; iva) {
			switch (iv.id) {
				case Setting.HEADER_TABLE_SIZE:
					header_table_size_seen = true;
					header_table_size = iv.value;
					break;
				case Setting.INITIAL_WINDOW_SIZE:
					new_initial_window_size = iv.value;
					break;
				default: break;
			}
		}
		if (header_table_size_seen)
			hd_inflater.changeTableSize(header_table_size);

		if (new_initial_window_size != -1) {
			rv = updateLocalInitialWindowSize(new_initial_window_size, local_settings.initial_window_size);
			if (rv != ErrorCode.OK) {
				return rv;
			}
		}
		
		foreach(iv; iva) {
			with(Setting) switch (iv.id) {
				case HEADER_TABLE_SIZE:
					local_settings.header_table_size = iv.value;
					break;
				case ENABLE_PUSH:
					local_settings.enable_push = iv.value;
					break;
				case MAX_CONCURRENT_STREAMS:
					local_settings.max_concurrent_streams = iv.value;
					break;
				case INITIAL_WINDOW_SIZE:
					local_settings.initial_window_size = iv.value;
					break;
				case MAX_FRAME_SIZE:
					local_settings.max_frame_size = iv.value;
					break;
				case MAX_HEADER_LIST_SIZE:
					local_settings.max_header_list_size = iv.value;
					break;
				default: break;
			}
		}
		
		pending_local_max_concurrent_stream = INITIAL_MAX_CONCURRENT_STREAMS;
		
		return ErrorCode.OK;
	}

	/*
	 * Re-prioritize |stream|. The new priority specification is |pri_spec|.
	 */
	void reprioritizeStream(Stream stream, ref PrioritySpec pri_spec) 
	{
		Stream dep_stream;
		Stream root_stream;
		PrioritySpec pri_spec_default;
		
		if (!stream.inDepTree())
			return;
		
		if (pri_spec.stream_id == stream.id) {
			terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "depend on itself");
			return;
		}
		
		if (pri_spec.stream_id != 0) {
			dep_stream = getStreamRaw(pri_spec.stream_id);
			
			if  (is_server && !dep_stream && idleStreamDetect(pri_spec.stream_id))
			{ 				
				dep_stream = openStream(pri_spec.stream_id, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
				
			} else if (!dep_stream || !dep_stream.inDepTree()) {
				pri_spec = pri_spec_default;
			}
		}
		
		if (pri_spec.stream_id == 0) {
			stream.removeSubtree();
			
			/* We have to update weight after removing stream from tree */
			stream.weight = pri_spec.weight;
			
			if (pri_spec.exclusive &&
				roots.num_streams <= MAX_DEP_TREE_LENGTH) {
				
				stream.makeTopmostRoot(this);
			} else {
				stream.makeRoot(this);
			}
			
			return;
		}
		
		assert(dep_stream);
		
		if (stream.subtreeContains(dep_stream)) {
			LOGF("stream: cycle detected, dep_stream(%s=%d stream(%s)=%d", dep_stream, dep_stream.id, stream, stream.id);
			
			dep_stream.removeSubtree();
			dep_stream.makeRoot(this);
		}
		
		stream.removeSubtree();
		
		/* We have to update weight after removing stream from tree */
		stream.weight = pri_spec.weight;
		
		root_stream = dep_stream.getRoot();
		
		if (root_stream.subStreams + stream.subStreams > MAX_DEP_TREE_LENGTH) 
		{
			stream.weight = DEFAULT_WEIGHT;
			
			stream.makeRoot(this);
			} else {
				if (pri_spec.exclusive)
				dep_stream.insertSubtree(stream, this);
			else
				dep_stream.addSubtree(stream, this);
		}
	}

	/*
	 * Terminates current $(D Session) with the |error_code|.  The |reason|
	 * is null-terminated debug string.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.INVALID_ARGUMENT
	 *     The |reason| is too long.
	 */	
	ErrorCode terminateSessionWithReason(FrameError error_code, string reason)
	{
		return terminateSession(last_proc_stream_id, error_code, reason);
	}
	
	/*
	 * Returns true if the number of outgoing opened streams is larger than or equal to
	 * remote_settings.max_concurrent_streams.
	 */
	bool isOutgoingConcurrentStreamsMax() 
	{
		return remote_settings.max_concurrent_streams <= num_outgoing_streams;
	}
	
	/*
	 * Returns true if the number of incoming opened streams is larger
	 * than or equal to
	 * local_settings.max_concurrent_streams.
	 */
	bool isIncomingConcurrentStreamsMax() 
	{
		return local_settings.max_concurrent_streams <= num_incoming_streams;
	}
	
	/*
	 * Returns true if the number of incoming opened streams is larger
	 * than or equal to session.pending_local_max_concurrent_stream.
	 */
	bool isIncomingConcurrentStreamsPendingMax()
	{
		return pending_local_max_concurrent_stream <= num_incoming_streams;
	}
	
	bool isHTTPMessagingEnabled() 
	{
		return (opt_flags & OptionsMask.NO_HTTP_MESSAGING) == 0;
	}
	
	/*
	 * Returns true if |frame| is trailer headers.
	 */
	bool isTrailerHeaders(Stream stream, in Frame frame) 
	{
		if (!stream || frame.hd.type != FrameType.HEADERS) {
			return false;
		}
		if (is_server) {
			return frame.headers.cat == HeadersCategory.HEADERS;
		}
		
		return frame.headers.cat == HeadersCategory.HEADERS && (stream.httpFlags & HTTPFlags.EXPECT_FINAL_RESPONSE) == 0;
	}
	
	/* Returns true if the |stream| is in reserved(remote) state */
	bool isReservedRemote(Stream stream)
	{
		return stream.state == StreamState.RESERVED && !isMyStreamId(stream.id);
	}
	
	/* Returns true if the |stream| is in reserved(local) state */
	bool isReservedLocal(Stream stream) {
		return stream.state == StreamState.RESERVED && isMyStreamId(stream.id);
	}

	/*
	 * Checks whether received stream_id is valid. 
	 */
	bool isNewPeerStreamId(int stream_id)
	{
		return stream_id != 0 && !isMyStreamId(stream_id) && last_recv_stream_id < stream_id;
	}
	

	/**
	 * @function
	 *
	 * Returns the last stream ID of a stream for which
	 * $(D Connector.onFrame) was invoked most recently.
	 * The returned value can be used as last_stream_id parameter for
	 * `submitGoAway()` and `terminateSession()`.
	 *
	 * This function always succeeds.
	 */
	int getLastProcStreamID() 
	{
		return last_proc_stream_id;
	}

	bool idleStreamDetect(int stream_id) 
	{
		/* Assume that stream object with stream_id does not exist */
		if (isMyStreamId(stream_id)) {
			if (next_stream_id <= cast(uint)stream_id) 
				return true;
			return false;
		}
		if (isNewPeerStreamId(stream_id))
			return true;
		
		return false;
	}

	void freeAllStreams() {
		foreach(stream; streams) 
		{
			OutboundItem item = stream.item;
			
			if (item && !item.queued && item != aob.item) 
			{
				item.free();
				Mem.free(item);
			}
			
			stream.free();
			Mem.free(stream);
		}
	}

	/*
	 * Returns Stream object whose stream ID is |stream_id|.  It
	 * could be null if such stream does not exist.  This function returns
	 * null if stream is marked as closed.
	 */
	Stream getStream(int stream_id) 
	{
		Stream stream;
		
		stream = streams.get(stream_id);
		
		if (!stream || (stream.flags & StreamFlags.CLOSED) || stream.state == StreamState.IDLE)
		{
			return null;
		}
		
		return stream;
	}
	/*
	 * This function behaves like getStream(), but it
	 * returns stream object even if it is marked as closed or in
	 * StreamState.IDLE state.
	 */
	Stream getStreamRaw(int stream_id) 
	{
		return streams.get(stream_id);
	}

	// terminates the session
	ErrorCode terminateSession(int last_stream_id, FrameError error_code, string reason) 
	{
		ErrorCode rv;
		string debug_data;
		
		if (goaway_flags & GoAwayFlags.TERM_ON_SEND) {
			return ErrorCode.OK;
		}
		
		if (!reason) {
			debug_data = null;
		} else {
			debug_data = reason;
		}
		
		rv = addGoAway(last_stream_id, error_code, debug_data, GoAwayAuxFlags.TERM_ON_SEND);
		
		if (rv != ErrorCode.OK) {
			return rv;
		}
		
		goaway_flags |= GoAwayFlags.TERM_ON_SEND;
		
		return ErrorCode.OK;
	}

	/*
	 * This function returns nonzero if session is closing.
	 */
	bool isClosing()
	{
		return (goaway_flags & GoAwayFlags.TERM_ON_SEND) != 0;
	}

	/*
	 * Check that we can send a frame to the |stream|. This function
	 * returns 0 if we can send a frame to the |frame|, or one of the
	 * following negative error codes:
	 *
	 * ErrorCode.STREAM_CLOSED
	 *   The stream is already closed.
	 * ErrorCode.STREAM_SHUT_WR
	 *   The stream is half-closed for transmission.
	 * ErrorCode.SESSION_CLOSING
	 *   This session is closing.
	 */
	ErrorCode predicateForStreamSend(Stream stream) 
	{
		if (!stream) {
			return ErrorCode.STREAM_CLOSED;
		}
		if (isClosing()) {
			return ErrorCode.SESSION_CLOSING;
		}
		if (stream.shutFlags & ShutdownFlag.WR) {
			return ErrorCode.STREAM_SHUT_WR;
		}
		return ErrorCode.OK;
	}

	/*
	 * This function checks request HEADERS frame, which opens stream, can
	 * be sent at this time.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.START_STREAM_NOT_ALLOWED
	 *     New stream cannot be created because of GOAWAY: session is
	 *     going down or received last_stream_id is strictly less than
	 *     frame.hd.stream_id.
	 * ErrorCode.STREAM_CLOSING
	 *     request HEADERS was canceled by RST_STREAM while it is in queue.
	 */
	ErrorCode predicateRequestHeadersSend(OutboundItem item) 
	{
		if (item.aux_data.headers.canceled) {
			return ErrorCode.STREAM_CLOSING;
		}
		/* If we are terminating session (GoAwayFlags.TERM_ON_SEND) or
		 * GOAWAY was received from peer, new request is not allowed. */
		
		if (goaway_flags & (GoAwayFlags.TERM_ON_SEND | GoAwayFlags.RECV)) 
		{
			return ErrorCode.START_STREAM_NOT_ALLOWED;
		}
		return ErrorCode.OK;
	}

	/*
	 * This function checks HEADERS, which is the first frame from the
	 * server, with the |stream| can be sent at this time.  The |stream|
	 * can be null.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.STREAM_CLOSED
	 *     The stream is already closed or does not exist.
	 * ErrorCode.STREAM_SHUT_WR
	 *     The transmission is not allowed for this stream (e.g., a frame
	 *     with END_STREAM flag set has already sent)
	 * ErrorCode.INVALID_STREAM_ID
	 *     The stream ID is invalid.
	 * ErrorCode.STREAM_CLOSING
	 *     RST_STREAM was queued for this stream.
	 * ErrorCode.INVALID_STREAM_STATE
	 *     The state of the stream is not valid.
	 * ErrorCode.SESSION_CLOSING
	 *   This session is closing.
	 */
	ErrorCode predicateResponseHeadersSend(Stream stream)
	{
		ErrorCode rv;
		rv = predicateForStreamSend(stream);
		if (rv != ErrorCode.OK) {
			return rv;
		}
		assert(stream);
		if (isMyStreamId(stream.id)) {
			return ErrorCode.INVALID_STREAM_ID;
		}
		if (stream.state == StreamState.OPENING) {
			return ErrorCode.OK;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		return ErrorCode.INVALID_STREAM_STATE;
	}

	/*
	 * This function checks HEADERS for reserved stream can be sent. The
	 * |stream| must be reserved state and the |session| is server side.
	 * The |stream| can be null.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * error codes:
	 *
	 * ErrorCode.STREAM_CLOSED
	 *   The stream is already closed.
	 * ErrorCode.STREAM_SHUT_WR
	 *   The stream is half-closed for transmission.
	 * ErrorCode.PROTO
	 *   The stream is not reserved state
	 * ErrorCode.STREAM_CLOSED
	 *   RST_STREAM was queued for this stream.
	 * ErrorCode.SESSION_CLOSING
	 *   This session is closing.
	 */
	ErrorCode predicatePushResponseHeadersSend(Stream stream)
	{
		ErrorCode rv;
		/* TODO Should disallow HEADERS if GOAWAY has already been issued? */
		rv = predicateForStreamSend(stream);
		if (rv != ErrorCode.OK) {
			return rv;
		}
		assert(stream);
		if (stream.state != StreamState.RESERVED) {
			return ErrorCode.PROTO;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		return ErrorCode.OK;
	}

	/*
	 * This function checks HEADERS, which is neither stream-opening nor
	 * first response header, with the |stream| can be sent at this time.
	 * The |stream| can be null.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.STREAM_CLOSED
	 *     The stream is already closed or does not exist.
	 * ErrorCode.STREAM_SHUT_WR
	 *     The transmission is not allowed for this stream (e.g., a frame
	 *     with END_STREAM flag set has already sent)
	 * ErrorCode.STREAM_CLOSING
	 *     RST_STREAM was queued for this stream.
	 * ErrorCode.INVALID_STREAM_STATE
	 *     The state of the stream is not valid.
	 * ErrorCode.SESSION_CLOSING
	 *   This session is closing.
	 */
	ErrorCode predicateHeadersSend(Stream stream) 
	{
		ErrorCode rv;
		rv = predicateForStreamSend(stream);
		if (rv != ErrorCode.OK) {
			return rv;
		}
		assert(stream);
		if (isMyStreamId(stream.id)) 
		{
			if (stream.state == StreamState.CLOSING) {
				return ErrorCode.STREAM_CLOSING;
			}
			return ErrorCode.OK;
		}
		if (stream.state == StreamState.OPENED) {
			return ErrorCode.OK;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		return ErrorCode.INVALID_STREAM_STATE;
	}

	/*
	 * This function checks PUSH_PROMISE frame |frame| with the |stream|
	 * can be sent at this time.  The |stream| can be null.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.START_STREAM_NOT_ALLOWED
	 *     New stream cannot be created because GOAWAY is already sent or
	 *     received.
	 * ErrorCode.PROTO
	 *     The client side attempts to send PUSH_PROMISE, or the server
	 *     sends PUSH_PROMISE for the stream not initiated by the client.
	 * ErrorCode.STREAM_CLOSED
	 *     The stream is already closed or does not exist.
	 * ErrorCode.STREAM_CLOSING
	 *     RST_STREAM was queued for this stream.
	 * ErrorCode.STREAM_SHUT_WR
	 *     The transmission is not allowed for this stream (e.g., a frame
	 *     with END_STREAM flag set has already sent)
	 * ErrorCode.PUSH_DISABLED
	 *     The remote peer disabled reception of PUSH_PROMISE.
	 * ErrorCode.SESSION_CLOSING
	 *   This session is closing.
	 */
	ErrorCode predicatePushPromiseSend(Stream stream) 
	{
		ErrorCode rv;
		
		if (!is_server) {
			return ErrorCode.PROTO;
		}
		
		rv = predicateForStreamSend(stream);
		if (rv != ErrorCode.OK) {
			return rv;
		}
		
		assert(stream);
		
		if (remote_settings.enable_push == 0) {
			return ErrorCode.PUSH_DISABLED;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		if (goaway_flags & GoAwayFlags.RECV) {
			return ErrorCode.START_STREAM_NOT_ALLOWED;
		}
		return ErrorCode.OK;
	}

	/*
	 * This function checks WINDOW_UPDATE with the stream ID |stream_id|
	 * can be sent at this time. Note that END_STREAM flag of the previous
	 * frame does not affect the transmission of the WINDOW_UPDATE frame.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.STREAM_CLOSED
	 *     The stream is already closed or does not exist.
	 * ErrorCode.STREAM_CLOSING
	 *     RST_STREAM was queued for this stream.
	 * ErrorCode.INVALID_STREAM_STATE
	 *     The state of the stream is not valid.
	 * ErrorCode.SESSION_CLOSING
	 *   This session is closing.
	 */
	ErrorCode predicateWindowUpdateSend(int stream_id)
	{
		Stream stream;
		if (stream_id == 0) {
			/* Connection-level window update */
			return ErrorCode.OK;
		}
		stream = getStream(stream_id);
		if (!stream) {
			return ErrorCode.STREAM_CLOSED;
		}
		if (isClosing()) {
			return ErrorCode.SESSION_CLOSING;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		if (isReservedLocal(stream)) {
			return ErrorCode.INVALID_STREAM_STATE;
		}
		return ErrorCode.OK;
	}

	/*
	 * This function checks DATA with the |stream| can be sent at this
	 * time.  The |stream| can be null.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.STREAM_CLOSED
	 *     The stream is already closed or does not exist.
	 * ErrorCode.STREAM_SHUT_WR
	 *     The transmission is not allowed for this stream (e.g., a frame
	 *     with END_STREAM flag set has already sent)
	 * ErrorCode.STREAM_CLOSING
	 *     RST_STREAM was queued for this stream.
	 * ErrorCode.INVALID_STREAM_STATE
	 *     The state of the stream is not valid.
	 * ErrorCode.SESSION_CLOSING
	 *   This session is closing.
	 */
	ErrorCode predicateDataSend(Stream stream) 
	{
		ErrorCode rv;
		rv = predicateForStreamSend(stream);
		if (rv != ErrorCode.OK) {
			return rv;
		}
		assert(stream);
		if (isMyStreamId(stream.id)) {
			/* Request body data */
			/* If stream.state is StreamState.CLOSING, RST_STREAM was queued but not yet sent. In this case, we won't send DATA frames. */
			if (stream.state == StreamState.CLOSING) {
				return ErrorCode.STREAM_CLOSING;
			}
			if (stream.state == StreamState.RESERVED) {
				return ErrorCode.INVALID_STREAM_STATE;
			}
			return ErrorCode.OK;
		}
		/* Response body data */
		if (stream.state == StreamState.OPENED) {
			return ErrorCode.OK;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		return ErrorCode.INVALID_STREAM_STATE;
	}


	/* Take into account settings max frame size and both connection-level flow control here */
	int enforceFlowControlLimits(Stream stream, int requested_window_size)
	{
		LOGF("send: remote windowsize connection=%d, remote maxframsize=%u, stream(id %d=%d",
				remote_window_size,
				remote_settings.max_frame_size, stream.id,
				stream.remoteWindowSize);
		
		return min(min(min(requested_window_size, stream.remoteWindowSize), remote_window_size), cast(int)remote_settings.max_frame_size);
	}
		
	/*
	 * Now we have SETTINGS synchronization, flow control error can be
	 * detected strictly. If DATA frame is received with length > 0 and
	 * current received window size + delta length is strictly larger than
	 * local window size, it is subject to FLOW_CONTROL_ERROR, so return
	 * false. Note that local_window_size is calculated after SETTINGS ACK is
	 * received from peer, so peer must honor this limit. If the resulting
	 * recv_window_size is strictly larger than MAX_WINDOW_SIZE,
	 * return false too.
	 */
	bool adjustRecvWindowSize(ref int _recv_window_size, size_t delta, int local_window_size) 
	{
		if (_recv_window_size > local_window_size - cast(int)delta ||
			_recv_window_size > MAX_WINDOW_SIZE - cast(int)delta) 
		{
			return false;
		}
		_recv_window_size += delta;
		return true;
	}
	/*
	 * Accumulates received bytes |delta_size| for stream-level flow
	 * control and decides whether to send WINDOW_UPDATE to that stream.
	 * If OptionFlags.NO_AUTO_WINDOW_UPDATE is set, WINDOW_UPDATE will not
	 * be sent.
	 */
	void updateRecvStreamWindowSize(Stream stream, size_t delta_size, int send_window_update) 
	{
		bool ok = adjustRecvWindowSize(stream.recvWindowSize, delta_size, stream.localWindowSize);
		if (!ok) {
			addRstStream(stream.id, FrameError.FLOW_CONTROL_ERROR);
			return;
		}
		/* We don't have to send WINDOW_UPDATE if the data received is the last chunk in the incoming stream. */
		if (send_window_update && !(opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE)) {
			/* We have to use local_settings here because it is the constraint the remote endpoint should honor. */
			if (shouldSendWindowUpdate(stream.localWindowSize, stream.recvWindowSize)) {
				addWindowUpdate(FrameFlags.NONE, stream.id, stream.recvWindowSize);
				stream.recvWindowSize = 0;
			}
		}
	}
	
	/*
	 * Accumulates received bytes |delta_size| for connection-level flow
	 * control and decides whether to send WINDOW_UPDATE to the
	 * connection.  If OptionFlags.NO_AUTO_WINDOW_UPDATE is set,
	 * WINDOW_UPDATE will not be sent.
	 */
	ErrorCode updateRecvConnectionWindowSize(size_t delta_size) 
	{
		ErrorCode rv;
		logDebug("updateRecvConnectionWindowSize");
		bool ok = adjustRecvWindowSize(recv_window_size, delta_size, local_window_size);
		if (!ok) {
			return terminateSession(FrameError.FLOW_CONTROL_ERROR);
		}
		logDebug("opt_flags: ", opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE, " raw: ", opt_flags);
		if (!(opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE))
		{
			
			if (shouldSendWindowUpdate(local_window_size, recv_window_size)) 
			{
				logDebug("Add Window Update");
				/* Use stream ID 0 to update connection-level flow control window */
				addWindowUpdate(FrameFlags.NONE, 0, recv_window_size);
				recv_window_size = 0;
			}
		} else 
			logDebug("Cannot add Window Update");
		return ErrorCode.OK;
	}
	
	ErrorCode updateConsumedSize(ref int consumed_size, ref int recv_window_size, int stream_id, size_t delta_size, int local_window_size) 
	{
		int recv_size;
		ErrorCode rv;
		
		if (cast(size_t)consumed_size > MAX_WINDOW_SIZE - delta_size)
		{
			return terminateSession(FrameError.FLOW_CONTROL_ERROR);
		}
		
		consumed_size += delta_size;
		
		/* recv_window_size may be smaller than consumed_size, because it may be decreased by negative value with http2_submit_window_update(). */
		recv_size = min(consumed_size, recv_window_size);
		
		if (shouldSendWindowUpdate(local_window_size, recv_size)) 
		{
			addWindowUpdate(FrameFlags.NONE, stream_id, recv_size);
			recv_window_size -= recv_size;
			consumed_size -= recv_size;
		}
		
		return ErrorCode.OK;
	}
	
	ErrorCode updateStreamConsumedSize(Stream stream, size_t delta_size) 
	{
		return updateConsumedSize(stream.consumedSize, stream.recvWindowSize, stream.id, delta_size, stream.localWindowSize);
	}
	
	ErrorCode updateConnectionConsumedSize(size_t delta_size) 
	{
		return updateConsumedSize(consumed_size, recv_window_size, 0, delta_size, local_window_size);
	}


	/*
	 * Returns the maximum length of next data read. If the
	 * connection-level and/or stream-wise flow control are enabled, the
	 * return value takes into account those current window sizes. The remote
	 * settings for max frame size is also taken into account.
	 */
	int nextDataRead(Stream stream) 
	{
		int window_size;
		
		window_size = enforceFlowControlLimits(stream, DATA_PAYLOADLEN);
		
		LOGF("send: available window=%d", window_size);
		
		return window_size > 0 ? window_size : 0;
	}

	int callSelectPadding(in Frame frame, size_t max_payloadlen) 
	{
		int rv;
		
		if (frame.hd.length >= max_payloadlen) {
			return frame.hd.length;
		}
		
		int max_paddedlen = cast(int) min(frame.hd.length + MAX_PADLEN, max_payloadlen);
		
		rv = connector.selectPaddingLength(frame, max_paddedlen);
		if (rv < cast(int)frame.hd.length || rv > cast(int)max_paddedlen) {
			return cast(int) ErrorCode.CALLBACK_FAILURE;
		}
		return rv;
	}	
	
	bool callOnFrameReady(in Frame frame)
	{
		return connector.onFrameReady(frame);
	}

	bool callOnFrameSent(in Frame frame)
	{
		return connector.onFrameSent(frame);
	}

	bool callOnFrameHeader(in FrameHeader hd) 
	{
		return connector.onFrameHeader(hd);
	}

	bool callOnHeaders(in Frame frame) 
	{
		LOGF("recv: call onHeaders callback stream_id=%d", frame.hd.stream_id);
		return connector.onHeaders(frame);

	}

	bool callOnHeaderField(in Frame frame, in HeaderField hf, ref bool pause, ref bool close) 
	{
		return connector.onHeaderField(frame, hf, pause, close);
	}

	int callRead(ubyte[] buf)
	{
		int len = connector.read(buf);

		if (len > 0) {
			if (cast(size_t) len > buf.length)
				return ErrorCode.CALLBACK_FAILURE;
		} else if (len < 0 && len != cast(int) ErrorCode.WOULDBLOCK && len != cast(int)ErrorCode.EOF)
			return ErrorCode.CALLBACK_FAILURE;
		
		return len;
	}

	bool callOnFrame(in Frame frame) 
	{
		return connector.onFrame(frame);
	}

	/*
	 * Checks that we can receive the DATA frame for stream, which is
	 * indicated by |session.iframe.frame.hd.stream_id|. If it is a
	 * connection error situation, GOAWAY frame will be issued by this
	 * function.
	 *
	 * If the DATA frame is allowed, returns 0.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.IGN_PAYLOAD
	 *   The reception of DATA frame is connection error; or should be
	 *   ignored.
	 */
	ErrorCode onDataFailFast() 
	{
		ErrorCode rv;
		Stream stream;
		int stream_id;
		string failure_reason;
		FrameError error_code = FrameError.PROTOCOL_ERROR;

		stream_id = iframe.frame.hd.stream_id;
		
		if (stream_id == 0) {
			/* The spec says that if a DATA frame is received whose stream ID
	       is 0, the recipient MUST respond with a connection error of
	       type PROTOCOL_ERROR. */
			failure_reason = "DATA: stream_id == 0";
			goto fail;
		}
		stream = getStream(stream_id);
		if (!stream) {
			if (idleStreamDetect(stream_id)) 
			{
				failure_reason = "DATA: stream in idle";
				error_code = FrameError.STREAM_CLOSED;
				goto fail;
			}
			return ErrorCode.IGN_PAYLOAD;
		}
		if (stream.shutFlags & ShutdownFlag.RD) {
			failure_reason = "DATA: stream in half-closed(remote)";
			error_code = FrameError.STREAM_CLOSED;
			goto fail;
		}
		
		if (isMyStreamId(stream_id)) {
			if (stream.state == StreamState.CLOSING) {
				return ErrorCode.IGN_PAYLOAD;
			}
			if (stream.state != StreamState.OPENED) {
				failure_reason = "DATA: stream not opened";
				goto fail;
			}
			return ErrorCode.OK;
		}
		if (stream.state == StreamState.RESERVED) {
			failure_reason = "DATA: stream in reserved";
			goto fail;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.IGN_PAYLOAD;
		}
		return ErrorCode.OK;
	fail:
		rv = terminateSessionWithReason(error_code, failure_reason);
		if (isFatal(rv)) {
			return rv;
		}
		return ErrorCode.IGN_PAYLOAD;
	}


	ErrorCode afterHeaderBlockReceived() 
	{
		ErrorCode rv;
		bool call_cb = 1;
		Frame* frame = &iframe.frame;
		Stream stream;
		
		/* We don't call Connector.onFrame if stream has been closed already or being closed. */
		stream = getStream(frame.hd.stream_id);
		if (!stream || stream.state == StreamState.CLOSING)
		{
			return ErrorCode.OK;
		}
		
		if (isHTTPMessagingEnabled()) {
			if (frame.hd.type == FrameType.PUSH_PROMISE) {
				Stream subject_stream;
				
				subject_stream = getStream(frame.push_promise.promised_stream_id);
				if (subject_stream) {
					if (!subject_stream.onRequestHeaders(*frame))
						rv = ErrorCode.ERROR;
				}
			} else {
				assert(frame.hd.type == FrameType.HEADERS);
				with(HeadersCategory) switch (frame.headers.cat) {
					case REQUEST:
						if (!stream.onRequestHeaders(*frame))
							rv = ErrorCode.ERROR;
						break;
					case RESPONSE:
					case PUSH_RESPONSE:
						if (!stream.onResponseHeaders())
							rv = ErrorCode.ERROR;
						break;
					case HEADERS:
						if (stream.httpFlags & HTTPFlags.EXPECT_FINAL_RESPONSE) {
							assert(!is_server);
							if (!stream.onResponseHeaders())
								rv = ErrorCode.ERROR;
						} else {						
							if (!stream.validateTrailerHeaders(*frame))
								rv = ErrorCode.ERROR;
						}
						break;
					default:
						assert(0);
				}
				if (rv == 0 && (frame.hd.flags & FrameFlags.END_STREAM)) {
					if (stream.validateRemoteEndStream())
						rv = ErrorCode.ERROR;
				}
			}
			if (rv != ErrorCode.OK) {
				int stream_id;
				
				if (frame.hd.type == FrameType.PUSH_PROMISE) {
					stream_id = frame.push_promise.promised_stream_id;
				} else {
					stream_id = frame.hd.stream_id;
				}
				
				call_cb = 0;
				
				addRstStream(stream_id, FrameError.PROTOCOL_ERROR);
			}
		}

		if (call_cb) {
			bool ok = callOnFrame(*frame);
			if (!ok) 
				return ErrorCode.CALLBACK_FAILURE;
		}
		
		if (frame.hd.type != FrameType.HEADERS) {
			return ErrorCode.OK;
		}
		
		switch (frame.headers.cat) {
			case HeadersCategory.REQUEST:
				endRequestHeadersReceived(*frame, stream);
				return ErrorCode.OK;
			case HeadersCategory.RESPONSE:
			case HeadersCategory.PUSH_RESPONSE:
				return endResponseHeadersReceived(*frame, stream);
			case HeadersCategory.HEADERS:
				return endHeadersReceived(*frame, stream);
			default:
				assert(0);
		}
	}

	ErrorCode processHeadersFrame() 
	{
		Frame* frame = &iframe.frame;
		Stream stream;
		
		frame.headers.unpack(iframe.sbuf[]);

		stream = getStream(frame.hd.stream_id);
		if (!stream) {
			frame.headers.cat = HeadersCategory.REQUEST;
			return onRequestHeaders(*frame);
		}
		
		if (isMyStreamId(frame.hd.stream_id))
		{
			if (stream.state == StreamState.OPENING) {
				frame.headers.cat = HeadersCategory.RESPONSE;
				return onResponseHeaders(*frame, stream);
			}
			frame.headers.cat = HeadersCategory.HEADERS;
			return onHeaders(*frame, stream);
		}
		if (stream.state == StreamState.RESERVED) {
			frame.headers.cat = HeadersCategory.PUSH_RESPONSE;
			return onPushResponseHeaders(*frame, stream);
		}
		frame.headers.cat = HeadersCategory.HEADERS;
		return onHeaders(*frame, stream);
	}

	ErrorCode processPriorityFrame()
	{
		Frame* frame = &iframe.frame;
		
		frame.priority.unpack(iframe.sbuf[]);
		
		return onPriority(*frame);
	}

	ErrorCode processRstStreamFrame()
	{
		Frame* frame = &iframe.frame;
		
		frame.rst_stream.unpack(iframe.sbuf[]);
		
		return onRstStream(*frame);
	}

	
	ErrorCode processSettingsFrame() 
	{
		Frame* frame = &iframe.frame;
		size_t i;
		Setting min_header_size_entry;
		
		min_header_size_entry = iframe.iva[INBOUND_NUM_IV - 1];
		
		if (min_header_size_entry.value < uint.max) {
			/* If we have less value, then we must have Setting.HEADER_TABLE_SIZE in i < iframe.niv */
			for (i = 0; i < iframe.niv; ++i) {
				if (iframe.iva[i].id == Setting.HEADER_TABLE_SIZE) {
					break;
				}
			}
			
			assert(i < iframe.niv);
			
			if (min_header_size_entry.value != iframe.iva[i].value) {
				iframe.iva[iframe.niv++] = iframe.iva[i];
				iframe.iva[i] = min_header_size_entry;
			}
		}
		
		frame.settings.unpack(iframe.iva);
		return onSettings(*frame, false /* ACK */);
	}

	ErrorCode processPushPromiseFrame()
	{
		Frame* frame = &iframe.frame;
		
		frame.push_promise.unpack(iframe.sbuf[]);
				
		return onPushPromise(*frame);
	}

	ErrorCode processPingFrame()
	{
		Frame* frame = &iframe.frame;
		
		frame.ping.unpack(iframe.sbuf[]);
		
		return onPing(*frame);
	}
	
	ErrorCode processGoAwayFrame() 
	{
		Frame* frame = &iframe.frame;
		
		frame.goaway.unpack(iframe.sbuf[], iframe.lbuf[]);
		
		iframe.lbuf = Buffer(null);
		
		return onGoAway(*frame);
	}

	ErrorCode processWindowUpdateFrame() 
	{
		Frame* frame = &iframe.frame;
		
		frame.window_update.unpack(iframe.sbuf[]);
		
		return onWindowUpdate(*frame);
	}

	/* For errors, this function only returns FATAL error. */
	ErrorCode processDataFrame() 
	{
		ErrorCode rv;
		rv = onData(iframe.frame);
		if (isFatal(rv)) {
			return rv;
		}
		return ErrorCode.OK;
	}

	ErrorCode handleInvalidStream(Frame frame, FrameError error_code) {
		
		addRstStream(frame.hd.stream_id, error_code);
		
		if (!connector.onInvalidFrame(frame, error_code))
			return ErrorCode.CALLBACK_FAILURE;
		
		return ErrorCode.OK;
	}
	
	ErrorCode handleInflateInvalidStream(Frame frame, FrameError error_code) {
		ErrorCode rv;
		rv = handleInvalidStream(frame, error_code);
		if (isFatal(rv)) {
			return rv;
		}
		return ErrorCode.IGN_HEADER_BLOCK;
	}

	/*
	 * Handles invalid frame which causes connection error.
	 */
	ErrorCode handleInvalidConnection(Frame frame, FrameError error_code, string reason)
	{
		if (!connector.onInvalidFrame(frame, error_code))
			return ErrorCode.CALLBACK_FAILURE;

		return terminateSessionWithReason(error_code, reason);
	}

	ErrorCode handleInflateInvalidConnection(Frame frame, FrameError error_code, string reason) {
		ErrorCode rv;
		rv = handleInvalidConnection(frame, error_code, reason);
		if (isFatal(rv)) {
			return rv;
		}
		return ErrorCode.IGN_HEADER_BLOCK;
	}


	/* Add padding to HEADERS or PUSH_PROMISE. We use frame.headers.padlen in this function 
	 * to use the fact that frame.push_promise has also padlen in the same position. */
	ErrorCode headersAddPad(Frame frame)
	{
		ErrorCode rv;
		int padded_payloadlen;
		Buffers framebufs = aob.framebufs;
		int padlen;
		int max_payloadlen;
		
		max_payloadlen = min(MAX_PAYLOADLEN, frame.hd.length + MAX_PADLEN);
		
		padded_payloadlen = callSelectPadding(frame, max_payloadlen);
		
		if (isFatal(padded_payloadlen)) {
			return cast(ErrorCode)padded_payloadlen;
		}
		
		padlen = padded_payloadlen - frame.hd.length;
		
		LOGF("send: padding selected: payloadlen=%d, padlen=%d", padded_payloadlen, padlen);
		
		frame.hd.addPad(framebufs, padlen);
			
		frame.headers.padlen = padlen;
		
		return ErrorCode.OK;
	}

	size_t estimateHeadersPayload(in HeaderField[] hfa, size_t additional) 
	{
		return hd_deflater.upperBound(hfa) + additional;
	}	

	/*
	 * Updates the remote initial window size of all active streams.  If
	 * error occurs, all streams may not be updated.
	 *
	 */
	ErrorCode updateRemoteInitialWindowSize(int new_initial_window_size) 
	{
		ErrorCode rv;
		auto new_window_size = new_initial_window_size;
		auto old_window_size = remote_settings.initial_window_size;
		
		foreach (stream; streams) 
		{
			
			bool ok = stream.updateRemoteInitialWindowSize(new_window_size, old_window_size);
			if (!ok) 
				return terminateSession(FrameError.FLOW_CONTROL_ERROR);
			
			/* If window size gets positive, push deferred DATA frame to outbound queue. */
			if (stream.remoteWindowSize > 0 && stream.isDeferredByFlowControl())				
				stream.resumeDeferredItem(StreamFlags.DEFERRED_FLOW_CONTROL, this);

		}
		
		return rv;
	}


	/*
	 * Updates the local initial window size of all active streams.  If
	 * error occurs, all streams may not be updated.
	 */
	ErrorCode updateLocalInitialWindowSize(int new_initial_window_size, int old_initial_window_size)
	{
		ErrorCode rv;
		auto new_window_size = new_initial_window_size;
		auto old_window_size = old_initial_window_size;
		
		foreach(stream; streams) {
			if (!stream.updateLocalInitialWindowSize(new_window_size, old_window_size))
				return terminateSession(FrameError.FLOW_CONTROL_ERROR);

			if (!(opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE)) {
				
				if (shouldSendWindowUpdate(stream.localWindowSize, stream.recvWindowSize)) {
					
					addWindowUpdate(FrameFlags.NONE, stream.id, stream.recvWindowSize);
					stream.recvWindowSize = 0;
				}
			}
		}
		return rv;
	}

	/*
	 * Returns the number of active streams, which includes streams in
	 * reserved state.
	 */
	size_t getNumActiveStreams() {
		return streams.length - num_closed_streams;
	}

	/* Closes non-idle and non-closed streams whose stream ID > last_stream_id. 
	 * If incoming is nonzero, we are going to close incoming streams.  
	 * Otherwise, close outgoing streams. */
	ErrorCode closeStreamOnGoAway(int last_stream_id, int incoming)
	{
		ErrorCode rv;
		
		foreach(stream; streams) {
			if (!incoming || (isMyStreamId(stream.id) && incoming))
				continue;
			
			if (stream.state != StreamState.IDLE && (stream.flags & StreamFlags.CLOSED) == 0 && stream.id > last_stream_id)
			{
				rv = closeStream(stream.id, FrameError.REFUSED_STREAM);
				if (isFatal(rv))
					return rv;
			}
		}
		
		return rv;
	}
	
	void cycleWeightOutboundItem(OutboundItem item, int ini_weight) 
	{
		if (item.weight == MIN_WEIGHT || item.weight > ini_weight) {
			
			item.weight = ini_weight;
			
			if (item.cycle == last_cycle) {
				item.cycle = ++last_cycle;
			} else {
				item.cycle = last_cycle;
			}
		} else {
			--item.weight;
		}
	}
	
	/*
	 * This function serializes frame for transmission.
	 *
	 * This function returns 0 if it succeeds, or one of negative error
	 * codes, including both fatal and non-fatal ones.
	 */
	ErrorCode prepareFrame(OutboundItem item)
	{
		ErrorCode rv;
		Frame* frame = &item.frame;
		
		if (frame.hd.type != FrameType.DATA) {
			with(FrameType) switch (frame.hd.type) {
				case HEADERS: {
					HeadersAuxData *aux_data;
					size_t estimated_payloadlen;
					
					aux_data = &item.aux_data.headers;
					
					estimated_payloadlen = estimateHeadersPayload(frame.headers.hfa, PRIORITY_SPECLEN);
					
					if (estimated_payloadlen > MAX_HEADERSLEN) {
						return ErrorCode.FRAME_SIZE_ERROR;
					}
					
					if (frame.headers.cat == HeadersCategory.REQUEST) {
						/* initial HEADERS, which opens stream */
						Stream stream = openStream(frame.hd.stream_id, StreamFlags.NONE, frame.headers.pri_spec, StreamState.INITIAL, aux_data.stream_user_data);
						
						rv = predicateRequestHeadersSend(item);
						if (rv != ErrorCode.OK) {
							return rv;
						}
						
						if (isHTTPMessagingEnabled()) {
							stream.setRequestMethod(*frame);
						}
					} else {
						Stream stream = getStream(frame.hd.stream_id);
						
						if (predicatePushResponseHeadersSend(stream) == 0)
						{
							frame.headers.cat = HeadersCategory.PUSH_RESPONSE;                        
							if (aux_data.stream_user_data)
								stream.userData = aux_data.stream_user_data;
						} else if (predicateResponseHeadersSend(stream) == 0) {
							frame.headers.cat = HeadersCategory.RESPONSE;
						} else {
							frame.headers.cat = HeadersCategory.HEADERS;
							
							rv = predicateHeadersSend(stream);
							
							if (rv != ErrorCode.OK) {
								if (stream && stream.item == item) 
									stream.detachItem(this);
								return rv;
							}
						}
					}
					
					rv = frame.headers.pack(aob.framebufs, hd_deflater);
					
					if (rv != ErrorCode.OK) {
						return rv;
					}
					
					LOGF("send: before padding, HEADERS serialized in %d bytes", aob.framebufs.length);
					
					rv = headersAddPad(*frame);
					
					if (rv != ErrorCode.OK) {
						return rv;
					}
					
					LOGF("send: HEADERS finally serialized in %d bytes", aob.framebufs.length);
					
					break;
				}
				case PRIORITY: {
					if (isClosing()) {
						return ErrorCode.SESSION_CLOSING;
					}
					/* PRIORITY frame can be sent at any time and to any stream ID. */
					frame.priority.pack(aob.framebufs);
					
					/* Peer can send PRIORITY frame against idle stream to create
				       "anchor" in dependency tree.  Only client can do this in
				       libhttp2.  In libhttp2, only server retains non-active (closed
				       or idle) streams in memory, so we don't open stream here. */
					break;
				}
				case RST_STREAM:
					if (isClosing()) {
						return ErrorCode.SESSION_CLOSING;
					}
					frame.rst_stream.pack(aob.framebufs);
					break;
				case SETTINGS: {
					rv = frame.settings.pack(aob.framebufs);
					if (rv != ErrorCode.OK) {
						return rv;
					}
					break;
				}
				case PUSH_PROMISE: {
					Stream stream;
					HeadersAuxData *aux_data;
					PrioritySpec pri_spec;
					size_t estimated_payloadlen;
					
					aux_data = &item.aux_data.headers;
					
					stream = getStream(frame.hd.stream_id);
					
					/* stream could be null if associated stream was already closed. */
					if (stream)
						pri_spec = PrioritySpec(stream.id, DEFAULT_WEIGHT, 0);
					
					openStream(frame.push_promise.promised_stream_id, StreamFlags.NONE, pri_spec, StreamState.RESERVED, aux_data.stream_user_data);
					
					estimated_payloadlen = estimateHeadersPayload(frame.push_promise.hfa, 0);
					
					if (estimated_payloadlen > MAX_HEADERSLEN)
						return ErrorCode.FRAME_SIZE_ERROR;
					
					/* predicte should fail if stream is null. */
					rv = predicatePushPromiseSend(stream);
					if (rv != ErrorCode.OK) {
						return rv;
					}
					
					assert(stream);
					
					rv = frame.push_promise.pack(aob.framebufs, hd_deflater);
					if (rv != 0)
						return rv;
					
					rv = headersAddPad(*frame);
					if (rv != 0)
						return rv;               
					
					break;
				}
				case PING:
					if (isClosing()) {
						return ErrorCode.SESSION_CLOSING;
					}
					frame.ping.pack(aob.framebufs);
					break;
				case WINDOW_UPDATE: {
					rv = predicateWindowUpdateSend(frame.hd.stream_id);
					if (rv != ErrorCode.OK) {
						return rv;
					}
					frame.window_update.pack(aob.framebufs);
					break;
				}
				case GOAWAY:
					rv = frame.goaway.pack(aob.framebufs);
					if (rv != ErrorCode.OK) {
						return rv;
					}
					local_last_stream_id = frame.goaway.last_stream_id;
					
					break;
				default:
					return ErrorCode.INVALID_ARGUMENT;
			}
			return ErrorCode.OK;
		} else {
			int next_readmax;
			Stream stream = getStream(frame.hd.stream_id);
			
			if (stream) {
				assert(stream.item == item);
			}
			
			rv = predicateDataSend(stream);
			if (rv != ErrorCode.OK) {
				if (stream)
					stream.detachItem(this);          
				
				return rv;
			}
			/* Assuming stream is not null */
			assert(stream);
			next_readmax = nextDataRead(stream);
			
			if (next_readmax == 0) {
				
				/* This must be true since we only pop DATA frame item from queue when session.remote_window_size > 0 */
				assert(remote_window_size > 0);
				
				stream.deferItem(StreamFlags.DEFERRED_FLOW_CONTROL, this);            
				aob.item = null;
				aob.reset();
				return ErrorCode.DEFERRED;
			}
			
			rv = packData(aob.framebufs, next_readmax, *frame, item.aux_data.data);
			if (rv == ErrorCode.DEFERRED) {
				stream.deferItem(StreamFlags.DEFERRED_USER, this);
				aob.item = null;
				aob.reset();
				return ErrorCode.DEFERRED;
			}
			if (rv == ErrorCode.TEMPORAL_CALLBACK_FAILURE) {
				stream.detachItem(this);            
				addRstStream(frame.hd.stream_id, FrameError.INTERNAL_ERROR);
				return ErrorCode.TEMPORAL_CALLBACK_FAILURE;
			}
			if (rv != 0)
				stream.detachItem(this);
			return ErrorCode.OK;
		}
	}
	
	/*
	 * Called after a frame is sent.  This function runs
	 * $(D Connector.onFrameSent) and handles stream closure upon END_STREAM
	 * or RST_STREAM.  This function does not reset aob.  It is a
	 * responsibility of $(D resetActiveOutboundItem).
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *     The callback function failed.
	 */
	ErrorCode afterFrameSent() 
	{
		ErrorCode rv;
		OutboundItem item = aob.item;
		Buffers framebufs = aob.framebufs;
		Frame* frame = &item.frame;
		
		if (frame.hd.type != FrameType.DATA) {
			
			if (frame.hd.type == FrameType.HEADERS || frame.hd.type == FrameType.PUSH_PROMISE) {
				
				if (framebufs.nextPresent()) {
					LOGF("send: CONTINUATION exists, just return");
					return ErrorCode.OK;
				}
			}
			bool ok = callOnFrameSent(*frame);
			if (!ok) {
				return ErrorCode.CALLBACK_FAILURE;
			}
			with(FrameType) switch (frame.hd.type) {
				case HEADERS: {
					HeadersAuxData *aux_data;
					Stream stream = getStream(frame.hd.stream_id);
					if (!stream) 
						break;                
					if (stream.item == item)
						stream.detachItem(this);
					
					final switch (frame.headers.cat) {
						case HeadersCategory.REQUEST: {
							stream.state = StreamState.OPENING;
							if (frame.hd.flags & FrameFlags.END_STREAM) {
								stream.shutdown(ShutdownFlag.WR);
							}
							rv = closeStreamIfShutRdWr(stream);
							if (isFatal(rv)) {
								return rv;
							}
							/* We assume aux_data is a pointer to HeadersAuxData */
							aux_data = &item.aux_data.headers;
							if (aux_data.data_prd.read_callback) {
								/* submitData() makes a copy of aux_data.data_prd */
								rv = submitData(this, FrameFlags.END_STREAM, frame.hd.stream_id, aux_data.data_prd);
								if (isFatal(rv)) {
									return rv;
								}
								/* TODO: submitData() may fail if stream has already DATA frame item.  We might have to handle it here. */
							}
							break;
						}
						case HeadersCategory.PUSH_RESPONSE:
							stream.flags = cast(StreamFlags)(stream.flags & ~StreamFlags.PUSH);
							++num_outgoing_streams;
							goto case HeadersCategory.RESPONSE;
						case HeadersCategory.RESPONSE:
							stream.state = StreamState.OPENED;
							goto case HeadersCategory.HEADERS;
						case HeadersCategory.HEADERS:
							if (frame.hd.flags & FrameFlags.END_STREAM) {
								stream.shutdown(ShutdownFlag.WR);
							}
							rv = closeStreamIfShutRdWr(stream);
							if (isFatal(rv)) {
								return rv;
							}
							/* We assume aux_data is a pointer to HeadersAuxData */
							aux_data = &item.aux_data.headers;
							if (aux_data.data_prd.read_callback) {
								rv = submitData(this, FrameFlags.END_STREAM, frame.hd.stream_id, aux_data.data_prd);
								if (isFatal(rv)) {
									return rv;
								}
								/* TODO submitData() may fail if stream has already DATA frame item. 
                             * We might have to handle it here. */
							}
							break;
					}
					break;
				}
				case PRIORITY: {
					Stream stream;
					
					if (is_server) {
						break;
					}
					
					stream = getStreamRaw(frame.hd.stream_id);
					
					if (!stream) {
						break;
					}
					
					reprioritizeStream(stream, frame.priority.pri_spec);
					
					break;
				}
				case RST_STREAM:
					rv = closeStream(frame.hd.stream_id, frame.rst_stream.error_code);
					if (isFatal(rv)) {
						return rv;
					}
					break;
				case GOAWAY: {
					GoAwayAuxData aux_data = item.aux_data.goaway;
					
					if ((aux_data.flags & GoAwayAuxFlags.SHUTDOWN_NOTICE) == 0) {
						
						if (aux_data.flags & GoAwayAuxFlags.TERM_ON_SEND) {
							goaway_flags |= GoAwayFlags.TERM_SENT;
						}
						
						goaway_flags |= GoAwayFlags.SENT;
						
						rv = closeStreamOnGoAway(frame.goaway.last_stream_id, 1);
						
						if (isFatal(rv)) {
							return rv;
						}
					}
					
					break;
				}
				default:
					break;
			}
			
			return ErrorCode.OK;
		}

		Stream stream = getStream(frame.hd.stream_id);
		DataAuxData *aux_data = &item.aux_data.data;

		/* We update flow control window after a frame was completely
	       sent. This is possible because we choose payload length not to
	       exceed the window */
		remote_window_size -= frame.hd.length;

		if (stream) {
			stream.remoteWindowSize = stream.remoteWindowSize - frame.hd.length;
		}
		
		if (stream && aux_data.eof) {
			stream.detachItem(this);
			
			/* Call onFrameSent after detachItem(), so that application can issue submitData() in the callback. */
			bool ok = callOnFrameSent(*frame);
			if (!ok) {
				return ErrorCode.CALLBACK_FAILURE;
			}
			
			if (frame.hd.flags & FrameFlags.END_STREAM) {
				int stream_closed;
				
				stream_closed = (stream.shutFlags & ShutdownFlag.RDWR) == ShutdownFlag.RDWR;
				
				stream.shutdown(ShutdownFlag.WR);
				
				rv = closeStreamIfShutRdWr(stream);
				if (isFatal(rv)) {
					return rv;
				}
				/* stream may be null if it was closed */
				if (stream_closed)
					stream = null;
			}
			return ErrorCode.OK;
		}
		
		bool ok = callOnFrameSent(*frame);
		
		if (!ok) {
			return ErrorCode.CALLBACK_FAILURE;
		}
		
		return ErrorCode.OK;
	}
	
	/*
	 * Called after a frame is sent and after $(D afterFrameSent). 
	 * This function is responsible for resetting aob.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *     The callback function failed.
	 */
	ErrorCode resetActiveOutboundItem() 
	{
		ErrorCode rv;
		OutboundItem item = aob.item;
		Buffers framebufs = aob.framebufs;
		Frame* frame = &item.frame;
		
		if (frame.hd.type != FrameType.DATA) {
			
			if (frame.hd.type == FrameType.HEADERS ||
				frame.hd.type == FrameType.PUSH_PROMISE) {
				
				if (framebufs.nextPresent()) {
					framebufs.cur = framebufs.cur.next;
					
					LOGF("send: next CONTINUATION frame, %d bytes", framebufs.cur.buf.length);
					
					return ErrorCode.OK;
				}
			}
			
			aob.reset();
			
			return ErrorCode.OK;

		}

		OutboundItem next_item;
		Stream stream;
		DataAuxData aux_data = item.aux_data.data;
		
		/* On EOF, we have already detached data.  Please note that
	       application may issue submitData() in
	       $(D Connector.onFrameSent) (call from afterFrameSent),
	       which attach data to stream.  We don't want to detach it. */
		if (aux_data.eof) {
			aob.reset();			
			return ErrorCode.OK;
		}
		
		stream = getStream(frame.hd.stream_id);
		
		/* If Session is closed or RST_STREAM was queued, we won't send further data. */
		if (predicateDataSend(stream) != 0) {
			if (stream)
				stream.detachItem(this);            
			aob.reset();
			
			return ErrorCode.OK;
		}
		
		/* Assuming stream is not null */
		assert(stream);
		next_item = getNextOutboundItem();
		
		/* Imagine we hit connection window size limit while sending DATA
	       frame.  If we decrement weight here, its stream might get
	       inferior share because the other streams' weight is not
	       decremented because of flow control. */
		if (remote_window_size > 0 || stream.remoteWindowSize <= 0) {
			cycleWeightOutboundItem(aob.item, stream.effectiveWeight);
		}
		
		/* If priority of this stream is higher or equal to other stream
	       waiting at the top of the queue, we continue to send this
	       data. */
		if (stream.dpri == StreamDPRI.TOP && (!next_item || PriorityQueue.compare(item, next_item) < 0)) 
		{
			int next_readmax = nextDataRead(stream);
			
			if (next_readmax == 0) {
				
				if (remote_window_size == 0 && stream.remoteWindowSize > 0) {
					
					/* If DATA cannot be sent solely due to connection level
		             window size, just push item to queue again.  We never pop
		             DATA item while connection level window size is 0. */
					ob_da_pq.push(aob.item);
					
					if (isFatal(rv)) {
						return rv;
					}
					
					aob.item.queued = 1;
				} else
					stream.deferItem(StreamFlags.DEFERRED_FLOW_CONTROL, this);
				
				aob.item = null;
				aob.reset();
				
				return ErrorCode.OK;
			}
			
			framebufs.reset();
			
			rv = packData(framebufs, next_readmax, *frame, aux_data);
			if (isFatal(rv)) {
				return rv;
			}
			if (rv == ErrorCode.DEFERRED) {
				stream.deferItem(StreamFlags.DEFERRED_USER, this);
				
				aob.item = null;
				aob.reset();
				
				return ErrorCode.OK;
			}
			if (rv == ErrorCode.TEMPORAL_CALLBACK_FAILURE)
			{
				/* Stop DATA frame chain and issue RST_STREAM to close the stream.  We don't return ErrorCode.TEMPORAL_CALLBACK_FAILURE intentionally. */
				addRstStream(frame.hd.stream_id, FrameError.INTERNAL_ERROR);
				stream.detachItem(this);
				aob.reset();
				return ErrorCode.OK;
			}
			
			assert(rv == 0);
			
			return ErrorCode.OK;
		}
		
		if (stream.dpri == StreamDPRI.TOP) {
			ob_da_pq.push(aob.item);
						
			aob.item.queued = true;
		}
		
		aob.item = null;
		aob.reset();
		return ErrorCode.OK;
	}

	// fetch data and feed it to data_arr
	ErrorCode memSendInternal(ref ubyte[] data_arr, bool fast_cb)
	{
		ErrorCode rv;
		Buffers framebufs = aob.framebufs;
		
		data_arr = null;

		for (;;) {
			final switch (aob.state) {
				case OutboundState.POP_ITEM: {
					OutboundItem item;
					
					item = popNextOutboundItem();
					if (!item) {
						return ErrorCode.OK;
					}
					
					if (item.frame.hd.type == FrameType.DATA || item.frame.hd.type == FrameType.HEADERS) {
						Frame* frame = &item.frame;
						Stream stream = getStream(frame.hd.stream_id);

						if (stream && item == stream.item && stream.dpri != StreamDPRI.TOP) {
							/* We have DATA with higher priority in queue within the same dependency tree. */
							break;
						}
					}
					
					rv = prepareFrame(item);
					if (rv == ErrorCode.DEFERRED) {
						LOGF("send: frame transmission deferred");
						break;
					}
					if (rv < 0) {
						int opened_stream_id;
						FrameError error_code = FrameError.INTERNAL_ERROR;
						import libhttp2.helpers : toString;
						LOGF("send: frame preparation failed with %s", toString(cast(ErrorCode)rv));
						/* TODO: If the error comes from compressor, the connection must be closed. */
						if (item.frame.hd.type != FrameType.DATA && !isFatal(rv)) {
							Frame* frame = &item.frame;
							/* The library is responsible for the transmission of WINDOW_UPDATE frame, so we don't call error callback for it. */
							if (frame.hd.type != FrameType.WINDOW_UPDATE && connector.onFrameFailure(*frame, rv) != 0)
							{
								item.free();
								Mem.free(item);
								return ErrorCode.CALLBACK_FAILURE;
							}
						}

						/* We have to close stream opened by failed request HEADERS or PUSH_PROMISE. */
						switch (item.frame.hd.type) {
							case FrameType.HEADERS:
								if (item.frame.headers.cat == HeadersCategory.REQUEST) {
									opened_stream_id = item.frame.hd.stream_id;
									if (item.aux_data.headers.canceled) {
										error_code = item.aux_data.headers.error_code;
									}
								}
								break;
							case FrameType.PUSH_PROMISE:
								opened_stream_id = item.frame.push_promise.promised_stream_id;
								break;

							default: break;
						}
						if (opened_stream_id) {
							/* careful not to override rv */
							ErrorCode rv2;
							rv2 = closeStream(opened_stream_id, error_code);
							
							if (isFatal(rv2)) {
								return rv2;
							}
						}

						item.free();
						Mem.free(item);
						aob.reset();
						
						if (rv == ErrorCode.HEADER_COMP) {
							/* If header compression error occurred, should terminiate connection. */
							rv = terminateSession(FrameError.INTERNAL_ERROR);
						}
						if (isFatal(rv)) {
							return rv;
						}
						break;
					}
					
					aob.item = item;
					
					framebufs.rewind();
					
					if (item.frame.hd.type != FrameType.DATA) {
						Frame* frame = &item.frame;
						
						LOGF("send: next frame: payloadlen=%d, type=%u, flags=0x%02x, stream_id=%d",
								frame.hd.length, frame.hd.type, frame.hd.flags,
								frame.hd.stream_id);
						
						bool ok = callOnFrameReady(*frame);
						if (!ok) {
							return ErrorCode.CALLBACK_FAILURE;
						}
					} else {
						LOGF("send: next frame: DATA");
					}
					
					LOGF("send: start transmitting frame type=%u, length=%d",
							framebufs.cur.buf.pos[3],
							framebufs.cur.buf.last - framebufs.cur.buf.pos);
					
					aob.state = OutboundState.SEND_DATA;
					
					break;
				}
				case OutboundState.SEND_DATA: {
					size_t datalen;
					Buffer* buf = &framebufs.cur.buf;
					
					if (buf.pos == buf.last) {
						LOGF("send: end transmission of a frame");

						/* Frame has completely sent */
						if (fast_cb) {
							rv = resetActiveOutboundItem();
						} else {
							rv = afterFrameSent();
							if (rv < 0) {
								/* FATAL */
								assert(isFatal(rv));
								return rv;
							}
							rv = resetActiveOutboundItem();
						}
						if (rv < 0) {
							/* FATAL */
							assert(isFatal(rv));
							return rv;
						}
						/* We have already adjusted the next state */
						break;
					}

					datalen = buf.length;
					data_arr = buf.pos[0 .. datalen];
					
					/* We increment the offset here. If send_callback does not send everything, we will adjust it. */
					buf.pos += datalen;
					
					return ErrorCode.OK;
				}
			}
		}
	}

	/*
	 * Inflates header block in the memory pointed by |input| with |input.length|
	 * bytes. If this function returns ErrorCode.PAUSE, the caller must
	 * call this function again, until it returns 0 or one of negative
	 * error code.  If |call_header_cb| is zero, the on_header_callback
	 * are not invoked and the function never return ErrorCode.PAUSE. If
	 * the given |in| is the last chunk of header block, the |final| must
	 * be nonzero. If header block is successfully processed (which is
	 * indicated by the return value 0, ErrorCode.PAUSE or
	 * ErrorCode.TEMPORAL_CALLBACK_FAILURE), the number of processed
	 * input bytes is assigned to the |*readlen_ptr|.
	 *
	 * This function return 0 if it succeeds, or one of the negative error
	 * codes:
	 *
	 * ErrorCode.CALLBACK_FAILURE
	 *     The callback function failed.
	 * ErrorCode.TEMPORAL_CALLBACK_FAILURE
	 *     The callback returns this error code, indicating that this
	 *     stream should be RST_STREAMed..
	 * ErrorCode.PAUSE
	 *     The callback function returned ErrorCode.PAUSE
	 * ErrorCode.HEADER_COMP
	 *     Header decompression failed
	 */
	ErrorCode inflateHeaderBlock(Frame frame, ref size_t readlen_ref, ubyte[] input, bool is_final, bool call_header_cb) 
	{
		int proclen;
		ErrorCode rv;
		InflateFlag inflate_flag;
		HeaderField hf;
		Stream stream;
		Stream subject_stream;
		bool trailer;
		
		readlen_ref = 0;
		stream = getStream(frame.hd.stream_id);
		
		if (frame.hd.type == FrameType.PUSH_PROMISE) {
			subject_stream = getStream(frame.push_promise.promised_stream_id);
		} else {
			subject_stream = stream;
			trailer = isTrailerHeaders(stream, frame);
		}
		
		LOGF("recv: decoding header block %d bytes", input.length);
		size_t inlen = input.length;
		ubyte* inptr = input.ptr;
		for (;;) {
			inflate_flag = InflateFlag.NONE;
			proclen = hd_inflater.inflate(hf, inflate_flag, inptr[0 .. inlen], is_final);
			
			if (isFatal(cast(int)proclen)) {
				return cast(ErrorCode)proclen;
			}
			
			if (proclen < 0) {
				if (iframe.state == InboundState.READ_HEADER_BLOCK) 
				{
					if (stream && stream.state != StreamState.CLOSING) 
					{
						/* Adding RST_STREAM here is very important. It prevents
                       from invoking subsequent callbacks for the same stream ID. */
						addRstStream(frame.hd.stream_id, FrameError.COMPRESSION_ERROR);
						
					}
				}
				rv = terminateSession(FrameError.COMPRESSION_ERROR);
				if (isFatal(rv)) {
					return rv;
				}
				
				return ErrorCode.HEADER_COMP;
			}
			
			inptr += proclen;
			inlen -= proclen;
			readlen_ref += proclen;
			
			LOGF("recv: proclen=%d", proclen);
			
			if (call_header_cb && (inflate_flag & InflateFlag.EMIT)) {
				if (subject_stream && isHTTPMessagingEnabled()) {
					bool ok = validateHeaderField(subject_stream, frame, hf, trailer);
					if (!ok) {
						LOGF("recv: HTTP error: type=%d, id=%d, header %.*s: %.*s",
								frame.hd.type, subject_stream.id, cast(int)hf.name.length,
								hf.name, cast(int)hf.value.length, hf.value);
						
						addRstStream(subject_stream.id, FrameError.PROTOCOL_ERROR);
						return ErrorCode.TEMPORAL_CALLBACK_FAILURE;
					}
				}
				if (call_header_cb) {
					bool pause;
					bool close;
					bool ok = callOnHeaderField(frame, hf, pause, close);
					if (!ok)
						return ErrorCode.CALLBACK_FAILURE;
					if (close)
						return ErrorCode.TEMPORAL_CALLBACK_FAILURE;
					if (pause)
						return ErrorCode.PAUSE;
					
				}
			}
			if (inflate_flag & InflateFlag.FINAL) {
				hd_inflater.endHeaders();
				break;
			}
			if ((inflate_flag & InflateFlag.EMIT) == 0 && inlen == 0) {
				break;
			}
		}
		return ErrorCode.OK;
	}

package: /* Used only for tests */
	/*
	 * Returns top of outbound frame queue. This function returns null if
	 * queue is empty.
	 */
	@property OutboundItem ob_pq_top() {
		return ob_pq.top;
	}
	
package:
	HashMap!(int, Stream) streams;
	
	StreamRoots roots;
	
	/// Priority Queue for outbound frames other than stream-starting HEADERS and DATA
	PriorityQueue ob_pq;

	/// Priority Queue for outbound stream-starting HEADERS frame
	PriorityQueue ob_ss_pq;
	
	/// Priority Queue for DATA frame 
	PriorityQueue ob_da_pq;
	
	ActiveOutboundItem aob;
	InboundFrame iframe;
	Deflater hd_deflater;
	Inflater hd_inflater;
	Connector connector;
	
	/// Sequence number of outbound frame to maintain the order of enqueue if priority is equal.
	long next_seq;
	
	/** Reset count of OutboundItem's weight.  We decrements
        weight each time DATA is sent to simulate resource sharing.  We
        use priority queue and larger weight has the precedence.  If
        weight is reached to lowest weight, it resets to its initial
        weight.  If this happens, other items which have the lower weight
        currently but same initial weight cannot send DATA until item
        having large weight is decreased.  To avoid this, we use this
        cycle variable.  Initally, this is set to 1.  If weight gets
        lowest weight, and if item's cycle == last_cycle, we increments
        last_cycle and assigns it to item's cycle.  Otherwise, just
        assign last_cycle.  In priority queue comparator, we first
        compare items' cycle value.  Lower cycle value has the
        precedence. */
	ulong last_cycle = 1;
	
	/// Points to the latest closed stream.  null if there is no closed stream.  
	/// Notes: Only used when session is initialized as server.
	Stream closed_stream_head;
	
	/// Points to the oldest closed stream.  null if there is no closed stream.  
	/// Notes: Only used when session is initialized as server.
	Stream closed_stream_tail;
	
	/// Points to the latest idle stream.  null if there is no idle stream.  
	/// Notes: Only used when session is initialized as server .
	Stream idle_stream_head;
	
	/// Points to the oldest idle stream.  null if there is no idle stream. 
	/// Notes: Only used when session is initialized as server.
	Stream idle_stream_tail;
	
	/// In-flight SETTINGS values. null for no in-flight SETTINGS. 
	Setting[] inflight_iva;
	
	/// The number of outgoing streams. This will be capped by remote_settings.max_concurrent_streams.
	size_t num_outgoing_streams;
	
	/// The number of incoming streams. This will be capped by local_settings.max_concurrent_streams.
	size_t num_incoming_streams;
	
	/// The number of closed streams still kept in |streams| hash.  The closed streams can be accessed
	/// through single linked list |closed_stream_head|. 
	/// Notes: The current implementation only keeps incoming streams if session is initialized as server.
	size_t num_closed_streams;
	
	/// The number of idle streams kept in |streams| hash. The idle streams can be accessed through doubly linked list
	/// |idle_stream_head|.  
	/// Notes: The current implementation only keeps idle streams if session is initialized as server.
	size_t num_idle_streams;
	
	/// Next Stream ID. Made unsigned int to detect >= (1 << 31). 
	uint next_stream_id;

	/// The largest stream ID received so far
	int last_recv_stream_id;
	
	/// The largest stream ID which has been processed in some way. 
	/// Notes: This value will be used as last-stream-id when sending GOAWAY frame.
	int last_proc_stream_id;
	
	/// Counter of unique ID of PING. Wraps when it exceeds max_UNIQUE_ID */
	uint next_unique_id;
	
	/// This is the last-stream-ID we have sent in GOAWAY
	int local_last_stream_id = (1u << 31) - 1;
	
	/// This is the value in GOAWAY frame received from remote endpoint.
	int remote_last_stream_id = (1u << 31) - 1;
	
	/// Current sender window size. This value is computed against the current initial window size of remote endpoint.
	int remote_window_size = INITIAL_CONNECTION_WINDOW_SIZE;
	
	/// Keep track of the number of bytes received without WINDOW_UPDATE. This could be negative after
	/// submitting negative value to WINDOW_UPDATE.
	int recv_window_size;
	
	/// The number of bytes consumed by the application and now is subject to WINDOW_UPDATE. 
	/// Notes: This is only used when auto WINDOW_UPDATE is turned off. 
	int consumed_size;
	
	/// The amount of recv_window_size cut using submitting negative value to WINDOW_UPDATE
	int recv_reduction;
	
	/// window size for local flow control. It is initially set to INITIAL_CONNECTION_WINDOW_SIZE and could be
	/// increased/decreased by submitting WINDOW_UPDATE. See submitWindowUpdate().
	int local_window_size = INITIAL_CONNECTION_WINDOW_SIZE;	
	
	/// Settings value received from the remote endpoint. We just use ID as index. The index = 0 is unused. 
	SettingsStorage remote_settings;
	
	/// Settings value of the local endpoint.
	SettingsStorage local_settings;
	
	/// Option flags. This is bitwise-OR of 0 or more of OptionsMask.
	OptionsMask opt_flags;
	
	/// Unacked local Setting.MAX_CONCURRENT_STREAMS value. We use this to refuse the incoming stream if it exceeds this value. 
	uint pending_local_max_concurrent_stream = INITIAL_MAX_CONCURRENT_STREAMS;
	
	/// true if the session is server side. 
	bool is_server;
	
	/// Flags indicating GOAWAY is sent and/or recieved. 
	GoAwayFlags goaway_flags = GoAwayFlags.NONE;
	

}
/**
 * @function
 *
 * Serializes the SETTINGS values |iv| in the |buf|.  The size of the
 * |buf| is specified by |buflen|.  The number of entries in the |iv|
 * array is given by |niv|.  The required space in |buf| for the |niv|
 * entries is `8*niv` bytes and if the given buffer is too small, an
 * error is returned.  This function is used mainly for creating a
 * SETTINGS payload to be sent with the `HTTP2-Settings` header
 * field in an HTTP Upgrade request.  The data written in |buf| is NOT
 * base64url encoded and the application is responsible for encoding.
 *
 * This function returns the number of bytes written in |buf|, or one
 * of the following negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |iv| contains duplicate settings ID or invalid value.
 *
 * $(D ErrorCode.INSUFF_BUFSIZE)
 *     The provided |buflen| size is too small to hold the output.
 */
int packSettingsPayload(ubyte[] buf, in Setting[] iva)
{
	if (!iva.check()) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	if (buf.length < (iva.length * FRAME_SETTINGS_ENTRY_LENGTH)) {
		return ErrorCode.INSUFF_BUFSIZE;
	}
	
	return Settings.pack(buf, iva);
}

/**
 * Submits HEADERS frame and optionally one or more DATA frames.
 *
 * The |pri_spec| is priority specification of this request. 
 * To specify the priority, use `PrioritySpec()`.
 *
 * The `pri_spec.weight` must be in [$(D MIN_WEIGHT),
 * $(D MAX_WEIGHT)], inclusive.  If `pri_spec.weight` is
 * strictly less than $(D MIN_WEIGHT), it becomes
 * $(D MIN_WEIGHT).  If it is strictly greater than
 * $(D MAX_WEIGHT), it becomes $(D MAX_WEIGHT).
 *
 * The |hfa| is an array of header fields $(D HeaderField) with
 * |hfa.length| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |hfa| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all header fields in |hfa|.  It
 * also lower-cases all names in |hfa|.  The order of elements in
 * |hfa| is preserved.
 *
 * HTTP/2 specification has requirement about header fields in the
 * request HEADERS.  See the specification for more details.
 *
 * If |data_prd| is not `null`, it provides data which will be sent
 * in subsequent DATA frames.  In this case, a method that allows
 * request message bodies
 * (http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9) must
 * be specified with `:method` key in |hfa| (e.g. `POST`).  This
 * function does not take ownership of the |data_prd|.  The function
 * copies the members of the |data_prd|.  If |data_prd| is `null`,
 * HEADERS have END_STREAM set.  The |stream_user_data| is data
 * associated to the stream opened by this request and can be an
 * arbitrary pointer, which can be retrieved later by
 * `getStreamUserData()`.
 *
 * This function returns assigned stream ID if it succeeds, or one of
 * the following negative error codes:
 * 
 * $(D ErrorCode.STREAM_ID_NOT_AVAILABLE)
 *     No stream ID is available because maximum stream ID was
 *     reached.
 *
 * .. warning::
 *
 *   This function returns assigned stream ID if it succeeds.  But
 *   that stream is not opened yet. The application must not submit
 *   a frame to that stream ID before $(D Connector.onFrameReady) is called for this
 *   frame.
 *
 */
int submitRequest(Session session, in PrioritySpec pri_spec, in HeaderField[] hfa, in DataProvider data_prd, void* stream_user_data = null)
{
	FrameFlags flags = setRequestFlags(pri_spec, data_prd);
	
	return submitHeadersSharedHfa(session, flags, -1, pri_spec, hfa, data_prd, stream_user_data, false);
}

/**
 * Submits response HEADERS frame and optionally one or more DATA
 * frames against the stream |stream_id|.
 *
 * The |hfa| is an array of $(D HeaderField) with
 * |hfa.length| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |hfa| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all header fields in |hfa|.  It
 * also lower-cases all names in |hfa|.  The order of elements in
 * |hfa| is preserved.
 *
 * HTTP/2 specification has requirement about header fields in the
 * response HEADERS.  See the specification for more details.
 *
 * If |data_prd| is not `null`, it provides data which will be sent
 * in subsequent DATA frames.  This function does not take ownership
 * of the |data_prd|.  The function copies the members of the
 * |data_prd|.  If |data_prd| is `null`, HEADERS will have
 * END_STREAM flag set.
 *
 * This method can be used as normal HTTP response and push response.
 * When pushing a resource using this function, the $(D Session) must be
 * configured using `new Session()` or its variants and
 * the target stream denoted by the |stream_id| must be reserved using
 * `submitPushPromise()`.
 *
 * To send non-final response headers (e.g., HTTP status 101), don't
 * use this function because this function half-closes the outbound
 * stream.  Instead, use `submitHeaders()` for this purpose.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 * 
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 *
 * .. warning::
 *
 *   Calling this function twice for the same stream ID may lead to
 *   program crash.  It is generally considered to a programming error
 *   to commit response twice.
 */
ErrorCode submitResponse(Session session, int stream_id, in HeaderField[] hfa, in DataProvider data_prd)
{
	FrameFlags flags = setResponseFlags(data_prd);
	return cast(ErrorCode)submitHeadersSharedHfa(session, flags, stream_id, PrioritySpec.init, hfa, data_prd, null, true);
}

/**
 * Submits HEADERS frame. The |flags| is bitwise OR of the
 * following values:
 *
 * * $(D FrameFlags.END_STREAM)
 *
 * If |flags| includes $(D FrameFlags.END_STREAM), this frame has
 * END_STREAM flag set.
 *
 * The library handles the CONTINUATION frame internally and it
 * correctly sets END_HEADERS to the last sequence of the PUSH_PROMISE
 * or CONTINUATION frame.
 *
 * If the |stream_id| is -1, this frame is assumed as request (i.e.,
 * request HEADERS frame which opens new stream).  In this case, the
 * assigned stream ID will be returned.  Otherwise, specify stream ID
 * in |stream_id|.
 *
 * The |pri_spec| is priority specification of this request.  init
 * means the default priority.  To specify the priority,
 * use $(D PrioritySpec) constructor. 
 *
 * The `pri_spec.weight` must be in [$(D MIN_WEIGHT),
 * $(D MAX_WEIGHT)], inclusive.  If `pri_spec.weight` is
 * strictly less than $(D MIN_WEIGHT), it becomes
 * $(D MIN_WEIGHT).  If it is strictly greater than
 * $(D MAX_WEIGHT), it becomes $(D MAX_WEIGHT).
 *
 * The |hfa| is an array of header fields $(D HeaderField) with
 * |hfa.length| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |hfa| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all header fields in |hfa|.  It
 * also lower-cases all names in |hfa|.  The order of elements in
 * |hfa| is preserved.
 *
 * The |stream_user_data| is a pointer to an arbitrary data which is
 * associated to the stream this frame will open.  Therefore it is
 * only used if this frame opens streams, in other words, it changes
 * stream state from idle or reserved to open.
 *
 * This function is low-level in a sense that the application code can
 * specify flags directly.  For usual HTTP request,
 * `submitRequest()` is useful.
 *
 * This function returns newly assigned stream ID if it succeeds and
 * |stream_id| is -1.  Otherwise, this function returns 0 if it
 * succeeds, or one of the following negative error codes:
 * 
 * $(D ErrorCode.STREAM_ID_NOT_AVAILABLE)
 *     No stream ID is available because maximum stream ID was
 *     reached.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 *
 * .. warning::
 *
 *   This function returns assigned stream ID if it succeeds and
 *   |stream_id| is -1.  But that stream is not opened yet.  The
 *   application must not submit frame to that stream ID before
 *   $(D Connector.onFrameHeader) is called for this
 *   frame.
 *
 */
ErrorCode submitHeaders(Session session, FrameFlags flags, int stream_id = -1, in PrioritySpec pri_spec = PrioritySpec.init, in HeaderField[] hfa = null, void *stream_user_data = null)
{
	flags &= FrameFlags.END_STREAM;
	
	if (pri_spec != PrioritySpec.init)
		flags |= FrameFlags.PRIORITY;
	
	return submitHeadersSharedHfa(session, flags, stream_id, pri_spec, hfa, DataProvider.init, stream_user_data, false);
}

/**
 * Submits one or more DATA frames to the stream |stream_id|.  The
 * data to be sent are provided by |data_prd|.  If |flags| contains
 * $(D FrameFlags.END_STREAM), the last DATA frame has END_STREAM
 * flag set.
 *
 * This function does not take ownership of the |data_prd|.  The
 * function copies the members of the |data_prd|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 * 
 * $(D ErrorCode.DATA_EXIST)
 *     DATA has been already submitted and not fully processed yet.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 * $(D ErrorCode.STREAM_CLOSED)
 *     The stream was alreay closed; or the |stream_id| is invalid.
 *
 * .. note::
 *
 *   Currently, only one data is allowed for a stream at a time.
 *   Submitting data more than once before first data is finished
 *   results in $(D ErrorCode.DATA_EXIST) error code.  The
 *   earliest callback which tells that previous data is done is
 *   $(D Connector.onFrameSent).  In side that callback,
 *   new data can be submitted using `submitData()`.  Of
 *   course, all data except for last one must not have
 *   $(D FrameFlags.END_STREAM) flag set in |flags|.
 */
ErrorCode submitData(Session session, FrameFlags flags, int stream_id, in DataProvider data_prd)
{
	OutboundItem item;
	Frame* frame;
	DataAuxData* aux_data;
	DataFlags nflags = cast(DataFlags)(flags & FrameFlags.END_STREAM);
	
	if (stream_id == 0)
		return ErrorCode.INVALID_ARGUMENT;

	item = Mem.alloc!OutboundItem(session);
	scope(failure) Mem.free(item);
	
	frame = &item.frame;
	aux_data = &item.aux_data.data;
	aux_data.data_prd = data_prd;
	aux_data.eof = false;
	aux_data.flags = nflags;
	
	/* flags are sent on transmission */
	frame.data = Data(FrameFlags.NONE, stream_id);
	scope(failure) frame.data.free();
	session.addItem(item);
	return ErrorCode.OK;
}

/**
 * Submits PRIORITY frame to change the priority of stream |stream_id|
 * to the priority specification |pri_spec|.
 *
 *
 * The |pri_spec| is priority specification of this request.  `null`
 * is not allowed for this function. To specify the priority, use
 * `PrioritySpec.init`.  This function will copy its data
 * members.
 *
 * The `pri_spec.weight` must be in [$(D MIN_WEIGHT),
 * $(D MAX_WEIGHT)], inclusive.  If `pri_spec.weight` is
 * strictly less than $(D MIN_WEIGHT), it becomes
 * $(D MIN_WEIGHT).  If it is strictly greater than
 * $(D MAX_WEIGHT), it becomes $(D MAX_WEIGHT).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0; or the |pri_spec| is null; or trying to
 *     depend on itself.
 */
ErrorCode submitPriority(Session session, int stream_id, in PrioritySpec pri_spec)
{
	OutboundItem item;
	Frame* frame;
	PrioritySpec copy_pri_spec;

	if (stream_id == 0 || pri_spec == PrioritySpec.init)
		return ErrorCode.INVALID_ARGUMENT;
	
	if (stream_id == pri_spec.stream_id)
		return ErrorCode.INVALID_ARGUMENT;
	
	copy_pri_spec = pri_spec;
	
	copy_pri_spec.adjustWeight();
	
	item = Mem.alloc!OutboundItem(session);
	scope(failure) Mem.free(item);
	frame = &item.frame;
	
	frame.priority = Priority(stream_id, copy_pri_spec);
	scope(failure) frame.priority.free();

	session.addItem(item);
	return ErrorCode.OK;
}


/**
 * @function
 *
 * Submits RST_STREAM frame to cancel/reject the stream |stream_id|
 * with the error code |error_code|.
 *
 * The pre-defined error code is one of $(D FrameError).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 */
ErrorCode submitRstStream(Session session, int stream_id, FrameError error_code)
{
	if (stream_id == 0)
		return ErrorCode.INVALID_ARGUMENT;
	
	session.addRstStream(stream_id, error_code);
	return ErrorCode.OK;
}

/**
 * @function
 *
 * Stores local settings and submits SETTINGS frame.  The |iva| is the
 * pointer to the array of $(D Setting).  The |iv.length|
 * indicates the number of settings.
 *
 * This function does not take ownership of the |iva|.  This function
 * copies all the elements in the |iva|.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than max_WINDOW_SIZE,
 * RST_STREAM is issued against such a stream.
 *
 * SETTINGS with $(D FrameFlags.ACK) is automatically submitted
 * by the library and application could not send it at its will.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |iv| contains invalid value (e.g., initial window size
 *     strictly greater than (1 << 31) - 1.
 * $(D ErrorCode.TOO_MANY_INFLIGHT_SETTINGS)
 *     There is already another in-flight SETTINGS.  Note that the
 *     current implementation only allows 1 in-flight SETTINGS frame
 *     without ACK flag set.
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode submitSettings(Session session, in Setting[] iva)
{
	return session.addSettings(FrameFlags.NONE, iva);
}

/**
 * Submits PUSH_PROMISE frame.
 *
 * The |stream_id| must be client initiated stream ID.
 *
 * The |hfa| is an array of $(D HeaderField) with
 * |hfa.length| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |hfa| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all header fieldss in |hfa|.  It
 * also lower-cases all names in |hfa|.  The order of elements in
 * |hfa| is preserved.
 *
 * The |promised_stream_user_data| is a pointer to an arbitrary data
 * which is associated to the promised stream this frame will open and
 * make it in reserved state.  It is available using $(D Session.getStreamUserData).  
 * The application can access it in $(D Connector.onFrameHeader) and
 * $(D Connector.onFrameSent) of this frame.
 *
 * The client side is not allowed to use this function.
 *
 * To submit response headers and data, use
 * `submitResponse()`.
 *
 * This function returns assigned promised stream ID if it succeeds,
 * or one of the following negative error codes:
 * 
 * $(D ErrorCode.PROTO)
 *     This function was invoked when $(D Session) is initialized as
 *     client.
 * $(D ErrorCode.STREAM_ID_NOT_AVAILABLE)
 *     No stream ID is available because maximum stream ID was
 *     reached.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0; The |stream_id| does not designate stream
 *     that peer initiated.
 *
 * .. warning::
 *
 *   This function returns assigned promised stream ID if it succeeds.
 *   But that stream is not opened yet.  The application must not
 *   submit frame to that stream ID before
 *   $(D Connector.onFrameHeader) is called for this
 *   frame.
 *
 */
int submitPushPromise(Session session, int stream_id, in HeaderField[] hfa, void* promised_stream_user_data)
{
	OutboundItem item;
	Frame* frame;
	HeaderField[] hfa_copy;
	FrameFlags flags_copy;
	int promised_stream_id;

	if (stream_id == 0 || session.isMyStreamId(stream_id)) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	if (!session.is_server)
		return ErrorCode.PROTO;
	
	/* All 32bit signed stream IDs are spent. */
	if (session.next_stream_id > int.max) {
		return ErrorCode.STREAM_ID_NOT_AVAILABLE;
	}
	
	item = Mem.alloc!OutboundItem(session);
	scope(failure) 
		Mem.free(item);

	item.aux_data.headers.stream_user_data = promised_stream_user_data;
	
	frame = &item.frame;
	bool is_owner;
	hfa_copy = hfa.copy();
	is_owner = true;
	scope(failure) if (is_owner) Mem.free(hfa_copy);
	flags_copy = FrameFlags.END_HEADERS;
	
	promised_stream_id = session.next_stream_id;
	session.next_stream_id += 2;

	is_owner = false;
	frame.push_promise = PushPromise(flags_copy, stream_id,	promised_stream_id, hfa_copy);
	scope(failure) frame.push_promise.free();

	session.addItem(item);

	return promised_stream_id;
}

/**
 * Submits PING frame.  You don't have to send PING back when you
 * received PING frame.  The library automatically submits PING frame
 * in this case.
 *
 * The |flags| is currently ignored and should be
 * $(D FrameFlags.NONE).
 *
 * If the |opaque_data| is non `null`, then it should point to the 8
 * bytes array of memory to specify opaque data to send with PING
 * frame.  If the |opaque_data| is `null`, zero-cleared 8 bytes will
 * be sent as opaque data.
 */
void submitPing(Session session, in ubyte[] opaque_data)
{
	return session.addPing(FrameFlags.NONE, opaque_data);
}

/**
 * @function
 *
 * Submits GOAWAY frame with the last stream ID |last_stream_id| and
 * the error code |error_code|.
 *
 * The pre-defined error code is one of $(D FrameError).
 *
 * The |flags| is currently ignored and should be
 * $(D FrameFlags.NONE).
 *
 * The |last_stream_id| is peer's stream ID or 0.  So if $(D Session) is
 * initialized as client, |last_stream_id| must be even or 0.  If
 * $(D Session) is initialized as server, |last_stream_id| must be odd or
 * 0.
 *
 * The HTTP/2 specification says last_stream_id must not be increased
 * from the value previously sent.  So the actual value sent as
 * last_stream_id is the minimum value between the given
 * |last_stream_id| and the last_stream_id previously sent to the
 * peer.
 *
 * If the |opaque_data| is not `null` and |opaque_data_len| is not
 * zero, those data will be sent as additional debug data.  The
 * library makes a copy of the memory region pointed by |opaque_data|
 * with the length |opaque_data_len|, so the caller does not need to
 * keep this memory after the return of this function.  If the
 * |opaque_data_len| is 0, the |opaque_data| could be `null`.
 *
 * After successful transmission of GOAWAY, following things happen.
 * All incoming streams having strictly more than |last_stream_id| are
 * closed.  All incoming HEADERS which starts new stream are simply
 * ignored.  After all active streams are handled, both
 * `wantRead()` and `wantWrite()` return 0 and the application can close session.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 * 
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |opaque_data.length| is too large; the |last_stream_id| is invalid.
 */
ErrorCode submitGoAway(Session session, int last_stream_id, FrameError error_code, in string opaque_data)
{
	if (session.goaway_flags & GoAwayFlags.TERM_ON_SEND) {
		return ErrorCode.OK;
	}
	return session.addGoAway(last_stream_id, error_code, opaque_data, GoAwayAuxFlags.NONE);
}

/**
 * Submits WINDOW_UPDATE frame.
 *
 * The |flags| is currently ignored and should be
 * $(D FrameFlags.NONE).
 *
 * If the |window_size_increment| is positive, the WINDOW_UPDATE with
 * that value as window_size_increment is queued.  If the
 * |window_size_increment| is larger than the received bytes from the
 * remote endpoint, the local window size is increased by that
 * difference.
 *
 * If the |window_size_increment| is negative, the local window size
 * is decreased by -|window_size_increment|.  If automatic
 * WINDOW_UPDATE is enabled
 * $(D Options.setNoAutoWindowUpdate), and the library
 * decided that the WINDOW_UPDATE should be submitted, then
 * WINDOW_UPDATE is queued with the current received bytes count.
 *
 * If the |window_size_increment| is 0, the function does nothing and
 * returns 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.FLOW_CONTROL)
 *     The local window size overflow or gets negative.
 */
ErrorCode submitWindowUpdate(Session session, int stream_id, int window_size_increment)
{
	ErrorCode rv;
	Stream stream;
	if (window_size_increment == 0) {
		return ErrorCode.OK;
	}
	FrameFlags flags;
	if (stream_id == 0) {
		rv = adjustLocalWindowSize(session.local_window_size, session.recv_window_size, session.recv_reduction, window_size_increment);
		if (rv != ErrorCode.OK) {
			return rv;
		}
	} else {
		stream = session.getStream(stream_id);
		if (!stream) {
			return ErrorCode.OK;
		}
		
		rv = adjustLocalWindowSize(stream.localWindowSize, stream.recvWindowSize, stream.recvReduction, window_size_increment);
		if (rv != ErrorCode.OK) {
			return rv;
		}
	}
	
	if (window_size_increment > 0) {
		if (stream_id == 0) {
			session.consumed_size = max(0, session.consumed_size - window_size_increment);
		} else {
			stream.consumedSize = max(0, stream.consumedSize - window_size_increment);
		}
		
		session.addWindowUpdate(flags, stream_id, window_size_increment);
	}
	return ErrorCode.OK;
}


/**
 * Signals to the client that the server started graceful shutdown
 * procedure.
 *
 * This function is only usable for server.  If this function is
 * called with client side session, this function returns
 * $(D ErrorCode.INVALID_STATE).
 *
 * To gracefully shutdown HTTP/2 session, server should call this
 * function to send GOAWAY with last_stream_id (1u << 31) - 1.  And
 * after some delay (e.g., 1 RTT), send another GOAWAY with the stream
 * ID that the server has some processing using
 * `submitGoAway()`.  See also `getLastProcStreamID()`.
 *
 * Unlike `submitGoAway()`, this function just sends GOAWAY
 * and does nothing more.  This is a mere indication to the client
 * that session shutdown is imminent.  The application should call
 * `submitGoAway()` with appropriate last_stream_id after
 * this call.
 *
 * If one or more GOAWAY frame have been already sent by either
 * `submitGoAway()` or `terminateSession()`, this function has no effect.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_STATE)
 *     The $(D Session) is initialized as client.
 */
ErrorCode submitShutdownNotice(Session session)
{
	if (!session.is_server) {
		return ErrorCode.INVALID_STATE;
	}
	if (session.goaway_flags)
		return ErrorCode.OK;

	return session.addGoAway((1u << 31) - 1, FrameError.NO_ERROR, null, GoAwayAuxFlags.SHUTDOWN_NOTICE);
}

private: 

FrameFlags setResponseFlags(in DataProvider data_prd) 
{
	FrameFlags flags = FrameFlags.NONE;

	if (data_prd == DataProvider.init || !data_prd.read_callback) 
		flags |= FrameFlags.END_STREAM;

	return flags;
}

FrameFlags setRequestFlags(in PrioritySpec pri_spec, in DataProvider data_prd)
{
	FrameFlags flags = FrameFlags.NONE;
	if (!data_prd.read_callback)
		flags |= FrameFlags.END_STREAM;
		
	if (pri_spec != PrioritySpec.init) 
		flags |= FrameFlags.PRIORITY;
		
	return flags;
}

/* This function takes ownership of |hfa_copy|. Regardless of the
   return value, the caller must not free |hfa_copy| after this
   function returns. */
int submitHeadersShared(Session session, FrameFlags flags, int stream_id, 
						const ref PrioritySpec pri_spec, HeaderField[] hfa_copy,
						in DataProvider data_prd, void *stream_user_data, bool attach_stream)
{
	ErrorCode rv;
	FrameFlags flags_copy;
	OutboundItem item;
	Frame* frame;
	HeadersCategory hcat;
	bool owns_hfa = true;
	scope(failure) if (owns_hfa) Mem.free(hfa_copy);
		
	if (stream_id == 0) {
		Mem.free(hfa_copy);
		return ErrorCode.INVALID_ARGUMENT;
	}

	item = Mem.alloc!OutboundItem(session);
	scope(failure) Mem.free(item);

	if (data_prd.read_callback) {
		item.aux_data.headers.data_prd = data_prd;
	}
	
	item.aux_data.headers.stream_user_data = stream_user_data;
	item.aux_data.headers.attach_stream = attach_stream;
	
	flags_copy = cast(FrameFlags)((flags & (FrameFlags.END_STREAM | FrameFlags.PRIORITY)) | FrameFlags.END_HEADERS);
	
	if (stream_id == -1) {
		if (session.next_stream_id > int.max) {
			Mem.free(item);
			Mem.free(hfa_copy);
			return ErrorCode.STREAM_ID_NOT_AVAILABLE;
		}
		
		stream_id = session.next_stream_id;
		session.next_stream_id += 2;

		hcat = HeadersCategory.REQUEST;
	} else {
		/* More specific categorization will be done later. */
		hcat = HeadersCategory.HEADERS;
	}
	
	frame = &item.frame;

	owns_hfa = false;
	frame.headers = Headers(flags_copy, stream_id, hcat, pri_spec, hfa_copy);
	session.addItem(item);
	
	if (rv != ErrorCode.OK) {
		frame.headers.free();
		Mem.free(item);
		return rv;
	}
	
	if (hcat == HeadersCategory.REQUEST)
		return stream_id;
	
	return ErrorCode.OK;
}



ErrorCode submitHeadersSharedHfa(Session session, FrameFlags flags, int stream_id, in PrioritySpec pri_spec, in HeaderField[] hfa, 
						   in DataProvider data_prd, void *stream_user_data, bool attach_stream) 
{
	HeaderField[] hfa_copy = hfa.copy();
	PrioritySpec copy_pri_spec = pri_spec;
	copy_pri_spec.adjustWeight();

	return cast(ErrorCode) submitHeadersShared(session, flags, stream_id, copy_pri_spec, hfa_copy, data_prd, stream_user_data, attach_stream);
}

public:

/**
 * A helper function for dealing with NPN in client side or ALPN in
 * server side.  The |input| contains peer's protocol list in preferable
 * order.  The format of |input| is length-prefixed and not
 * null-terminated.  For example, `HTTP-draft-04/2.0` and
 * `http/1.1` stored in |input| like this::
 *
 *     in[0] = 17
 *     in[1..17] = "HTTP-draft-04/2.0"
 *     in[18] = 8
 *     in[19..26] = "http/1.1"
 *     inlen = 27
 *
 * The selection algorithm is as follows:
 *
 * 1. If peer's list contains HTTP/2 protocol the library supports,
 *    it is selected and returns 1. The following step is not taken.
 *
 * 2. If peer's list contains `http/1.1`, this function selects
 *    `http/1.1` and returns 0.  The following step is not taken.
 *
 * 3. This function selects nothing and returns -1 (So called
 *    non-overlap case).  In this case, |output| is left
 *    untouched.
 *
 * Selecting `HTTP-draft-04/2.0` means that `HTTP-draft-04/2.0` is
 * written into |*out| and its length (which is 17) is assigned to
 * |*outlen|.
 *
 * For ALPN, refer to
 * https://tools.ietf.org/html/draft-ietf-tls-applayerprotoneg-05
 *
 * See http://technotes.googlecode.com/git/nextprotoneg.html for more
 * details about NPN.
 *
 * For NPN, to use this method you should do something like::
 *
 *     static int select_next_proto_cb(SSL* ssl,
 *                                     unsigned char **out,
 *                                     unsigned char *outlen,
 *                                     const unsigned char *in,
 *                                     unsigned int inlen,
 *                                     void *arg)
 *     {
 *         int rv;
 *         rv = selectNextProtocol(out, outlen, in, inlen);
 *         if(rv == 1) {
 *             (cast(MyType*)arg).http2_selected = 1;
 *         }
 *         return SSL_TLSEXT_ERR_OK;
 *     }
 *     ...
 *     SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, my_obj);
 *
 */
int selectNextProtocol(ref ubyte[] output, in ubyte[] input)
{
	size_t i;
	size_t len;
	while (i < input.length)
	{
		len = input[i];
		++i;
		ubyte[] proto = cast(ubyte[]) input[i .. i+len];
		i += len;
		if (proto == PROTOCOL_ALPN) {
			output = proto;
			return 1;
		}
		if (proto == HTTP_1_1_ALPN) {
			output = proto;
			return ErrorCode.OK;
		}
	}
	return -1;
}



/**
 * Returns true if the $(D RV) library error code
 * |lib_error| is fatal.
 */
bool isFatal(int lib_error) { return lib_error < ErrorCode.FATAL; }


/// Configuration options
enum OptionFlags {
	/**
   * This option prevents the library from sending WINDOW_UPDATE for a
   * connection automatically.  If this option is set to nonzero, the
   * library won't send WINDOW_UPDATE for DATA until application calls
   * $(D Session.consume) to indicate the amount of consumed
   * DATA.  By default, this option is set to zero.
   */
	NO_AUTO_WINDOW_UPDATE = 1,
	/**
   * This option sets the Setting.MAX_CONCURRENT_STREAMS value of
   * remote endpoint as if it is received in SETTINGS frame. Without
   * specifying this option, before the local endpoint receives
   * Setting.MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
   * endpoint, Setting.MAX_CONCURRENT_STREAMS is unlimited. This may
   * cause problem if local endpoint submits lots of requests
   * initially and sending them at once to the remote peer may lead to
   * the rejection of some requests. Specifying this option to the
   * sensible value, say 100, may avoid this kind of issue. This value
   * will be overwritten if the local endpoint receives
   * Setting.MAX_CONCURRENT_STREAMS from the remote endpoint.
   */
	PEER_MAX_CONCURRENT_STREAMS = 1 << 1,
	RECV_CLIENT_PREFACE = 1 << 2,
	NO_HTTP_MESSAGING = 1 << 3,
}

/// Struct to store option values for http2_session.
struct Options {
private:
	/// Bitwise OR of http2_option_flag to determine which fields are specified.
	uint m_opt_set_mask;

	uint m_peer_max_concurrent_streams;

	bool m_no_auto_window_update;

	bool m_recv_client_preface;

	bool m_no_http_messaging;
public:
	@property uint peer_max_concurrent_streams() const { return m_peer_max_concurrent_streams; }
	@property uint opt_set_mask() const { return m_opt_set_mask; }
	@property bool no_auto_window_update() const { return m_no_auto_window_update; }
	@property bool recv_client_preface() const { return m_recv_client_preface; }
	@property bool no_http_messaging() const { return m_no_http_messaging; }

	/**
	 * This option prevents the library from sending WINDOW_UPDATE for a
	 * connection automatically.  If this option is set to nonzero, the
	 * library won't send WINDOW_UPDATE for DATA until application calls
	 * `consume()` to indicate the consumed amount of
	 * data.  Don't use `http2_submit_window_update()` for this purpose.
	 * By default, this option is set to zero.
	 */
	@property void setNoAutoWindowUpdate(bool val)
	{
		if (val) m_opt_set_mask |= OptionFlags.NO_AUTO_WINDOW_UPDATE;
		else m_opt_set_mask |= ~OptionFlags.NO_AUTO_WINDOW_UPDATE;
		m_no_auto_window_update = val;
	}

	/**
	 * This option sets the Setting.MAX_CONCURRENT_STREAMS value of
	 * remote endpoint as if it is received in SETTINGS frame.  Without
	 * specifying this option, before the local endpoint receives
	 * Setting.MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
	 * endpoint, Setting.MAX_CONCURRENT_STREAMS is unlimited.  This may
	 * cause problem if local endpoint submits lots of requests initially
	 * and sending them at once to the remote peer may lead to the
	 * rejection of some requests.  Specifying this option to the sensible
	 * value, say 100, may avoid this kind of issue. This value will be
	 * overwritten if the local endpoint receives
	 * Setting.MAX_CONCURRENT_STREAMS from the remote endpoint.
	 */
	void setPeerMaxConcurrentStreams(uint val)
	{
		m_opt_set_mask |= OptionFlags.PEER_MAX_CONCURRENT_STREAMS;
		m_peer_max_concurrent_streams = val;
	}

	/**
	 * By default, libhttp2 library only handles HTTP/2 frames and does not
	 * recognize first 24 bytes of client connection preface.  This design
	 * choice is done due to the fact that server may want to detect the
	 * application protocol based on first few bytes on clear text
	 * communication.  But for simple servers which only speak HTTP/2, it
	 * is easier for developers if libhttp2 library takes care of client
	 * connection preface.
	 *
	 * If this option is used with nonzero |val|, libhttp2 library checks
	 * first 24 bytes client connection preface.  If it is not a valid
	 * one, $(D Session.recv) and $(D Session.memRecv) will
	 * return error $(D ErrorCode.BAD_PREFACE), which is fatal error.
	 */
	void setRecvClientPreface(bool val)
	{
		m_opt_set_mask |= OptionFlags.RECV_CLIENT_PREFACE;
		m_recv_client_preface = val;
	}

	/**
	 * By default, libhttp2 library enforces subset of HTTP Messaging rules
	 * described in `HTTP/2 specification, section 8
	 * <https://tools.ietf.org/html/draft-ietf-httpbis-http2-17#section-8>`_.
	 * See `HTTP Messaging`_ section for details.  For those applications
	 * who use libhttp2 library as non-HTTP use, give nonzero to |val| to
	 * disable this enforcement.
	 */
	void setNoHTTPMessaging(bool val)
	{
		m_opt_set_mask |= OptionFlags.NO_HTTP_MESSAGING;
		m_no_http_messaging = val;
	}

}