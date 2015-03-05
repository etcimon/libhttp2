/*
 * libhttp2 - HTTP/2 D Library
 *
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
 * Copyright (c) 2015 Etienne Cimon
 * 
 * License: MIT
 */
module libhttp2.session;

import libhttp2.types;
import libhttp2.frame;
import libhttp2.stream;
import libhttp2.policy;
import libhttp2.deflater;
import libhttp2.inflater;
import libhttp2.buffers;
import libhttp2.priority_queue;

import memutils.circularbuffer;
import memutils.vector;
import memutils.hashmap;

import std.algorithm : min, max;

//http2_optmask
enum OptionsMask {
    NO_AUTO_WINDOW_UPDATE = 1 << 0,
    RECV_CLIENT_PREFACE = 1 << 1,
    NO_HTTP_MESSAGING = 1 << 2,
}

//http2_outbound_state
enum OutboundState {
    POP_ITEM,
    SEND_DATA
}

//http2_active_outbound_item
struct ActiveOutboundItem {
    OutboundItem item;
    Buffers framebufs;
	OutboundState state = OutboundState.POP_ITEM;

	void reset() {
		DEBUGF(fprintf(stderr, "send: reset http2_active_outbound_item\n"));
		DEBUGF(fprintf(stderr, "send: aob.item = %p\n", aob.item));
		item.free();
		Mem.free(item);
		item = null;
		framebufs.reset();
		state = OutboundState.POP_ITEM;
	}
}

//http2_inbound_state
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

//http2_inbound_frame
struct InboundFrame {
    Frame frame;
    /* Storage for extension frame payload.  frame.ext.payload points
     to this structure to avoid frequent memory allocation. */
    ExtFramePayload ext_frame_payload;

    /* The received SETTINGS entry. The protocol says that we only cares
     about the defined settings ID. If unknown ID is received, it is
     ignored.  We use last entry to hold minimum header table size if
     same settings are multiple times. */
    Setting[INBOUND_NUM_IV] iv;

    /// buffer pointers to small buffer, raw_sbuf 
    Buffer sbuf;

    /// buffer pointers to large buffer, raw_lbuf
    Buffer lbuf;

    /// Large buffer, malloced on demand
    ubyte *raw_lbuf;

    /* The number of entry filled in |iv| */
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

		sbuf.last = memcpy(sbuf.last, input, readlen);
		
		return readlen;
	}
	
	/*
	 * Unpacks SETTINGS entry in iframe.sbuf.
	 */
	void inbound_frame_set_settings_entry(InboundFrame *iframe) 
	{
		Setting iv;
		size_t i;
		
		http2_frame_unpack_settings_entry(&iv, iframe.sbuf.pos);
		
		with(Setting) switch (iv.id) {
			case HEADER_TABLE_SIZE:
			case ENABLE_PUSH:
			case MAX_CONCURRENT_STREAMS:
			case INITIAL_WINDOW_SIZE:
			case MAX_FRAME_SIZE:
			case MAX_HEADER_LIST_SIZE:
				break;
			default:
				DEBUGF(fprintf(stderr, "recv: ignore unknown settings id=0x%02x\n",
						iv.id));
				return;
		}
		
		for (i = 0; i < iframe.niv; ++i) {
			if (iframe.iv[i].id == iv.id) {
				iframe.iv[i] = iv;
				break;
			}
		}
		
		if (i == iframe.niv) {
			iframe.iv[iframe.niv++] = iv;
		}
		
		if (iv.id == Setting.HEADER_TABLE_SIZE &&
			iv.value < iframe.iv[http2_INBOUND_NUM_IV - 1].value) {
			
			iframe.iv[http2_INBOUND_NUM_IV - 1] = iv;
		}
	}
	
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
		DEBUGF(fprintf(stderr, "recv: no padding in payload\n"));
		return 0;
	}
	
	/*
	 * Computes number of padding based on flags. This function returns
	 * padlen if it succeeds, or -1.
	 */
	int computePad() 
	{
		/* 1 for Pad Length field */
		int _padlen = sbuf.pos[0] + 1;
		
		DEBUGF(fprintf(stderr, "recv: padlen=%zu\n", padlen));

		/* We cannot use iframe.frame.hd.length because of CONTINUATION */
		if (_padlen - 1 > iframe.payloadleft) {
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
	int effectiveReadLength(size_t payloadleft, size_t readlen) 
	{
		size_t trail_padlen = iframe.frame.trailPadlen(iframe.padlen);
		
		if (trail_padlen > payloadleft) {
			size_t padlen;
			padlen = trail_padlen - payloadleft;
			if (readlen < padlen) {
				return -1;
			} else {
				return readlen - padlen;
			}
		}
		return readlen;
	}
}

//http2_settings_storage
struct SettingsStorage {
	uint header_table_size = HD_DEFAULT_MAX_BUFFER_SIZE;
	uint enable_push = 1;
	uint max_concurrent_streams = INITIAL_MAX_CONCURRENT_STREAMS;
	uint initial_window_size = INITIAL_WINDOW_SIZE;
	uint max_frame_size = MAX_FRAME_SIZE_MIN;
	uint max_header_list_size = uint.max;
}

//http2_goaway_flag
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

//http2_update_window_size_arg
/// Struct used when updating initial window size of each active stream.
struct UpdateWindowSizeArgs{
    Session session;
    int new_window_size, old_window_size;
}

//http2_close_stream_on_goaway_arg
struct CloseStreamOnGoAwayArgs {
    Session session;

    /// linked list of streams to close
    Stream head;
    int last_stream_id;

    /* nonzero if GOAWAY is sent to peer, which means we are going to
     close incoming streams.  zero if GOAWAY is received from peer and
     we are going to close outgoing streams. */
    int incoming;
}

class Session {

	this(bool server, in Options options, in Policy callbacks)
	{
		ErrorCode rv;


		if (server) {
			is_server = true;
			next_stream_id = 2; // server IDs always pair
		}
		else
			next_stream_id = 1; // client IDs always impair

		hd_inflater = Inflater();
		scope(failure) hd_inflater.free();

		hd_deflater = Deflater();
		scope(failure) hd_deflater.free();

		ob_pq = PriorityQueue(128);
		scope(failure) ob_pq.free();

		ob_ss_pq = PriorityQueue(128);
		scope(failure) ob_ss_pq.free();

		ob_da_pq = PriorityQueue(128);
		scope(failure) ob_da_pq.free();

		/* 1 for Pad Field. */
		aob.framebufs = Buffers(FRAMEBUF_CHUNKLEN, FRAMEBUF_MAX_NUM, 1, FRAME_HDLEN + 1);
		scope(failure) aob.framebufs.free();

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
		
		policy = callbacks;

		inboundFrameReset();
		
		if  (is_server && opt_flags & OptionsMask.RECV_CLIENT_PREFACE) 
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
		Mem.free(inflight_iv);
		roots.free();
		freeAllStreams();
		aob.reset();
		inboundFrameReset();
		ob_pq.free();
		ob_ss_pq.free();
		ob_da_pq.free();
		hd_deflater.free();
		hd_inflater.free();
		aob.framebufs.free();
	}

	/**
	 * Sends pending frames to the remote peer.
	 *
	 * This function retrieves the highest prioritized frame from the
	 * outbound queue and sends it to the remote peer.  It does this as
	 * many as possible until the user callback $(D Policy.write) returns
	 * $(D ErrorCode.WOULDBLOCK) or the outbound queue becomes empty.
	 * 
	 * This function calls several $(D Policy) functions which are passed
	 * when initializing the $(D Session).  Here is the simple time chart
	 * which tells when each callback is invoked:
	 *
	 * 1. Get the next frame to be sent from a priority sorted outbound queue.
	 *
	 * 2. Prepare transmission of the frame.
	 *
	 * 3. $(D Policy.onFrameFailure) may be invoked if the control frame cannot 
	 * 	  be sent because some preconditions are not met (e.g., request HEADERS 
	 * 	  cannot be sent after GOAWAY). This then aborts the following steps.
	 *
	 * 4. $(D Policy.selectPaddingLength) is invoked if the frame is HEADERS, 
	 *    PUSH_PROMISE or DATA.
	 *
	 * 5. If the frame is request HEADERS, the stream is opened here.
	 *
	 * 6. $(D Policy.onFrameReady) is invoked.
	 *
	 * 7. $(D Policy.write) is invoked one or more times to send the frame.
	 *
	 * 8. $(D Policy.onFrameSent) is invoked after all data is transmitted.
	 *
	 * 9. $(D Policy.onStreamExit) may be invoked if the transmission of the frame 
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
			rv = memSendInternal(data, false);
			if (rv < 0)
				return rv;
			else if (data.length == 0)
				return 0;
			
			sentlen = policy.write(data);
			
			if (sentlen < 0) {
				if (cast(ErrorCode) sentlen == ErrorCode.WOULDBLOCK) {
					/* Transmission canceled. Rewind the offset */
					framebufs.cur.buf.pos -= data.length;					
					return 0;
				}
				
				return ErrorCode.CALLBACK_FAILURE;
			}
			
			/* Rewind the offset to the amount of unsent bytes */
			framebufs.cur.buf.pos -= data.length - sentlen;
		}
		
		assert(false);
	}

	/**
	 * @function
	 *
	 * Returns the serialized data to send.
	 *
	 * This function behaves like `send()` except that it
	 * does not use $(D Policy.write) to transmit data.
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
		
		return 0;
	}

	/**
	 * Receives frames from the remote peer.
	 *
	 * This function receives as many frames as possible until the user
	 * callback $(D Policy.read) returns $(D ErrorCode.WOULDBLOCK).  
	 * This function calls several $(D Policy) functions which are passed 
	 * when initializing the $(D Session).  
	 * 
	 * Here is the simple time chart which tells when each callback is invoked:
	 *
	 * 1. $(D Policy.read) is invoked one or more times to receive the frame header.
	 *
	 * 2. $(D Policy.onFrameHeader) is invoked after the frame header is received.
	 *
	 * 3. If the frame is DATA frame:
	 *
	 *    1. $(D Policy.read) is invoked one or more times to receive the DATA payload. 
	 * 
	 * 	  2. $(D Policy.onDataChunkRecv) is invoked alternatively with $(D Policy.read) 
	 *       for each chunk of data.
	 *
	 *    2. $(D Policy.onFrame) may be invoked if one DATA frame is completely received.
	 * 
	 * 	  3. $(D Policy.onStreamExit) may be invoked if the reception of the frame triggers 
	 *  	 closure of the stream.
	 *
	 * 4. If the frame is the control frame:
	 *
	 *    1. $(D Policy.read) is invoked one or more times to receive the whole frame.
	 *
	 *    2. If the received frame is valid, then following actions are
	 *       taken.  
	 * 		- If the frame is either HEADERS or PUSH_PROMISE:
	 *      	- $(D Policy.onHeaders) is invoked first.
	 * 			- $(D Policy.onHeader) is invoked for each header name/value pair.
	 * 			- $(D Policy.onFrame) is invoked after all name/value pairs.
	 * 		- For other frames:
	 *       	- $(D Policy.onFrame) is invoked.  
	 *          - $(D Policy.onStreamExit) may be invoked if the reception of the frame 
	 * 			  triggers the closure of the stream.
	 *
	 *    3. $(D Policy.onInvalidFrame) may be invoked if the received frame is unpacked 
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
	 *     `http2_option_set_recv_client_preface()` is used.
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
					return cast(int)proclen;
				}
				assert(proclen == readlen);
			} else if (readlen == 0 || readlen == ErrorCode.WOULDBLOCK) {
				return 0;
			} else if (readlen == ErrorCode.EOF) {
				return ErrorCode.EOF;
			} else if (readlen < 0) {
				return ErrorCode.CALLBACK_FAILURE;
			}
		}
	}

	/**
	 * @function
	 *
	 * Processes data |input| as an input from the remote endpoint.  The
	 * |inlen| indicates the number of bytes in the |in|.
	 *
	 * This function behaves like $(D Session.recv) except that it
	 * does not use $(D Policy.read) to receive data; the
	 * |input| is the only data for the invocation of this function.  If all
	 * bytes are processed, this function returns.  The other policy
	 * are called in the same way as they are in $(D Session.recv).
	 *
	 * In the current implementation, this function always tries to
	 * process all input data unless either an error occurs or
	 * $(D ErrorCode.PAUSE) is returned from $(D Policy.onHeader) or
	 * $(D Policy.onDataChunkRecv).  If $(D ErrorCode.PAUSE) is used, 
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
	 *     `http2_option_set_recv_client_preface()` is used.
	 */
	int memRecv(Session session, in ubyte[] input) 
	{
		ubyte *pos = input.ptr;
		const ubyte *first = input.ptr;
		const ubyte *last = input.ptr + input.length;
		InboundFrame *iframe = &session.iframe;
		size_t readlen;
		int padlen;
		ErrorCode rv;
		int busy = 0;
		http2_frame_hd cont_hd;
		Stream stream;
		size_t pri_fieldlen;
		http2_mem *mem;
		
		DEBUGF(fprintf(stderr, "recv: connection recv_window_size=%d, local_window=%d\n", session.recv_window_size, session.local_window_size));
		
		mem = &session.mem;
		
		for (;;) {
			with(InboundState) switch (iframe.state) {
				case READ_CLIENT_PREFACE:
					readlen = min(inlen, iframe.payloadleft);
					
					if (memcmp(CLIENT_CONNECTION_PREFACE.ptr + CLIENT_CONNECTION_PREFACE.length - iframe.payloadleft, pos, readlen) != 0) 
					{
						return ErrorCode.BAD_PREFACE;
					}
					
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					if (iframe.payloadleft == 0) {
						inboundFrameReset();
						iframe.state = READ_FIRST_SETTINGS;
					}
					
					break;
				case READ_FIRST_SETTINGS:
					DEBUGF(fprintf(stderr, "recv: [READ_FIRST_SETTINGS]\n"));
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					
					if (http2_buf_mark_avail(&iframe.sbuf)) {
						return pos - first;
					}
					
					if (iframe.sbuf.pos[3] != FrameType.SETTINGS || (iframe.sbuf.pos[4] & FrameFlags.ACK))
					{
						
						iframe.state = IGN_ALL;
						
						rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "SETTINGS expected");
						
						if (isFatal(rv)) {
							return rv;
						}
						
						return inlen;
					}
					
					iframe.state = READ_HEAD;
					
					/* Fall through */
				case READ_HEAD: {
					int on_begin_frame_called = 0;
					
					DEBUGF(fprintf(stderr, "recv: [READ_HEAD]\n"));
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					
					if (http2_buf_mark_avail(&iframe.sbuf)) {
						return pos - first;
					}
					
					http2_frame_unpack_frame_hd(&iframe.frame.hd, iframe.sbuf.pos);
					iframe.payloadleft = iframe.frame.hd.length;
					
					DEBUGF(fprintf(stderr, "recv: payloadlen=%zu, type=%u, flags=0x%02x, stream_id=%d\n",
							iframe.frame.hd.length, iframe.frame.hd.type,
							iframe.frame.hd.flags, iframe.frame.hd.stream_id));
					
					if (iframe.frame.hd.length > session.local_settings.max_frame_size) {
						DEBUGF(fprintf(stderr, "recv: length is too large %zu > %u\n",
								iframe.frame.hd.length,
								session.local_settings.max_frame_size));
						
						busy = 1;
						
						iframe.state = IGN_PAYLOAD;
						
						rv = terminateSessionWithReason(FrameError.FRAME_SIZE_ERROR, "too large frame size");
						
						if (isFatal(rv)) {
							return rv;
						}
						
						break;
					}
					
					switch (iframe.frame.hd.type) {
						case FrameType.DATA: {
							DEBUGF(fprintf(stderr, "recv: DATA\n"));
							
							iframe.frame.hd.flags &=
								(FrameFlags.END_STREAM | FrameFlags.PADDED);
							/* Check stream is open. If it is not open or closing,
                           ignore payload. */
							busy = 1;
							
							rv = session_on_data_received_fail_fast(session);
							if (rv == ErrorCode.IGN_PAYLOAD) {
								DEBUGF(fprintf(stderr, "recv: DATA not allowed stream_id=%d\n", iframe.frame.hd.stream_id));
								iframe.state = IGN_DATA;
								break;
							}
							
							if (isFatal(rv)) {
								return rv;
							}
							
							rv = iframe.handlePad();
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
							
							DEBUGF(fprintf(stderr, "recv: HEADERS\n"));
							
							iframe.frame.hd.flags &= (FrameFlags.END_STREAM | FrameFlags.END_HEADERS | FrameFlags.PADDED | FrameFlags.PRIORITY);
							
							rv = iframe.handlePad();
							if (rv < 0) {
								busy = 1;
								
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
							
							pri_fieldlen = http2_frame_priority_len(iframe.frame.hd.flags);
							
							if (pri_fieldlen > 0) {
								if (iframe.payloadleft < pri_fieldlen) {
									busy = 1;
									iframe.state = FRAME_SIZE_ERROR;
									break;
								}
								
								iframe.state = READ_NBYTE;
								
								iframe.setMark(pri_fieldlen);
								
								break;
							}
							
							/* Call on_begin_frame_callback here because
                           session_process_headers_frame() may call
                           on_begin_headers_callback */
							rv = session_call_on_begin_frame(session, &iframe.frame.hd);
							
							if (isFatal(rv)) {
								return rv;
							}
							
							on_begin_frame_called = 1;
							
							rv = session_process_headers_frame(session);
							if (isFatal(rv)) {
								return rv;
							}
							
							busy = 1;
							
							if (rv == ErrorCode.IGN_HEADER_BLOCK) {
								iframe.state = IGN_HEADER_BLOCK;
								break;
							}
							
							iframe.state = READ_HEADER_BLOCK;
							
							break;
						case FrameType.PRIORITY:
							DEBUGF(fprintf(stderr, "recv: PRIORITY\n"));
							
							iframe.frame.hd.flags = FrameFlags.NONE;
							
							if (iframe.payloadleft != PRIORITY_SPECLEN) {
								busy = 1;
								
								iframe.state = FRAME_SIZE_ERROR;
								
								break;
							}
							
							iframe.state = READ_NBYTE;
							
							iframe.setMark(PRIORITY_SPECLEN);
							
							break;
						case FrameType.RST_STREAM:
						case FrameType.WINDOW_UPDATE:
							static if (DEBUGBUILD) {
								switch (iframe.frame.hd.type) {
									case FrameType.RST_STREAM:
										DEBUGF(fprintf(stderr, "recv: RST_STREAM\n"));
										break;
									case FrameType.WINDOW_UPDATE:
										DEBUGF(fprintf(stderr, "recv: WINDOW_UPDATE\n"));
										break;
								}
							}
							
							iframe.frame.hd.flags = FrameFlags.NONE;
							
							if (iframe.payloadleft != 4) {
								busy = 1;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							
							iframe.setMark(4);
							
							break;
						case FrameType.SETTINGS:
							DEBUGF(fprintf(stderr, "recv: SETTINGS\n"));
							
							iframe.frame.hd.flags &= FrameFlags.ACK;
							
							if ((iframe.frame.hd.length % FRAME_SETTINGS_ENTRY_LENGTH) ||
								((iframe.frame.hd.flags & FrameFlags.ACK) && iframe.payloadleft > 0)) {
								busy = 1;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_SETTINGS;
							
							if (iframe.payloadleft) {
								iframe.setMark(FRAME_SETTINGS_ENTRY_LENGTH);
								break;
							}
							
							busy = 1;
							
							iframe.setMark(0);
							
							break;
						case FrameType.PUSH_PROMISE:
							DEBUGF(fprintf(stderr, "recv: PUSH_PROMISE\n"));
							
							iframe.frame.hd.flags &=
								(FrameFlags.END_HEADERS | FrameFlags.PADDED);
							
							rv = iframe.handlePad();
							if (rv < 0) {
								busy = 1;
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
								busy = 1;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							
							iframe.setMark(4);
							
							break;
						case FrameType.PING:
							DEBUGF(fprintf(stderr, "recv: PING\n"));
							
							iframe.frame.hd.flags &= FrameFlags.ACK;
							
							if (iframe.payloadleft != 8) {
								busy = 1;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							iframe.setMark(8);
							
							break;
						case FrameType.GOAWAY:
							DEBUGF(fprintf(stderr, "recv: GOAWAY\n"));
							
							iframe.frame.hd.flags = FrameFlags.NONE;
							
							if (iframe.payloadleft < 8) {
								busy = 1;
								iframe.state = FRAME_SIZE_ERROR;
								break;
							}
							
							iframe.state = READ_NBYTE;
							iframe.setMark(8);
							
							break;
						case FrameType.CONTINUATION:
							DEBUGF(fprintf(stderr, "recv: unexpected CONTINUATION\n"));
							
							/* Receiving CONTINUATION in this state are subject to connection error of type PROTOCOL_ERROR */
							rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "CONTINUATION: unexpected");
							if (isFatal(rv))
							{
								return rv;
							}
							
							busy = 1;
							
							iframe.state = IGN_PAYLOAD;
							
							break;
						default:
							DEBUGF(fprintf(stderr, "recv: unknown frame\n"));
							
							/* Silently ignore unknown frame type. */
							
							busy = 1;
							
							iframe.state = IGN_PAYLOAD;
							
							break;
					}
					
					if (!on_begin_frame_called) {
						switch (iframe.state) {
							case IGN_HEADER_BLOCK:
							case IGN_PAYLOAD:
							case FRAME_SIZE_ERROR:
							case IGN_DATA:
								break;
							default:
								rv = session_call_on_begin_frame(session, &iframe.frame.hd);
								
								if (isFatal(rv)) {
									return rv;
								}
						}
					}
					
					break;
				}
				case READ_NBYTE:
					DEBUGF(fprintf(stderr, "recv: [READ_NBYTE]\n"));
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					iframe.payloadleft -= readlen;
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu, left=%zd\n", readlen, iframe.payloadleft, iframe.sbuf.markAvailable));
					
					if (http2_buf_mark_avail(&iframe.sbuf)) {
						return pos - first;
					}
					
					switch (iframe.frame.hd.type) {
						case FrameType.HEADERS:
							if (iframe.padlen == 0 &&
								(iframe.frame.hd.flags & FrameFlags.PADDED)) {
								padlen = iframe.computePad();
								if (padlen < 0) {
									busy = 1;
									rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "HEADERS: invalid padding");
									if (isFatal(rv)) {
										return rv;
									}
									iframe.state = IGN_PAYLOAD;
									break;
								}
								iframe.frame.headers.padlen = padlen;
								
								pri_fieldlen = http2_frame_priority_len(iframe.frame.hd.flags);
								
								if (pri_fieldlen > 0) {
									if (iframe.payloadleft < pri_fieldlen) {
										busy = 1;
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
							
							rv = session_process_headers_frame(session);
							if (isFatal(rv)) {
								return rv;
							}
							
							busy = 1;
							
							if (rv == ErrorCode.IGN_HEADER_BLOCK) {
								iframe.state = IGN_HEADER_BLOCK;
								break;
							}
							
							iframe.state = READ_HEADER_BLOCK;
							
							break;
						case FrameType.PRIORITY:
							rv = session_process_priority_frame(session);
							if (isFatal(rv)) {
								return rv;
							}
							
							inboundFrameReset();
							
							break;
						case FrameType.RST_STREAM:
							rv = session_process_rst_stream_frame(session);
							if (isFatal(rv)) {
								return rv;
							}
							
							inboundFrameReset();
							
							break;
						case FrameType.PUSH_PROMISE:
							if (iframe.padlen == 0 && (iframe.frame.hd.flags & FrameFlags.PADDED)) {
								padlen = iframe.computePad();
								if (padlen < 0) {
									busy = 1;
									rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: invalid padding");
									if (isFatal(rv)) {
										return rv;
									}
									iframe.state = IGN_PAYLOAD;
									break;
								}
								
								iframe.frame.push_promise.padlen = padlen;
								
								if (iframe.payloadleft < 4) {
									busy = 1;
									iframe.state = FRAME_SIZE_ERROR;
									break;
								}
								
								iframe.state = READ_NBYTE;
								
								iframe.setMark(4);
								
								break;
							}
							
							rv = session_process_push_promise_frame(session);
							if (isFatal(rv)) {
								return rv;
							}
							
							busy = 1;
							
							if (rv == ErrorCode.IGN_HEADER_BLOCK) {
								iframe.state = IGN_HEADER_BLOCK;
								break;
							}
							
							iframe.state = READ_HEADER_BLOCK;
							
							break;
						case FrameType.PING:
							rv = session_process_ping_frame(session);
							if (isFatal(rv)) {
								return rv;
							}
							
							inboundFrameReset();
							
							break;
						case FrameType.GOAWAY: {
							size_t debuglen;
							
							/* 8 is Last-stream-ID + Error Code */
							debuglen = iframe.frame.hd.length - 8;
							
							if (debuglen > 0) {
								iframe.raw_lbuf = http2_mem_malloc(mem, debuglen);
								
								if (iframe.raw_lbuf == null) {
									return ErrorCode.NOMEM;
								}
								
								http2_buf_wrap_init(&iframe.lbuf, iframe.raw_lbuf, debuglen);
							}
							
							busy = 1;
							
							iframe.state = READ_GOAWAY_DEBUG;
							
							break;
						}
						case FrameType.WINDOW_UPDATE:
							rv = session_process_window_update_frame(session);
							if (isFatal(rv)) {
								return rv;
							}
							
							inboundFrameReset();
							
							break;
						default:
							/* This is unknown frame */
							inboundFrameReset();
							
							break;
					}
					break;
				case READ_HEADER_BLOCK:
				case IGN_HEADER_BLOCK: {
					int data_readlen;
					static if (DEBUGBUILD) {
						if (iframe.state == READ_HEADER_BLOCK) {
							fprintf(stderr, "recv: [READ_HEADER_BLOCK]\n");
						} else {
							fprintf(stderr, "recv: [IGN_HEADER_BLOCK]\n");
						}
					}
					
					readlen = iframe.readLength(pos, last);
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n", readlen,
							iframe.payloadleft - readlen));
					
					data_readlen = iframe.effectiveReadLength(iframe.payloadleft - readlen, readlen);
					
					if (data_readlen >= 0) {
						size_t trail_padlen;
						size_t hd_proclen = 0;
						trail_padlen = iframe.frame.trailPadlen(iframe.padlen);
						DEBUGF(fprintf(stderr, "recv: block final=%d\n",
								(iframe.frame.hd.flags & FrameFlags.END_HEADERS) &&
								iframe.payloadleft - data_readlen == trail_padlen));
						
						rv = inflate_header_block(session, &iframe.frame, &hd_proclen, cast(ubyte *)pos, data_readlen,
							(iframe.frame.hd.flags & FrameFlags.END_HEADERS) && iframe.payloadleft - data_readlen == trail_padlen, iframe.state == READ_HEADER_BLOCK);
						
						if (isFatal(rv)) {
							return rv;
						}
						
						if (rv == ErrorCode.PAUSE) {
							pos += hd_proclen;
							iframe.payloadleft -= hd_proclen;
							
							return pos - first;
						}
						
						if (rv == ErrorCode.TEMPORAL_CALLBACK_FAILURE) {
							/* The application says no more headers. We decompress the
				             rest of the header block but not invoke on_header_callback
				             and on_frame_recv_callback. */
							pos += hd_proclen;
							iframe.payloadleft -= hd_proclen;
							
							addReset(iframe.frame.hd.stream_id, FrameError.INTERNAL_ERROR);
							busy = 1;
							iframe.state = IGN_HEADER_BLOCK;
							break;
						}
						
						pos += readlen;
						iframe.payloadleft -= readlen;
						
						if (rv == ErrorCode.HEADER_COMP) {
							/* GOAWAY is already issued */
							if (iframe.payloadleft == 0) {
								inboundFrameReset();
							} else {
								busy = 1;
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
						
						if (iframe.state == READ_HEADER_BLOCK) {
							iframe.state = EXPECT_CONTINUATION;
						} else {
							iframe.state = IGN_CONTINUATION;
						}
					} else {
						if (iframe.state == READ_HEADER_BLOCK) {
							rv = session_after_header_block_received(session);
							if (isFatal(rv)) {
								return rv;
							}
						}
						inboundFrameReset();
					}
					break;
				}
				case IGN_PAYLOAD:
					DEBUGF(fprintf(stderr, "recv: [IGN_PAYLOAD]\n"));
					
					readlen = iframe.readLength(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n", readlen,
							iframe.payloadleft));
					
					if (iframe.payloadleft) {
						break;
					}
					
					switch (iframe.frame.hd.type) {
						case FrameType.HEADERS:
						case FrameType.PUSH_PROMISE:
						case FrameType.CONTINUATION:
							/* Mark inflater bad so that we won't perform further decoding */
							session.hd_inflater.ctx.bad = 1;
							break;
						default:
							break;
					}
					
					inboundFrameReset();
					
					break;
				case FRAME_SIZE_ERROR:
					DEBUGF(fprintf(stderr, "recv: [FRAME_SIZE_ERROR]\n"));
					
					rv = session_handle_frame_size_error(session, &iframe.frame);
					if (isFatal(rv)) {
						return rv;
					}
					
					busy = 1;
					
					iframe.state = IGN_PAYLOAD;
					
					break;
				case READ_SETTINGS:
					DEBUGF(fprintf(stderr, "recv: [READ_SETTINGS]\n"));
					
					readlen = iframe.read(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n", readlen,
							iframe.payloadleft));
					
					if (http2_buf_mark_avail(&iframe.sbuf)) {
						break;
					}
					
					if (readlen > 0) {
						inbound_frame_set_settings_entry(iframe);
					}
					if (iframe.payloadleft) {
						iframe.setMark(FRAME_SETTINGS_ENTRY_LENGTH);
						break;
					}
					
					rv = session_process_settings_frame(session);
					
					if (isFatal(rv)) {
						return rv;
					}
					
					inboundFrameReset();
					
					break;
				case READ_GOAWAY_DEBUG:
					DEBUGF(fprintf(stderr, "recv: [READ_GOAWAY_DEBUG]\n"));
					
					readlen = iframe.readLength(pos, last);
					
					iframe.lbuf.last = http2_cpymem(iframe.lbuf.last, pos, readlen);
					
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n", readlen,
							iframe.payloadleft));
					
					if (iframe.payloadleft) {
						assert(http2_buf_avail(&iframe.lbuf) > 0);
						
						break;
					}
					
					rv = session_process_goaway_frame(session);
					
					if (isFatal(rv)) {
						return rv;
					}
					
					inboundFrameReset();
					
					break;
				case EXPECT_CONTINUATION:
				case IGN_CONTINUATION:
					static if (DEBUGBUILD) {
						if (iframe.state == EXPECT_CONTINUATION) {
							fprintf(stderr, "recv: [EXPECT_CONTINUATION]\n");
						} else {
							fprintf(stderr, "recv: [IGN_CONTINUATION]\n");
						}
					}
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					
					if (http2_buf_mark_avail(&iframe.sbuf)) {
						return pos - first;
					}
					
					http2_frame_unpack_frame_hd(&cont_hd, iframe.sbuf.pos);
					iframe.payloadleft = cont_hd.length;
					
					DEBUGF(fprintf(stderr, "recv: payloadlen=%zu, type=%u, flags=0x%02x, "
							"stream_id=%d\n",
							cont_hd.length, cont_hd.type, cont_hd.flags,
							cont_hd.stream_id));
					
					if (cont_hd.type != FrameType.CONTINUATION ||
						cont_hd.stream_id != iframe.frame.hd.stream_id) {
						DEBUGF(fprintf(stderr, "recv: expected stream_id=%d, type=%d, but "
								"got stream_id=%d, type=%d\n",
								iframe.frame.hd.stream_id, FrameType.CONTINUATION,
								cont_hd.stream_id, cont_hd.type));
						rv = terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "unexpected non-CONTINUATION frame or stream_id is invalid");
						if (isFatal(rv)) {
							return rv;
						}
						
						busy = 1;
						
						iframe.state = IGN_PAYLOAD;
						
						break;
					}
					
					/* CONTINUATION won't bear FrameFlags.PADDED flag */                
					iframe.frame.hd.flags |= cont_hd.flags & FrameFlags.END_HEADERS;
					iframe.frame.hd.length += cont_hd.length;
					
					busy = 1;
					
					if (iframe.state == EXPECT_CONTINUATION) {
						iframe.state = READ_HEADER_BLOCK;
						
						rv = session_call_on_begin_frame(session, &cont_hd);
						
						if (isFatal(rv)) {
							return rv;
						}
					} else {
						iframe.state = IGN_HEADER_BLOCK;
					}
					
					break;
				case READ_PAD_DATA:
					DEBUGF(fprintf(stderr, "recv: [READ_PAD_DATA]\n"));
					
					readlen = iframe.read(pos, last);
					pos += readlen;
					iframe.payloadleft -= readlen;
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu, left=%zu\n",
							readlen, iframe.payloadleft,
							http2_buf_mark_avail(&iframe.sbuf)));
					
					if (http2_buf_mark_avail(&iframe.sbuf)) {
						return pos - first;
					}
					
					/* Pad Length field is subject to flow control */
					rv = session_update_recv_connection_window_size(session, readlen);
					if (isFatal(rv)) {
						return rv;
					}
					
					/* Pad Length field is consumed immediately */
					rv = http2_session_consume(session, iframe.frame.hd.stream_id, readlen);
					
					if (isFatal(rv)) {
						return rv;
					}
					
					stream = getStream(iframe.frame.hd.stream_id);
					if (stream) {
						rv = session_update_recv_stream_window_size(
							session, stream, readlen,
							iframe.payloadleft ||
							(iframe.frame.hd.flags & FrameFlags.END_STREAM) == 0);
						if (isFatal(rv)) {
							return rv;
						}
					}
					
					busy = 1;
					
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
					DEBUGF(fprintf(stderr, "recv: [READ_DATA]\n"));
					
					readlen = iframe.readLength(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n", readlen,
							iframe.payloadleft));
					
					if (readlen > 0) {
						int data_readlen;
						
						rv = session_update_recv_connection_window_size(session, readlen);
						if (isFatal(rv)) {
							return rv;
						}
						
						stream = getStream(iframe.frame.hd.stream_id);
						if (stream) {
							rv = session_update_recv_stream_window_size(
								session, stream, readlen,
								iframe.payloadleft ||
								(iframe.frame.hd.flags & FrameFlags.END_STREAM) == 0);
							if (isFatal(rv)) {
								return rv;
							}
						}
						
						data_readlen = iframe.effectiveReadLength(iframe.payloadleft, readlen);
						
						padlen = readlen - data_readlen;
						
						if (padlen > 0) {
							/* Padding is considered as "consumed" immediately */
							rv = http2_session_consume(session, iframe.frame.hd.stream_id,
								padlen);
							
							if (isFatal(rv)) {
								return rv;
							}
						}
						
						DEBUGF(fprintf(stderr, "recv: data_readlen=%zd\n", data_readlen));
						
						if (stream && data_readlen > 0) {
							if (session_enforce_http_messaging(session)) {
								if (http2_http_on_data_chunk(stream, data_readlen) != 0) {
									addReset(iframe.frame.hd.stream_id, FrameError.PROTOCOL_ERROR);
									busy = 1;
									iframe.state = IGN_DATA;
									break;
								}
							}
							if (session.policy.on_data_chunk_recv_callback) {
								rv = session.policy.on_data_chunk_recv_callback(
									session, iframe.frame.hd.flags, iframe.frame.hd.stream_id,
									pos - readlen, data_readlen);
								if (rv == ErrorCode.PAUSE) {
									return pos - first;
								}
								
								if (isFatal(rv)) {
									return ErrorCode.CALLBACK_FAILURE;
								}
							}
						}
					}
					
					if (iframe.payloadleft) {
						break;
					}
					
					rv = session_process_data_frame(session);
					if (isFatal(rv)) {
						return rv;
					}
					
					inboundFrameReset();
					
					break;
				case IGN_DATA:
					DEBUGF(fprintf(stderr, "recv: [IGN_DATA]\n"));
					
					readlen = iframe.readLength(pos, last);
					iframe.payloadleft -= readlen;
					pos += readlen;
					
					DEBUGF(fprintf(stderr, "recv: readlen=%zu, payloadleft=%zu\n", readlen,
							iframe.payloadleft));
					
					if (readlen > 0) {
						/* Update connection-level flow control window for ignored DATA frame too */
						rv = session_update_recv_connection_window_size(session, readlen);
						if (isFatal(rv)) {
							return rv;
						}
						
						if (session.opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE) {
							
							/* Ignored DATA is considered as "consumed" immediately. */
							rv = session_update_connection_consumed_size(session, readlen);
							
							if (isFatal(rv)) {
								return rv;
							}
						}
					}
					
					if (iframe.payloadleft) {
						break;
					}
					
					inboundFrameReset();
					
					break;
				case IGN_ALL:
					return inlen;
			}
			
			if (!busy && pos == last) {
				break;
			}
			
			busy = 0;
		}
		
		assert(pos == last);
		
		return pos - first;
	}

	/**
	 * @function
	 *
	 * Puts back previously deferred DATA frame in the stream |stream_id|
	 * to the outbound queue.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The stream does not exist; or no deferred data exist.
	 */
	ErrorCode http2_session_resume_data(Session session, int stream_id);

	/**
	 * @function
	 *
	 * Returns true value if $(D Session) wants to receive data from the
	 * remote peer.
	 *
	 * If both `http2_session_want_read()` and
	 * `http2_session_want_write()` return 0, the application should
	 * drop the connection.
	 */
	bool http2_session_want_read(Session session);

	/**
	 * @function
	 *
	 * Returns true value if $(D Session) wants to send data to the remote
	 * peer.
	 *
	 * If both `http2_session_want_read()` and
	 * `http2_session_want_write()` return 0, the application should
	 * drop the connection.
	 */
	bool http2_session_want_write(Session session);

	/**
	 * @function
	 *
	 * Returns stream_user_data for the stream |stream_id|.  The
	 * stream_user_data is provided by `http2_submit_request()`,
	 * `http2_submit_headers()` or
	 * `http2_session_set_stream_user_data()`.  Unless it is set using
	 * `http2_session_set_stream_user_data()`, if the stream is
	 * initiated by the remote endpoint, stream_user_data is always
	 * `null`.  If the stream does not exist, this function returns
	 * `null`.
	 */
	void *http2_session_get_stream_user_data(Session session, int stream_id);

	/**
	 * @function
	 *
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
	ErrorCode http2_session_set_stream_user_data(Session session, int stream_id, void *stream_user_data);

	/**
	 * @function
	 *
	 * Returns the number of frames in the outbound queue.  This does not
	 * include the deferred DATA frames.
	 */
	size_t http2_session_get_outbound_queue_size(Session session);

	/**
	 * @function
	 *
	 * Returns the number of DATA payload in bytes received without
	 * WINDOW_UPDATE transmission for the stream |stream_id|.  The local
	 * (receive) window size can be adjusted by
	 * `http2_submit_window_update()`.  This function takes into account
	 * that and returns effective data length.  In particular, if the
	 * local window size is reduced by submitting negative
	 * window_size_increment with `http2_submit_window_update()`, this
	 * function returns the number of bytes less than actually received.
	 *
	 * This function returns -1 if it fails.
	 */
	int http2_session_get_stream_effective_recv_data_length(Session session, int stream_id);

	/**
	 * @function
	 *
	 * Returns the local (receive) window size for the stream |stream_id|.
	 * The local window size can be adjusted by
	 * `http2_submit_window_update()`.  This function takes into account
	 * that and returns effective window size.
	 *
	 * This function returns -1 if it fails.
	 */
	int http2_session_get_stream_effective_local_window_size(Session session, int stream_id);

	/**
	 * @function
	 *
	 * Returns the number of DATA payload in bytes received without
	 * WINDOW_UPDATE transmission for a connection.  The local (receive)
	 * window size can be adjusted by `http2_submit_window_update()`.
	 * This function takes into account that and returns effective data
	 * length.  In particular, if the local window size is reduced by
	 * submitting negative window_size_increment with
	 * `http2_submit_window_update()`, this function returns the number
	 * of bytes less than actually received.
	 *
	 * This function returns -1 if it fails.
	 */
	int http2_session_get_effective_recv_data_length(Session session);

	/**
	 * @function
	 *
	 * Returns the local (receive) window size for a connection.  The
	 * local window size can be adjusted by
	 * `http2_submit_window_update()`.  This function takes into account
	 * that and returns effective window size.
	 *
	 * This function returns -1 if it fails.
	 */
	int http2_session_get_effective_local_window_size(Session session);

	/**
	 * @function
	 *
	 * Returns the remote window size for a given stream |stream_id|.
	 *
	 * This is the amount of flow-controlled payload (e.g., DATA) that the
	 * local endpoint can send without stream level WINDOW_UPDATE.  There
	 * is also connection level flow control, so the effective size of
	 * payload that the local endpoint can actually send is
	 * min(`http2_session_get_stream_remote_window_size()`,
	 * `http2_session_get_remote_window_size()`).
	 *
	 * This function returns -1 if it fails.
	 */
	int http2_session_get_stream_remote_window_size(Session session, int stream_id);

	/**
	 * @function
	 *
	 * Returns the remote window size for a connection.
	 *
	 * This function always succeeds.
	 */
	int http2_session_get_remote_window_size(Session session);

	/**
	 * @function
	 *
	 * Returns 1 if local peer half closed the given stream |stream_id|.
	 * Returns 0 if it did not.  Returns -1 if no such stream exists.
	 */
	bool http2_session_get_stream_local_close(Session session, int stream_id);

	/**
	 * @function
	 *
	 * Returns 1 if remote peer half closed the given stream |stream_id|.
	 * Returns 0 if it did not.  Returns -1 if no such stream exists.
	 */
	bool http2_session_get_stream_remote_close(Session session, int stream_id);

	/**
	 * @function
	 *
	 * Signals the session so that the connection should be terminated.
	 *
	 * The last stream ID is the minimum value between the stream ID of a
	 * stream for which :type:`http2_on_frame_recv_callback` was called
	 * most recently and the last stream ID we have sent to the peer
	 * previously.
	 *
	 * The |error_code| is the error code of this GOAWAY frame.  The
	 * pre-defined error code is one of $(D FrameError).
	 *
	 * After the transmission, both `http2_session_want_read()` and
	 * `http2_session_want_write()` return 0.
	 *
	 * This function should be called when the connection should be
	 * terminated after sending GOAWAY.  If the remaining streams should
	 * be processed after GOAWAY, use `http2_submit_goaway()` instead.
	 */
	ErrorCode terminateSession(FrameError error_code)
	{
		return terminateSession(last_proc_stream_id, error_code, null);
	}


	/**
	 * @function
	 *
	 * Signals the session so that the connection should be terminated.
	 *
	 * This function behaves like `http2_session_terminate_session()`,
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
	 * @function
	 *
	 * Returns the value of SETTINGS |id| notified by a remote endpoint.
	 * The |id| must be one of values defined in $(D SettingsID).
	 */
	uint http2_session_get_remote_settings(Session session, SettingsID id);

	/**
	 * @function
	 *
	 * Tells the $(D Session) that next stream ID is |next_stream_id|.  The
	 * |next_stream_id| must be equal or greater than the value returned
	 * by `http2_session_get_next_stream_id()`.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The |next_stream_id| is strictly less than the value
	 *     `http2_session_get_next_stream_id()` returns.
	 */
	ErrorCode http2_session_set_next_stream_id(Session session, int next_stream_id);

	/**
	 * @function
	 *
	 * Returns the next outgoing stream ID.  Notice that return type is
	 * uint.  If we run out of stream ID for this session, this
	 * function returns 1 << 31.
	 */
	uint http2_session_get_next_stream_id(Session session);

	/**
	 * @function
	 *
	 * Tells the $(D Session) that |size| bytes for a stream denoted by
	 * |stream_id| were consumed by application and are ready to
	 * WINDOW_UPDATE.  This function is intended to be used without
	 * automatic window update (see
	 * `http2_option_set_no_auto_window_update()`).
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.INVALID_ARGUMENT)
	 *     The |stream_id| is 0.
	 * $(D ErrorCode.INVALID_STATE)
	 *     Automatic WINDOW_UPDATE is not disabled.
	 */
	ErrorCode http2_session_consume(Session session, int stream_id, size_t size);

	/**
	 * @function
	 *
	 * Performs post-process of HTTP Upgrade request.  This function can
	 * be called from both client and server, but the behavior is very
	 * different in each other.
	 *
	 * If called from client side, the |settings_payload| must be the
	 * value sent in `HTTP2-Settings` header field and must be decoded
	 * by base64url decoder.  The |settings_payloadlen| is the length of
	 * |settings_payload|.  The |settings_payload| is unpacked and its
	 * setting values will be submitted using `http2_submit_settings()`.
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
	ErrorCode http2_session_upgrade(Session session, const ubyte *settings_payload, size_t settings_payloadlen, void *stream_user_data);

	/*
	 * Returns true if |stream_id| is initiated by local endpoint.
	 */	
	bool isMyStreamId(int stream_id)
	{
		int rem;
		if (stream_id == 0) {
			return 0;
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
	 */
	void addItem(OutboundItem item) 
	{
		/* TODO: Return error if stream is not found for the frame requiring stream presence. */
		Stream stream = getStream(frame.hd.stream_id);
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
		         SETTINGS_MAX_CONCURRENT_STREAMS */
				/* TODO: If 2 HEADERS are submitted for reserved stream, then
		         both of them are queued into ob_ss_pq, which is not
		         desirable. */
				if (frame.headers.cat == HeadersCategory.REQUEST) {
					session.ob_ss_pq.push(item);                
					item.queued = 1;
				} else if (stream && (stream.state == StreamState.RESERVED || item.aux_data.headers.attach_stream)) {
					item.weight = stream.effectiveWeight;
					item.cycle = session.last_cycle;                
					attachItem(stream, item, session);
				} else {
					session.ob_pq.push(item);                
					item.queued = 1;
				}
			} else {
				session.ob_pq.push(item);            
				item.queued = 1;
			}
			
			return;
		}
		
		if (!stream) {
			return ErrorCode.STREAM_CLOSED;
		}
		
		if (stream.item) {
			return ErrorCode.DATA_EXIST;
		}
		
		item.weight = stream.effectiveWeight;
		item.cycle = session.last_cycle;
		
		attachItem(stream, item, session);
	}

	/*
	 * Adds RST_STREAM frame for the stream |stream_id| with the error
	 * code |error_code|. This is a convenient function built on top of
	 * http2_session_add_frame() to add RST_STREAM easily.
	 *
	 * This function simply returns without adding RST_STREAM frame if
	 * given stream is in HTTP2_STREAM_CLOSING state, because multiple
	 * RST_STREAM for a stream is redundant.
	 */
	void addReset(int stream_id, FrameError error_code) 
	{
		ErrorCode rv;
		OutboundItem item;
		Frame* frame;
		Stream stream;
		
		stream = getStream(stream_id);
		if (stream && stream.state == StreamState.CLOSING) 
			return 0;		
		
		/* Cancel pending request HEADERS in ob_ss_pq if this RST_STREAM refers to that stream. */
		if (!server && isMyStreamId(stream_id) && ob_ss_pq.top)
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
		
		frame.rst_stream = Reset(stream_id, error_code);
		addItem(item);
	}

	/*
	 * Adds PING frame. This is a convenient functin built on top of
	 * http2_session_add_frame() to add PING easily.
	 *
	 * If the |opaque_data| is not null, it must point to 8 bytes memory
	 * region of data. The data pointed by |opaque_data| is copied. It can
	 * be null. In this case, 8 bytes null is used.
	 *
	 */
	void http2_session_add_ping(Session session, FrameFlags flags, const ubyte *opaque_data);

	/*
	 * Adds GOAWAY frame with the last-stream-ID |last_stream_id| and the
	 * error code |error_code|. This is a convenient function built on top
	 * of http2_session_add_frame() to add GOAWAY easily.  The
	 * |aux_flags| are bitwise-OR of one or more of
	 * http2_goaway_aux_flag.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * 
	 * ErrorCode.INVALID_ARGUMENT
	 *     The |opaque_data_len| is too large.
	 */
	ErrorCode http2_session_add_goaway(Session session, int last_stream_id, FrameError error_code, const ubyte *opaque_data, size_t opaque_data_len, ubyte aux_flags);

	/*
	 * Adds WINDOW_UPDATE frame with stream ID |stream_id| and
	 * window-size-increment |window_size_increment|. This is a convenient
	 * function built on top of http2_session_add_frame() to add
	 * WINDOW_UPDATE easily.
	 */
	void http2_session_add_window_update(Session session, FrameFlags flags, int stream_id, int window_size_increment);

	/*
	 * Adds SETTINGS frame.
	 */
	void http2_session_add_settings(Session session, FrameFlags flags, const http2_settings_entry *iv, size_t niv);

	/**
	 * Creates new stream in $(D Session) with stream ID |stream_id|,
	 * priority |pri_spec| and flags |flags|.  The |flags| is bitwise OR
	 * of http2_stream_flag.  Since this function is called when initial
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
	Stream openStream(int stream_id, StreamFlags flags, ref PrioritySpec pri_spec_in, StreamState initial_state, void *stream_user_data)
	{
		ErrorCode rv;
		Stream stream;
		Stream dep_stream = null;
		Stream root_stream;
		bool stream_alloc;
		PrioritySpec pri_spec_default;
		PrioritySpec *pri_spec = &pri_spec_in;
		
		stream = getStreamRaw(stream_id);
		
		if (stream) {
			assert(stream.state == StreamState.IDLE);
			assert(stream.inDepTree());
			detachIdleStream(stream);
			stream.remove();
		} else {
			if (session.server && initial_state != StreamState.IDLE && !isMyStreamId(stream_id))				
				adjustClosedStream(1);
			stream = Mem.alloc!Stream();
			stream_alloc = true;
		}
		
		scope(failure) if (stream_alloc) Mem.free(stream);
		
		if (pri_spec.stream_id != 0) {
			dep_stream = getStreamRaw(pri_spec.stream_id);
			
			if  (is_server && !dep_stream && idleStreamDetect(pri_spec.stream_id)) 
			{
				/* Depends on idle stream, which does not exist in memory. Assign default priority for it. */            
				dep_stream = openStream(pri_spec.stream_id, FrameFlags.NONE, pri_spec_default, StreamState.IDLE, null);
			} else if (!dep_stream || !dep_stream.inDepTree()) {
				/* If dep_stream is not part of dependency tree, stream will get default priority. */
				pri_spec = pri_spec_default;
			}
		}
		
		if (initial_state == StreamState.RESERVED)
			flags |= StreamFlags.PUSH;
		
		stream.initialize(stream_id, flags, initial_state, pri_spec.weight, roots, 
			remote_settings.initial_window_size, local_settings.initial_window_size, stream_user_data);
		
		if (stream_alloc)
			streams[stream_id] = stream;
		
		scope(failure) if (stream_alloc) streams.remove(stream_id);
		
		switch (initial_state) {
			case StreamState.RESERVED:
				if (isMyStreamId(stream_id)) {
					/* half closed (remote) */
					http2_stream_shutdown(stream, ShutdownFlag.RD);
				} else {
					/* half closed (local) */
					http2_stream_shutdown(stream, ShutdownFlag.WR);
				}
				/* Reserved stream does not count in the concurrent streams limit. That is one of the DOS vector. */
				break;
			case StreamState.IDLE:
				/* Idle stream does not count toward the concurrent streams limit. This is used as anchor node in dependency tree. */
				assert(server);
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
		
		root_stream = dep_stream.getDepRoot();
		
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
	
		DEBUGF(fprintf(stderr, "stream: stream(%p)=%d close\n", stream, stream.id));
			
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
		if (policy.on_stream_close_callback(session, stream_id, error_code) != 0)
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
		stream.flags |= StreamFlags.CLOSED;
		
		if  (is_server && stream.inDepTree())
		{
			/* On server side, retain stream at most MAX_CONCURRENT_STREAMS
		       combined with the current active incoming streams to make
		       dependency tree work better. */
			keepClosedStream(stream);
		} else {
			destroyStream(stream);
		}
		return 0;
	}

	/*
	 * Deletes |stream| from memory.  After this function returns, stream
	 * cannot be accessed.
	 *
	 */
	void destroyStream(Stream stream)
	{
		DEBUGF(fprintf(stderr, "stream: destroy closed stream(%p)=%d\n", stream, stream.id));
		
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
		DEBUGF(fprintf(stderr, "stream: keep closed stream(%p)=%d, state=%d\n", stream, stream.id, stream.state));
		
		if (session.closed_stream_tail) {
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
		DEBUGF(fprintf(stderr, "stream: keep idle stream(%p)=%d, state=%d\n", stream, stream.id, stream.state));
		
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
		
		DEBUGF(fprintf(stderr, "stream: detach idle stream(%p)=%d, state=%d\n", stream, stream.id, stream.state));
		
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
		
		DEBUGF(fprintf(stderr, "stream: adjusting kept closed streams  num_closed_streams=%zu, num_incoming_streams=%zu, max_concurrent_streams=%zu\n",
				session.num_closed_streams, session.num_incoming_streams,
				num_stream_max));

		while (session.num_closed_streams > 0 && num_closed_streams + num_incoming_streams + offset > num_stream_max)
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
		size_t max;
		
		/* Make minimum number of idle streams 2 so that allocating 2
	     streams at once is easy.  This happens when PRIORITY frame to
	     idle stream, which depends on idle stream which does not
	     exist. */
		max = max(2, min(local_settings.max_concurrent_streams, pending_local_max_concurrent_stream));
		
		DEBUGF(fprintf(stderr, "stream: adjusting kept idle streams num_idle_streams=%zu, max=%zu\n", num_idle_streams, max));
		
		while (num_idle_streams > max) {
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
		return 0;
	}

	ErrorCode http2_session_end_request_headers_received(Session session, http2_frame *frame,
		Stream stream);

	ErrorCode http2_session_end_response_headers_received(Session session, http2_frame *frame, Stream stream);

	ErrorCode http2_session_end_headers_received(Session session, http2_frame *frame, Stream stream);

	ErrorCode http2_session_on_request_headers_received(Session session, http2_frame *frame);

	ErrorCode http2_session_on_response_headers_received(Session session, http2_frame *frame, Stream stream);

	ErrorCode http2_session_on_push_response_headers_received(Session session, http2_frame *frame, Stream stream);

	/*
	 * Called when HEADERS is received, assuming |frame| is properly
	 * initialized.  This function does first validate received frame and
	 * then open stream and call callback functions.
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
	ErrorCode http2_session_on_headers_received(Session session, http2_frame *frame, Stream stream);

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
	ErrorCode http2_session_on_priority_received(Session session, http2_frame *frame);

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
	ErrorCode http2_session_on_rst_stream_received(Session session, http2_frame *frame);

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
	ErrorCode http2_session_on_settings_received(Session session, http2_frame *frame, int noack);

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
	ErrorCode http2_session_on_push_promise_received(Session session, http2_frame *frame);

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
	ErrorCode http2_session_on_ping_received(Session session, http2_frame *frame);

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
	ErrorCode http2_session_on_goaway_received(Session session, http2_frame *frame);

	/*
	 * Called when WINDOW_UPDATE is recieved, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * ErrorCode.CALLBACK_FAILURE
	 *   The callback function failed.
	 */
	ErrorCode http2_session_on_window_update_received(Session session, http2_frame *frame);

	/*
	 * Called when DATA is received, assuming |frame| is properly
	 * initialized.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * ErrorCode.CALLBACK_FAILURE
	 *   The callback function failed.
	 */
	ErrorCode http2_session_on_data_received(Session session, http2_frame *frame);

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
	ErrorCode http2_session_pack_data(Session session, http2_bufs *bufs, size_t datamax, http2_frame *frame, http2_data_aux_data *aux_data);

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
			if (session_is_outgoing_concurrent_streams_max(session)) {
				if (session.remote_window_size == 0 || ob_da_pq.empty)
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
		
		if (session_is_outgoing_concurrent_streams_max(session) ||
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
	OutboundItem getNextOutboundItem(Session session) {
		OutboundItem item;
		OutboundItem headers_item;
		
		if (ob_pq.empty) {
			if (ob_ss_pq.empty) {
				if (remote_window_size == 0 || ob_da_pq.empty)
					return null;				
				
				return ob_da_pq.top;
			}
			
			/* Return item only when concurrent connection limit is not reached */
			if (session_is_outgoing_concurrent_streams_max(session)) {
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
		
		if (session_is_outgoing_concurrent_streams_max(session) || 
			item.weight > headers_item.weight ||
			(item.weight == headers_item.weight && item.seq < headers_item.seq))
		{
			return item;
		}
		
		return headers_item;
	}
	
	/*
	 * Updates local settings with the |iv|. The number of elements in the
	 * array pointed by the |iv| is given by the |iv.length|.  This function
	 * assumes that the all settings_id member in |iv| are in range 1 to
	 * HTTP2_SETTINGS_MAX, inclusive.
	 *
	 * While updating individual stream's local window size, if the window
	 * size becomes strictly larger than HTTP2_MAX_WINDOW_SIZE,
	 * RST_STREAM is issued against such a stream.
	 */
	void http2_session_update_local_settings(Session session, http2_settings_entry *iv, size_t niv);

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
			return terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "depend on itself");
		}
		
		if (pri_spec.stream_id != 0) {
			dep_stream = getStreamRaw(pri_spec.stream_id);
			
			if  (is_server && !dep_stream && idleStreamDetect(pri_spec.stream_id))
			{ 				
				dep_stream = openStream(pri_spec.stream_id, FrameFlags.NONE, pri_spec_default, StreamState.IDLE, null);
				
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
				
				rv = stream.makeTopmostRoot(this);
			} else {
				rv = stream.makeRoot(this);
			}
			
			return rv;
		}
		
		assert(dep_stream);
		
		if (stream.subtreeContains(dep_stream)) {
			DEBUGF(fprintf(stderr, "stream: cycle detected, dep_stream(%p)=%d stream(%p)=%d\n",
					dep_stream, dep_stream.id, stream,
					stream.id));
			
			dep_stream.removeSubtree();
			dep_stream.makeRoot(session);
		}
		
		stream.removeSubtree();
		
		/* We have to update weight after removing stream from tree */
		stream.weight = pri_spec.weight;
		
		root_stream = dep_stream.getDepRoot();
		
		if (root_stream.subStreams + stream.subStreams > MAX_DEP_TREE_LENGTH) 
		{
			stream.weight = DEFAULT_WEIGHT;
			
			stream.makeRoot(session);
			} else {
				if (pri_spec.exclusive)
				dep_stream.insertSubtree(stream, session);
			else
				dep_stream.addSubtree(stream, session);
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
	
private:
	
	/*
	 * Returns non-zero if the number of outgoing opened streams is larger
	 * than or equal to
	 * remote_settings.max_concurrent_streams.
	 */
	bool session_is_outgoing_concurrent_streams_max(Session session) 
	{
		return session.remote_settings.max_concurrent_streams <= session.num_outgoing_streams;
	}
	
	/*
	 * Returns non-zero if the number of incoming opened streams is larger
	 * than or equal to
	 * local_settings.max_concurrent_streams.
	 */
	bool session_is_incoming_concurrent_streams_max(Session session) 
	{
		return session.local_settings.max_concurrent_streams <= session.num_incoming_streams;
	}
	
	/*
	 * Returns non-zero if the number of incoming opened streams is larger
	 * than or equal to
	 * session.pending_local_max_concurrent_stream.
	 */
	bool session_is_incoming_concurrent_streams_pending_max(Session session)
	{
		return session.pending_local_max_concurrent_stream <= session.num_incoming_streams;
	}
	
	bool session_enforce_http_messaging(Session session) 
	{
		return (session.opt_flags & HTTP2_OPTMASK_NO_HTTP_MESSAGING) == 0;
	}
	
	/*
	 * Returns nonzero if |frame| is trailer headers.
	 */
	bool session_trailer_headers(Session session, http2_stream *stream, http2_frame *frame) 
	{
		if (!stream || frame.hd.type != FrameType.HEADERS) {
			return 0;
		}
		if (session.server) {
			return frame.headers.cat == HeadersCategory.HEADERS;
		}
		
		return frame.headers.cat == HTTP2_HCAT_HEADERS &&
			(stream.http_flags & HTTPFlags.EXPECT_FINAL_RESPONSE) == 0;
	}
	
	/* Returns nonzero if the |stream| is in reserved(remote) state */
	bool state_reserved_remote(Session session, http2_stream *stream)
	{
		return stream.state == StreamState.RESERVED && !isMyStreamId(stream.stream_id);
	}
	
	/* Returns nonzero if the |stream| is in reserved(local) state */
	bool state_reserved_local(Session session, http2_stream *stream) {
		return stream.state == StreamState.RESERVED && isMyStreamId(stream.stream_id);
	}

	/*
	 * Checks whether received stream_id is valid. 
	 */
	bool isNewPeerStreamId(int stream_id)
	{
		return stream_id != 0 && !isMyStreamId(session, stream_id) && session.last_recv_stream_id < stream_id;
	}
	

	/**
	 * @function
	 *
	 * Returns the last stream ID of a stream for which
	 * :type:`http2_on_frame_recv_callback` was invoked most recently.
	 * The returned value can be used as last_stream_id parameter for
	 * `http2_submit_goaway()` and
	 * `http2_session_terminate_session2()`.
	 *
	 * This function always succeeds.
	 */
	void http2_session_get_last_proc_stream_id(Session session);

	void inboundFrameReset()
	{
		/* A bit risky code, since if this function is called from Session(), we rely on the fact that
     	   iframe.frame.hd.type is 0, so that no free is performed. */
		with (FrameType) switch (iframe.frame.hd.type) {
			case HEADERS:
				iframe.frame.headers.free();
				break;
			case PRIORITY:
				iframe.frame.priority.free();
				break;
			case RST_STREAM:
				iframe.frame.rst_stream.free();
				break;
			case SETTINGS:
				iframe.frame.settings.free();
				break;
			case PUSH_PROMISE:
				iframe.frame.push_promise.free();
				break;
			case PING:
				iframe.frame.ping.free();
				break;
			case GOAWAY:
				iframe.frame.goaway.free();
				break;
			case WINDOW_UPDATE:
				iframe.frame.window_update.free();
				break;
		}
		
		destroy(iframe.frame);
		destroy(iframe.ext_frame_payload);
		
		iframe.state = InboundState.IB_READ_HEAD;
		
		iframe.sbuf = Buffer(iframe.raw_sbuf.ptr[0 .. iframe.raw_sbuf.sizeof]);
		iframe.sbuf.mark += FRAME_HDLEN;
		
		iframe.lbuf.free();
		iframe.lbuf = Buffer();
		
		destroy(iframe.iv);
		iframe.payloadleft = 0;
		iframe.padlen = 0;
		iframe.iv[INBOUND_NUM_IV - 1].id = SETTINGS_HEADER_TABLE_SIZE;
		iframe.iv[INBOUND_NUM_IV - 1].value = uint.max;
	}

	bool idleStreamDetect(int stream_id) 
	{
		/* Assume that stream object with stream_id does not exist */
		if (isMyStreamId(stream_id)) {
			if (next_stream_id <= cast(uint)stream_id) 
				return 1;
			return 0;
		}
		if (isNewPeerStreamId(stream_id))
			return 1;
		
		return 0;
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
		
		if (stream == null || (stream.flags & StreamFlags.CLOSED) || stream.state == StreamState.IDLE)
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
	ErrorCode terminateSession(int last_stream_id, uint error_code, string reason) 
	{
		ErrorCode rv;
		string debug_data;
		
		if (goaway_flags & GoAwayFlags.TERM_ON_SEND) {
			return 0;
		}
		
		if (reason == null) {
			debug_data = null;
		} else {
			debug_data = reason;
		}
		
		rv = addGoaway(last_stream_id, error_code, debug_data, GoAwayAuxFlags.TERM_ON_SEND);
		
		if (rv != 0) {
			return rv;
		}
		
		goaway_flags |= GoAwayFlags.TERM_ON_SEND;
		
		return 0;
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
		if (stream == null) {
			return ErrorCode.STREAM_CLOSED;
		}
		if (isClosing()) {
			return ErrorCode.SESSION_CLOSING;
		}
		if (stream.shutFlags & ShutdownFlag.WR) {
			return ErrorCode.STREAM_SHUT_WR;
		}
		return 0;
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
		return 0;
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
		if (rv != 0) {
			return rv;
		}
		assert(stream);
		if (isMyStreamId(stream.id)) {
			return ErrorCode.INVALID_STREAM_ID;
		}
		if (stream.state == StreamState.OPENING) {
			return 0;
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
		if (rv != 0) {
			return rv;
		}
		assert(stream);
		if (stream.state != StreamState.RESERVED) {
			return ErrorCode.PROTO;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		return 0;
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
		if (rv != 0) {
			return rv;
		}
		assert(stream);
		if (isMyStreamId(stream.id)) 
		{
			if (stream.state == StreamState.CLOSING) {
				return ErrorCode.STREAM_CLOSING;
			}
			return 0;
		}
		if (stream.state == StreamState.OPENED) {
			return 0;
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
		
		if (!server) {
			return ErrorCode.PROTO;
		}
		
		rv = predicateForStreamSend(stream);
		if (rv != 0) {
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
		return 0;
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
			return 0;
		}
		stream = getStream(stream_id);
		if (stream == null) {
			return ErrorCode.STREAM_CLOSED;
		}
		if (isClosing()) {
			return ErrorCode.SESSION_CLOSING;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		if (state_reserved_local(session, stream)) {
			return ErrorCode.INVALID_STREAM_STATE;
		}
		return 0;
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
	int predicateDataSend(Session session, Stream stream) 
	{
		ErrorCode rv;
		rv = predicateForStreamSend(stream);
		if (rv != 0) {
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
			return 0;
		}
		/* Response body data */
		if (stream.state == StreamState.OPENED) {
			return 0;
		}
		if (stream.state == StreamState.CLOSING) {
			return ErrorCode.STREAM_CLOSING;
		}
		return ErrorCode.INVALID_STREAM_STATE;
	}


	/* Take into account settings max frame size and both connection-level flow control here */
	int enforceFlowControlLimits(Stream stream, int requested_window_size)
	{
		DEBUGF(fprintf(stderr, "send: remote windowsize connection=%d, remote maxframsize=%u, stream(id %d)=%d\n",
				remote_window_size,
				remote_settings.max_frame_size, stream.id,
				stream.remoteWindowSize));
		
		return min(min(min(requested_window_size, stream.remoteWindowSize), remote_window_size), cast(int)remote_settings.max_frame_size);
	}

	/*
	 * Returns the maximum length of next data read. If the
	 * connection-level and/or stream-wise flow control are enabled, the
	 * return value takes into account those current window sizes. The remote
	 * settings for max frame size is also taken into account.
	 */
	size_t nextDataRead(Stream stream) 
	{
		int window_size;
		
		window_size = enforceFlowControlLimits(stream, DATA_PAYLOADLEN);
		
		DEBUGF(fprintf(stderr, "send: available window=%zd\n", window_size));
		
		return window_size > 0 ? cast(size_t)window_size : 0;
	}

	int callSelectPadding(in Frame frame, size_t max_payloadlen) 
	{
		int rv;
		
		if (frame.hd.length >= max_payloadlen) {
			return frame.hd.length;
		}
		
		size_t max_paddedlen;
		
		max_paddedlen = min(frame.hd.length + MAX_PADLEN, max_payloadlen);
		
		rv = policy.selectPaddingLength(frame, max_paddedlen);
		if (rv < cast(int)frame.hd.length || rv > cast(int)max_paddedlen) {
			return cast(int) ErrorCode.CALLBACK_FAILURE;
		}
		return rv;
	}	
	
	ErrorCode callOnFrameReady(Frame frame) {
		ErrorCode rv;
		rv = policy.onFrameReady(frame);
		if (rv != 0) {
			return ErrorCode.CALLBACK_FAILURE;
		}
		return 0;
	}

	ErrorCode callOnFrameSent(Frame frame) {
		ErrorCode rv;
		rv = policy.onFrameSent(frame);
		if (rv != 0) {
			return ErrorCode.CALLBACK_FAILURE;
		}
		return 0;
	}

	int callRead(out ubyte[] buf)
	{
		int len = policy.read(buf);
		
		if (len > 0) {
			if (cast(size_t) len > buf.length)
				return ErrorCode.CALLBACK_FAILURE;
		} else if (len < 0 && rv != cast(int)ErrorCode.WOULDBLOCK && rv != cast(int)ErrorCode.EOF)
			return ErrorCode.CALLBACK_FAILURE;
		
		return len;
	}

	/* Add padding to HEADERS or PUSH_PROMISE. We use frame.headers.padlen in this function 
	 * to use the fact that frame.push_promise has also padlen in the same position. */
	ErrorCode headersAddPad(Frame frame)
	{
		ErrorCode rv;
		int padded_payloadlen;
		Buffers framebufs = aob.framebufs;
		size_t padlen;
		size_t max_payloadlen;
		
		max_payloadlen = min(MAX_PAYLOADLEN, frame.hd.length + MAX_PADLEN);
		
		padded_payloadlen = callSelectPadding(frame, max_payloadlen);
		
		if (isFatal(cast(int)padded_payloadlen)) {
			return cast(int)padded_payloadlen;
		}
		
		padlen = padded_payloadlen - frame.hd.length;
		
		DEBUGF(fprintf(stderr, "send: padding selected: payloadlen=%zd, padlen=%zu\n", padded_payloadlen, padlen));
		
		rv = http2_frame_add_pad(framebufs, &frame.hd, padlen);
		
		if (rv != 0) {
			return rv;
		}
		
		frame.headers.padlen = padlen;
		
		return 0;
	}

	size_t estimateHeadersPayload(in NVPair[] nva, size_t additional) 
	{
		return hd_deflater.upperBound(nva) + additional;
	}
	
	
	/* Closes non-idle and non-closed streams whose stream ID > last_stream_id. 
	 * If incoming is nonzero, we are going to close incoming streams.  
	 * Otherwise, close outgoing streams. */
	ErrorCode closeStreamOnGoAway(Session session, int last_stream_id, int incoming)
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
					
					estimated_payloadlen = estimateHeadersPayload(frame.headers.nva, PRIORITY_SPECLEN);
					
					if (estimated_payloadlen > MAX_HEADERSLEN) {
						return ErrorCode.FRAME_SIZE_ERROR;
					}
					
					if (frame.headers.cat == HeadersCategory.REQUEST) {
						/* initial HEADERS, which opens stream */
						Stream stream = openStream(frame.hd.stream_id, StreamFlags.NONE, frame.headers.pri_spec, StreamState.INITIAL, aux_data.stream_user_data);
						
						rv = predicateRequestHeadersSend(item);
						if (rv != 0) {
							return rv;
						}
						
						if (session_enforce_http_messaging(session)) {
							http2_http_record_request_method(stream, frame);
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
							
							if (rv != 0) {
								if (stream && stream.item == item) 
									stream.detachItem(session);
								return rv;
							}
						}
					}
					
					rv = frame.headers.pack(session.aob.framebufs, hd_deflater);
					
					if (rv != 0) {
						return rv;
					}
					
					DEBUGF(fprintf(stderr, "send: before padding, HEADERS serialized in %zd bytes\n", aob.framebufs.length));
					
					rv = headersAddPad(frame);
					
					if (rv != 0) {
						return rv;
					}
					
					DEBUGF(fprintf(stderr, "send: HEADERS finally serialized in %zd bytes\n",
							http2_bufs_len(&session.aob.framebufs)));
					
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
				       nghttp2.  In nghttp2, only server retains non-active (closed
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
					if (rv != 0) {
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
					
					estimated_payloadlen = estimateHeadersPayload(frame.push_promise.nva, 0);
					
					if (estimated_payloadlen > MAX_HEADERSLEN)
						return ErrorCode.FRAME_SIZE_ERROR;
					
					/* predicte should fail if stream is null. */
					rv = predicatePushPromiseSend(stream);
					if (rv != 0) {
						return rv;
					}
					
					assert(stream);
					
					rv = frame.push_promise.pack(aob.framebufs, hd_deflater);
					if (rv != 0)
						return rv;
					
					rv = headersAddPad(frame);
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
					if (rv != 0) {
						return rv;
					}
					frame.window_update.pack(aob.framebufs);
					break;
				}
				case GOAWAY:
					rv = frame.goaway.pack(aob.framebufs);
					if (rv != 0) {
						return rv;
					}
					local_last_stream_id = frame.goaway.last_stream_id;
					
					break;
				default:
					return ErrorCode.INVALID_ARGUMENT;
			}
			return 0;
		} else {
			size_t next_readmax;
			Stream stream = getStream(frame.hd.stream_id);
			
			if (stream) {
				assert(stream.item == item);
			}
			
			rv = predicateDataSend(stream);
			if (rv != 0) {
				if (stream)
					stream.detachItem(session);          
				
				return rv;
			}
			/* Assuming stream is not null */
			assert(stream);
			next_readmax = nextDataRead(stream);
			
			if (next_readmax == 0) {
				
				/* This must be true since we only pop DATA frame item from queue when session.remote_window_size > 0 */
				assert(session.remote_window_size > 0);
				
				stream.deferItem(StreamFlags.DEFERRED_FLOW_CONTROL, this);            
				aob.item = null;
				aob.reset();
				return ErrorCode.DEFERRED;
			}
			
			rv = http2_session_pack_data(session, aob.framebufs, next_readmax, frame, &item.aux_data.data);
			if (rv == ErrorCode.DEFERRED) {
				stream.deferItem(StreamFlags.DEFERRED_USER, this);
				aob.item = null;
				aob.reset();
				return ErrorCode.DEFERRED;
			}
			if (rv == ErrorCode.TEMPORAL_CALLBACK_FAILURE) {
				stream.detachItem(session);            
				addReset(frame.hd.stream_id, FrameError.INTERNAL_ERROR);
				return ErrorCode.TEMPORAL_CALLBACK_FAILURE;
			}
			if (rv != 0)
				stream.detachItem(session);
			return 0;
		}
	}
	
	/*
	 * Called after a frame is sent.  This function runs
	 * $(D Policy.onFrameSent) and handles stream closure upon END_STREAM
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
					DEBUGF(fprintf(stderr, "send: CONTINUATION exists, just return\n"));
					return 0;
				}
			}
			rv = callOnFrameSent(frame);
			if (isFatal(rv)) {
				return rv;
			}
			with(FrameType) switch (frame.hd.type) {
				case HEADERS: {
					HeadersAuxData *aux_data;
					Stream stream = getStream(frame.hd.stream_id);
					if (!stream) 
						break;                
					if (stream.item == item)
						stream.detachItem(this);
					
					switch (frame.headers.cat) {
						case HeadersCategory.REQUEST: {
							stream.state = StreamState.OPENING;
							if (frame.hd.flags & FrameFlags.END_STREAM) {
								http2_stream_shutdown(stream, ShutdownFlag.WR);
							}
							rv = closeStreamIfShutRdWr(stream);
							if (isFatal(rv)) {
								return rv;
							}
							/* We assume aux_data is a pointer to HeadersAuxData */
							aux_data = &item.aux_data.headers;
							if (aux_data.data_prd.read_callback) {
								/* http2_submit_data() makes a copy of aux_data.data_prd */
								rv = http2_submit_data(session, FrameFlags.END_STREAM,
									frame.hd.stream_id, &aux_data.data_prd);
								if (isFatal(rv)) {
									return rv;
								}
								/* TODO: http2_submit_data() may fail if stream has already DATA frame item.  We might have to handle it here. */
							}
							break;
						}
						case HeadersCategory.PUSH_RESPONSE:
							stream.flags &= ~StreamFlags.PUSH;
							++num_outgoing_streams;
							/* Fall through */
						case HeadersCategory.RESPONSE:
							stream.state = StreamState.OPENED;
							/* Fall through */
						case HeadersCategory.HEADERS:
							if (frame.hd.flags & FrameFlags.END_STREAM) {
								http2_stream_shutdown(stream, ShutdownFlag.WR);
							}
							rv = closeStreamIfShutRdWr(stream);
							if (isFatal(rv)) {
								return rv;
							}
							/* We assume aux_data is a pointer to HeadersAuxData */
							aux_data = &item.aux_data.headers;
							if (aux_data.data_prd.read_callback) {
								rv = http2_submit_data(session, FrameFlags.END_STREAM, frame.hd.stream_id, &aux_data.data_prd);
								if (isFatal(rv)) {
									return rv;
								}
								/* TODO http2_submit_data() may fail if stream has already DATA frame item. 
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
					
					reprioritizeStream(stream, &frame.priority.pri_spec);
					
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
			
			return 0;
		}

		Stream stream = getStream(frame.hd.stream_id);
		DataAuxData *aux_data = &item.aux_data.data;

		/* We update flow control window after a frame was completely
	       sent. This is possible because we choose payload length not to
	       exceed the window */
		remote_window_size -= frame.hd.length;

		if (stream) {
			stream.remoteWindowSize -= frame.hd.length;
		}
		
		if (stream && aux_data.eof) {
			stream.detachItem(this);
			
			/* Call onFrameSent after detachItem(), so that application can issue http2_submit_data() in the callback. */
			rv = callOnFrameSent(frame);
			if (isFatal(rv)) {
				return rv;
			}
			
			if (frame.hd.flags & FrameFlags.END_STREAM) {
				int stream_closed;
				
				stream_closed = (stream.shutFlags & ShutdownFlag.RDWR) == ShutdownFlag.RDWR;
				
				http2_stream_shutdown(stream, ShutdownFlag.WR);
				
				rv = closeStreamIfShutRdWr(stream);
				if (isFatal(rv)) {
					return rv;
				}
				/* stream may be null if it was closed */
				if (stream_closed)
					stream = null;
			}
			return 0;
		}
		
		rv = callOnFrameSent(frame);
		
		if (isFatal(rv)) {
			return rv;
		}
		
		return 0;
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
					
					DEBUGF(fprintf(stderr, "send: next CONTINUATION frame, %zu bytes\n", framebufs.cur.buf.length));
					
					return 0;
				}
			}
			
			aob.reset();
			
			return 0;

		}

		OutboundItem next_item;
		Stream stream;
		DataAuxData aux_data = item.aux_data.data;
		
		/* On EOF, we have already detached data.  Please note that
	       application may issue http2_submit_data() in
	       $(D Policy.onFrameSent) (call from afterFrameSent),
	       which attach data to stream.  We don't want to detach it. */
		if (aux_data.eof) {
			aob.reset();			
			return 0;
		}
		
		stream = getStream(frame.hd.stream_id);
		
		/* If Session is closed or RST_STREAM was queued, we won't send further data. */
		if (predicateDataSend(stream) != 0) {
			if (stream)
				stream.detachItem(this);            
			aob.reset();
			
			return 0;
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
			size_t next_readmax = nextDataRead(stream);
			
			if (next_readmax == 0) {
				
				if (session.remote_window_size == 0 && stream.remoteWindowSize > 0) {
					
					/* If DATA cannot be sent solely due to connection level
		             window size, just push item to queue again.  We never pop
		             DATA item while connection level window size is 0. */
					rv = session.ob_da_pq.push(aob.item);
					
					if (isFatal(rv)) {
						return rv;
					}
					
					aob.item.queued = 1;
				} else
					stream.deferItem(StreamFlags.DEFERRED_FLOW_CONTROL, this);
				
				aob.item = null;
				aob.reset();
				
				return 0;
			}
			
			framebufs.reset();
			
			rv = http2_session_pack_data(session, framebufs, next_readmax, frame, aux_data);
			if (isFatal(rv)) {
				return rv;
			}
			if (rv == ErrorCode.DEFERRED) {
				stream.deferItem(StreamFlags.DEFERRED_USER, this);
				
				aob.item = null;
				aob.reset();
				
				return 0;
			}
			if (rv == ErrorCode.TEMPORAL_CALLBACK_FAILURE)
			{
				/* Stop DATA frame chain and issue RST_STREAM to close the stream.  We don't return ErrorCode.TEMPORAL_CALLBACK_FAILURE intentionally. */
				addReset(frame.hd.stream_id, FrameError.INTERNAL_ERROR);
				stream.detachItem(this);
				aob.reset();
				return 0;
			}
			
			assert(rv == 0);
			
			return 0;
		}
		
		if (stream.dpri == StreamDPRI.TOP) {
			rv = session.ob_da_pq.push(aob.item);
			
			if (isFatal(rv)) {
				return rv;
			}
			
			aob.item.queued = 1;
		}
		
		aob.item = null;
		aob.reset();
		return 0;
	}

	// fetch data and feed it to data_arr
	ErrorCode memSendInternal(ref ubyte[] data_arr, bool fast_cb)
	{
		ErrorCode rv;
		Buffers framebufs = aob.framebufs;
		
		data_arr = null;

		for (;;) {
			switch (aob.state) {
				case OutboundState.POP_ITEM: {
					OutboundItem item;
					
					item = popNextOutboundItem();
					if (item == null) {
						return 0;
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
						DEBUGF(fprintf(stderr, "send: frame transmission deferred\n"));
						break;
					}
					if (rv < 0) {
						int opened_stream_id;
						FrameError error_code = FrameError.INTERNAL_ERROR;
						
						DEBUGF(fprintf(stderr, "send: frame preparation failed with %s\n", toString(cast(ErrorCode)rv)));
						/* TODO: If the error comes from compressor, the connection must be closed. */
						if (item.frame.hd.type != FrameType.DATA && !isFatal(rv)) {
							Frame* frame = &item.frame;
							/* The library is responsible for the transmission of WINDOW_UPDATE frame, so we don't call error callback for it. */
							if (frame.hd.type != FrameType.WINDOW_UPDATE && policy.onFrameFailure(*frame, rv) != 0)
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
						}
						if (opened_stream_id) {
							/* careful not to override rv */
							int rv2;
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
						
						DEBUGF(fprintf(stderr, "send: next frame: payloadlen=%zu, type=%u, flags=0x%02x, stream_id=%d\n",
								frame.hd.length, frame.hd.type, frame.hd.flags,
								frame.hd.stream_id));
						
						rv = callOnFrameReady(session, *frame);
						if (isFatal(rv)) {
							return rv;
						}
					} else {
						DEBUGF(fprintf(stderr, "send: next frame: DATA\n"));
					}
					
					DEBUGF(fprintf(stderr,
							"send: start transmitting frame type=%u, length=%zd\n",
							framebufs.cur.buf.pos[3],
							framebufs.cur.buf.last - framebufs.cur.buf.pos));
					
					aob.state = OutboundState.SEND_DATA;
					
					break;
				}
				case OutboundState.SEND_DATA: {
					size_t datalen;
					Buffer buf = framebufs.cur.buf;
					
					if (buf.pos == buf.last) {
						DEBUGF(fprintf(stderr, "send: end transmission of a frame\n"));

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
					
					return 0;
				}
			}
		}
	}

package: /* Used only for tests */
	/*
	 * Returns top of outbound frame queue. This function returns null if
	 * queue is empty.
	 */
	@property OutboundItem ob_pq_top() {
		return ob_pq.top;
	}
	
private:
	HashMap!Stream streams;
	
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
	Policy policy;
	
	/// Sequence number of outbound frame to maintain the order of enqueue if priority is equal.
	long next_seq;
	
	/** Reset count of http2_outbound_item's weight.  We decrements
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
	Setting[] inflight_iv;
	
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
	
	/// The number of bytes allocated for nvbuf
	size_t nvbuflen;
	
	/// Next Stream ID. Made unsigned int to detect >= (1 << 31). 
	uint next_stream_id;

	/// The largest stream ID received so far
	int last_recv_stream_id;
	
	/// The largest stream ID which has been processed in some way. 
	/// Notes: This value will be used as last-stream-id when sending GOAWAY frame.
	int last_proc_stream_id;
	
	/// Counter of unique ID of PING. Wraps when it exceeds HTTP2_MAX_UNIQUE_ID */
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
	
	/// window size for local flow control. It is initially set to HTTP2_INITIAL_CONNECTION_WINDOW_SIZE and could be
	/// increased/decreased by submitting WINDOW_UPDATE. See http2_submit_window_update().
	int local_window_size = INITIAL_CONNECTION_WINDOW_SIZE;	
	
	/// Settings value received from the remote endpoint. We just use ID as index. The index = 0 is unused. 
	SettingsStorage remote_settings;
	
	/// Settings value of the local endpoint.
	SettingsStorage local_settings;
	
	/// Option flags. This is bitwise-OR of 0 or more of http2_optmask.
	OptionsMask opt_flags;
	
	/// Unacked local SETTINGS_MAX_CONCURRENT_STREAMS value. We use this to refuse the incoming stream if it exceeds this value. 
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
size_t http2_pack_settings_payload(ubyte[] buf, const ref Setting[] iv)
{
	if (!http2_iv_check(iv, niv)) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	if (buflen < (niv * FRAME_SETTINGS_ENTRY_LENGTH)) {
		return ErrorCode.INSUFF_BUFSIZE;
	}
	
	return http2_frame_pack_settings_payload(buf, iv, niv);
}

/**
 * @function
 *
 * Submits HEADERS frame and optionally one or more DATA frames.
 *
 * The |pri_spec| is priority specification of this request.  `null`
 * means the default priority (see
 * `http2_priority_spec_default_init()`).  To specify the priority,
 * use `http2_priority_spec_init()`.  If |pri_spec| is not `null`,
 * this function will copy its data members.
 *
 * The `pri_spec.weight` must be in [$(D HTTP2_MIN_WEIGHT),
 * $(D HTTP2_MAX_WEIGHT)], inclusive.  If `pri_spec.weight` is
 * strictly less than $(D HTTP2_MIN_WEIGHT), it becomes
 * $(D HTTP2_MIN_WEIGHT).  If it is strictly greater than
 * $(D HTTP2_MAX_WEIGHT), it becomes $(D HTTP2_MAX_WEIGHT).
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * HTTP/2 specification has requirement about header fields in the
 * request HEADERS.  See the specification for more details.
 *
 * If |data_prd| is not `null`, it provides data which will be sent
 * in subsequent DATA frames.  In this case, a method that allows
 * request message bodies
 * (http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9) must
 * be specified with `:method` key in |nva| (e.g. `POST`).  This
 * function does not take ownership of the |data_prd|.  The function
 * copies the members of the |data_prd|.  If |data_prd| is `null`,
 * HEADERS have END_STREAM set.  The |stream_user_data| is data
 * associated to the stream opened by this request and can be an
 * arbitrary pointer, which can be retrieved later by
 * `http2_session_get_stream_user_data()`.
 *
 * This function returns assigned stream ID if it succeeds, or one of
 * the following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.STREAM_ID_NOT_AVAILABLE)
 *     No stream ID is available because maximum stream ID was
 *     reached.
 *
 * .. warning::
 *
 *   This function returns assigned stream ID if it succeeds.  But
 *   that stream is not opened yet.  The application must not submit
 *   frame to that stream ID before
 *   :type:`http2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
ErrorCode http2_submit_request(Session session, in PrioritySpec pri_spec, in NVPair[] nva, in DataProvider data_prd, void *stream_user_data)
{
	ubyte flags;
	
	if (pri_spec && http2_priority_spec_check_default(pri_spec)) {
		pri_spec = null;
	}

	flags = set_request_flags(pri_spec, data_prd);
	
	return submit_headers_shared_nva(session, flags, -1, pri_spec, nva, nvlen,
		data_prd, stream_user_data, 0);
}

/**
 * @function
 *
 * Submits response HEADERS frame and optionally one or more DATA
 * frames against the stream |stream_id|.
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
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
 * configured using `http2_session_server_new()` or its variants and
 * the target stream denoted by the |stream_id| must be reserved using
 * `http2_submit_push_promise()`.
 *
 * To send non-final response headers (e.g., HTTP status 101), don't
 * use this function because this function half-closes the outbound
 * stream.  Instead, use `http2_submit_headers()` for this purpose.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 *
 * .. warning::
 *
 *   Calling this function twice for the same stream ID may lead to
 *   program crash.  It is generally considered to a programming error
 *   to commit response twice.
 */
ErrorCode http2_submit_response(Session session, int stream_id, in NVPair[] nva, in DataProvider data_prd)
{
	ubyte flags = set_response_flags(data_prd);
	return submit_headers_shared_nva(session, flags, stream_id, null, nva, data_prd, null, 1);
}

/**
 * @function
 *
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
 * The |pri_spec| is priority specification of this request.  `null`
 * means the default priority (see
 * `http2_priority_spec_default_init()`).  To specify the priority,
 * use `http2_priority_spec_init()`.  If |pri_spec| is not `null`,
 * this function will copy its data members.
 *
 * The `pri_spec.weight` must be in [$(D HTTP2_MIN_WEIGHT),
 * $(D HTTP2_MAX_WEIGHT)], inclusive.  If `pri_spec.weight` is
 * strictly less than $(D HTTP2_MIN_WEIGHT), it becomes
 * $(D HTTP2_MIN_WEIGHT).  If it is strictly greater than
 * $(D HTTP2_MAX_WEIGHT), it becomes $(D HTTP2_MAX_WEIGHT).
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * The |stream_user_data| is a pointer to an arbitrary data which is
 * associated to the stream this frame will open.  Therefore it is
 * only used if this frame opens streams, in other words, it changes
 * stream state from idle or reserved to open.
 *
 * This function is low-level in a sense that the application code can
 * specify flags directly.  For usual HTTP request,
 * `http2_submit_request()` is useful.
 *
 * This function returns newly assigned stream ID if it succeeds and
 * |stream_id| is -1.  Otherwise, this function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
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
 *   :type:`http2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
ErrorCode http2_submit_headers(Session session, FrameFlags flags, int stream_id, const PrioritySpec pri_spec, in NVPair[] nva, void *stream_user_data)
{
	flags &= FrameFlags.END_STREAM;
	
	if (pri_spec && !http2_priority_spec_check_default(pri_spec)) {
		flags |= FrameFlags.PRIORITY;
	} else {
		pri_spec = null;
	}
	
	return submit_headers_shared_nva(session, flags, stream_id, pri_spec, nva, nvlen, null, stream_user_data, 0);
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
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
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
 *   :type:`http2_on_frame_send_callback`.  In side that callback,
 *   new data can be submitted using `http2_submit_data()`.  Of
 *   course, all data except for last one must not have
 *   $(D FrameFlags.END_STREAM) flag set in |flags|.
 */
ErrorCode http2_submit_data(Session session, FrameFlags flags, int stream_id, in DataProvider data_prd)
{
	int rv;
	http2_outbound_item *item;
	http2_frame *frame;
	http2_data_aux_data *aux_data;
	ubyte nflags = flags & FrameFlags.END_STREAM;
	http2_mem *mem;
	
	mem = &session.mem;
	
	if (stream_id == 0) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	aux_data = &item.aux_data.data;
	aux_data.data_prd = *data_prd;
	aux_data.eof = 0;
	aux_data.flags = nflags;
	
	/* flags are sent on transmission */
	http2_frame_data_init(&frame.data, FrameFlags.NONE, stream_id);
	
	rv = http2_session_add_item(session, item);
	if (rv != 0) {
		http2_frame_data_free(&frame.data);
		http2_mem_free(mem, item);
		return rv;
	}
	return 0;
}

/**
 * @function
 *
 * Submits PRIORITY frame to change the priority of stream |stream_id|
 * to the priority specification |pri_spec|.
 *
 *
 * The |pri_spec| is priority specification of this request.  `null`
 * is not allowed for this function. To specify the priority, use
 * `http2_priority_spec_init()`.  This function will copy its data
 * members.
 *
 * The `pri_spec.weight` must be in [$(D HTTP2_MIN_WEIGHT),
 * $(D HTTP2_MAX_WEIGHT)], inclusive.  If `pri_spec.weight` is
 * strictly less than $(D HTTP2_MIN_WEIGHT), it becomes
 * $(D HTTP2_MIN_WEIGHT).  If it is strictly greater than
 * $(D HTTP2_MAX_WEIGHT), it becomes $(D HTTP2_MAX_WEIGHT).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0; or the |pri_spec| is null; or trying to
 *     depend on itself.
 */
ErrorCode http2_submit_priority(Session session, int stream_id, const ref PrioritySpec pri_spec)
{
	int rv;
	http2_outbound_item *item;
	http2_frame *frame;
	http2_priority_spec copy_pri_spec;
	http2_mem *mem;
	
	mem = &session.mem;
	
	if (stream_id == 0 || !pri_spec) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	if (stream_id == pri_spec.stream_id) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	copy_pri_spec = *pri_spec;
	
	adjust_priority_spec_weight(&copy_pri_spec);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_priority_init(&frame.priority, stream_id, &copy_pri_spec);
	
	rv = http2_session_add_item(session, item);
	
	if (rv != 0) {
		http2_frame_priority_free(&frame.priority);
		http2_mem_free(mem, item);
		
		return rv;
	}
	
	return 0;
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
ErrorCode http2_submit_rst_stream(Session session, int stream_id, FrameError error_code)
{
	if (stream_id == 0) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	return addReset(stream_id, error_code);
}

/**
 * @function
 *
 * Stores local settings and submits SETTINGS frame.  The |iv| is the
 * pointer to the array of :type:`http2_settings_entry`.  The |niv|
 * indicates the number of :type:`http2_settings_entry`.
 *
 * This function does not take ownership of the |iv|.  This function
 * copies all the elements in the |iv|.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than HTTP2_MAX_WINDOW_SIZE,
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
ErrorCode http2_submit_settings(Session session, in Setting[] iv)
{
	return http2_session_add_settings(session, FrameFlags.NONE, iv, niv);
}

/**
 * @function
 *
 * Submits PUSH_PROMISE frame.
 *
 * The |stream_id| must be client initiated stream ID.
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * The |promised_stream_user_data| is a pointer to an arbitrary data
 * which is associated to the promised stream this frame will open and
 * make it in reserved state.  It is available using
 * `http2_session_get_stream_user_data()`.  The application can
 * access it in :type:`http2_before_frame_send_callback` and
 * :type:`http2_on_frame_send_callback` of this frame.
 *
 * The client side is not allowed to use this function.
 *
 * To submit response headers and data, use
 * `http2_submit_response()`.
 *
 * This function returns assigned promised stream ID if it succeeds,
 * or one of the following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
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
 *   :type:`http2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
ErrorCode http2_submit_push_promise(Session session, int stream_id, in NVPair[] nva, void *promised_stream_user_data)
{
	http2_outbound_item *item;
	http2_frame *frame;
	NVPair nva_copy;
	ubyte flags_copy;
	int promised_stream_id;
	int rv;
	http2_mem *mem;
	
	mem = &session.mem;
	
	if (stream_id == 0 || isMyStreamId(stream_id)) {
		return ErrorCode.INVALID_ARGUMENT;
	}
	
	if (!session.server) {
		return ErrorCode.PROTO;
	}
	
	/* All 32bit signed stream IDs are spent. */
	if (session.next_stream_id > int.max) {
		return ErrorCode.STREAM_ID_NOT_AVAILABLE;
	}
	
	item = Mem.alloc!OutboundItem(session);
	
	item.aux_data.headers.stream_user_data = promised_stream_user_data;
	
	frame = &item.frame;
	
	rv = http2_nv_array_copy(&nva_copy, nva, nvlen, mem);
	if (rv < 0) {
		http2_mem_free(mem, item);
		return rv;
	}
	
	flags_copy = FrameFlags.END_HEADERS;
	
	promised_stream_id = session.next_stream_id;
	session.next_stream_id += 2;
	
	http2_frame_push_promise_init(&frame.push_promise, flags_copy, stream_id,
		promised_stream_id, nva_copy, nvlen);
	
	rv = http2_session_add_item(session, item);
	
	if (rv != 0) {
		http2_frame_push_promise_free(&frame.push_promise, mem);
		http2_mem_free(mem, item);
		
		return rv;
	}
	
	return promised_stream_id;
}

/**
 * @function
 *
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
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_submit_ping(Session session, const ubyte *opaque_data)
{
	return http2_session_add_ping(session, FrameFlags.NONE, opaque_data);
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
 * `http2_session_want_read()` and `http2_session_want_write()`
 * return 0 and the application can close session.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |opaque_data_len| is too large; the |last_stream_id| is
 *     invalid.
 */
ErrorCode http2_submit_goaway(Session session, int last_stream_id, FrameError error_code, const ubyte *opaque_data, size_t opaque_data_len)
{
	if (session.goaway_flags & GoAwayFlags.TERM_ON_SEND) {
		return 0;
	}
	return http2_session_add_goaway(session, last_stream_id, error_code,
		opaque_data, opaque_data_len,
		GoAwayAuxFlags.NONE);
}

/**
 * @function
 *
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
 * (`http2_option_set_no_auto_window_update()`), and the library
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
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_submit_window_update(Session session, int stream_id, int window_size_increment)
{
	int rv;
	http2_stream *stream = 0;
	if (window_size_increment == 0) {
		return 0;
	}
	flags = 0;
	if (stream_id == 0) {
		rv = http2_adjust_local_window_size(
			&session.local_window_size, &session.recv_window_size,
			&session.recv_reduction, &window_size_increment);
		if (rv != 0) {
			return rv;
		}
	} else {
		stream = http2_session_get_stream(session, stream_id);
		if (!stream) {
			return 0;
		}
		
		rv = http2_adjust_local_window_size(
			&stream.local_window_size, &stream.recv_window_size,
			&stream.recv_reduction, &window_size_increment);
		if (rv != 0) {
			return rv;
		}
	}
	
	if (window_size_increment > 0) {
		if (stream_id == 0) {
			session.consumed_size =
				http2_max(0, session.consumed_size - window_size_increment);
		} else {
			stream.consumed_size =
				http2_max(0, stream.consumed_size - window_size_increment);
		}
		
		return http2_session_add_window_update(session, flags, stream_id,
			window_size_increment);
	}
	return 0;
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
 * `http2_submit_goaway()`.  See also
 * `http2_session_get_last_proc_stream_id()`.
 *
 * Unlike `http2_submit_goaway()`, this function just sends GOAWAY
 * and does nothing more.  This is a mere indication to the client
 * that session shutdown is imminent.  The application should call
 * `http2_submit_goaway()` with appropriate last_stream_id after
 * this call.
 *
 * If one or more GOAWAY frame have been already sent by either
 * `http2_submit_goaway()` or `http2_session_terminate_session()`,
 * this function has no effect.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_STATE)
 *     The $(D Session) is initialized as client.
 */
ErrorCode http2_submit_shutdown_notice(Session session)
{
	if (!session.server) {
		return ErrorCode.INVALID_STATE;
	}
	if (session.goaway_flags) {
		return 0;
	}
	return http2_session_add_goaway(session, (1u << 31) - 1, FrameError.NO_ERROR, null, 0, GoAwayAuxFlags.SHUTDOWN_NOTICE);
}

private: 

ubyte set_response_flags(const http2_data_provider *data_prd) {
	ubyte flags = FrameFlags.NONE;
	if (!data_prd || !data_prd.read_callback) {
		flags |= FrameFlags.END_STREAM;
	}
	return flags;
}

ubyte set_request_flags(const http2_priority_spec *pri_spec,
	const http2_data_provider *data_prd) {
	ubyte flags = FrameFlags.NONE;
	if (!data_prd || !data_prd.read_callback) {
		flags |= FrameFlags.END_STREAM;
	}
	
	if (pri_spec) {
		flags |= FrameFlags.PRIORITY;
	}
	
	return flags;
}

/* This function takes ownership of |nva_copy|. Regardless of the
   return value, the caller must not free |nva_copy| after this
   function returns. */
int submit_headers_shared(Session session, FrameFlags flags, int stream_id, 
						  const ref PrioritySpec pri_spec, NVPair[] nva_copy,
						  in DataProvider data_prd, void *stream_user_data, ubyte attach_stream)
{
	int rv;
	ubyte flags_copy;
	OutboundItem item;
	Frame frame;
	HeadersCategory hcat;
		
	if (stream_id == 0) {
		rv = ErrorCode.INVALID_ARGUMENT;
		goto fail;
	}

	item = Mem.alloc!OutboundItem(session);

	if (data_prd != null && data_prd.read_callback != null) {
		item.aux_data.headers.data_prd = *data_prd;
	}
	
	item.aux_data.headers.stream_user_data = stream_user_data;
	item.aux_data.headers.attach_stream = attach_stream;
	
	flags_copy = (flags & (FrameFlags.END_STREAM | FrameFlags.PRIORITY)) | FrameFlags.END_HEADERS;
	
	if (stream_id == -1) {
		if (session.next_stream_id > int.max) {
			rv = ErrorCode.STREAM_ID_NOT_AVAILABLE;
			goto fail;
		}
		
		stream_id = session.next_stream_id;
		session.next_stream_id += 2;

		hcat = HeadersCategory.REQUEST;
	} else {
		/* More specific categorization will be done later. */
		hcat = HeadersCategory.HEADERS;
	}
	
	frame = &item.frame;
	
	http2_frame_headers_init(&frame.headers, flags_copy, stream_id, hcat, pri_spec, nva_copy, nvlen);
	
	rv = http2_session_add_item(session, item);
	
	if (rv != 0) {
		http2_frame_headers_free(&frame.headers, mem);
		goto fail2;
	}
	
	if (hcat == HeadersCategory.REQUEST) {
		return stream_id;
	}
	
	return 0;
	
fail:
	/* http2_frame_headers_init() takes ownership of nva_copy. */
	http2_nv_array_del(nva_copy, mem);
fail2:
	http2_mem_free(mem, item);
	
	return rv;
}

void adjust_priority_spec_weight(ref PrioritySpec pri_spec) {
	if (pri_spec.weight < MIN_WEIGHT) {
		pri_spec.weight = MIN_WEIGHT;
	} else if (pri_spec.weight > MAX_WEIGHT) {
		pri_spec.weight = MAX_WEIGHT;
	}
}

int submit_headers_shared_nva(Session session, FrameFlags flags, int stream_id, in PrioritySpec pri_spec,
							  in NVPair[] nva, in DataProvider data_prd, void *stream_user_data, ubyte attach_stream) {
	int rv;
	NVPair nva_copy;
	PrioritySpec copy_pri_spec;

	if (pri_spec) {
		copy_pri_spec = *pri_spec;
		adjust_priority_spec_weight(&copy_pri_spec);
	} else {
		http2_priority_spec_default_init(&copy_pri_spec);
	}

	rv = http2_nv_array_copy(&nva_copy, nva, nvlen, mem);
	if (rv < 0) {
		return rv;
	}
	
	return submit_headers_shared(session, flags, stream_id, &copy_pri_spec, nva_copy, nvlen, data_prd, stream_user_data, attach_stream);
}

/**
 * @function
 *
 * A helper function for dealing with NPN in client side or ALPN in
 * server side.  The |in| contains peer's protocol list in preferable
 * order.  The format of |in| is length-prefixed and not
 * null-terminated.  For example, `HTTP-draft-04/2.0` and
 * `http/1.1` stored in |in| like this::
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
 *    non-overlap case).  In this case, |out| and |outlen| are left
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
 *         rv = http2_select_next_protocol(out, outlen, in, inlen);
 *         if(rv == 1) {
 *             ((MyType*)arg).http2_selected = 1;
 *         }
 *         return SSL_TLSEXT_ERR_OK;
 *     }
 *     ...
 *     SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, my_obj);
 *
 */
int http2_select_next_protocol(ref char[] output, in char[] input);

/**
 * @function
 *
 * Returns a pointer to a http2_info struct with version information
 * about the run-time library in use.  The |least_version| argument
 * can be set to a 24 bit numerical value for the least accepted
 * version number and if the condition is not met, this function will
 * return a `null`.  Pass in 0 to skip the version checking.
 */
http2_info *http2_version(int least_version);


/**
 * @function
 *
 * Returns true if HTTP header field name |name| of length |len| is
 * valid according to http://tools.ietf.org/html/rfc7230#section-3.2
 *
 * Because this is a header field name in HTTP2, the upper cased alphabet
 * is treated as error.
 */
bool http2_check_header_name(const ubyte *name, size_t len);

/**
 * @function
 *
 * Returns true if HTTP header field value |value| of length |len|
 * is valid according to
 * http://tools.ietf.org/html/rfc7230#section-3.2
 */
bool http2_check_header_value(const ubyte *value, size_t len);

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
   * http2_session_consume() to indicate the amount of consumed
   * DATA.  By default, this option is set to zero.
   */
	NO_AUTO_WINDOW_UPDATE = 1,
	/**
   * This option sets the SETTINGS_MAX_CONCURRENT_STREAMS value of
   * remote endpoint as if it is received in SETTINGS frame. Without
   * specifying this option, before the local endpoint receives
   * SETTINGS_MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
   * endpoint, SETTINGS_MAX_CONCURRENT_STREAMS is unlimited. This may
   * cause problem if local endpoint submits lots of requests
   * initially and sending them at once to the remote peer may lead to
   * the rejection of some requests. Specifying this option to the
   * sensible value, say 100, may avoid this kind of issue. This value
   * will be overwritten if the local endpoint receives
   * SETTINGS_MAX_CONCURRENT_STREAMS from the remote endpoint.
   */
	PEER_MAX_CONCURRENT_STREAMS = 1 << 1,
	RECV_CLIENT_PREFACE = 1 << 2,
	NO_HTTP_MESSAGING = 1 << 3,
}

//http2_option
/// Struct to store option values for http2_session.
struct Options {
	/// Bitwise OR of http2_option_flag to determine which fields are specified.
	uint opt_set_mask;

	uint peer_max_concurrent_streams;

	bool no_auto_window_update;

	bool recv_client_preface;

	bool no_http_messaging;


	/**
	 * @function
	 *
	 * Initializes |*option_ptr| with default values.
	 *
	 * When the application finished using this object, it can use
	 * `http2_option_del()` to free its memory.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.NOMEM)
	 *     Out of memory.
	 */
	ErrorCode http2_option_new(http2_option **option_ptr);

	/**
	 * @function
	 *
	 * Frees any resources allocated for |option|.  If |option| is
	 * `null`, this function does nothing.
	 */
	void http2_option_del(http2_option *option);

	/**
	 * @function
	 *
	 * This option prevents the library from sending WINDOW_UPDATE for a
	 * connection automatically.  If this option is set to nonzero, the
	 * library won't send WINDOW_UPDATE for DATA until application calls
	 * `http2_session_consume()` to indicate the consumed amount of
	 * data.  Don't use `http2_submit_window_update()` for this purpose.
	 * By default, this option is set to zero.
	 */
	void http2_option_set_no_auto_window_update(http2_option *option, int val);

	/**
	 * @function
	 *
	 * This option sets the SETTINGS_MAX_CONCURRENT_STREAMS value of
	 * remote endpoint as if it is received in SETTINGS frame.  Without
	 * specifying this option, before the local endpoint receives
	 * SETTINGS_MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
	 * endpoint, SETTINGS_MAX_CONCURRENT_STREAMS is unlimited.  This may
	 * cause problem if local endpoint submits lots of requests initially
	 * and sending them at once to the remote peer may lead to the
	 * rejection of some requests.  Specifying this option to the sensible
	 * value, say 100, may avoid this kind of issue. This value will be
	 * overwritten if the local endpoint receives
	 * SETTINGS_MAX_CONCURRENT_STREAMS from the remote endpoint.
	 */
	void http2_option_set_peer_max_concurrent_streams(http2_option *option, uint val);

	/**
	 * @function
	 *
	 * By default, nghttp2 library only handles HTTP/2 frames and does not
	 * recognize first 24 bytes of client connection preface.  This design
	 * choice is done due to the fact that server may want to detect the
	 * application protocol based on first few bytes on clear text
	 * communication.  But for simple servers which only speak HTTP/2, it
	 * is easier for developers if nghttp2 library takes care of client
	 * connection preface.
	 *
	 * If this option is used with nonzero |val|, nghttp2 library checks
	 * first 24 bytes client connection preface.  If it is not a valid
	 * one, $(D Session.recv) and $(D Session.memRecv) will
	 * return error $(D ErrorCode.BAD_PREFACE), which is fatal error.
	 */
	void http2_option_set_recv_client_preface(http2_option *option, int val);

	/**
	 * @function
	 *
	 * By default, nghttp2 library enforces subset of HTTP Messaging rules
	 * described in `HTTP/2 specification, section 8
	 * <https://tools.ietf.org/html/draft-ietf-httpbis-http2-17#section-8>`_.
	 * See `HTTP Messaging`_ section for details.  For those applications
	 * who use nghttp2 library as non-HTTP use, give nonzero to |val| to
	 * disable this enforcement.
	 */
	void http2_option_set_no_http_messaging(http2_option *option, int val);

	void http2_option_set_no_auto_window_update(http2_option *option, int val) {
		option.opt_set_mask |= OptionFlags.NO_AUTO_WINDOW_UPDATE;
		option.no_auto_window_update = val;
	}

	void http2_option_set_peer_max_concurrent_streams(http2_option *option,
		uint val) {
		option.opt_set_mask |= OptionFlags.PEER_MAX_CONCURRENT_STREAMS;
		option.peer_max_concurrent_streams = val;
	}

	void http2_option_set_recv_client_preface(http2_option *option, int val) {
		option.opt_set_mask |= OptionFlags.RECV_CLIENT_PREFACE;
		option.recv_client_preface = val;
	}

	void http2_option_set_no_http_messaging(http2_option *option, int val) {
		option.opt_set_mask |= OptionFlags.NO_HTTP_MESSAGING;
		option.no_http_messaging = val;
	}

}