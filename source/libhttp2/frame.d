/**
 * Frame
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.frame;
import libhttp2.constants;
import libhttp2.types;
import libhttp2.stream;
import libhttp2.buffers;
import libhttp2.huffman;
import libhttp2.helpers;
import libhttp2.deflater;

struct FrameHeader 
{
	/// The length after this header
	uint length;
	FrameType type;
	FrameFlags flags;
	int stream_id;

	ubyte reserved = 0;

	this(uint _length, FrameType _type, FrameFlags _flags, int _stream_id) 
	{
		length = _length;
		type = _type;
		flags = _flags;
		stream_id = _stream_id;
	}

	// unpack buf into FrameHeader
	this(in ubyte* buf) {
		unpack(buf);
	}

	void unpack(in ubyte* buf) {
		length = read!uint(buf) >> 8;
		type = cast(FrameType) buf[3];
		flags = cast(FrameFlags) buf[4];
		stream_id = read!uint(&buf[5]) & STREAM_ID_MASK;
	}

	void unpack(in ubyte[] buf) {
		length = read!uint(buf) >> 8;
		type = cast(FrameType)buf[3];
		flags = cast(FrameFlags)buf[4];
		stream_id = read!uint(buf[5 .. $]) & STREAM_ID_MASK;
	}

	// pack FrameHeader into buf
	void pack(ubyte[] buf) {
		write!uint(buf, cast(uint)(length << 8));
		buf[3] = cast(ubyte) type;
		buf[4] = cast(ubyte) flags;
		write!uint(buf[5 .. $], cast(uint)stream_id);
		/* ignore hd.reserved for now */
	}

	/*
	 * Call this function after payload was serialized, but not before
	 * changing buf.pos and serializing frame header.
	 *
	 * This function assumes bufs.cur points to the last buf chain of the
	 * frame(s).
	 *
	 * This function serializes frame header for HEADERS/PUSH_PROMISE and
	 * handles their successive CONTINUATION frames.
	 *
	 * We don't process any padding here.
	 */
	void packShared(Buffers bufs) 
	{
		Buffer* buf;
		Buffers.Chain ci;
		Buffers.Chain ce;

		buf = &bufs.head.buf;
		length = buf.length;
		
		LOGF("send: HEADERS/PUSH_PROMISE, payloadlen=%zu\n", length);
		
		/* We have multiple frame buffers, which means one or more
	       CONTINUATION frame is involved. Remove END_HEADERS flag from the
	       first frame. */
		if (bufs.head != bufs.cur) {
			flags &= ~FrameFlags.END_HEADERS;
		}
		
		buf.pos -= FRAME_HDLEN;
		pack((*buf)[]);
		
		if (bufs.head != bufs.cur) {
			/* 2nd and later frames are CONTINUATION frames. */
			type = FrameType.CONTINUATION;
			/* We don't have no flags except for last CONTINUATION */
			flags = FrameFlags.NONE;
			
			ce = bufs.cur;
			
			for (ci = bufs.head.next; ci != ce; ci = ci.next) {
				buf = &ci.buf;
				
				length = buf.length;
				
				LOGF("send: int CONTINUATION, payloadlen=%zu\n", length);
				
				buf.pos -= FRAME_HDLEN;
				pack((*buf)[]);
			}
			
			buf = &ci.buf;
			length = buf.length;
			/* Set END_HEADERS flag for last CONTINUATION */
			flags = FrameFlags.END_HEADERS;
			
			LOGF("send: last CONTINUATION, payloadlen=%zu\n", length);
			
			buf.pos -= FRAME_HDLEN;
			pack((*buf)[]);
		}
	}


	void addPad(Buffers bufs, int padlen) 
	{
		Buffer* buf;
		
		if (padlen == 0) {
			LOGF("send: padlen = 0, nothing to do\n");
			
			return ;
		}
		
		/*
	   * We have arranged bufs like this:
	   *
	   *  0                   1                   2                   3
	   *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   * | |Frame header     | Frame payload...                          :
	   * +-+-----------------+-------------------------------------------+
	   * | |Frame header     | Frame payload...                          :
	   * +-+-----------------+-------------------------------------------+
	   * | |Frame header     | Frame payload...                          :
	   * +-+-----------------+-------------------------------------------+
	   *
	   * We arranged padding so that it is included in the first frame
	   * completely.  For padded frame, we are going to adjust buf.pos of
	   * frame which includes padding and serialize (memmove) frame header
	   * in the correct position.  Also extends buf.last to include
	   * padding.
	   */
		
		buf = &bufs.head.buf;
		
		assert(buf.available >= cast(size_t)(padlen - 1));
		
		frameSetPad(buf, padlen);
		
		length += padlen;
		flags |= FrameFlags.PADDED;
		
		LOGF("send: final payloadlen=%zu, padlen=%zu\n", length, padlen);
	}

	void free(){}
}

/// The HEADERS frame.  It has the following members:
struct Headers
{    
	FrameHeader hd;
	
	/// The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
	size_t padlen;
	
	/// The priority specification
	PrioritySpec pri_spec;
	
	/// The header fields.
	HeaderField[] hfa;
	
	/// The category of this HEADERS frame.
	HeadersCategory cat;

	/*
	 * Initializes HEADERS frame |frame| with given values.  |frame| takes
	 * ownership of |hfa|, so caller must not free it. If |stream_id| is
	 * not assigned yet, it must be -1.
	 */
	this(FrameFlags flags, int stream_id, HeadersCategory _cat, in PrioritySpec _pri_spec, HeaderField[] _hfa) {
		hd = FrameHeader(0, FrameType.HEADERS, flags, stream_id);
		padlen = 0;
		hfa = _hfa;
		cat = _cat;
		pri_spec = _pri_spec;
	}

	void free() {
		Mem.free(hfa);
	}

	/*
	 * Packs HEADERS frame in wire format and store it in |bufs|.
	 * This function expands |bufs| as necessary to store frame.
	 *
	 * The caller must make sure that bufs.reset() is called before calling this function.
	 *
	 * hd.length is assigned after length is determined during
	 * packing process. CONTINUATION frames are also serialized in this
	 * function. This function does not handle padding.
	 *
	 * This function returns 0 if it succeeds, or returns one of the
	 * following negative error codes:
	 *
	 * ErrorCode.HEADER_COMP
	 *     The deflate operation failed.
	 */
	ErrorCode pack(Buffers bufs, ref Deflater deflater) 
	{
		size_t hf_offset;
		ErrorCode rv;
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		hf_offset = blockOffset();
		
		buf = &bufs.cur.buf;
		
		buf.pos += hf_offset;
		buf.last = buf.pos;
		
		/* This call will adjust buf.last to the correct position */
		rv = deflater.deflate(bufs, hfa);
		
		if (rv == ErrorCode.BUFFER_ERROR)
			rv = ErrorCode.HEADER_COMP;

		buf.pos -= hf_offset;
		
		if (rv != 0)
			return rv;
		
		if (hd.flags & FrameFlags.PRIORITY) {
			pri_spec.unpack((*buf)[]);
		}
		
		padlen = 0;
		hd.length = bufs.length;
		
		hd.packShared(bufs);

		return ErrorCode.OK;
	}

	/*
	 * Unpacks HEADERS frame byte sequence into this.  This function
	 * only unpacks bytes that come before header field and
	 * after possible Pad Length field.
	 */
	void unpack(in ubyte[] payload) {
		if (hd.flags & FrameFlags.PRIORITY)
			pri_spec = PrioritySpec(payload);
	}

	/*
	 * Returns the offset from the HEADERS frame payload where the
	 * compressed header block starts. The frame payload does not include
	 * frame header.
	 */
	size_t blockOffset() {
		return hd.flags.priorityLength();
	}

}



/// The DATA frame.  The received data is delivered via http2_on_data_chunk_recv_callback
struct Data
{
	FrameHeader hd;
	/// The length of the padding in this frame. This includes PAD_HIGH and PAD_LOW.
	int padlen;

	this(FrameFlags flags, int stream_id) {
		/* At this moment, the length of DATA frame is unknown */
		hd = FrameHeader(0, FrameType.DATA, flags, stream_id);
		padlen = 0;
	}
	
	void free() {}

}


/// The structure to specify stream dependency.
struct PrioritySpec
{
	/// The stream ID of the stream to depend on. Specifying 0 makes stream not depend any other stream.
	int stream_id;
	int weight = DEFAULT_WEIGHT;
	bool exclusive;

	this(in ubyte[] data) {
		unpack(data);
	}

	/**
	 * Packs the PrioritySpec in |buf|.  This function assumes |buf| has
	 * enough space for serialization.
	 */
	void pack(ubyte[] buf) {
		write!uint(buf, stream_id);
		if (exclusive) 
			buf[0] |= 0x80;
		buf[4] = cast(ubyte)(weight - 1);
	}

	/**
	 * Unpacks the priority specification from payload |payload| of length
	 * |payload.length| to |pri_spec|. This function
	 * assumes the |payload| contains whole priority specification.
	 */
	void unpack(in ubyte[] payload) {
		stream_id = read!uint(payload) & STREAM_ID_MASK;
		exclusive = (payload[0] & 0x80) > 0;
		weight = payload[4] + 1;
	}
	
	/**
	 * Initializes PrioritySpec with the |stream_id| of the stream to depend
	 * on with |weight| and its exclusive flag.  If |exclusive| is
	 * true, exclusive flag is set.
	 *
	 * The |weight| must be in [$(D HTTP2_MIN_WEIGHT), $(D HTTP2_MAX_WEIGHT)], inclusive.
	 */
	this(int _stream_id, int _weight, bool _exclusive) {
		stream_id = _stream_id;
		weight = _weight;
		exclusive = _exclusive;
	}	

	void adjustWeight() {
		if (weight < MIN_WEIGHT) {
			weight = MIN_WEIGHT;
		} else if (weight > MAX_WEIGHT) {
			weight = MAX_WEIGHT;
		}
	}
}



/// The PRIORITY frame.  It has the following members:
struct Priority {
	FrameHeader hd;
	PrioritySpec pri_spec;

	this(int stream_id, in PrioritySpec _pri_spec = PrioritySpec.init) 
	{
		hd = FrameHeader(PRIORITY_SPECLEN, FrameType.PRIORITY, FrameFlags.NONE, stream_id);
		pri_spec = _pri_spec;
	}
	
	void free(){}

	/*
	 * Packs PRIORITY frame |frame| in wire format and store it in
	 * |bufs|.
	 *
	 * The caller must make sure that bufs.reset() is called
	 * before calling this function.
	 */
	void pack(Buffers bufs) {
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.head.buf;

		assert(buf.available >= PRIORITY_SPECLEN);
		
		buf.pos -= FRAME_HDLEN;
		
		hd.pack((*buf)[]);
		
		pri_spec.pack(buf.last[0 .. buf.available]);
		
		buf.last += PRIORITY_SPECLEN;
	}
	
	/*
	 * Unpacks PRIORITY wire format into this.
	 */
	void unpack(in ubyte[] payload) {
		pri_spec = PrioritySpec(payload);
	}

}

/// The RST_STREAM frame.  It has the following members:
struct RstStream {	
	FrameHeader hd;
	FrameError error_code;

	this(int stream_id, FrameError _error_code)
	{
		hd = FrameHeader(4, FrameType.RST_STREAM, FrameFlags.NONE, stream_id);
		error_code = _error_code;
	}
	
	void free(){}

	/*
	 * Packs RST_STREAM frame |frame| in wire frame format and store it in
	 * |bufs|.
	 *
	 * The caller must make sure that bufs.reset() is called
	 * before calling this function.
	 */
	void pack(Buffers bufs) 
	{
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.head.buf;
		
		assert(buf.available >= 4);
		
		buf.pos -= FRAME_HDLEN;
		
		hd.pack((*buf)[]);
		
		write!uint(buf.last, error_code);
		buf.last += 4;
	}
	
	/*
	 * Unpacks RST_STREAM frame byte sequence into |frame|.
	 */
	void unpack(in ubyte[] payload) {
		error_code = cast(FrameError)read!uint(payload);
	}
}

/// The SETTINGS frame
struct Settings {
	FrameHeader hd;
	Setting[] iva;

	/*
	 * Initializes SETTINGS frame |frame| with given values. |frame| takes
	 * ownership of |iv|, so caller must not free it. The |flags| are
	 * bitwise-OR of one or more of FrameFlags, the only permissible value is ACK.
	 */
	this(FrameFlags flags, Setting[] _iva) {
		// TODO: Allow only FrameFlags.ACK ?
		hd = FrameHeader(cast(uint)_iva.length * FRAME_SETTINGS_ENTRY_LENGTH, FrameType.SETTINGS, flags, 0);
		iva = _iva;
	}
	
	void free() { Mem.free(iva); }


	/*
	 * Packs SETTINGS frame in wire format and store it in |bufs|.
	 *
	 * The caller must make sure that bufs.reset() is called
	 * before calling this function.
	 *
	 * This function returns 0 if it succeeds, or returns one of the
	 * following negative error codes:
	 *
	 * ErrorCode.FRAME_SIZE_ERROR
	 *     The length of the frame is too large.
	 */
	ErrorCode pack(Buffers bufs) {
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.head.buf;
		
		if (buf.available < cast(size_t) hd.length) {
			return ErrorCode.FRAME_SIZE_ERROR;
		}

		buf.pos -= FRAME_HDLEN;
		
		hd.pack((*buf)[]);
		
		buf.last += pack(buf.last[0 .. buf.available], iva);
		
		return ErrorCode.OK;
	}

	
	/*
	 * Makes a copy of |_iva| in |iva|.
	 */
	void unpack(Setting[] _iva) 
	{
		if (iva) free();

		if (_iva.length == 0) {
			iva = null;
			return;
		}
		iva = Mem.alloc!(Setting[])(_iva.length);
		memcpy(iva.ptr, _iva.ptr, _iva.length * Setting.sizeof);
		
	}

	void unpack(in ubyte[] payload) {
		unpack(iva, payload);
	}

	/*
	 * Unpacks SETTINGS payload into |iva|. The number of entries are
	 * assigned to the |niv|. This function allocates enough memory
	 * to store the result in |iva|. The caller is responsible to free
	 * |iva| after its use.
	 */
	static void unpack(Setting[] iva, in ubyte[] payload) {
		size_t i;
		
		size_t len = payload.length / FRAME_SETTINGS_ENTRY_LENGTH;
		
		if (len == 0) {
			iva = null;
			return;
		}
		
		iva = Mem.alloc!(Setting[])(len);

		foreach(ref iv; iva) {
			size_t off = i * FRAME_SETTINGS_ENTRY_LENGTH;
			iv.unpack(&payload[off]);
		}
	}

	/*
	 * Packs the |_iva|, which includes |_iva.length| entries, in the |buf|,
	 * assuming the |buf| has at least 8 * |_iva.length| bytes.
	 *
	 * Returns the number of bytes written into the |buf|.
	 */
	static int pack(ubyte[] buf, in Setting[] _iva)
	{
		size_t i;
		for (i = 0; i < _iva.length; ++i, buf = buf[FRAME_SETTINGS_ENTRY_LENGTH .. $]) {
			write!ushort(buf, _iva[i].id);
			write!uint(buf[2 .. $], _iva[i].value);
		}
		return cast(int) (FRAME_SETTINGS_ENTRY_LENGTH * _iva.length);
	}

}

/// The PUSH_PROMISE frame.  
struct PushPromise {    
	FrameHeader hd;
	
	/// The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
	size_t padlen;
	
	/// The header fields.
	HeaderField[] hfa;
	
	/// The promised stream ID
	int promised_stream_id;
	
	/// 0
	ubyte reserved = 0;
	
	/*
	 * Initializes PUSH_PROMISE frame with given values.  PushPromise
	 * takes ownership of |hfa|, so caller must not free it.
	 */
	this(FrameFlags flags, int stream_id, int _promised_stream_id, HeaderField[] _hfa) {
		hd = FrameHeader(0, FrameType.PUSH_PROMISE, flags, stream_id);
		hfa = _hfa;
		promised_stream_id = _promised_stream_id;
	}
	
	void free() { Mem.free(hfa); }

	/*
	 * Packs PUSH_PROMISE frame in wire format and store it in
	 * |bufs|.  This function expands |bufs| as necessary to store
	 * frame.
	 *
	 * The caller must make sure that bufs.reset() is called
	 * before calling this function.
	 *
	 * frame.hd.length is assigned after length is determined during
	 * packing process. CONTINUATION frames are also serialized in this
	 * function. This function does not handle padding.
	 *
	 * This function returns 0 if it succeeds, or returns one of the
	 * following negative error codes:
	 *
	 * ErrorCode.HEADER_COMP
	 *     The deflate operation failed.
	 */
	ErrorCode pack(Buffers bufs, ref Deflater deflater) 
	{
		size_t hf_offset = 4;
		ErrorCode rv;
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.cur.buf;
		
		buf.pos += hf_offset;
		buf.last = buf.pos;
		
		/* This call will adjust buf.last to the correct position */
		rv = deflater.deflate(bufs, hfa);
		
		if (rv == ErrorCode.BUFFER_ERROR)
			rv = ErrorCode.HEADER_COMP;
		
		buf.pos -= hf_offset;
		
		if (rv != 0)
			return rv;
		
		write!uint(buf.pos, promised_stream_id);
		
		padlen = 0;
		hd.length = bufs.length;
		
		hd.packShared(bufs);
		return ErrorCode.OK;
	}
	
	/*
	 * Unpacks PUSH_PROMISE frame byte sequence.  This
	 * function only unpacks bytes that come before name/value header
	 * block and after possible Pad Length field.
	 *
	 * TODO: handle END_HEADERS flag is not set
	 */
	void unpack(in ubyte[] payload) {
		promised_stream_id = read!uint(payload) & STREAM_ID_MASK;
		hfa = null;
	}
}

/// The PING frame.
struct Ping {    
	FrameHeader hd;
	ubyte[8] opaque_data;

	/*
	 * Initializes PING frame with given values. If the
	 * |opaque_data| is not null, it must point to 8 bytes memory region
	 * of data. The data pointed by |opaque_data| is copied. It can be
	 * null. In this case, 8 bytes null is used.
	 */
	this(FrameFlags flags, in ubyte[] _opaque_data) {
		hd = FrameHeader(8, FrameType.PING, flags, 0);
		if (opaque_data.length > 0)
			opaque_data[0 .. min(8, _opaque_data.length)] = _opaque_data[0 .. min(8, _opaque_data.length)];
		else
			opaque_data = null;
	}
	
	void free(){}

	/*
	 * Packs PING frame in wire format and store it in |bufs|.
	 *
	 * The caller must make sure that bufs.reset() is called
	 * before calling this function.
	 */
	void pack(Buffers bufs) {
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.head.buf;
		
		assert(buf.available >= 8);
		
		buf.pos -= FRAME_HDLEN;
		
		hd.pack((*buf)[]);
		
		memcpy(buf.last, opaque_data.ptr, opaque_data.sizeof);

	}
	
	/*
	 * Unpacks PING wire format into |frame|.
	 */
	void unpack(in ubyte[] _opaque_data)
	{
		if (opaque_data.length > 0)
			opaque_data[0 .. min(8, _opaque_data.length)] = _opaque_data[0 .. min(8, _opaque_data.length)];
	}
}

/// The GOAWAY frame. 
struct GoAway {
	FrameHeader hd;
	int last_stream_id;
	FrameError error_code;
	/// The additional debug data
	string opaque_data;
	ubyte reserved = 0;

	/*
	 * Initializes GOAWAY frame with given values. On success, this function takes ownership
	 * of |opaque_data|, so caller must not free it. 
	 */
	this(int _last_stream_id, FrameError _error_code, string _opaque_data) {
		hd = FrameHeader(cast(uint)(8 + _opaque_data.length), FrameType.GOAWAY, FrameFlags.NONE, 0);
		last_stream_id = _last_stream_id;
		error_code = _error_code;
		opaque_data = _opaque_data;
	}

	void free() { Mem.free(opaque_data); }


	/*
	 * Packs GOAWAY frame in wire format and store it in |bufs|.
	 * This function expands |bufs| as necessary to store frame.
	 *
	 * The caller must make sure that bufs.reset() is called
	 * before calling this function.
	 *
	 * This function returns 0 if it succeeds or one of the following
	 * negative error codes:
	 *
	 * ErrorCode.FRAME_SIZE_ERROR
	 *     The length of the frame is too large.
	 */
	ErrorCode pack(Buffers bufs) 
	{
		ErrorCode rv;
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.head.buf;
		
		buf.pos -= FRAME_HDLEN;
		
		hd.pack((*buf)[]);
		
		write!uint(buf.last, last_stream_id);
		buf.last += 4;
		
		write!uint(buf.last, error_code);
		buf.last += 4;
		
		rv = bufs.add(cast(string)opaque_data);
		
		if (rv == ErrorCode.BUFFER_ERROR)
			return ErrorCode.FRAME_SIZE_ERROR;

		return rv;
	}
	
	/*
	 * Unpacks GOAWAY wire format.  The |payload| of length
	 * |payloadlen| contains first 8 bytes of payload.  The
	 * |var_gift_payload| contains the remaining payload and its 
	 * buffer is gifted to the function and then
	 * |frame|.  The |var_gift_payload| must be freed by GoAway.free().
	 */
	void unpack(in ubyte[] payload, ubyte[] var_gift_payload)
	{
		last_stream_id = read!uint(payload) & STREAM_ID_MASK;
		error_code = cast(FrameError) read!uint(payload[4 .. $]);
		opaque_data = cast(string)var_gift_payload;
	}
		
	/*
	 * Unpacks GOAWAY wire format.  This function only exists
	 * for unit test.  After allocating buffer for debug data, this
	 * function internally calls http2_frame_unpack_goaway_payload().
	 */
	void unpack(in ubyte[] payload) 
	{
		ubyte[] var_gift_payload;
		size_t var_gift_payloadlen;
		size_t payloadlen = payload.length;
		
		if (payloadlen > 8) {
			var_gift_payloadlen = payloadlen - 8;
		} else {
			var_gift_payloadlen = 0;
		}

		if (!var_gift_payloadlen) {
			var_gift_payload = null;
		} else {
			var_gift_payload = Mem.alloc!(ubyte[])(var_gift_payloadlen);						
			memcpy(var_gift_payload.ptr, payload.ptr + 8, var_gift_payloadlen);
		}
		
		unpack(payload,	var_gift_payload);
	}

}

/// The WINDOW_UPDATE frame.
struct WindowUpdate {    
	FrameHeader hd;	
	int window_size_increment;	
	ubyte reserved = 0;

	this(FrameFlags flags, int stream_id,  int _window_size_increment)
	{
		hd = FrameHeader(4, FrameType.WINDOW_UPDATE, flags, stream_id);
		window_size_increment = _window_size_increment;
	}
	
	void free(){}

	/*
	 * Packs WINDOW_UPDATE frame in wire frame format and store it
	 * in |bufs|.
	 *
	 * The caller must make sure that bufs.reset() is called
	 * before calling this function.
	 */
	void pack(Buffers bufs) {
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		buf = &bufs.head.buf;
		
		assert(buf.available >= 4);
		
		buf.pos -= FRAME_HDLEN;
		
		hd.pack((*buf)[]);
		
		write!uint(buf.last, window_size_increment);
		buf.last += 4;
	}
	
	/*
	 * Unpacks WINDOW_UPDATE frame byte sequence.
	 */
	void unpack(in ubyte[] payload) {
		window_size_increment = read!uint(payload) & WINDOW_SIZE_INCREMENT_MASK;
	}

}


/*
 * This union includes all frames to pass them to various function
 * calls as http2_frame type.  The CONTINUATION frame is omitted
 * from here because the library deals with it internally.
 */
union Frame
{
	FrameHeader hd;
	Data data;
	Headers headers;
	Priority priority;
	RstStream rst_stream;
	Settings settings;
	PushPromise push_promise;
	Ping ping;
	GoAway goaway;
	WindowUpdate window_update;

	/*
	 * Returns the number of padding bytes after payload.  The total
	 * padding length is given in the |padlen|.  The returned value does
	 * not include the Pad Length field.
	 */
	size_t trailPadlen(size_t padlen)
	{
		return padlen - ((hd.flags & FrameFlags.PADDED) > 0);
	}

	void unpack(in ubyte[] input)
	{
		const(ubyte)[] payload = input[FRAME_HDLEN .. $];
		size_t payloadoff;

		hd.unpack(input);

		with (FrameType) final switch (hd.type) {
			case HEADERS:
				payloadoff = cast(size_t) ((hd.flags & FrameFlags.PADDED) > 0);
				headers.unpack(payload[payloadoff .. $]);
				break;
			case PRIORITY:
				priority.unpack(payload);
				break;
			case RST_STREAM:
				rst_stream.unpack(payload);
				break;
			case SETTINGS:
				settings.unpack(payload);
				break;
			case PUSH_PROMISE:
				push_promise.unpack(payload);
				break;
			case PING:
				ping.unpack(payload);
				break;
			case GOAWAY:
				goaway.unpack(payload);
				break;
			case WINDOW_UPDATE:
				window_update.unpack(payload);
				break;
			case DATA:
			case CONTINUATION:
				break;

		}
	}

	void unpack(Buffers bufs) {
		Buffer *buf;
		
		/* Assuming we have required data in first buffer. We don't decode
		   header block so, we don't mind its space */
		buf = &bufs.head.buf;
		unpack((*buf)[]);
	}
}

/// struct used for HEADERS and PUSH_PROMISE frame
struct HeadersAuxData {
	DataProvider data_prd;
	void *stream_user_data;
	
	/// error code when request HEADERS is canceled by RST_STREAM while it is in queue. 
	FrameError error_code;
	
	/// nonzero if request HEADERS is canceled.  The error code is stored in |error_code|.
	bool canceled;
	
	/// nonzero if this item should be attached to stream object to make it under priority control
	bool attach_stream;
}

/// struct used for DATA frame
struct DataAuxData {
	/// The data to be sent for this DATA frame.
	DataProvider data_prd;
	
	/**
    * The flags of DATA frame.  We use separate flags here and
    * http2_data frame.  The latter contains flags actually sent to
    * peer.  This |flags| may contain END_STREAM and only
    * when |eof| becomes nonzero, flags in http2_data has
    * END_STREAM set.
    */
	DataFlags flags;

	/// The flag to indicate whether EOF was reached or not. Initially |eof| is 0. It becomes 1 after all data were read.
	bool eof;
}

enum GoAwayAuxFlags {
	NONE = 0x0,
	/// indicates that session should be terminated after the transmission of this frame.
	TERM_ON_SEND = 0x1,
	/// indicates that this GOAWAY is just a notification for graceful shutdown.  
	/// No http2_session.goaway_flags should be updated on the reaction to this frame.
	SHUTDOWN_NOTICE = 0x2,
}

/// struct used for GOAWAY frame
struct GoAwayAuxData {
	GoAwayAuxFlags flags;
}

/// Additional data which cannot be stored in Frame struct
union AuxData {
	DataAuxData data;
	HeadersAuxData headers;
	GoAwayAuxData goaway;
}

class OutboundItem {
	import libhttp2.session : Session;
	Frame frame;
	AuxData aux_data;
	long seq;
	
	/// Reset count of weight. See comment for last_cycle
	ulong cycle;
	
	/// The priority used in priority comparion.  Larger is served ealier.
	int weight = OB_EX_WEIGHT;
	
	/// true if this object is queued.
	bool queued;

	this() { }

	this(Session session) {
		seq = session.next_seq++;
	}

	void free() {

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
	}

}

int bytes_compar(const ubyte* a, size_t alen, const ubyte* b, size_t blen) {
	import std.c.string : memcmp;
	int rv;
	
	if (alen == blen) {
		return memcmp(a, b, alen);
	}
	
	if (alen < blen) {
		rv = memcmp(a, b, alen);
		
		if (rv == 0) {
			return -1;
		}
		
		return rv;
	}
	
	rv = memcmp(a, b, blen);
	
	if (rv == 0) {
		return 1;
	}
	
	return rv;
}

// true if everything is fine, false otherwise
bool check(in Setting[] iva) 
{
	foreach (entry; iva) {
		with(Setting) switch (entry.id) {
			case HEADER_TABLE_SIZE:
				if (entry.value > MAX_HEADER_TABLE_SIZE) {
					return true;
				}
				break;
			case MAX_CONCURRENT_STREAMS:
				break;
			case ENABLE_PUSH:
				if (entry.value != 0 && entry.value != 1) {
					return true;
				}
				break;
			case INITIAL_WINDOW_SIZE:
				if (entry.value > cast(uint)MAX_WINDOW_SIZE) {
					return true;
				}
				break;
			case MAX_FRAME_SIZE:
				if (entry.value < MAX_FRAME_SIZE_MIN ||
					entry.value > MAX_FRAME_SIZE_MAX) {
					return true;
				}
				break;
			case MAX_HEADER_LIST_SIZE:
				break;
			default:
				break;
		}
	}
	return false;
}

void frameSetPad(Buffer* buf, int padlen) 
{
	import std.c.string : memmove, memset;
	int trail_padlen;
	int newlen;
	
	LOGF("send: padlen=%zu, shift left 1 bytes\n", padlen);
	
	memmove(buf.pos - 1, buf.pos, FRAME_HDLEN);
	
	--buf.pos;
	
	buf.pos[4] |= FrameFlags.PADDED;
	
	newlen = (read!uint(buf.pos) >> 8) + padlen;
	write!uint(buf.pos, cast(uint)((newlen << 8) + buf.pos[3]));
	
	trail_padlen = padlen - 1;
	buf.pos[FRAME_HDLEN] = cast(ubyte) trail_padlen;
	
	/* zero out padding */
	memset(buf.last, 0, trail_padlen);
	/* extend buffers trail_padlen bytes, since we ate previous padlen -
     trail_padlen byte(s) */
	buf.last += trail_padlen;
}

/**
 * Returns the number of priority field depending on the |flags|.  If
 * |flags| has neither NGFLAG_PRIORITY_GROUP nor
 * NGFLAG_PRIORITY_DEPENDENCY set, return 0.
 */
size_t priorityLength(FrameFlags flags) {
	if (flags & FrameFlags.PRIORITY) {
		return PRIORITY_SPECLEN;
	}
	
	return 0;
}
