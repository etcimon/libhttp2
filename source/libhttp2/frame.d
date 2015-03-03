/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
module libhttp2.frame;
import libhttp2.constants;
import libhttp2.types;
import libhttp2.stream;
import libhttp2.buffers;
import libhttp2.huffman_decoder;

const STREAM_ID_MASK = ((1 << 31) - 1);
const PRI_GROUP_ID_MASK = ((1 << 31) - 1);
const PRIORITY_MASK = ((1 << 31) - 1);
const WINDOW_SIZE_INCREMENT_MASK = ((1 << 31) - 1);
const SETTINGS_ID_MASK = ((1 << 24) - 1);

/* The number of bytes of frame header. */
const FRAME_HDLEN = 9;

const MAX_FRAME_SIZE_MAX = ((1 << 24) - 1);
const MAX_FRAME_SIZE_MIN = (1 << 14);

const MAX_PAYLOADLEN = 16384;

/* The one frame buffer length for tranmission.  We may use several of
   them to support CONTINUATION.  To account for Pad Length field, we
   allocate extra 1 byte, which saves extra large memcopying. */
const FRAMEBUF_CHUNKLEN = (FRAME_HDLEN + 1 + MAX_PAYLOADLEN);

/// Number of inbound buffer
const FRAMEBUF_MAX_NUM = 5;

/// The default length of DATA frame payload.
const DATA_PAYLOADLEN = MAX_FRAME_SIZE_MIN;

/// Maximum headers payload length, calculated in compressed form.
/// This applies to transmission only.
const MAX_HEADERSLEN = 65536;

/// The number of bytes for each SETTINGS entry
const FRAME_SETTINGS_ENTRY_LENGTH = 6;

/// The maximum header table size in $(D Setting.HEADER_TABLE_SIZE)
const MAX_HEADER_TABLE_SIZE = ((1u << 31) - 1);

/// Length of priority related fields in HEADERS/PRIORITY frames
const PRIORITY_SPECLEN = 5;

/// Maximum length of padding in bytes.
const MAX_PADLEN = 256;

/// A bit higher weight for non-DATA frames
const OB_EX_WEIGHT = 300;

/// Higher weight for SETTINGS
const OB_SETTINGS_WEIGHT = 301;

/// Highest weight for PING
const OB_PING_WEIGHT = 302;

//http2_frame_hd
struct FrameHeader 
{
	/// The length after this header
	uint length;
	FrameType type;
	FrameFlags flags;
	int stream_id;
	/// 0
	ubyte reserved;

	// unpack buf into FrameHeader
	this(in ubyte* buf) {
		length = read!uint(buf) >> 8;
		type = FrameType(buf[3]);
		flags = FrameFlags(buf[4]);
		stream_id = read!uint(&buf[5]) & STREAM_ID_MASK;
	}

	// pack FrameHeader into buf
	void pack(out ubyte* buf) {
		write!uint(buf, cast(uint)(length << 8));
		buf[3] = cast(ubyte) type;
		buf[4] = cast(ubyte) flags;
		write!uint(buf[5 .. $], hd.stream_id);
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
	int packShared(Buffers bufs) 
	{
		Buffer* buf;
		Chain ci;
		Chain ce;

		buf = &bufs.head.buf;
		length = buf.length;
		
		DEBUGF(fprintf(stderr, "send: HEADERS/PUSH_PROMISE, payloadlen=%zu\n", length));
		
		/* We have multiple frame buffers, which means one or more
	       CONTINUATION frame is involved. Remove END_HEADERS flag from the
	       first frame. */
		if (bufs.head != bufs.cur) {
			flags &= ~FrameFlags.END_HEADERS;
		}
		
		buf.pos -= FRAME_HDLEN;
		pack(buf.pos);
		
		if (bufs.head != bufs.cur) {
			/* 2nd and later frames are CONTINUATION frames. */
			type = FrameType.CONTINUATION;
			/* We don't have no flags except for last CONTINUATION */
			flags = FrameFlags.NONE;
			
			ce = bufs.cur;
			
			for (ci = bufs.head.next; ci != ce; ci = ci.next) {
				buf = &ci.buf;
				
				length = http2_buf_len(buf);
				
				DEBUGF(fprintf(stderr, "send: int CONTINUATION, payloadlen=%zu\n", length));
				
				buf.pos -= FRAME_HDLEN;
				pack(buf.pos);
			}
			
			buf = &ci.buf;
			length = http2_buf_len(buf);
			/* Set END_HEADERS flag for last CONTINUATION */
			flags = FrameFlags.END_HEADERS;
			
			DEBUGF(fprintf(stderr, "send: last CONTINUATION, payloadlen=%zu\n", length));
			
			buf.pos -= FRAME_HDLEN;
			pack(buf.pos);
		}
		
		return 0;
	}

	void free(){}
}

// http2_headers
/// The HEADERS frame.  It has the following members:
struct Headers
{    
	FrameHeader hd;
	
	/// The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
	size_t padlen;
	
	/// The priority specification
	PrioritySpec pri_spec;
	
	/// The name/value pairs.
	NVPair[] nva;
	
	/// The category of this HEADERS frame.
	HeadersCategory cat;

	/*
	 * Initializes HEADERS frame |frame| with given values.  |frame| takes
	 * ownership of |nva|, so caller must not free it. If |stream_id| is
	 * not assigned yet, it must be -1.
	 */
	this(FrameFlags flags, int stream_id, HeadersCategory _cat, in PrioritySpec _pri_spec, NVPair[] _nva) {
		hd = FrameHeader(0, FrameType.HEADERS, flags, stream_id);
		padlen = 0;
		nva = _nva;
		cat = _cat;
		
		if (pri_spec) {
			pri_spec = _pri_spec;
		} else {
			http2_priority_spec_default_init(&frame.pri_spec);
		}
	}

	void free() {
		Mem.free(nva);
	}

	/*
	 * Packs HEADERS frame |frame| in wire format and store it in |bufs|.
	 * This function expands |bufs| as necessary to store frame.
	 *
	 * The caller must make sure that bufs.reset() is called before calling this function.
	 *
	 * frame.hd.length is assigned after length is determined during
	 * packing process.  CONTINUATION frames are also serialized in this
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
		size_t nv_offset;
		int rv;
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		nv_offset = blockOffset(frame);
		
		buf = &bufs.cur.buf;
		
		buf.pos += nv_offset;
		buf.last = buf.pos;
		
		/* This call will adjust buf.last to the correct position */
		rv = deflater.deflateBufs(bufs, frame.nva);
		
		if (rv == ErrorCode.BUFFER_ERROR) {
			rv = ErrorCode.HEADER_COMP;
		}
		
		buf.pos -= nv_offset;
		
		if (rv != 0) {
			return rv;
		}
		
		if (frame.hd.flags & FrameFlags.PRIORITY) {
			http2_frame_pack_priority_spec(buf.pos, &frame.pri_spec);
		}
		
		frame.padlen = 0;
		frame.hd.length = http2_bufs_len(bufs);
		
		return frame.hd.packShared(bufs);
	}

	/*
	 * Unpacks HEADERS frame byte sequence into this.  This function
	 * only unpacks bytes that come before name/value header block and
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
	size_t blockOffset(ref Headers frame) {
		return frame.hd.flags.priorityLength();
	}

}



// http2_data
/// The DATA frame.  The received data is delivered via http2_on_data_chunk_recv_callback
struct Data
{
	FrameHeader hd;
	/// The length of the padding in this frame. This includes PAD_HIGH and PAD_LOW.
	size_t padlen;

	this(FrameFlags flags, int stream_id) {
		/* At this moment, the length of DATA frame is unknown */
		hd = FrameHeader(0, FrameType.DATA, flags, stream_id);
		padlen = 0;
	}
	
	void free() {}

}


//http2_priority_spec
/// The structure to specify stream dependency.
struct PrioritySpec
{
	/// The stream ID of the stream to depend on. Specifying 0 makes stream not depend any other stream.
	int parent;
	int weight = DEFAULT_WEIGHT;
	bool exclusive;
	
	/**
	 * Packs the PrioritySpec in |buf|.  This function assumes |buf| has
	 * enough space for serialization.
	 */
	void pack(out ubyte* buf) {
		write!uint(buf, pri_spec.stream_id);
		if (exclusive) 
			buf[0] |= 0x80;
		buf[4] = weight - 1;
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
		exclusive = _exclusive != 0;
	}
	

}



//http2_priority
/// The PRIORITY frame.  It has the following members:
struct Priority {
	FrameHeader hd;
	PrioritySpec pri_spec;

	this(int stream_id, in PrioritySpec _pri_spec) 
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
		
		hd.pack(buf.pos);
		
		pri_spec.pack(buf.last);
		
		buf.last += PRIORITY_SPECLEN;
	}
	
	/*
	 * Unpacks PRIORITY wire format into this.
	 */
	void unpack(in ubyte[] payload) {
		pri_spec = PrioritySpec(payload);
	}

}

//http2_rst_stream
/// The RST_STREAM frame.  It has the following members:
struct Reset {	
	FrameHeader hd;
	FrameError error_code;

	this(int stream_id, FrameError _error_code)
	{
		hd = FrameHeader(4, FrameType.RST_STREAM, FrameFlags.NONE, stream_id);
		error_code = _error_code;
	}
	
	void free(){}
}


//http2_settings_entry
struct Setting {
	alias SettingCode = ubyte;
	/// Notes: If we add SETTINGS, update the capacity of HTTP2_INBOUND_NUM_IV as well
	enum : SettingCode {
		HEADER_TABLE_SIZE = 0x01,
		ENABLE_PUSH = 0x02,
		MAX_CONCURRENT_STREAMS = 0x03,
		INITIAL_WINDOW_SIZE = 0x04,
		MAX_FRAME_SIZE = 0x05,
		MAX_HEADER_LIST_SIZE = 0x06
	}

	/// The SETTINGS ID.
	SettingCode id;
	uint value;
}

/// The SETTINGS frame
struct Settings {
	FrameHeader hd;
	Setting[] settings;

	/*
	 * Initializes SETTINGS frame |frame| with given values. |frame| takes
	 * ownership of |iv|, so caller must not free it. The |flags| are
	 * bitwise-OR of one or more of FrameFlags, the only permissible value is ACK.
	 */
	this(FrameFlags flags, Setting[] _iv) {
		// TODO: Allow only FrameFlags.ACK ?
		hd = FrameHeader(iv.length * FRAME_SETTINGS_ENTRY_LENGTH, FrameType.SETTINGS, flags, 0);
		iv = _iv;
	}
	
	void free() { Mem.free(iv); }
}

//http2_push_promise
/// The PUSH_PROMISE frame.  
struct PushPromise {    
	FrameHeader hd;
	
	/// The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
	size_t padlen;
	
	/// The name/value pairs.
	NVPair[] nva;
	
	/// The promised stream ID
	int promised_stream_id;
	
	/// 0
	ubyte reserved;
	
	/*
	 * Initializes PUSH_PROMISE frame with given values.  PushPromise
	 * takes ownership of |nva|, so caller must not free it.
	 */
	this(FrameFlags flags, int stream_id, int _promised_stream_id, NVPair[] _nva) {
		hd = FrameHeader(0, FrameType.PUSH_PROMISE, flags, stream_id);
		nva = _nva;
		promised_stream_id = _promised_stream_id;
	}
	
	void free() { Mem.free(nva); }
}

// http2_ping
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
			opaque_data[0 .. _opaque_data.length] = _opaque_data[0 .. $];
	}
	
	void free(){}

}

//http2_goaway
/// The GOAWAY frame. 
struct GoAway {
	FrameHeader hd;
	int last_stream_id;
	FrameError error_code;
	/// The additional debug data
	ubyte[] opaque_data;
	ubyte reserved = 0;

	/*
	 * Initializes GOAWAY frame with given values. On success, this function takes ownership
	 * of |opaque_data|, so caller must not free it. 
	 */
	this(int _last_stream_id, FrameError _error_code, ubyte[] _opaque_data) {
		hd = FrameHeader(8 + _opaque_data.length, FrameType.GOAWAY, FrameFlags.NONE, 0);
		last_stream_id = _last_stream_id;
		error_code = _error_code;
		opaque_data = _opaque_data;
	}

	void free() { Mem.free(opaque_data); }

}

//http2_window_update
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
}

//http2_extension
/// The extension frame.
struct Extension {    
	FrameHeader hd;
	
	/**
   * The pointer to extension payload.  The exact pointer type is
   * determined by hd.type.
   *
   * If hd.type == ALTSVC it is a pointer to http2_ext_altsvc
   */
	void *payload;
}

// http2_ext_altsvc
/// The ALTSVC extension frame payload.  It has following members:
struct ExtALTSVC {
	ubyte[] protocol_id;
	ubyte[] host;
	ubyte[] origin;
	uint max_age;
	ushort port;
}

//http2_frame
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
	Reset rst_stream;
	Settings settings;
	PushPromise push_promise;
	Ping ping;
	GoAway goaway;
	WindowUpdate window_update;
	Extension ext;

	/*
	 * Returns the number of padding bytes after payload.  The total
	 * padding length is given in the |padlen|.  The returned value does
	 * not include the Pad Length field.
	 */
	size_t trailPadlen(size_t padlen)
	{
		return padlen - ((hd.flags & FrameFlags.PADDED) > 0);
	}

}


//http2_ext_frame_payload
/// Union of extension frame payload
union ExtFramePayload 
{ 
	ExtALTSVC altsvc; 
}

//http2_headers_aux_data
/// struct used for HEADERS and PUSH_PROMISE frame
struct HeadersAuxData {
	DataProvider data_prd;
	void *stream_user_data;
	
	/// error code when request HEADERS is canceled by RST_STREAM while it is in queue. 
	FrameError error_code;
	
	/// nonzero if request HEADERS is canceled.  The error code is stored in |error_code|.
	ubyte canceled;
	
	/// nonzero if this item should be attached to stream object to make it under priority control
	ubyte attach_stream;
}

//http2_data_aux_data
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
	ubyte eof;
}

enum GoAwayAuxFlags {
	NONE = 0x0,
	/// indicates that session should be terminated after the transmission of this frame.
	ON_SEND = 0x1,
	/// indicates that this GOAWAY is just a notification for graceful shutdown.  
	/// No http2_session.goaway_flags should be updated on the reaction to this frame.
	SHUTDOWN_NOTICE = 0x2,
}

// http2_goaway_aux_data
/// struct used for GOAWAY frame
struct GoAwayAuxData {
	GoAwayAuxFlags flags;
}

//http2_aux_data
/// Additional data which cannot be stored in Frame struct
union AuxData {
	DataAuxData data;
	HeadersAuxData headers;
	GoAwayAuxData goaway;
}

//http2_outbound_item
class OutboundItem {
	Frame frame;
	AuxData aux_data;
	long seq;
	
	/// Reset count of weight. See comment for last_cycle
	ulong cycle;
	
	/// The priority used in priority comparion.  Larger is served ealier.
	int weight;
	
	/// true if this object is queued.
	bool queued;
}


/*
 * Packs RST_STREAM frame |frame| in wire frame format and store it in
 * |bufs|.
 *
 * The caller must make sure that nghttp2_bufs_reset(bufs) is called
 * before calling this function.
 *
 * This function always succeeds and returns 0.
 */
int http2_frame_pack_rst_stream(Buffers bufs,
	ref Reset frame) {
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	assert(http2_buf_avail(buf) >= 4);
	
	buf.pos -= FRAME_HDLEN;
	
	frame.hd.pack(buf.pos);
	
	write!uint(buf.last, frame.error_code);
	buf.last += 4;
	
	return 0;
}

/*
 * Unpacks RST_STREAM frame byte sequence into |frame|.
 */
void http2_frame_unpack_rst_stream_payload(ref Reset frame,
	const ubyte* payload,
	size_t payloadlen) {
	frame.error_code = read!uint(payload);
}

/*
 * Packs SETTINGS frame |frame| in wire format and store it in
 * |bufs|.
 *
 * The caller must make sure that nghttp2_bufs_reset(bufs) is called
 * before calling this function.
 *
 * This function returns 0 if it succeeds, or returns one of the
 * following negative error codes:
 *
 * ErrorCode.FRAME_SIZE_ERROR
 *     The length of the frame is too large.
 */
ErrorCode http2_frame_pack_settings(Buffers bufs, http2_settings *frame) {
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	if (http2_buf_avail(buf) < cast(size_t)frame.hd.length) {
		return ErrorCode.FRAME_SIZE_ERROR;
	}
	
	buf.pos -= FRAME_HDLEN;
	
	frame.hd.pack(buf.pos);
	
	buf.last +=
		http2_frame_pack_settings_payload(buf.last, frame.iv, frame.niv);
	
	return 0;
}

/*
 * Packs the |iv|, which includes |niv| entries, in the |buf|,
 * assuming the |buf| has at least 8 * |niv| bytes.
 *
 * Returns the number of bytes written into the |buf|.
 */
size_t http2_frame_pack_settings_payload(ubyte* buf, in Setting[] iv)
{
	size_t i;
	for (i = 0; i < niv; ++i, buf += FRAME_SETTINGS_ENTRY_LENGTH) {
		write!ushort(buf, iv[i].settings_id);
		write!uint(buf + 2, iv[i].value);
	}
	return FRAME_SETTINGS_ENTRY_LENGTH * niv;
}

/*
 * Makes a copy of |iv| in frame.settings.iv. The |niv| is assigned
 * to frame.settings.niv.
 *
 */
void http2_frame_unpack_settings_payload(http2_settings *frame, Setting[] iv) 
{
	size_t payloadlen = niv * sizeof(http2_settings_entry);
	
	if (niv == 0) {
		frame.iv = null;
	} else {
		frame.iv = http2_mem_malloc(mem, payloadlen);
		
		if (frame.iv == null) {
			return ErrorCode.NOMEM;
		}
		
		memcpy(frame.iv, iv, payloadlen);
	}
	
	frame.niv = niv;
	return 0;
}

void http2_frame_unpack_settings_entry(ref Setting iv, const ubyte* payload) {
	iv.settings_id = read!ushort(payload);
	iv-value = read!uint(&payload[2]);
}

/*
 * Unpacks SETTINGS payload into |*iv_ptr|. The number of entries are
 * assigned to the |*niv_ptr|. This function allocates enough memory
 * to store the result in |*iv_ptr|. The caller is responsible to free
 * |*iv_ptr| after its use.
 */
void http2_frame_unpack_settings_payload2(ref Setting[] iv, in ubyte[] payload) {
	size_t i;
	
	*niv_ptr = payload.length / FRAME_SETTINGS_ENTRY_LENGTH;
	
	if (*niv_ptr == 0) {
		*iv = null;
		
		return 0;
	}
	
	*iv_ptr =
		http2_mem_malloc(mem, (*niv_ptr) * sizeof(http2_settings_entry));
	
	if (*iv_ptr == null) {
		return ErrorCode.NOMEM;
	}
	
	for (i = 0; i < *niv_ptr; ++i) {
		size_t off = i * FRAME_SETTINGS_ENTRY_LENGTH;
		http2_frame_unpack_settings_entry(&(*iv_ptr)[i], &payload[off]);
	}
	
	return 0;
}

/*
 * Packs PUSH_PROMISE frame |frame| in wire format and store it in
 * |bufs|.  This function expands |bufs| as necessary to store
 * frame.
 *
 * The caller must make sure that nghttp2_bufs_reset(bufs) is called
 * before calling this function.
 *
 * frame.hd.length is assigned after length is determined during
 * packing process.  CONTINUATION frames are also serialized in this
 * function. This function does not handle padding.
 *
 * This function returns 0 if it succeeds, or returns one of the
 * following negative error codes:
 *
 * ErrorCode.HEADER_COMP
 *     The deflate operation failed.
 */
ErrorCode http2_frame_pack_push_promise(Buffers bufs, ref PushPromise frame, ref HuffmanDeflater deflater) 
{
	size_t nv_offset = 4;
	int rv;
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.cur.buf;
	
	buf.pos += nv_offset;
	buf.last = buf.pos;
	
	/* This call will adjust buf.last to the correct position */
	rv = http2_hd_deflate_hd_bufs(deflater, bufs, frame.nva);
	
	if (rv == ErrorCode.BUFFER_ERROR) {
		rv = ErrorCode.HEADER_COMP;
	}
	
	buf.pos -= nv_offset;
	
	if (rv != 0) {
		return rv;
	}
	
	write!uint(buf.pos, frame.promised_stream_id);
	
	frame.padlen = 0;
	frame.hd.length = http2_bufs_len(bufs);
	
	return frame.hd.packShared(bufs);
}

/*
 * Unpacks PUSH_PROMISE frame byte sequence into |frame|.  This
 * function only unapcks bytes that come before name/value header
 * block and after possible Pad Length field.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * ErrorCode.PROTO
 *     TODO END_HEADERS flag is not set
 */
int http2_frame_unpack_push_promise_payload(ref PushPromise frame, in ubyte[] payload) {
	frame.promised_stream_id = read!uint(payload) & STREAM_ID_MASK;
	frame.nva = null;
	return 0;
}

/*
 * Packs PING frame |frame| in wire format and store it in
 * |bufs|.
 *
 * The caller must make sure that nghttp2_bufs_reset(bufs) is called
 * before calling this function.
 *
 * This function always succeeds and returns 0.
 */
int http2_frame_pack_ping(Buffers bufs, http2_ping *frame) {
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	assert(http2_buf_avail(buf) >= 8);
	
	buf.pos -= FRAME_HDLEN;
	
	frame.hd.pack(buf.pos);
	
	buf.last =
		http2_cpymem(buf.last, frame.opaque_data, sizeof(frame.opaque_data));
	
	return 0;
}

/*
 * Unpacks PING wire format into |frame|.
 */
void http2_frame_unpack_ping_payload(http2_ping *frame,
	const ubyte* payload,
	size_t payloadlen) {
	memcpy(frame.opaque_data, payload, sizeof(frame.opaque_data));
}

/*
 * Packs GOAWAY frame |frame| in wire format and store it in |bufs|.
 * This function expands |bufs| as necessary to store frame.
 *
 * The caller must make sure that nghttp2_bufs_reset(bufs) is called
 * before calling this function.
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * ErrorCode.FRAME_SIZE_ERROR
 *     The length of the frame is too large.
 */
ErrorCode http2_frame_pack_goaway(Buffers bufs, http2_goaway *frame) {
	int rv;
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	buf.pos -= FRAME_HDLEN;
	
	frame.hd.pack(buf.pos);
	
	write!uint(buf.last, frame.last_stream_id);
	buf.last += 4;
	
	write!uint(buf.last, frame.error_code);
	buf.last += 4;
	
	rv = http2_bufs_add(bufs, frame.opaque_data, frame.opaque_data_len);
	
	if (rv == ErrorCode.BUFFER_ERROR) {
		return ErrorCode.FRAME_SIZE_ERROR;
	}
	
	if (rv != 0) {
		return rv;
	}
	
	return 0;
}

/*
 * Unpacks GOAWAY wire format into |frame|.  The |payload| of length
 * |payloadlen| contains first 8 bytes of payload.  The
 * |var_gift_payload| of length |var_gift_payloadlen| contains
 * remaining payload and its buffer is gifted to the function and then
 * |frame|.  The |var_gift_payloadlen| must be freed by
 * http2_frame_goaway_free().
 */
void http2_frame_unpack_goaway_payload(http2_goaway *frame,
	const ubyte* payload,
	size_t payloadlen,
	ubyte* var_gift_payload,
	size_t var_gift_payloadlen) {
	frame.last_stream_id = read!uint(payload) & STREAM_ID_MASK;
	frame.error_code = read!uint(payload + 4);
	
	frame.opaque_data = var_gift_payload;
	frame.opaque_data_len = var_gift_payloadlen;
}

/*
 * Unpacks GOAWAY wire format into |frame|.  This function only exists
 * for unit test.  After allocating buffer for debug data, this
 * function internally calls http2_frame_unpack_goaway_payload().
 */
void http2_frame_unpack_goaway_payload2(http2_goaway *frame,
	const ubyte* payload,
	size_t payloadlen, http2_mem *mem) {
	ubyte* var_gift_payload;
	size_t var_gift_payloadlen;
	
	if (payloadlen > 8) {
		var_gift_payloadlen = payloadlen - 8;
	} else {
		var_gift_payloadlen = 0;
	}
	
	payloadlen -= var_gift_payloadlen;
	
	if (!var_gift_payloadlen) {
		var_gift_payload = null;
	} else {
		var_gift_payload = http2_mem_malloc(mem, var_gift_payloadlen);
		
		if (var_gift_payload == null) {
			return ErrorCode.NOMEM;
		}
		
		memcpy(var_gift_payload, payload + 8, var_gift_payloadlen);
	}
	
	http2_frame_unpack_goaway_payload(frame, payload, payloadlen,
		var_gift_payload, var_gift_payloadlen);
	
	return 0;
}

/*
 * Packs WINDOW_UPDATE frame |frame| in wire frame format and store it
 * in |bufs|.
 *
 * The caller must make sure that nghttp2_bufs_reset(bufs) is called
 * before calling this function.
 *
 * This function always succeeds and returns 0.
 */
int http2_frame_pack_window_update(Buffers bufs,
	http2_window_update *frame) {
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	assert(http2_buf_avail(buf) >= 4);
	
	buf.pos -= FRAME_HDLEN;
	
	frame.hd.pack(buf.pos);
	
	write!uint(buf.last, frame.window_size_increment);
	buf.last += 4;
	
	return 0;
}

/*
 * Unpacks WINDOW_UPDATE frame byte sequence into |frame|.
 */
void http2_frame_unpack_window_update_payload(http2_window_update *frame,
	const ubyte* payload,
	size_t payloadlen) {
	frame.window_size_increment =
		read!uint(payload) & WINDOW_SIZE_INCREMENT_MASK;
}

/*
 * Makes copy of |iv| and return the copy. The |niv| is the number of
 * entries in |iv|. This function returns the pointer to the copy if
 * it succeeds, or null.
 */
http2_settings_entry *http2_frame_iv_copy(const http2_settings_entry *iv,
	size_t niv, http2_mem *mem) {
	http2_settings_entry *iv_copy;
	size_t len = niv * sizeof(http2_settings_entry);
	
	if (len == 0) {
		return null;
	}
	
	iv_copy = http2_mem_malloc(mem, len);
	
	if (iv_copy == null) {
		return null;
	}
	
	memcpy(iv_copy, iv, len);
	
	return iv_copy;
}

int http2_nv_equal(const http2_nv *a, const http2_nv *b) {
	return a.namelen == b.namelen && a.valuelen == b.valuelen &&
		memcmp(a.name, b.name, a.namelen) == 0 &&
			memcmp(a.value, b.value, a.valuelen) == 0;
}

void http2_nv_array_del(http2_nv *nva, http2_mem *mem) {
	http2_mem_free(mem, nva);
}

int bytes_compar(const ubyte* a, size_t alen, const ubyte* b, size_t blen) {
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

int http2_nv_compare_name(const http2_nv *lhs, const http2_nv *rhs) {
	return bytes_compar(lhs.name, lhs.namelen, rhs.name, rhs.namelen);
}

int nv_compar(const void *lhs, const void *rhs) {
	const http2_nv *a = (const http2_nv *)lhs;
	const http2_nv *b = (const http2_nv *)rhs;
	int rv;
	
	rv = bytes_compar(a.name, a.namelen, b.name, b.namelen);
	
	if (rv == 0) {
		return bytes_compar(a.value, a.valuelen, b.value, b.valuelen);
	}
	
	return rv;
}

void http2_nv_array_sort(http2_nv *nva, size_t nvlen) {
	qsort(nva, nvlen, sizeof(http2_nv), nv_compar);
}

int http2_nv_array_copy(http2_nv **nva_ptr, const http2_nv *nva,
	size_t nvlen, http2_mem *mem) {
	size_t i;
	ubyte* data;
	size_t buflen = 0;
	http2_nv *p;
	
	for (i = 0; i < nvlen; ++i) {
		buflen += nva[i].namelen + nva[i].valuelen;
	}
	
	if (nvlen == 0) {
		*nva_ptr = null;
		
		return 0;
	}
	
	buflen += sizeof(http2_nv) * nvlen;
	
	*nva_ptr = http2_mem_malloc(mem, buflen);
	
	if (*nva_ptr == null) {
		return ErrorCode.NOMEM;
	}
	
	p = *nva_ptr;
	data = (ubyte* )(*nva_ptr) + sizeof(http2_nv) * nvlen;
	
	for (i = 0; i < nvlen; ++i) {
		p.flags = nva[i].flags;
		
		memcpy(data, nva[i].name, nva[i].namelen);
		p.name = data;
		p.namelen = nva[i].namelen;
		http2_downcase(p.name, p.namelen);
		data += nva[i].namelen;
		memcpy(data, nva[i].value, nva[i].valuelen);
		p.value = data;
		p.valuelen = nva[i].valuelen;
		data += nva[i].valuelen;
		++p;
	}
	return 0;
}

int http2_iv_check(const http2_settings_entry *iv, size_t niv) 
{
	size_t i;
	for (i = 0; i < niv; ++i) {
		switch (iv[i].settings_id) {
			case SETTINGS_HEADER_TABLE_SIZE:
				if (iv[i].value > MAX_HEADER_TABLE_SIZE) {
					return 0;
				}
				break;
			case SETTINGS_MAX_CONCURRENT_STREAMS:
				break;
			case SETTINGS_ENABLE_PUSH:
				if (iv[i].value != 0 && iv[i].value != 1) {
					return 0;
				}
				break;
			case SETTINGS_INITIAL_WINDOW_SIZE:
				if (iv[i].value > cast(uint)MAX_WINDOW_SIZE) {
					return 0;
				}
				break;
			case SETTINGS_MAX_FRAME_SIZE:
				if (iv[i].value < MAX_FRAME_SIZE_MIN ||
					iv[i].value > MAX_FRAME_SIZE_MAX) {
					return 0;
				}
				break;
			case SETTINGS_MAX_HEADER_LIST_SIZE:
				break;
		}
	}
	return 1;
}

void frame_set_pad(Buffer* buf, size_t padlen) 
{
	size_t trail_padlen;
	size_t newlen;
	
	DEBUGF(fprintf(stderr, "send: padlen=%zu, shift left 1 bytes\n", padlen));
	
	memmove(buf.pos - 1, buf.pos, FRAME_HDLEN);
	
	--buf.pos;
	
	buf.pos[4] |= FrameFlags.PADDED;
	
	newlen = (read!uint(buf.pos) >> 8) + padlen;
	write!uint(buf.pos, (uint)((newlen << 8) + buf.pos[3]));
	
	trail_padlen = padlen - 1;
	buf.pos[FRAME_HDLEN] = trail_padlen;
	
	/* zero out padding */
	memset(buf.last, 0, trail_padlen);
	/* extend buffers trail_padlen bytes, since we ate previous padlen -
     trail_padlen byte(s) */
	buf.last += trail_padlen;
	
	return;
}

int http2_frame_add_pad(Buffers bufs, ref FrameHeader hd, size_t padlen) 
{
	Buffer* buf;
	
	if (padlen == 0) {
		DEBUGF(fprintf(stderr, "send: padlen = 0, nothing to do\n"));
		
		return 0;
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
	
	assert(http2_buf_avail(buf) >= cast(size_t)padlen - 1);
	
	frame_set_pad(buf, padlen);
	
	hd.length += padlen;
	hd.flags |= FrameFlags.PADDED;
	
	DEBUGF(fprintf(stderr, "send: final payloadlen=%zu, padlen=%zu\n", hd.length,
			padlen));
	
	return 0;
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
