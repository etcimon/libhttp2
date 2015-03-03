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

//http2_ext_frame_payload
/// Union of extension frame payload
union ExtFramePayload 
{ 
	ExtALTSVC altsvc; 
}

/// A bit higher weight for non-DATA frames
const OB_EX_WEIGHT = 300;

/// Higher weight for SETTINGS
const OB_SETTINGS_WEIGHT = 301;

/// Highest weight for PING
const OB_PING_WEIGHT = 302;

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

	//http2_frame_unpack_frame_hd
	this(in ubyte* buf) {
		length = read!uint(buf) >> 8;
		type = FrameType(buf[3]);
		flags = FrameFlags(buf[4]);
		stream_id = read!uint(&buf[5]) & STREAM_ID_MASK;
	}

	//http2_frame_pack_frame_hd
	void pack(out ubyte* buf) {
		write!uint(buf, cast(uint)(length << 8));
		buf[3] = cast(ubyte) type;
		buf[4] = cast(ubyte) flags;
		write!uint(buf[5 .. $], hd.stream_id);
		/* ignore hd.reserved for now */
	}
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
	 * ErrorCode.NOMEM
	 *     Out of memory.
	 */
	int pack(Buffers bufs, ref Headers frame, ref HuffmanDeflater deflater) 
	{
		size_t nv_offset;
		int rv;
		Buffer* buf;
		
		assert(bufs.head == bufs.cur);
		
		nv_offset = http2_frame_headers_payload_nv_offset(frame);
		
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
		
		if (frame.hd.flags & FrameFlags.PRIORITY) {
			http2_frame_pack_priority_spec(buf.pos, &frame.pri_spec);
		}
		
		frame.padlen = 0;
		frame.hd.length = http2_bufs_len(bufs);
		
		return frame_pack_headers_shared(bufs, &frame.hd);
	}

}

void http2_frame_priority_init(ref Priority frame, int stream_id, in PrioritySpec pri_spec) 
{
	frame.hd = FrameHeader(PRIORITY_SPECLEN, FrameType.PRIORITY, FrameFlags.NONE, stream_id);
	frame.pri_spec = *pri_spec;
}

void http2_frame_priority_free(ref Priority frame) {}

void http2_frame_rst_stream_init(ref Reset frame, int stream_id, FrameError error_code)
{
	frame.hd = FrameHeader(4, FrameType.RST_STREAM, FrameFlags.NONE, stream_id);
	frame.error_code = error_code;
}

void http2_frame_rst_stream_free(ref Reset frame) {}

/*
 * Initializes SETTINGS frame |frame| with given values. |frame| takes
 * ownership of |iv|, so caller must not free it. The |flags| are
 * bitwise-OR of one or more of nghttp2_settings_flag.
 */
void http2_frame_settings_init(ref Settings frame, FrameFlags flags, Setting[] iv) {
	frame.hd = FrameHeader(iv.length * FRAME_SETTINGS_ENTRY_LENGTH, FrameType.SETTINGS, flags, 0);
	frame.niv = niv;
	frame.iv = iv;
}

void http2_frame_settings_free(ref Settings frame) {
	http2_mem_free(mem, frame.iv);
}

/*
 * Initializes PUSH_PROMISE frame |frame| with given values.  |frame|
 * takes ownership of |nva|, so caller must not free it.
 */
void http2_frame_push_promise_init(ref PushPromise frame, FrameFlags flags,	int stream_id,	int promised_stream_id,	NVPair[] nva) {
	frame.hd = FrameHeader(0, FrameType.PUSH_PROMISE, flags, stream_id);
	frame.padlen = 0;
	frame.nva = nva;
	frame.promised_stream_id = promised_stream_id;
	frame.reserved = 0;
}

void http2_frame_push_promise_free(http2_push_promise *frame,
	http2_mem *mem) {
	http2_nv_array_del(frame.nva, mem);
}

/*
 * Initializes PING frame |frame| with given values. If the
 * |opqeue_data| is not null, it must point to 8 bytes memory region
 * of data. The data pointed by |opaque_data| is copied. It can be
 * null. In this case, 8 bytes null is used.
 */
void http2_frame_ping_init(ref Ping frame, FrameFlags flags, const ubyte* opaque_data) {
	frame.hd = FrameHeader(8, FrameType.PING, flags, 0);
	if (opaque_data) {
		memcpy(frame.opaque_data, opaque_data, sizeof(frame.opaque_data));
	} else {
		memset(frame.opaque_data, 0, sizeof(frame.opaque_data));
	}
}

void http2_frame_ping_free(http2_ping *frame) {}

/*
 * Initializes GOAWAY frame |frame| with given values. On success,
 * this function takes ownership of |opaque_data|, so caller must not
 * free it. If the |opaque_data_len| is 0, opaque_data could be null.
 */
void http2_frame_goaway_init(ref GoAway frame, int last_stream_id, FrameError error_code, ubyte[] opaque_data) {
	frame.hd = FrameHeader(8 + opaque_data.length, FrameType.GOAWAY, FrameFlags.NONE, 0);
	frame.last_stream_id = last_stream_id;
	frame.error_code = error_code;
	frame.opaque_data = opaque_data;
	frame.opaque_data_len = opaque_data_len;
	frame.reserved = 0;
}

void http2_frame_goaway_free(ref GoAway frame, http2_mem *mem) {
	http2_mem_free(mem, frame.opaque_data);
}

void http2_frame_window_update_init(ref WindowUpdate frame, FrameFlags flags, int stream_id,  int window_size_increment) {
	frame.hd = FrameHeader(4, FrameType.WINDOW_UPDATE, flags, stream_id);
	frame.window_size_increment = window_size_increment;
	frame.reserved = 0;
}

void http2_frame_window_update_free(ref WindowUpdate frame) {}

/*
 * Returns the number of padding bytes after payload.  The total
 * padding length is given in the |padlen|.  The returned value does
 * not include the Pad Length field.
 */
size_t http2_frame_trail_padlen(ref Frame frame, size_t padlen) {
	return padlen - ((frame.hd.flags & FrameFlags.PADDED) > 0);
}

void http2_frame_data_init(http2_data *frame, FrameFlags flags, int stream_id) {
	/* At this moment, the length of DATA frame is unknown */
	frame.hd = FrameHeader(0, FrameType.DATA, flags, stream_id);
	frame.padlen = 0;
}

void http2_frame_data_free(ref Data frame) {}

/**
 * Returns the number of priority field depending on the |flags|.  If
 * |flags| has neither NGFLAG_PRIORITY_GROUP nor
 * NGFLAG_PRIORITY_DEPENDENCY set, return 0.
 */
size_t http2_frame_priority_len(FrameFlags flags) {
	if (flags & FrameFlags.PRIORITY) {
		return PRIORITY_SPECLEN;
	}
	
	return 0;
}

/*
 * Returns the offset from the HEADERS frame payload where the
 * compressed header block starts. The frame payload does not include
 * frame header.
 */
size_t http2_frame_headers_payload_nv_offset(ref Headers frame) {
	return http2_frame_priority_len(frame.hd.flags);
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
int frame_pack_headers_shared(Buffers bufs,	ref FrameHeader frame_hd) {
	Buffer* buf;
	Chain ci;
	Chain ce;
	FrameHeader hd;
	
	buf = &bufs.head.buf;

	hd = frame_hd;
	hd.length = buf.length;
	
	DEBUGF(fprintf(stderr, "send: HEADERS/PUSH_PROMISE, payloadlen=%zu\n", hd.length));
	
	/* We have multiple frame buffers, which means one or more
     CONTINUATION frame is involved. Remove END_HEADERS flag from the
     first frame. */
	if (bufs.head != bufs.cur) {
		hd.flags &= ~FrameFlags.END_HEADERS;
	}
	
	buf.pos -= FRAME_HDLEN;
	http2_frame_pack_frame_hd(buf.pos, &hd);
	
	if (bufs.head != bufs.cur) {
		/* 2nd and later frames are CONTINUATION frames. */
		hd.type = FrameType.CONTINUATION;
		/* We don't have no flags except for last CONTINUATION */
		hd.flags = FrameFlags.NONE;
		
		ce = bufs.cur;
		
		for (ci = bufs.head.next; ci != ce; ci = ci.next) {
			buf = &ci.buf;
			
			hd.length = http2_buf_len(buf);
			
			DEBUGF(fprintf(stderr, "send: int CONTINUATION, payloadlen=%zu\n",
					hd.length));
			
			buf.pos -= FRAME_HDLEN;
			http2_frame_pack_frame_hd(buf.pos, &hd);
		}
		
		buf = &ci.buf;
		hd.length = http2_buf_len(buf);
		/* Set END_HEADERS flag for last CONTINUATION */
		hd.flags = FrameFlags.END_HEADERS;
		
		DEBUGF(fprintf(stderr, "send: last CONTINUATION, payloadlen=%zu\n",
				hd.length));
		
		buf.pos -= FRAME_HDLEN;
		http2_frame_pack_frame_hd(buf.pos, &hd);
	}
	
	return 0;
}

/**
 * Packs the |pri_spec| in |buf|.  This function assumes |buf| has
 * enough space for serialization.
 */
void http2_frame_pack_priority_spec(ubyte* buf, in PrioritySpec pri_spec) {
	write!uint(buf, pri_spec.stream_id);
	if (pri_spec.exclusive) {
		buf[0] |= 0x80;
	}
	buf[4] = pri_spec.weight - 1;
}

/**
 * Unpacks the priority specification from payload |payload| of length
 * |payloadlen| to |pri_spec|.  The |flags| is used to determine what
 * kind of priority specification is in |payload|.  This function
 * assumes the |payload| contains whole priority specification.
 */
void http2_frame_unpack_priority_spec(ref PrioritySpec pri_spec, FrameFlags flags, in ubyte[] payload) {
	int dep_stream_id;
	ubyte exclusive;
	int weight;
	
	dep_stream_id = read!uint(payload) & STREAM_ID_MASK;
	exclusive = (payload[0] & 0x80) > 0;
	weight = payload[4] + 1;
	
	http2_priority_spec_init(pri_spec, dep_stream_id, weight, exclusive);
}

/*
 * Unpacks HEADERS frame byte sequence into |frame|.  This function
 * only unapcks bytes that come before name/value header block and
 * after possible Pad Length field.
 *
 * This function always succeeds and returns 0.
 */
int http2_frame_unpack_headers_payload(ref Headers frame, in ubyte[] payload) {
	if (frame.hd.flags & FrameFlags.PRIORITY) {
		http2_frame_unpack_priority_spec(&frame.pri_spec, frame.hd.flags, payload);
	} else {
		http2_priority_spec_default_init(&frame.pri_spec);
	}
	
	frame.nva = null;
	frame.nvlen = 0;
	
	return 0;
}

/*
 * Packs PRIORITY frame |frame| in wire format and store it in
 * |bufs|.
 *
 * The caller must make sure that nghttp2_bufs_reset(bufs) is called
 * before calling this function.
 *
 * This function always succeeds and returns 0.
 */
int http2_frame_pack_priority(Buffers bufs, http2_priority *frame) {
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	assert(http2_buf_avail(buf) >= PRIORITY_SPECLEN);
	
	buf.pos -= FRAME_HDLEN;
	
	http2_frame_pack_frame_hd(buf.pos, &frame.hd);
	
	http2_frame_pack_priority_spec(buf.last, &frame.pri_spec);
	
	buf.last += PRIORITY_SPECLEN;
	
	return 0;
}

/*
 * Unpacks PRIORITY wire format into |frame|.
 */
void http2_frame_unpack_priority_payload(ref Priority frame,
	const ubyte* payload,
	size_t payloadlen) {
	http2_frame_unpack_priority_spec(&frame.pri_spec, frame.hd.flags, payload, payloadlen);
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
	
	http2_frame_pack_frame_hd(buf.pos, &frame.hd);
	
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
int http2_frame_pack_settings(Buffers bufs, http2_settings *frame) {
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	if (http2_buf_avail(buf) < cast(size_t)frame.hd.length) {
		return ErrorCode.FRAME_SIZE_ERROR;
	}
	
	buf.pos -= FRAME_HDLEN;
	
	http2_frame_pack_frame_hd(buf.pos, &frame.hd);
	
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
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 */
int http2_frame_unpack_settings_payload(http2_settings *frame, Setting[] iv) 
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
 *
 * This function returns 0 if it succeeds or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 */
int http2_frame_unpack_settings_payload2(ref Setting[] iv, in ubyte[] payload) {
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
 * ErrorCode.NOMEM
 *     Out of memory.
 */
int http2_frame_pack_push_promise(Buffers bufs, ref PushPromise frame, ref HuffmanDeflater deflater) 
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
	
	return frame_pack_headers_shared(bufs, &frame.hd);
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
	
	http2_frame_pack_frame_hd(buf.pos, &frame.hd);
	
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
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.FRAME_SIZE_ERROR
 *     The length of the frame is too large.
 */
int http2_frame_pack_goaway(Buffers bufs, http2_goaway *frame) {
	int rv;
	Buffer* buf;
	
	assert(bufs.head == bufs.cur);
	
	buf = &bufs.head.buf;
	
	buf.pos -= FRAME_HDLEN;
	
	http2_frame_pack_frame_hd(buf.pos, &frame.hd);
	
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
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 */
int http2_frame_unpack_goaway_payload2(http2_goaway *frame,
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
	
	http2_frame_pack_frame_hd(buf.pos, &frame.hd);
	
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



size_t inbound_frame_payload_readlen(InboundFrame *iframe, const ubyte* input, const ubyte* last)
{
	return http2_min(cast (size_t)(last - input), iframe.payloadleft);
}

/*
 * Resets iframe.sbuf and advance its mark pointer by |left| bytes.
 */
void inbound_frame_set_mark(InboundFrame *iframe, size_t left)
{
	http2_buf_reset(&iframe.sbuf);
	iframe.sbuf.mark += left;
}

size_t inbound_frame_buf_read(InboundFrame *iframe, const ubyte* input, const ubyte* last) 
{
	size_t readlen;
	
	readlen = http2_min(last - input, http2_buf_mark_avail(&iframe.sbuf));
	
	iframe.sbuf.last = http2_cpymem(iframe.sbuf.last, input, readlen);
	
	return readlen;
}

/*
 * Unpacks SETTINGS entry in iframe.sbuf.
 */
void inbound_frame_set_settings_entry(InboundFrame *iframe) 
{
	http2_settings_entry iv;
	size_t i;
	
	http2_frame_unpack_settings_entry(&iv, iframe.sbuf.pos);
	
	with(Setting) switch (iv.settings_id) {
		case HEADER_TABLE_SIZE:
		case ENABLE_PUSH:
		case MAX_CONCURRENT_STREAMS:
		case INITIAL_WINDOW_SIZE:
		case MAX_FRAME_SIZE:
		case MAX_HEADER_LIST_SIZE:
			break;
		default:
			DEBUGF(fprintf(stderr, "recv: ignore unknown settings id=0x%02x\n",
					iv.settings_id));
			return;
	}
	
	for (i = 0; i < iframe.niv; ++i) {
		if (iframe.iv[i].settings_id == iv.settings_id) {
			iframe.iv[i] = iv;
			break;
		}
	}
	
	if (i == iframe.niv) {
		iframe.iv[iframe.niv++] = iv;
	}
	
	if (iv.settings_id == Setting.HEADER_TABLE_SIZE &&
		iv.value < iframe.iv[http2_INBOUND_NUM_IV - 1].value) {
		
		iframe.iv[http2_INBOUND_NUM_IV - 1] = iv;
	}
}

/*
 * Checks PADDED flags and set iframe.sbuf to read them accordingly.
 * If padding is set, this function returns 1.  If no padding is set,
 * this function returns 0.  On error, returns -1.
 */
int inbound_frame_handle_pad(InboundFrame *iframe, ref FrameHeader hd)
{
	if (hd.flags & FrameFlags.PADDED) {
		if (hd.length < 1) {
			return -1;
		}
		inbound_frame_set_mark(iframe, 1);
		return 1;
	}
	DEBUGF(fprintf(stderr, "recv: no padding in payload\n"));
	return 0;
}

/*
 * Computes number of padding based on flags. This function returns
 * the calculated length if it succeeds, or -1.
 */
int inbound_frame_compute_pad(InboundFrame *iframe) 
{
	size_t padlen;
	
	/* 1 for Pad Length field */
	padlen = iframe.sbuf.pos[0] + 1;
	
	DEBUGF(fprintf(stderr, "recv: padlen=%zu\n", padlen));
	
	/* We cannot use iframe.frame.hd.length because of CONTINUATION */
	if (padlen - 1 > iframe.payloadleft) {
		return -1;
	}
	
	iframe.padlen = padlen;
	
	return padlen;
}

/*
 * This function returns the effective payload length in the data of
 * length |readlen| when the remaning payload is |payloadleft|. The
 * |payloadleft| does not include |readlen|. If padding was started
 * strictly before this data chunk, this function returns -1.
 */
int inbound_frame_effective_readlen(InboundFrame *iframe, size_t payloadleft, size_t readlen) 
{
	size_t trail_padlen = http2_frame_trail_padlen(&iframe.frame, iframe.padlen);
	
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
