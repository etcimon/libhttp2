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
const DATA_PAYLOADLEN =  MAX_FRAME_SIZE_MIN;

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
    uint error_code;
    
    /// nonzero if request HEADERS is canceled.  The error code is stored in |error_code|.
    ubyte canceled;
    
    /// nonzero if this item should be attached to stream object to make it under priority control
    ubyte attach_stream;
} ;

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
struct OutboundItem {
    Frame frame;
    AuxData aux_data;
    long seq;
    /// Reset count of weight. See comment for last_cycle in http2_session.h
    ulong cycle;
    
    /// The priority used in priority comparion.  Larger is served ealier.
    int weight;
    
    /// nonzero if this object is queued.
    bool queued;
}

void http2_frame_pack_frame_hd(ubyte *buf, const http2_frame_hd *hd)
{
    http2_put_uint32be(&buf[0], cast(uint)(hd.length << 8));
  buf[3] = hd.type;
  buf[4] = hd.flags;
  http2_put_uint32be(&buf[5], hd.stream_id);
  /* ignore hd.reserved for now */
}

void http2_frame_unpack_frame_hd(http2_frame_hd *hd, const ubyte *buf) {
  hd.length = http2_get_uint32(&buf[0]) >> 8;
  hd.type = buf[3];
  hd.flags = buf[4];
  hd.stream_id = http2_get_uint32(&buf[5]) & STREAM_ID_MASK;
  hd.reserved = 0;
}

/**
 * Initializes frame header |hd| with given parameters.  Reserved bit
 * is set to 0.
 */
void http2_frame_hd_init(http2_frame_hd *hd, size_t length, ubyte type,
                           ubyte flags, int stream_id) {
  hd.length = length;
  hd.type = type;
  hd.flags = flags;
  hd.stream_id = stream_id;
  hd.reserved = 0;
}

/*
 * Initializes HEADERS frame |frame| with given values.  |frame| takes
 * ownership of |nva|, so caller must not free it. If |stream_id| is
 * not assigned yet, it must be -1.
 */
void http2_frame_headers_init(http2_headers *frame, ubyte flags,
                                int stream_id, http2_headers_category cat,
                                const http2_priority_spec *pri_spec,
                                http2_nv *nva, size_t nvlen) {
  http2_frame_hd_init(&frame.hd, 0, HEADERS, flags, stream_id);
  frame.padlen = 0;
  frame.nva = nva;
  frame.nvlen = nvlen;
  frame.cat = cat;

  if (pri_spec) {
    frame.pri_spec = *pri_spec;
  } else {
    http2_priority_spec_default_init(&frame.pri_spec);
  }
}

void http2_frame_headers_free(http2_headers *frame, http2_mem *mem)
{
  http2_nv_array_del(frame.nva, mem);
}

void http2_frame_priority_init(http2_priority *frame, int stream_id, const http2_priority_spec *pri_spec) 
{
  http2_frame_hd_init(&frame.hd, PRIORITY_SPECLEN, PRIORITY,
                        FrameFlags.NONE, stream_id);
  frame.pri_spec = *pri_spec;
}

void http2_frame_priority_free(http2_priority *frame) {}

void http2_frame_rst_stream_init(http2_rst_stream *frame, int stream_id,
                                   uint error_code) {
  http2_frame_hd_init(&frame.hd, 4, RST_STREAM, FrameFlags.NONE,
                        stream_id);
  frame.error_code = error_code;
}

void http2_frame_rst_stream_free(http2_rst_stream *frame) {}

/*
 * Initializes SETTINGS frame |frame| with given values. |frame| takes
 * ownership of |iv|, so caller must not free it. The |flags| are
 * bitwise-OR of one or more of nghttp2_settings_flag.
 */
void http2_frame_settings_init(http2_settings *frame, ubyte flags, http2_settings_entry *iv, size_t niv) {
  http2_frame_hd_init(&frame.hd, niv * FRAME_SETTINGS_ENTRY_LENGTH,
                        SETTINGS, flags, 0);
  frame.niv = niv;
  frame.iv = iv;
}

void http2_frame_settings_free(http2_settings *frame, http2_mem *mem) {
  http2_mem_free(mem, frame.iv);
}

/*
 * Initializes PUSH_PROMISE frame |frame| with given values.  |frame|
 * takes ownership of |nva|, so caller must not free it.
 */
void http2_frame_push_promise_init(http2_push_promise *frame, ubyte flags,
                                     int stream_id,
                                     int promised_stream_id,
                                     http2_nv *nva, size_t nvlen) {
  http2_frame_hd_init(&frame.hd, 0, PUSH_PROMISE, flags, stream_id);
  frame.padlen = 0;
  frame.nva = nva;
  frame.nvlen = nvlen;
  frame.promised_stream_id = promised_stream_id;
  frame.reserved = 0;
}

void http2_frame_push_promise_free(http2_push_promise *frame,
                                     http2_mem *mem) {
  http2_nv_array_del(frame.nva, mem);
}

/*
 * Initializes PING frame |frame| with given values. If the
 * |opqeue_data| is not NULL, it must point to 8 bytes memory region
 * of data. The data pointed by |opaque_data| is copied. It can be
 * NULL. In this case, 8 bytes NULL is used.
 */
void http2_frame_ping_init(http2_ping *frame, ubyte flags,
                             const ubyte *opaque_data) {
  http2_frame_hd_init(&frame.hd, 8, PING, flags, 0);
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
 * free it. If the |opaque_data_len| is 0, opaque_data could be NULL.
 */
void http2_frame_goaway_init(http2_goaway *frame, int last_stream_id, uint error_code, ubyte *opaque_data, size_t opaque_data_len) {
  http2_frame_hd_init(&frame.hd, 8 + opaque_data_len, GOAWAY,
                        FrameFlags.NONE, 0);
  frame.last_stream_id = last_stream_id;
  frame.error_code = error_code;
  frame.opaque_data = opaque_data;
  frame.opaque_data_len = opaque_data_len;
  frame.reserved = 0;
}

void http2_frame_goaway_free(http2_goaway *frame, http2_mem *mem) {
  http2_mem_free(mem, frame.opaque_data);
}

void http2_frame_window_update_init(http2_window_update *frame,
                                      ubyte flags, int stream_id,
                                      int window_size_increment) {
  http2_frame_hd_init(&frame.hd, 4, WINDOW_UPDATE, flags, stream_id);
  frame.window_size_increment = window_size_increment;
  frame.reserved = 0;
}

void http2_frame_window_update_free(http2_window_update *frame) {}

/*
 * Returns the number of padding bytes after payload.  The total
 * padding length is given in the |padlen|.  The returned value does
 * not include the Pad Length field.
 */
size_t http2_frame_trail_padlen(http2_frame *frame, size_t padlen) {
  return padlen - ((frame.hd.flags & FrameFlags.PADDED) > 0);
}

void http2_frame_data_init(http2_data *frame, ubyte flags,
                             int stream_id) {
  /* At this moment, the length of DATA frame is unknown */
  http2_frame_hd_init(&frame.hd, 0, DATA, flags, stream_id);
  frame.padlen = 0;
}

void http2_frame_data_free(http2_data *frame) {}

/**
 * Returns the number of priority field depending on the |flags|.  If
 * |flags| has neither NGFLAG_PRIORITY_GROUP nor
 * NGFLAG_PRIORITY_DEPENDENCY set, return 0.
 */
size_t http2_frame_priority_len(ubyte flags) {
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
size_t http2_frame_headers_payload_nv_offset(http2_headers *frame) {
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
static int frame_pack_headers_shared(http2_bufs *bufs,
                                     http2_frame_hd *frame_hd) {
  http2_buf *buf;
  http2_buf_chain *ci, *ce;
  http2_frame_hd hd;

  buf = &bufs.head.buf;

  hd = *frame_hd;
  hd.length = http2_buf_len(buf);

  DEBUGF(fprintf(stderr, "send: HEADERS/PUSH_PROMISE, payloadlen=%zu\n",
                 hd.length));

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
    hd.type = CONTINUATION;
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
 * NGERR_HEADER_COMP
 *     The deflate operation failed.
 * NGERR_NOMEM
 *     Out of memory.
 */
int http2_frame_pack_headers(http2_bufs *bufs, http2_headers *frame,
                               http2_hd_deflater *deflater) {
  size_t nv_offset;
  int rv;
  http2_buf *buf;

  assert(bufs.head == bufs.cur);

  nv_offset = http2_frame_headers_payload_nv_offset(frame);

  buf = &bufs.cur.buf;

  buf.pos += nv_offset;
  buf.last = buf.pos;

  /* This call will adjust buf.last to the correct position */
  rv = http2_hd_deflate_hd_bufs(deflater, bufs, frame.nva, frame.nvlen);

  if (rv == ERR_BUFFER_ERROR) {
    rv = ERR_HEADER_COMP;
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

/**
 * Packs the |pri_spec| in |buf|.  This function assumes |buf| has
 * enough space for serialization.
 */
void http2_frame_pack_priority_spec(ubyte *buf,
                                      const http2_priority_spec *pri_spec) {
  http2_put_uint32be(buf, pri_spec.stream_id);
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
void http2_frame_unpack_priority_spec(http2_priority_spec *pri_spec,
                                        ubyte flags,
                                        const ubyte *payload,
                                        size_t payloadlen) {
  int dep_stream_id;
  ubyte exclusive;
  int weight;

  dep_stream_id = http2_get_uint32(payload) & STREAM_ID_MASK;
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
int http2_frame_unpack_headers_payload(http2_headers *frame,
                                         const ubyte *payload,
                                         size_t payloadlen) {
  if (frame.hd.flags & FrameFlags.PRIORITY) {
    http2_frame_unpack_priority_spec(&frame.pri_spec, frame.hd.flags,
                                       payload, payloadlen);
  } else {
    http2_priority_spec_default_init(&frame.pri_spec);
  }

  frame.nva = NULL;
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
int http2_frame_pack_priority(http2_bufs *bufs, http2_priority *frame) {
  http2_buf *buf;

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
void http2_frame_unpack_priority_payload(http2_priority *frame,
                                           const ubyte *payload,
                                           size_t payloadlen) {
  http2_frame_unpack_priority_spec(&frame.pri_spec, frame.hd.flags, payload,
                                     payloadlen);
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
int http2_frame_pack_rst_stream(http2_bufs *bufs,
                                  http2_rst_stream *frame) {
  http2_buf *buf;

  assert(bufs.head == bufs.cur);

  buf = &bufs.head.buf;

  assert(http2_buf_avail(buf) >= 4);

  buf.pos -= FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf.pos, &frame.hd);

  http2_put_uint32be(buf.last, frame.error_code);
  buf.last += 4;

  return 0;
}

/*
 * Unpacks RST_STREAM frame byte sequence into |frame|.
 */
void http2_frame_unpack_rst_stream_payload(http2_rst_stream *frame,
                                             const ubyte *payload,
                                             size_t payloadlen) {
  frame.error_code = http2_get_uint32(payload);
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
 * NGERR_FRAME_SIZE_ERROR
 *     The length of the frame is too large.
 */
int http2_frame_pack_settings(http2_bufs *bufs, http2_settings *frame) {
  http2_buf *buf;

  assert(bufs.head == bufs.cur);

  buf = &bufs.head.buf;

  if (http2_buf_avail(buf) < cast(size_t)frame.hd.length) {
    return ERR_FRAME_SIZE_ERROR;
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
size_t http2_frame_pack_settings_payload(ubyte *buf,
                                           const http2_settings_entry *iv,
                                           size_t niv) {
  size_t i;
  for (i = 0; i < niv; ++i, buf += FRAME_SETTINGS_ENTRY_LENGTH) {
    http2_put_uint16be(buf, iv[i].settings_id);
    http2_put_uint32be(buf + 2, iv[i].value);
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
 * NGERR_NOMEM
 *     Out of memory.
 */
int http2_frame_unpack_settings_payload(http2_settings *frame,
                                          http2_settings_entry *iv,
                                          size_t niv, http2_mem *mem) {
  size_t payloadlen = niv * sizeof(http2_settings_entry);

  if (niv == 0) {
    frame.iv = NULL;
  } else {
    frame.iv = http2_mem_malloc(mem, payloadlen);

    if (frame.iv == NULL) {
      return ERR_NOMEM;
    }

    memcpy(frame.iv, iv, payloadlen);
  }

  frame.niv = niv;
  return 0;
}

void http2_frame_unpack_settings_entry(http2_settings_entry *iv,
                                         const ubyte *payload) {
    iv.settings_id = http2_get_uint16(payload);
    iv-value = http2_get_uint32(&payload[2]);
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
 * NGERR_NOMEM
 *     Out of memory.
 */
int http2_frame_unpack_settings_payload2(http2_settings_entry **iv_ptr,
                                           size_t *niv_ptr,
                                           const ubyte *payload,
                                           size_t payloadlen,
                                           http2_mem *mem) {
  size_t i;

  *niv_ptr = payloadlen / FRAME_SETTINGS_ENTRY_LENGTH;

  if (*niv_ptr == 0) {
    *iv_ptr = NULL;

    return 0;
  }

  *iv_ptr =
      http2_mem_malloc(mem, (*niv_ptr) * sizeof(http2_settings_entry));

  if (*iv_ptr == NULL) {
    return ERR_NOMEM;
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
 * NGERR_HEADER_COMP
 *     The deflate operation failed.
 * NGERR_NOMEM
 *     Out of memory.
 */
int http2_frame_pack_push_promise(http2_bufs *bufs,
                                    http2_push_promise *frame,
                                    http2_hd_deflater *deflater) {
  size_t nv_offset = 4;
  int rv;
  http2_buf *buf;

  assert(bufs.head == bufs.cur);

  buf = &bufs.cur.buf;

  buf.pos += nv_offset;
  buf.last = buf.pos;

  /* This call will adjust buf.last to the correct position */
  rv = http2_hd_deflate_hd_bufs(deflater, bufs, frame.nva, frame.nvlen);

  if (rv == ERR_BUFFER_ERROR) {
    rv = ERR_HEADER_COMP;
  }

  buf.pos -= nv_offset;

  if (rv != 0) {
    return rv;
  }

  http2_put_uint32be(buf.pos, frame.promised_stream_id);

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
 * NGERR_PROTO
 *     TODO END_HEADERS flag is not set
 */
int http2_frame_unpack_push_promise_payload(http2_push_promise *frame,
                                              const ubyte *payload,
                                              size_t payloadlen) {
  frame.promised_stream_id =
      http2_get_uint32(payload) & STREAM_ID_MASK;
  frame.nva = NULL;
  frame.nvlen = 0;
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
int http2_frame_pack_ping(http2_bufs *bufs, http2_ping *frame) {
  http2_buf *buf;

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
                                       const ubyte *payload,
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
 * NGERR_NOMEM
 *     Out of memory.
 * NGERR_FRAME_SIZE_ERROR
 *     The length of the frame is too large.
 */
int http2_frame_pack_goaway(http2_bufs *bufs, http2_goaway *frame) {
  int rv;
  http2_buf *buf;

  assert(bufs.head == bufs.cur);

  buf = &bufs.head.buf;

  buf.pos -= FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf.pos, &frame.hd);

  http2_put_uint32be(buf.last, frame.last_stream_id);
  buf.last += 4;

  http2_put_uint32be(buf.last, frame.error_code);
  buf.last += 4;

  rv = http2_bufs_add(bufs, frame.opaque_data, frame.opaque_data_len);

  if (rv == ERR_BUFFER_ERROR) {
    return ERR_FRAME_SIZE_ERROR;
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
                                         const ubyte *payload,
                                         size_t payloadlen,
                                         ubyte *var_gift_payload,
                                         size_t var_gift_payloadlen) {
  frame.last_stream_id = http2_get_uint32(payload) & STREAM_ID_MASK;
  frame.error_code = http2_get_uint32(payload + 4);

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
 * NGERR_NOMEM
 *     Out of memory.
 */
int http2_frame_unpack_goaway_payload2(http2_goaway *frame,
                                         const ubyte *payload,
                                         size_t payloadlen, http2_mem *mem) {
  ubyte *var_gift_payload;
  size_t var_gift_payloadlen;

  if (payloadlen > 8) {
    var_gift_payloadlen = payloadlen - 8;
  } else {
    var_gift_payloadlen = 0;
  }

  payloadlen -= var_gift_payloadlen;

  if (!var_gift_payloadlen) {
    var_gift_payload = NULL;
  } else {
    var_gift_payload = http2_mem_malloc(mem, var_gift_payloadlen);

    if (var_gift_payload == NULL) {
      return ERR_NOMEM;
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
int http2_frame_pack_window_update(http2_bufs *bufs,
                                     http2_window_update *frame) {
  http2_buf *buf;

  assert(bufs.head == bufs.cur);

  buf = &bufs.head.buf;

  assert(http2_buf_avail(buf) >= 4);

  buf.pos -= FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf.pos, &frame.hd);

  http2_put_uint32be(buf.last, frame.window_size_increment);
  buf.last += 4;

  return 0;
}

/*
 * Unpacks WINDOW_UPDATE frame byte sequence into |frame|.
 */
void http2_frame_unpack_window_update_payload(http2_window_update *frame,
                                                const ubyte *payload,
                                                size_t payloadlen) {
  frame.window_size_increment =
      http2_get_uint32(payload) & WINDOW_SIZE_INCREMENT_MASK;
}

/*
 * Makes copy of |iv| and return the copy. The |niv| is the number of
 * entries in |iv|. This function returns the pointer to the copy if
 * it succeeds, or NULL.
 */
http2_settings_entry *http2_frame_iv_copy(const http2_settings_entry *iv,
                                              size_t niv, http2_mem *mem) {
  http2_settings_entry *iv_copy;
  size_t len = niv * sizeof(http2_settings_entry);

  if (len == 0) {
    return NULL;
  }

  iv_copy = http2_mem_malloc(mem, len);

  if (iv_copy == NULL) {
    return NULL;
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

static int bytes_compar(const ubyte *a, size_t alen, const ubyte *b, size_t blen) {
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

static int nv_compar(const void *lhs, const void *rhs) {
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
  ubyte *data;
  size_t buflen = 0;
  http2_nv *p;

  for (i = 0; i < nvlen; ++i) {
    buflen += nva[i].namelen + nva[i].valuelen;
  }

  if (nvlen == 0) {
    *nva_ptr = NULL;

    return 0;
  }

  buflen += sizeof(http2_nv) * nvlen;

  *nva_ptr = http2_mem_malloc(mem, buflen);

  if (*nva_ptr == NULL) {
    return ERR_NOMEM;
  }

  p = *nva_ptr;
  data = (ubyte *)(*nva_ptr) + sizeof(http2_nv) * nvlen;

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
      if (iv[i].value > (uint)MAX_WINDOW_SIZE) {
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

static void frame_set_pad(http2_buf *buf, size_t padlen) 
{
  size_t trail_padlen;
  size_t newlen;

  DEBUGF(fprintf(stderr, "send: padlen=%zu, shift left 1 bytes\n", padlen));

  memmove(buf.pos - 1, buf.pos, FRAME_HDLEN);

  --buf.pos;

  buf.pos[4] |= FrameFlags.PADDED;

  newlen = (http2_get_uint32(buf.pos) >> 8) + padlen;
  http2_put_uint32be(buf.pos, (uint)((newlen << 8) + buf.pos[3]));

  trail_padlen = padlen - 1;
  buf.pos[FRAME_HDLEN] = trail_padlen;

  /* zero out padding */
  memset(buf.last, 0, trail_padlen);
  /* extend buffers trail_padlen bytes, since we ate previous padlen -
     trail_padlen byte(s) */
  buf.last += trail_padlen;

  return;
}

int http2_frame_add_pad(http2_bufs *bufs, http2_frame_hd *hd, size_t padlen) 
{
  http2_buf *buf;

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



static size_t inbound_frame_payload_readlen(InboundFrame *iframe, const ubyte *input, const ubyte *last)
{
	return http2_min(cast (size_t)(last - input), iframe.payloadleft);
}

/*
 * Resets iframe.sbuf and advance its mark pointer by |left| bytes.
 */
static void inbound_frame_set_mark(InboundFrame *iframe, size_t left)
{
	http2_buf_reset(&iframe.sbuf);
	iframe.sbuf.mark += left;
}

static size_t inbound_frame_buf_read(InboundFrame *iframe, const ubyte *input, const ubyte *last) 
{
	size_t readlen;
	
	readlen = http2_min(last - input, http2_buf_mark_avail(&iframe.sbuf));
	
	iframe.sbuf.last = http2_cpymem(iframe.sbuf.last, input, readlen);
	
	return readlen;
}

/*
 * Unpacks SETTINGS entry in iframe.sbuf.
 */
static void inbound_frame_set_settings_entry(InboundFrame *iframe) 
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
static int inbound_frame_handle_pad(InboundFrame *iframe, http2_frame_hd *hd)
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
static size_t inbound_frame_compute_pad(InboundFrame *iframe) 
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
static size_t inbound_frame_effective_readlen(InboundFrame *iframe, size_t payloadleft, size_t readlen) 
{
	size_t trail_padlen =
		http2_frame_trail_padlen(&iframe.frame, iframe.padlen);
	
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
