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
const HTTP2_OB_EX_WEIGHT = 300;

/// Higher weight for SETTINGS
const HTTP2_OB_SETTINGS_WEIGHT = 301;

/// Highest weight for PING
const HTTP2_OB_PING_WEIGHT = 302;

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

void pack(out ubyte[] buf, in FrameHeader h) nothrow {

}

void unpack(


version(none):

void http2_frame_pack_frame_hd(ubyte *buf, const http2_frame_hd *hd) {
	http2_put_uint32be(&buf[0], (uint)(hd->length << 8));
  buf[3] = hd->type;
  buf[4] = hd->flags;
  http2_put_uint32be(&buf[5], hd->stream_id);
  /* ignore hd->reserved for now */
}

void http2_frame_unpack_frame_hd(http2_frame_hd *hd, const ubyte *buf) {
  hd->length = http2_get_uint32(&buf[0]) >> 8;
  hd->type = buf[3];
  hd->flags = buf[4];
  hd->stream_id = http2_get_uint32(&buf[5]) & HTTP2_STREAM_ID_MASK;
  hd->reserved = 0;
}

void http2_frame_hd_init(http2_frame_hd *hd, size_t length, ubyte type,
                           ubyte flags, int stream_id) {
  hd->length = length;
  hd->type = type;
  hd->flags = flags;
  hd->stream_id = stream_id;
  hd->reserved = 0;
}

void http2_frame_headers_init(http2_headers *frame, ubyte flags,
                                int stream_id, http2_headers_category cat,
                                const http2_priority_spec *pri_spec,
                                http2_nv *nva, size_t nvlen) {
  http2_frame_hd_init(&frame->hd, 0, HTTP2_HEADERS, flags, stream_id);
  frame->padlen = 0;
  frame->nva = nva;
  frame->nvlen = nvlen;
  frame->cat = cat;

  if (pri_spec) {
    frame->pri_spec = *pri_spec;
  } else {
    http2_priority_spec_default_init(&frame->pri_spec);
  }
}

void http2_frame_headers_free(http2_headers *frame, http2_mem *mem) {
  http2_nv_array_del(frame->nva, mem);
}

void http2_frame_priority_init(http2_priority *frame, int stream_id,
                                 const http2_priority_spec *pri_spec) {
  http2_frame_hd_init(&frame->hd, HTTP2_PRIORITY_SPECLEN, HTTP2_PRIORITY,
                        FrameFlags.NONE, stream_id);
  frame->pri_spec = *pri_spec;
}

void http2_frame_priority_free(http2_priority *frame _U_) {}

void http2_frame_rst_stream_init(http2_rst_stream *frame, int stream_id,
                                   uint error_code) {
  http2_frame_hd_init(&frame->hd, 4, HTTP2_RST_STREAM, FrameFlags.NONE,
                        stream_id);
  frame->error_code = error_code;
}

void http2_frame_rst_stream_free(http2_rst_stream *frame _U_) {}

void http2_frame_settings_init(http2_settings *frame, ubyte flags,
                                 http2_settings_entry *iv, size_t niv) {
  http2_frame_hd_init(&frame->hd, niv * HTTP2_FRAME_SETTINGS_ENTRY_LENGTH,
                        HTTP2_SETTINGS, flags, 0);
  frame->niv = niv;
  frame->iv = iv;
}

void http2_frame_settings_free(http2_settings *frame, http2_mem *mem) {
  http2_mem_free(mem, frame->iv);
}

void http2_frame_push_promise_init(http2_push_promise *frame, ubyte flags,
                                     int stream_id,
                                     int promised_stream_id,
                                     http2_nv *nva, size_t nvlen) {
  http2_frame_hd_init(&frame->hd, 0, HTTP2_PUSH_PROMISE, flags, stream_id);
  frame->padlen = 0;
  frame->nva = nva;
  frame->nvlen = nvlen;
  frame->promised_stream_id = promised_stream_id;
  frame->reserved = 0;
}

void http2_frame_push_promise_free(http2_push_promise *frame,
                                     http2_mem *mem) {
  http2_nv_array_del(frame->nva, mem);
}

void http2_frame_ping_init(http2_ping *frame, ubyte flags,
                             const ubyte *opaque_data) {
  http2_frame_hd_init(&frame->hd, 8, HTTP2_PING, flags, 0);
  if (opaque_data) {
    memcpy(frame->opaque_data, opaque_data, sizeof(frame->opaque_data));
  } else {
    memset(frame->opaque_data, 0, sizeof(frame->opaque_data));
  }
}

void http2_frame_ping_free(http2_ping *frame _U_) {}

void http2_frame_goaway_init(http2_goaway *frame, int last_stream_id,
                               uint error_code, ubyte *opaque_data,
                               size_t opaque_data_len) {
  http2_frame_hd_init(&frame->hd, 8 + opaque_data_len, HTTP2_GOAWAY,
                        FrameFlags.NONE, 0);
  frame->last_stream_id = last_stream_id;
  frame->error_code = error_code;
  frame->opaque_data = opaque_data;
  frame->opaque_data_len = opaque_data_len;
  frame->reserved = 0;
}

void http2_frame_goaway_free(http2_goaway *frame, http2_mem *mem) {
  http2_mem_free(mem, frame->opaque_data);
}

void http2_frame_window_update_init(http2_window_update *frame,
                                      ubyte flags, int stream_id,
                                      int window_size_increment) {
  http2_frame_hd_init(&frame->hd, 4, HTTP2_WINDOW_UPDATE, flags, stream_id);
  frame->window_size_increment = window_size_increment;
  frame->reserved = 0;
}

void http2_frame_window_update_free(http2_window_update *frame _U_) {}

size_t http2_frame_trail_padlen(http2_frame *frame, size_t padlen) {
  return padlen - ((frame->hd.flags & FrameFlags.PADDED) > 0);
}

void http2_frame_data_init(http2_data *frame, ubyte flags,
                             int stream_id) {
  /* At this moment, the length of DATA frame is unknown */
  http2_frame_hd_init(&frame->hd, 0, HTTP2_DATA, flags, stream_id);
  frame->padlen = 0;
}

void http2_frame_data_free(http2_data *frame _U_) {}

size_t http2_frame_priority_len(ubyte flags) {
  if (flags & FrameFlags.PRIORITY) {
    return HTTP2_PRIORITY_SPECLEN;
  }

  return 0;
}

size_t http2_frame_headers_payload_nv_offset(http2_headers *frame) {
  return http2_frame_priority_len(frame->hd.flags);
}

/*
 * Call this function after payload was serialized, but not before
 * changing buf->pos and serializing frame header.
 *
 * This function assumes bufs->cur points to the last buf chain of the
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

  buf = &bufs->head->buf;

  hd = *frame_hd;
  hd.length = http2_buf_len(buf);

  DEBUGF(fprintf(stderr, "send: HEADERS/PUSH_PROMISE, payloadlen=%zu\n",
                 hd.length));

  /* We have multiple frame buffers, which means one or more
     CONTINUATION frame is involved. Remove END_HEADERS flag from the
     first frame. */
  if (bufs->head != bufs->cur) {
    hd.flags &= ~FrameFlags.END_HEADERS;
  }

  buf->pos -= HTTP2_FRAME_HDLEN;
  http2_frame_pack_frame_hd(buf->pos, &hd);

  if (bufs->head != bufs->cur) {
    /* 2nd and later frames are CONTINUATION frames. */
    hd.type = HTTP2_CONTINUATION;
    /* We don't have no flags except for last CONTINUATION */
    hd.flags = FrameFlags.NONE;

    ce = bufs->cur;

    for (ci = bufs->head->next; ci != ce; ci = ci->next) {
      buf = &ci->buf;

      hd.length = http2_buf_len(buf);

      DEBUGF(fprintf(stderr, "send: int CONTINUATION, payloadlen=%zu\n",
                     hd.length));

      buf->pos -= HTTP2_FRAME_HDLEN;
      http2_frame_pack_frame_hd(buf->pos, &hd);
    }

    buf = &ci->buf;
    hd.length = http2_buf_len(buf);
    /* Set END_HEADERS flag for last CONTINUATION */
    hd.flags = FrameFlags.END_HEADERS;

    DEBUGF(fprintf(stderr, "send: last CONTINUATION, payloadlen=%zu\n",
                   hd.length));

    buf->pos -= HTTP2_FRAME_HDLEN;
    http2_frame_pack_frame_hd(buf->pos, &hd);
  }

  return 0;
}

int http2_frame_pack_headers(http2_bufs *bufs, http2_headers *frame,
                               http2_hd_deflater *deflater) {
  size_t nv_offset;
  int rv;
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  nv_offset = http2_frame_headers_payload_nv_offset(frame);

  buf = &bufs->cur->buf;

  buf->pos += nv_offset;
  buf->last = buf->pos;

  /* This call will adjust buf->last to the correct position */
  rv = http2_hd_deflate_hd_bufs(deflater, bufs, frame->nva, frame->nvlen);

  if (rv == HTTP2_ERR_BUFFER_ERROR) {
    rv = HTTP2_ERR_HEADER_COMP;
  }

  buf->pos -= nv_offset;

  if (rv != 0) {
    return rv;
  }

  if (frame->hd.flags & FrameFlags.PRIORITY) {
    http2_frame_pack_priority_spec(buf->pos, &frame->pri_spec);
  }

  frame->padlen = 0;
  frame->hd.length = http2_bufs_len(bufs);

  return frame_pack_headers_shared(bufs, &frame->hd);
}

void http2_frame_pack_priority_spec(ubyte *buf,
                                      const http2_priority_spec *pri_spec) {
  http2_put_uint32be(buf, pri_spec->stream_id);
  if (pri_spec->exclusive) {
    buf[0] |= 0x80;
  }
  buf[4] = pri_spec->weight - 1;
}

void http2_frame_unpack_priority_spec(http2_priority_spec *pri_spec,
                                        ubyte flags _U_,
                                        const ubyte *payload,
                                        size_t payloadlen _U_) {
  int dep_stream_id;
  ubyte exclusive;
  int weight;

  dep_stream_id = http2_get_uint32(payload) & HTTP2_STREAM_ID_MASK;
  exclusive = (payload[0] & 0x80) > 0;
  weight = payload[4] + 1;

  http2_priority_spec_init(pri_spec, dep_stream_id, weight, exclusive);
}

int http2_frame_unpack_headers_payload(http2_headers *frame,
                                         const ubyte *payload,
                                         size_t payloadlen) {
  if (frame->hd.flags & FrameFlags.PRIORITY) {
    http2_frame_unpack_priority_spec(&frame->pri_spec, frame->hd.flags,
                                       payload, payloadlen);
  } else {
    http2_priority_spec_default_init(&frame->pri_spec);
  }

  frame->nva = NULL;
  frame->nvlen = 0;

  return 0;
}

int http2_frame_pack_priority(http2_bufs *bufs, http2_priority *frame) {
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(http2_buf_avail(buf) >= HTTP2_PRIORITY_SPECLEN);

  buf->pos -= HTTP2_FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf->pos, &frame->hd);

  http2_frame_pack_priority_spec(buf->last, &frame->pri_spec);

  buf->last += HTTP2_PRIORITY_SPECLEN;

  return 0;
}

void http2_frame_unpack_priority_payload(http2_priority *frame,
                                           const ubyte *payload,
                                           size_t payloadlen) {
  http2_frame_unpack_priority_spec(&frame->pri_spec, frame->hd.flags, payload,
                                     payloadlen);
}

int http2_frame_pack_rst_stream(http2_bufs *bufs,
                                  http2_rst_stream *frame) {
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(http2_buf_avail(buf) >= 4);

  buf->pos -= HTTP2_FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf->pos, &frame->hd);

  http2_put_uint32be(buf->last, frame->error_code);
  buf->last += 4;

  return 0;
}

void http2_frame_unpack_rst_stream_payload(http2_rst_stream *frame,
                                             const ubyte *payload,
                                             size_t payloadlen _U_) {
  frame->error_code = http2_get_uint32(payload);
}

int http2_frame_pack_settings(http2_bufs *bufs, http2_settings *frame) {
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  if (http2_buf_avail(buf) < (size_t)frame->hd.length) {
    return HTTP2_ERR_FRAME_SIZE_ERROR;
  }

  buf->pos -= HTTP2_FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf->pos, &frame->hd);

  buf->last +=
      http2_frame_pack_settings_payload(buf->last, frame->iv, frame->niv);

  return 0;
}

size_t http2_frame_pack_settings_payload(ubyte *buf,
                                           const http2_settings_entry *iv,
                                           size_t niv) {
  size_t i;
  for (i = 0; i < niv; ++i, buf += HTTP2_FRAME_SETTINGS_ENTRY_LENGTH) {
    http2_put_uint16be(buf, iv[i].settings_id);
    http2_put_uint32be(buf + 2, iv[i].value);
  }
  return HTTP2_FRAME_SETTINGS_ENTRY_LENGTH * niv;
}

int http2_frame_unpack_settings_payload(http2_settings *frame,
                                          http2_settings_entry *iv,
                                          size_t niv, http2_mem *mem) {
  size_t payloadlen = niv * sizeof(http2_settings_entry);

  if (niv == 0) {
    frame->iv = NULL;
  } else {
    frame->iv = http2_mem_malloc(mem, payloadlen);

    if (frame->iv == NULL) {
      return HTTP2_ERR_NOMEM;
    }

    memcpy(frame->iv, iv, payloadlen);
  }

  frame->niv = niv;
  return 0;
}

void http2_frame_unpack_settings_entry(http2_settings_entry *iv,
                                         const ubyte *payload) {
  iv->settings_id = http2_get_uint16(payload, FrameError = http2_get_uint32(&payload[2]);
}

int http2_frame_unpack_settings_payload2(http2_settings_entry **iv_ptr,
                                           size_t *niv_ptr,
                                           const ubyte *payload,
                                           size_t payloadlen,
                                           http2_mem *mem) {
  size_t i;

  *niv_ptr = payloadlen / HTTP2_FRAME_SETTINGS_ENTRY_LENGTH;

  if (*niv_ptr == 0) {
    *iv_ptr = NULL;

    return 0;
  }

  *iv_ptr =
      http2_mem_malloc(mem, (*niv_ptr) * sizeof(http2_settings_entry));

  if (*iv_ptr == NULL) {
    return HTTP2_ERR_NOMEM;
  }

  for (i = 0; i < *niv_ptr; ++i) {
    size_t off = i * HTTP2_FRAME_SETTINGS_ENTRY_LENGTH;
    http2_frame_unpack_settings_entry(&(*iv_ptr)[i], &payload[off]);
  }

  return 0;
}

int http2_frame_pack_push_promise(http2_bufs *bufs,
                                    http2_push_promise *frame,
                                    http2_hd_deflater *deflater) {
  size_t nv_offset = 4;
  int rv;
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->cur->buf;

  buf->pos += nv_offset;
  buf->last = buf->pos;

  /* This call will adjust buf->last to the correct position */
  rv = http2_hd_deflate_hd_bufs(deflater, bufs, frame->nva, frame->nvlen);

  if (rv == HTTP2_ERR_BUFFER_ERROR) {
    rv = HTTP2_ERR_HEADER_COMP;
  }

  buf->pos -= nv_offset;

  if (rv != 0) {
    return rv;
  }

  http2_put_uint32be(buf->pos, frame->promised_stream_id);

  frame->padlen = 0;
  frame->hd.length = http2_bufs_len(bufs);

  return frame_pack_headers_shared(bufs, &frame->hd);
}

int http2_frame_unpack_push_promise_payload(http2_push_promise *frame,
                                              const ubyte *payload,
                                              size_t payloadlen _U_) {
  frame->promised_stream_id =
      http2_get_uint32(payload) & HTTP2_STREAM_ID_MASK;
  frame->nva = NULL;
  frame->nvlen = 0;
  return 0;
}

int http2_frame_pack_ping(http2_bufs *bufs, http2_ping *frame) {
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(http2_buf_avail(buf) >= 8);

  buf->pos -= HTTP2_FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf->pos, &frame->hd);

  buf->last =
      http2_cpymem(buf->last, frame->opaque_data, sizeof(frame->opaque_data));

  return 0;
}

void http2_frame_unpack_ping_payload(http2_ping *frame,
                                       const ubyte *payload,
                                       size_t payloadlen _U_) {
  memcpy(frame->opaque_data, payload, sizeof(frame->opaque_data));
}

int http2_frame_pack_goaway(http2_bufs *bufs, http2_goaway *frame) {
  int rv;
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  buf->pos -= HTTP2_FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf->pos, &frame->hd);

  http2_put_uint32be(buf->last, frame->last_stream_id);
  buf->last += 4;

  http2_put_uint32be(buf->last, frame->error_code);
  buf->last += 4;

  rv = http2_bufs_add(bufs, frame->opaque_data, frame->opaque_data_len);

  if (rv == HTTP2_ERR_BUFFER_ERROR) {
    return HTTP2_ERR_FRAME_SIZE_ERROR;
  }

  if (rv != 0) {
    return rv;
  }

  return 0;
}

void http2_frame_unpack_goaway_payload(http2_goaway *frame,
                                         const ubyte *payload,
                                         size_t payloadlen _U_,
                                         ubyte *var_gift_payload,
                                         size_t var_gift_payloadlen) {
  frame->last_stream_id = http2_get_uint32(payload) & HTTP2_STREAM_ID_MASK;
  frame->error_code = http2_get_uint32(payload + 4);

  frame->opaque_data = var_gift_payload;
  frame->opaque_data_len = var_gift_payloadlen;
}

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
      return HTTP2_ERR_NOMEM;
    }

    memcpy(var_gift_payload, payload + 8, var_gift_payloadlen);
  }

  http2_frame_unpack_goaway_payload(frame, payload, payloadlen,
                                      var_gift_payload, var_gift_payloadlen);

  return 0;
}

int http2_frame_pack_window_update(http2_bufs *bufs,
                                     http2_window_update *frame) {
  http2_buf *buf;

  assert(bufs->head == bufs->cur);

  buf = &bufs->head->buf;

  assert(http2_buf_avail(buf) >= 4);

  buf->pos -= HTTP2_FRAME_HDLEN;

  http2_frame_pack_frame_hd(buf->pos, &frame->hd);

  http2_put_uint32be(buf->last, frame->window_size_increment);
  buf->last += 4;

  return 0;
}

void http2_frame_unpack_window_update_payload(http2_window_update *frame,
                                                const ubyte *payload,
                                                size_t payloadlen _U_) {
  frame->window_size_increment =
      http2_get_uint32(payload) & HTTP2_WINDOW_SIZE_INCREMENT_MASK;
}

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
  return a->namelen == b->namelen && a->valuelen == b->valuelen &&
         memcmp(a->name, b->name, a->namelen) == 0 &&
         memcmp(a->value, b->value, a->valuelen) == 0;
}

void http2_nv_array_del(http2_nv *nva, http2_mem *mem) {
  http2_mem_free(mem, nva);
}

static int bytes_compar(const ubyte *a, size_t alen, const ubyte *b,
                        size_t blen) {
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
  return bytes_compar(lhs->name, lhs->namelen, rhs->name, rhs->namelen);
}

static int nv_compar(const void *lhs, const void *rhs) {
  const http2_nv *a = (const http2_nv *)lhs;
  const http2_nv *b = (const http2_nv *)rhs;
  int rv;

  rv = bytes_compar(a->name, a->namelen, b->name, b->namelen);

  if (rv == 0) {
    return bytes_compar(a->value, a->valuelen, b->value, b->valuelen);
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
    return HTTP2_ERR_NOMEM;
  }

  p = *nva_ptr;
  data = (ubyte *)(*nva_ptr) + sizeof(http2_nv) * nvlen;

  for (i = 0; i < nvlen; ++i) {
    p->flags = nva[i].flags;

    memcpy(data, nva[i].name, nva[i].namelen);
    p->name = data;
    p->namelen = nva[i].namelen;
    http2_downcase(p->name, p->namelen);
    data += nva[i].namelen;
    memcpy(data, nva[i].value, nva[i].valuelen);
    p->value = data;
    p->valuelen = nva[i].valuelen;
    data += nva[i].valuelen;
    ++p;
  }
  return 0;
}

int http2_iv_check(const http2_settings_entry *iv, size_t niv) {
  size_t i;
  for (i = 0; i < niv; ++i) {
    switch (iv[i].settings_id) {
    case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
      if (iv[i].value > HTTP2_MAX_HEADER_TABLE_SIZE) {
        return 0;
      }
      break;
    case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
      break;
    case HTTP2_SETTINGS_ENABLE_PUSH:
      if (iv[i].value != 0 && iv[i].value != 1) {
        return 0;
      }
      break;
    case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      if (iv[i].value > (uint)HTTP2_MAX_WINDOW_SIZE) {
        return 0;
      }
      break;
    case HTTP2_SETTINGS_MAX_FRAME_SIZE:
      if (iv[i].value < HTTP2_MAX_FRAME_SIZE_MIN ||
          iv[i].value > HTTP2_MAX_FRAME_SIZE_MAX) {
        return 0;
      }
      break;
    case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
      break;
    }
  }
  return 1;
}

static void frame_set_pad(http2_buf *buf, size_t padlen) {
  size_t trail_padlen;
  size_t newlen;

  DEBUGF(fprintf(stderr, "send: padlen=%zu, shift left 1 bytes\n", padlen));

  memmove(buf->pos - 1, buf->pos, HTTP2_FRAME_HDLEN);

  --buf->pos;

  buf->pos[4] |= FrameFlags.PADDED;

  newlen = (http2_get_uint32(buf->pos) >> 8) + padlen;
  http2_put_uint32be(buf->pos, (uint)((newlen << 8) + buf->pos[3]));

  trail_padlen = padlen - 1;
  buf->pos[HTTP2_FRAME_HDLEN] = trail_padlen;

  /* zero out padding */
  memset(buf->last, 0, trail_padlen);
  /* extend buffers trail_padlen bytes, since we ate previous padlen -
     trail_padlen byte(s) */
  buf->last += trail_padlen;

  return;
}

int http2_frame_add_pad(http2_bufs *bufs, http2_frame_hd *hd,
                          size_t padlen) {
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
   * completely.  For padded frame, we are going to adjust buf->pos of
   * frame which includes padding and serialize (memmove) frame header
   * in the correct position.  Also extends buf->last to include
   * padding.
   */

  buf = &bufs->head->buf;

  assert(http2_buf_avail(buf) >= (size_t)padlen - 1);

  frame_set_pad(buf, padlen);

  hd->length += padlen;
  hd->flags |= FrameFlags.PADDED;

  DEBUGF(fprintf(stderr, "send: final payloadlen=%zu, padlen=%zu\n", hd->length,
                 padlen));

  return 0;
}
