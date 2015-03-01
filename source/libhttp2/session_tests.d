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
#define OB_CTRL(ITEM) http2_outbound_item_get_ctrl_frame(ITEM)
#define OB_CTRL_TYPE(ITEM) http2_outbound_item_get_ctrl_frame_type(ITEM)
#define OB_DATA(ITEM) http2_outbound_item_get_data_frame(ITEM)

struct {
  ubyte buf[65535];
  size_t length;
} accumulator;

struct {
  ubyte data[8192];
  ubyte *datamark;
  ubyte *datalimit;
  size_t feedseq[8192];
  size_t seqidx;
} scripted_data_feed;

struct {
  accumulator *acc;
  scripted_data_feed *df;
  int frame_recv_cb_called, invalid_frame_recv_cb_called;
  ubyte recv_frame_type;
  int frame_send_cb_called;
  ubyte sent_frame_type;
  int frame_not_send_cb_called;
  ubyte not_sent_frame_type;
  int not_sent_error;
  int stream_close_cb_called;
  uint stream_close_error_code;
  size_t data_source_length;
  int stream_id;
  size_t block_count;
  int data_chunk_recv_cb_called;
  const http2_frame *frame;
  size_t fixed_sendlen;
  int header_cb_called;
  int begin_headers_cb_called;
  http2_nv nv;
  size_t data_chunk_len;
  size_t padlen;
  int begin_frame_cb_called;
} my_user_data;

static const http2_nv reqnv[] = {
    MAKE_NV(":method", "GET"), MAKE_NV(":path", "/"),
    MAKE_NV(":scheme", "https"), MAKE_NV(":authority", "localhost"),
};

static const http2_nv resnv[] = {
    MAKE_NV(":status", "200"),
};

static void scripted_data_feed_init2(scripted_data_feed *df,
                                     http2_bufs *bufs) {
  http2_buf_chain *ci;
  http2_buf *buf;
  ubyte *ptr;
  size_t len;

  memset(df, 0, sizeof(scripted_data_feed));
  ptr = df.data;
  len = 0;

  for (ci = bufs.head; ci; ci = ci.next) {
    buf = &ci.buf;
    ptr = http2_cpymem(ptr, buf.pos, http2_buf_len(buf));
    len += http2_buf_len(buf);
  }

  df.datamark = df.data;
  df.datalimit = df.data + len;
  df.feedseq[0] = len;
}

static size_t null_send_callback(http2_session *session,
                                  const ubyte *data, size_t len,
                                  int flags, void *user_data) {
  return len;
}

static size_t fail_send_callback(http2_session *session,
                                  const ubyte *data, size_t len,
                                  int flags, void *user_data) {
  return HTTP2_ERR_CALLBACK_FAILURE;
}

static size_t fixed_bytes_send_callback(http2_session *session,
                                         const ubyte *data, size_t len,
                                         int flags, void *user_data) {
  size_t fixed_sendlen = ((my_user_data *)user_data).fixed_sendlen;
  return fixed_sendlen < len ? fixed_sendlen : len;
}

static size_t scripted_recv_callback(http2_session *session,
                                      ubyte *data, size_t len, int flags,
                                      void *user_data) {
  scripted_data_feed *df = ((my_user_data *)user_data).df;
  size_t wlen = df.feedseq[df.seqidx] > len ? len : df.feedseq[df.seqidx];
  memcpy(data, df.datamark, wlen);
  df.datamark += wlen;
  df.feedseq[df.seqidx] -= wlen;
  if (df.feedseq[df.seqidx] == 0) {
    ++df.seqidx;
  }
  return wlen;
}

static size_t eof_recv_callback(http2_session *session,
                                 ubyte *data, size_t len,
                                 int flags, void *user_data) {
  return HTTP2_ERR_EOF;
}

static size_t accumulator_send_callback(http2_session *session,
                                         const ubyte *buf, size_t len,
                                         int flags, void *user_data) {
  accumulator *acc = (cast(my_user_data *)user_data).acc;
  assert(acc.length + len < sizeof(acc.buf));
  memcpy(acc.buf + acc.length, buf, len);
  acc.length += len;
  return len;
}

static int on_begin_frame_callback(http2_session *session,
                                   const http2_frame_hd *hd,
                                   void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.begin_frame_cb_called;
  return 0;
}

static int on_frame_recv_callback(http2_session *session,
                                  const http2_frame *frame, void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.frame_recv_cb_called;
  ud.recv_frame_type = frame.hd.type;
  return 0;
}

static int on_invalid_frame_recv_callback(http2_session *session,
                                          const http2_frame *frame,
                                          http2_error_code error_code,
                                          void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.invalid_frame_recv_cb_called;
  return 0;
}

static int on_frame_send_callback(http2_session *session,
                                  const http2_frame *frame, void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.frame_send_cb_called;
  ud.sent_frame_type = frame.hd.type;
  return 0;
}

static int on_frame_not_send_callback(http2_session *session,
                                      const http2_frame *frame, int lib_error,
                                      void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.frame_not_send_cb_called;
  ud.not_sent_frame_type = frame.hd.type;
  ud.not_sent_error = lib_error;
  return 0;
}

static int on_data_chunk_recv_callback(http2_session *session,
                                       ubyte flags, int stream_id,
                                       const ubyte *data, size_t len,
                                       void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.data_chunk_recv_cb_called;
  ud.data_chunk_len = len;
  return 0;
}

static int pause_on_data_chunk_recv_callback(http2_session *session,
                                             ubyte flags,
                                             int stream_id,
                                             const ubyte *data,
                                             size_t len, void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.data_chunk_recv_cb_called;
  return HTTP2_ERR_PAUSE;
}

static size_t select_padding_callback(http2_session *session,
                                       const http2_frame *frame,
                                       size_t max_payloadlen, void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  return http2_min(max_payloadlen, frame.hd.length + ud.padlen);
}

static size_t too_large_data_source_length_callback(
    http2_session *session, ubyte frame_type, int stream_id,
    int session_remote_window_size,
    int stream_remote_window_size, uint remote_max_frame_size,
    void *user_data) {
  return HTTP2_MAX_FRAME_SIZE_MAX + 1;
}

static size_t smallest_length_data_source_length_callback(
    http2_session *session, ubyte frame_type, int stream_id,
    int session_remote_window_size,
    int stream_remote_window_size, uint remote_max_frame_size,
    void *user_data) {
  return 1;
}

static size_t fixed_length_data_source_read_callback(
    http2_session *session, int stream_id, ubyte *buf,
    size_t len, uint *data_flags, http2_data_source *source,
    void *user_data) {
  my_user_data *ud = (my_user_data *)user_data;
  size_t wlen;
  if (len < ud.data_source_length) {
    wlen = len;
  } else {
    wlen = ud.data_source_length;
  }
  ud.data_source_length -= wlen;
  if (ud.data_source_length == 0) {
    *data_flags |= HTTP2_DATA_FLAG_EOF;
  }
  return wlen;
}

static size_t temporal_failure_data_source_read_callback(
    http2_session *session, int stream_id, ubyte *buf,
    size_t len, uint *data_flags, http2_data_source *source,
    void *user_data) {
  return HTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

static size_t fail_data_source_read_callback(http2_session *session,
                                              int stream_id,
                                              ubyte *buf, size_t len,
                                              uint *data_flags,
                                              http2_data_source *source,
                                              void *user_data) {
  return HTTP2_ERR_CALLBACK_FAILURE;
}

/* static void no_stream_user_data_stream_close_callback */
/* (http2_session *session, */
/*  int stream_id, */
/*  http2_error_code error_code, */
/*  void *user_data) */
/* { */
/*   my_user_data* my_data = (my_user_data*)user_data; */
/*   ++my_data.stream_close_cb_called; */
/* } */

static size_t block_count_send_callback(http2_session *session,
                                         const ubyte *data, size_t len,
                                         int flags, void *user_data) {
  my_user_data *ud = (my_user_data *)user_data;
  size_t r;
  if (ud.block_count == 0) {
    r = HTTP2_ERR_WOULDBLOCK;
  } else {
    --ud.block_count;
    r = len;
  }
  return r;
}

static int on_header_callback(http2_session *session,
                              const http2_frame *frame, const ubyte *name,
                              size_t namelen, const ubyte *value,
                              size_t valuelen, ubyte flags,
                              void *user_data) {
  my_user_data *ud = (my_user_data *)user_data;
  ++ud.header_cb_called;
  ud.nv.name = (ubyte *)name;
  ud.nv.namelen = namelen;
  ud.nv.value = (ubyte *)value;
  ud.nv.valuelen = valuelen;

  ud.frame = frame;
  return 0;
}

static int pause_on_header_callback(http2_session *session,
                                    const http2_frame *frame,
                                    const ubyte *name, size_t namelen,
                                    const ubyte *value, size_t valuelen,
                                    ubyte flags, void *user_data) {
  on_header_callback(session, frame, name, namelen, value, valuelen, flags,
                     user_data);
  return HTTP2_ERR_PAUSE;
}

static int temporal_failure_on_header_callback(
    http2_session *session, const http2_frame *frame, const ubyte *name,
    size_t namelen, const ubyte *value, size_t valuelen, ubyte flags,
    void *user_data) {
  on_header_callback(session, frame, name, namelen, value, valuelen, flags,
                     user_data);
  return HTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

static int on_begin_headers_callback(http2_session *session,
                                     const http2_frame *frame,
                                     void *user_data) {
  my_user_data *ud = cast(my_user_data *)user_data;
  ++ud.begin_headers_cb_called;
  return 0;
}

static size_t defer_data_source_read_callback(http2_session *session,
                                               int stream_id,
                                               ubyte *buf, size_t len,
                                               uint *data_flags,
                                               http2_data_source *source,
                                               void *user_data) {
  return HTTP2_ERR_DEFERRED;
}

static int on_stream_close_callback(http2_session *session,
                                    int stream_id,
                                    http2_error_code error_code,
                                    void *user_data) {
  my_user_data *my_data = cast(my_user_data *)user_data;
  ++my_data.stream_close_cb_called;
  my_data.stream_close_error_code = error_code;

  return 0;
}

static http2_settings_entry *dup_iv(const http2_settings_entry *iv,
                                      size_t niv) {
  return http2_frame_iv_copy(iv, niv, http2_mem_default());
}

static http2_priority_spec pri_spec_default = {0, DEFAULT_WEIGHT, 0};

void test_http2_session_recv(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  http2_bufs bufs;
  size_t framelen;
  http2_frame frame;
  size_t i;
  http2_outbound_item *item;
  http2_nv *nva;
  size_t nvlen;
  http2_hd_deflater deflater;
  int rv;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_begin_frame_callback = on_begin_frame_callback;

  user_data.df = &df;

  http2_session_server_new(&session, &callbacks, &user_data);
  http2_hd_deflate_init(&deflater, mem);

  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 1,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);

  scripted_data_feed_init2(&df, &bufs);

  framelen = http2_bufs_len(&bufs);

  /* Send 1 byte per each read */
  for (i = 0; i < framelen; ++i) {
    df.feedseq[i] = 1;
  }

  http2_frame_headers_free(&frame.headers, mem);

  user_data.frame_recv_cb_called = 0;
  user_data.begin_frame_cb_called = 0;

  while ((size_t)df.seqidx < framelen) {
    assert(0 == http2_session_recv(session));
  }
  assert(1 == user_data.frame_recv_cb_called);
  assert(1 == user_data.begin_frame_cb_called);

  http2_bufs_reset(&bufs);

  /* Receive PRIORITY */
  http2_frame_priority_init(&frame.priority, 5, &pri_spec_default);

  rv = http2_frame_pack_priority(&bufs, &frame.priority);

  assert(0 == rv);

  http2_frame_priority_free(&frame.priority);

  scripted_data_feed_init2(&df, &bufs);

  user_data.frame_recv_cb_called = 0;
  user_data.begin_frame_cb_called = 0;

  assert(0 == http2_session_recv(session));
  assert(1 == user_data.frame_recv_cb_called);
  assert(1 == user_data.begin_frame_cb_called);

  http2_bufs_reset(&bufs);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);

  /* Some tests for frame too large */
  http2_session_server_new(&session, &callbacks, &user_data);

  /* Receive PING with too large payload */
  http2_frame_ping_init(&frame.ping, FrameFlags.NONE, NULL);

  rv = http2_frame_pack_ping(&bufs, &frame.ping);

  assert(0 == rv);

  /* Add extra 16 bytes */
  http2_bufs_seek_last_present(&bufs);
  assert(http2_buf_len(&bufs.cur.buf) >= 16);

  bufs.cur.buf.last += 16;
  http2_put_uint32be(
      bufs.cur.buf.pos,
      (uint)(((frame.hd.length + 16) << 8) + bufs.cur.buf.pos[3]));

  http2_frame_ping_free(&frame.ping);

  scripted_data_feed_init2(&df, &bufs);
  user_data.frame_recv_cb_called = 0;
  user_data.begin_frame_cb_called = 0;

  assert(0 == http2_session_recv(session));
  assert(0 == user_data.frame_recv_cb_called);
  assert(0 == user_data.begin_frame_cb_called);

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_FRAME_SIZE_ERROR == item.frame.goaway.error_code);
  assert(0 == http2_session_send(session));

  http2_bufs_free(&bufs);
  http2_session_del(session);
}

void test_http2_session_recv_invalid_stream_id(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  http2_bufs bufs;
  http2_frame frame;
  http2_hd_deflater deflater;
  int rv;
  http2_mem *mem;
  http2_nv *nva;
  size_t nvlen;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  user_data.df = &df;
  user_data.invalid_frame_recv_cb_called = 0;
  http2_session_server_new(&session, &callbacks, &user_data);
  http2_hd_deflate_init(&deflater, mem);

  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 2,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  scripted_data_feed_init2(&df, &bufs);
  http2_frame_headers_free(&frame.headers, mem);

  assert(0 == http2_session_recv(session));
  assert(1 == user_data.invalid_frame_recv_cb_called);

  http2_bufs_free(&bufs);
  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
}

void test_http2_session_recv_invalid_frame(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  scripted_data_feed df;
  my_user_data user_data;
  http2_bufs bufs;
  http2_frame frame;
  http2_nv *nva;
  size_t nvlen;
  http2_hd_deflater deflater;
  int rv;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.recv_callback = scripted_recv_callback;
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  user_data.df = &df;
  user_data.frame_send_cb_called = 0;
  http2_session_server_new(&session, &callbacks, &user_data);
  http2_hd_deflate_init(&deflater, mem);
  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 1,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  scripted_data_feed_init2(&df, &bufs);

  assert(0 == http2_session_recv(session));
  assert(0 == http2_session_send(session));
  assert(0 == user_data.frame_send_cb_called);

  /* Receive exactly same bytes of HEADERS is treated as error, because it has
   * pseudo headers and without END_STREAM flag set */
  scripted_data_feed_init2(&df, &bufs);

  assert(0 == http2_session_recv(session));
  assert(0 == http2_session_send(session));
  assert(1 == user_data.frame_send_cb_called);
  assert(HTTP2_RST_STREAM == user_data.sent_frame_type);

  http2_bufs_free(&bufs);
  http2_frame_headers_free(&frame.headers, mem);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
}

void test_http2_session_recv_eof(void) {
  http2_session *session;
  http2_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.recv_callback = eof_recv_callback;

  http2_session_client_new(&session, &callbacks, NULL);
  assert(HTTP2_ERR_EOF == http2_session_recv(session));

  http2_session_del(session);
}

void test_http2_session_recv_data(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  ubyte data[8092];
  size_t rv;
  http2_outbound_item *item;
  http2_stream *stream;
  http2_frame_hd hd;
  int i;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  http2_session_client_new(&session, &callbacks, &ud);

  /* Create DATA frame with length 4KiB */
  memset(data, 0, sizeof(data));
  hd.length = 4096;
  hd.type = HTTP2_DATA;
  hd.flags = FrameFlags.NONE;
  hd.stream_id = 1;
  http2_frame_pack_frame_hd(data, &hd);

  /* stream 1 is not opened, so it must be responded with connection
     error.  This is not mandated by the spec */
  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = http2_session_mem_recv(session, data, HTTP2_FRAME_HDLEN + 4096);
  assert(HTTP2_FRAME_HDLEN + 4096 == rv);

  assert(0 == ud.data_chunk_recv_cb_called);
  assert(0 == ud.frame_recv_cb_called);
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);

  http2_session_del(session);

  http2_session_client_new(&session, &callbacks, &ud);

  /* Create stream 1 with CLOSING state. DATA is ignored. */
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_CLOSING, NULL);
  /* Set initial window size 16383 to check stream flow control,
     isolating it from the conneciton flow control */
  stream.local_window_size = 16383;

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = http2_session_mem_recv(session, data, HTTP2_FRAME_HDLEN + 4096);
  assert(HTTP2_FRAME_HDLEN + 4096 == rv);

  assert(0 == ud.data_chunk_recv_cb_called);
  assert(0 == ud.frame_recv_cb_called);
  item = http2_session_get_next_ob_item(session);
  assert(NULL == item);

  /* This is normal case. DATA is acceptable. */
  stream.state = HTTP2_STREAM_OPENED;

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = http2_session_mem_recv(session, data, HTTP2_FRAME_HDLEN + 4096);
  assert(HTTP2_FRAME_HDLEN + 4096 == rv);

  assert(1 == ud.data_chunk_recv_cb_called);
  assert(1 == ud.frame_recv_cb_called);

  assert(NULL == http2_session_get_next_ob_item(session));

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = http2_session_mem_recv(session, data, HTTP2_FRAME_HDLEN + 4096);
  assert(HTTP2_FRAME_HDLEN + 4096 == rv);

  /* Now we got data more than initial-window-size / 2, WINDOW_UPDATE
     must be queued */
  assert(1 == ud.data_chunk_recv_cb_called);
  assert(1 == ud.frame_recv_cb_called);
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(1 == item.frame.window_update.hd.stream_id);
  assert(0 == http2_session_send(session));

  /* Set initial window size to 1MiB, so that we can check connection
     flow control individually */
  stream.local_window_size = 1 << 20;
  /* Connection flow control takes into account DATA which is received
     in the error condition. We have received 4096 * 4 bytes of
     DATA. Additional 4 DATA frames, connection flow control will kick
     in. */
  for (i = 0; i < 5; ++i) {
    rv = http2_session_mem_recv(session, data, HTTP2_FRAME_HDLEN + 4096);
    assert(HTTP2_FRAME_HDLEN + 4096 == rv);
  }
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(0 == item.frame.window_update.hd.stream_id);
  assert(0 == http2_session_send(session));

  /* Reception of DATA with stream ID = 0 causes connection error */
  hd.length = 4096;
  hd.type = HTTP2_DATA;
  hd.flags = FrameFlags.NONE;
  hd.stream_id = 0;
  http2_frame_pack_frame_hd(data, &hd);

  ud.data_chunk_recv_cb_called = 0;
  ud.frame_recv_cb_called = 0;
  rv = http2_session_mem_recv(session, data, HTTP2_FRAME_HDLEN + 4096);
  assert(HTTP2_FRAME_HDLEN + 4096 == rv);

  assert(0 == ud.data_chunk_recv_cb_called);
  assert(0 == ud.frame_recv_cb_called);
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_PROTOCOL_ERROR == item.frame.goaway.error_code);

  http2_session_del(session);
}

void test_http2_session_recv_continuation(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_nv *nva;
  size_t nvlen;
  http2_frame frame;
  http2_bufs bufs;
  http2_buf *buf;
  size_t rv;
  my_user_data ud;
  http2_hd_deflater deflater;
  ubyte data[1024];
  size_t datalen;
  http2_frame_hd cont_hd;
  http2_priority_spec pri_spec;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_header_callback = on_header_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_begin_frame_callback = on_begin_frame_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  http2_hd_deflate_init(&deflater, mem);

  /* Make 1 HEADERS and insert CONTINUATION header */
  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.NONE, 1,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  /* make sure that all data is in the first buf */
  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  http2_frame_headers_free(&frame.headers, mem);

  /* HEADERS's payload is 1 byte */
  memcpy(data, buf.pos, HTTP2_FRAME_HDLEN + 1);
  datalen = HTTP2_FRAME_HDLEN + 1;
  buf.pos += HTTP2_FRAME_HDLEN + 1;

  http2_put_uint32be(data, (1 << 8) + data[3]);

  /* First CONTINUATION, 2 bytes */
  http2_frame_hd_init(&cont_hd, 2, HTTP2_CONTINUATION, FrameFlags.NONE,
                        1);

  http2_frame_pack_frame_hd(data + datalen, &cont_hd);
  datalen += HTTP2_FRAME_HDLEN;

  memcpy(data + datalen, buf.pos, cont_hd.length);
  datalen += cont_hd.length;
  buf.pos += cont_hd.length;

  /* Second CONTINUATION, rest of the bytes */
  http2_frame_hd_init(&cont_hd, http2_buf_len(buf), HTTP2_CONTINUATION,
                        FrameFlags.END_HEADERS, 1);

  http2_frame_pack_frame_hd(data + datalen, &cont_hd);
  datalen += HTTP2_FRAME_HDLEN;

  memcpy(data + datalen, buf.pos, cont_hd.length);
  datalen += cont_hd.length;
  buf.pos += cont_hd.length;

  assert(0 == http2_buf_len(buf));

  ud.header_cb_called = 0;
  ud.begin_frame_cb_called = 0;

  rv = http2_session_mem_recv(session, data, datalen);
  assert((size_t)datalen == rv);
  assert(4 == ud.header_cb_called);
  assert(3 == ud.begin_frame_cb_called);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);

  /* Expecting CONTINUATION, but get the other frame */
  http2_session_server_new(&session, &callbacks, &ud);

  http2_hd_deflate_init(&deflater, mem);

  /* HEADERS without END_HEADERS flag */
  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.NONE, 1,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  http2_bufs_reset(&bufs);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_headers_free(&frame.headers, mem);

  /* make sure that all data is in the first buf */
  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  memcpy(data, buf.pos, http2_buf_len(buf));
  datalen = http2_buf_len(buf);

  /* Followed by PRIORITY */
  http2_priority_spec_default_init(&pri_spec);

  http2_frame_priority_init(&frame.priority, 1, &pri_spec);
  http2_bufs_reset(&bufs);

  rv = http2_frame_pack_priority(&bufs, &frame.priority);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  memcpy(data + datalen, buf.pos, http2_buf_len(buf));
  datalen += http2_buf_len(buf);

  ud.begin_headers_cb_called = 0;
  rv = http2_session_mem_recv(session, data, datalen);
  assert((size_t)datalen == rv);

  assert(1 == ud.begin_headers_cb_called);
  assert(HTTP2_GOAWAY ==
            http2_session_get_next_ob_item(session).frame.hd.type);

  http2_bufs_free(&bufs);
  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
}

void test_http2_session_recv_headers_with_priority(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_nv *nva;
  size_t nvlen;
  http2_frame frame;
  http2_bufs bufs;
  http2_buf *buf;
  size_t rv;
  my_user_data ud;
  http2_hd_deflater deflater;
  http2_outbound_item *item;
  http2_priority_spec pri_spec;
  http2_stream *stream;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  http2_hd_deflate_init(&deflater, mem);

  open_stream(session, 1);

  /* With FrameFlags.PRIORITY without exclusive flag set */
  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);

  http2_priority_spec_init(&pri_spec, 1, 99, 0);

  http2_frame_headers_init(&frame.headers,
                             FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
                             3, HTTP2_HCAT_HEADERS, &pri_spec, nva, nvlen);

  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_headers_free(&frame.headers, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf));

  assert(http2_buf_len(buf) == rv);
  assert(1 == ud.frame_recv_cb_called);

  stream = http2_session_get_stream(session, 3);

  assert(99 == stream.weight);
  assert(1 == stream.dep_prev.stream_id);

  http2_bufs_reset(&bufs);

  /* With FrameFlags.PRIORITY, but cut last 1 byte to make it
     invalid. */
  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);

  http2_priority_spec_init(&pri_spec, 0, 99, 0);

  http2_frame_headers_init(&frame.headers,
                             FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
                             5, HTTP2_HCAT_HEADERS, &pri_spec, nva, nvlen);

  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > HTTP2_FRAME_HDLEN + 5);

  http2_frame_headers_free(&frame.headers, mem);

  buf = &bufs.head.buf;
  /* Make payload shorter than required length to store priority
     group */
  http2_put_uint32be(buf.pos, (4 << 8) + buf.pos[3]);

  ud.frame_recv_cb_called = 0;

  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf));

  assert(http2_buf_len(buf) == rv);
  assert(0 == ud.frame_recv_cb_called);

  stream = http2_session_get_stream(session, 5);

  assert(NULL == stream);

  item = http2_session_get_next_ob_item(session);
  assert(NULL != item);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_FRAME_SIZE_ERROR == item.frame.goaway.error_code);

  http2_bufs_reset(&bufs);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);

  /* Check dep_stream_id == stream_id */
  http2_session_server_new(&session, &callbacks, &ud);

  http2_hd_deflate_init(&deflater, mem);

  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);

  http2_priority_spec_init(&pri_spec, 1, 0, 0);

  http2_frame_headers_init(&frame.headers,
                             FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
                             1, HTTP2_HCAT_HEADERS, &pri_spec, nva, nvlen);

  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_headers_free(&frame.headers, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf));

  assert(http2_buf_len(buf) == rv);
  assert(0 == ud.frame_recv_cb_called);

  stream = http2_session_get_stream(session, 1);

  assert(NULL == stream);

  item = http2_session_get_next_ob_item(session);
  assert(NULL != item);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_PROTOCOL_ERROR == item.frame.goaway.error_code);

  http2_bufs_reset(&bufs);

  http2_bufs_free(&bufs);
  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
}

void test_http2_session_recv_premature_headers(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_nv *nva;
  size_t nvlen;
  http2_frame frame;
  http2_bufs bufs;
  http2_buf *buf;
  size_t rv;
  my_user_data ud;
  http2_hd_deflater deflater;
  http2_outbound_item *item;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));

  http2_session_server_new(&session, &callbacks, &ud);

  http2_hd_deflate_init(&deflater, mem);

  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 1,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_headers_free(&frame.headers, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  /* Intentionally feed payload cutting last 1 byte off */
  http2_put_uint32be(buf.pos,
                       (uint)(((frame.hd.length - 1) << 8) + buf.pos[3]));
  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf) - 1);

  assert((size_t)(http2_buf_len(buf) - 1) == rv);

  item = http2_session_get_next_ob_item(session);
  assert(NULL != item);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);
  assert(HTTP2_COMPRESSION_ERROR == item.frame.rst_stream.error_code);

  http2_bufs_free(&bufs);
  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
}

void test_http2_session_recv_unknown_frame(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  ubyte data[16384];
  size_t datalen;
  http2_frame_hd hd;
  size_t rv;

  http2_frame_hd_init(&hd, 16000, 99, FrameFlags.NONE, 0);

  http2_frame_pack_frame_hd(data, &hd);
  datalen = HTTP2_FRAME_HDLEN + hd.length;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  ud.frame_recv_cb_called = 0;

  /* Unknown frame must be ignored */
  rv = http2_session_mem_recv(session, data, datalen);

  assert(rv == (size_t)datalen);
  assert(0 == ud.frame_recv_cb_called);
  assert(NULL == http2_session_get_next_ob_item(session));

  http2_session_del(session);
}

void test_http2_session_recv_unexpected_continuation(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  ubyte data[16384];
  size_t datalen;
  http2_frame_hd hd;
  size_t rv;
  http2_outbound_item *item;

  http2_frame_hd_init(&hd, 16000, HTTP2_CONTINUATION,
                        FrameFlags.END_HEADERS, 1);

  http2_frame_pack_frame_hd(data, &hd);
  datalen = HTTP2_FRAME_HDLEN + hd.length;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  open_stream(session, 1);

  ud.frame_recv_cb_called = 0;

  /* unexpected CONTINUATION must be treated as connection error */
  rv = http2_session_mem_recv(session, data, datalen);

  assert(rv == (size_t)datalen);
  assert(0 == ud.frame_recv_cb_called);

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_GOAWAY == item.frame.hd.type);

  http2_session_del(session);
}

void test_http2_session_recv_settings_header_table_size(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_frame frame;
  http2_bufs bufs;
  http2_buf *buf;
  size_t rv;
  my_user_data ud;
  http2_settings_entry iv[3];
  http2_nv nv = MAKE_NV(":authority", "example.org");
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, &ud);

  iv[0].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 3000;

  iv[1].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16384;

  http2_frame_settings_init(&frame.settings, FrameFlags.NONE, dup_iv(iv, 2),
                              2);

  rv = http2_frame_pack_settings(&bufs, &frame.settings);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_settings_free(&frame.settings, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf));

  assert(rv == http2_buf_len(buf));
  assert(1 == ud.frame_recv_cb_called);

  assert(3000 == session.remote_settings.header_table_size);
  assert(16384 == session.remote_settings.initial_window_size);

  http2_bufs_reset(&bufs);

  /* 2 SETTINGS_HEADER_TABLE_SIZE */
  iv[0].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 3001;

  iv[1].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16383;

  iv[2].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[2].value = 3001;

  http2_frame_settings_init(&frame.settings, FrameFlags.NONE, dup_iv(iv, 3),
                              3);

  rv = http2_frame_pack_settings(&bufs, &frame.settings);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_settings_free(&frame.settings, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf));

  assert(rv == http2_buf_len(buf));
  assert(1 == ud.frame_recv_cb_called);

  assert(3001 == session.remote_settings.header_table_size);
  assert(16383 == session.remote_settings.initial_window_size);

  http2_bufs_reset(&bufs);

  /* 2 SETTINGS_HEADER_TABLE_SIZE; first entry clears dynamic header
     table. */

  http2_submit_request(session, NULL, &nv, 1, NULL, NULL);
  http2_session_send(session);

  assert(0 < session.hd_deflater.ctx.hd_table.len);

  iv[0].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 0;

  iv[1].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16382;

  iv[2].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[2].value = 4096;

  http2_frame_settings_init(&frame.settings, FrameFlags.NONE, dup_iv(iv, 3),
                              3);

  rv = http2_frame_pack_settings(&bufs, &frame.settings);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_settings_free(&frame.settings, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf));

  assert(rv == http2_buf_len(buf));
  assert(1 == ud.frame_recv_cb_called);

  assert(4096 == session.remote_settings.header_table_size);
  assert(16382 == session.remote_settings.initial_window_size);
  assert(0 == session.hd_deflater.ctx.hd_table.len);

  http2_bufs_reset(&bufs);

  /* 2 SETTINGS_HEADER_TABLE_SIZE; second entry clears dynamic header
     table. */

  http2_submit_request(session, NULL, &nv, 1, NULL, NULL);
  http2_session_send(session);

  assert(0 < session.hd_deflater.ctx.hd_table.len);

  iv[0].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 3000;

  iv[1].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16381;

  iv[2].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[2].value = 0;

  http2_frame_settings_init(&frame.settings, FrameFlags.NONE, dup_iv(iv, 3),
                              3);

  rv = http2_frame_pack_settings(&bufs, &frame.settings);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_settings_free(&frame.settings, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  ud.frame_recv_cb_called = 0;

  rv = http2_session_mem_recv(session, buf.pos, http2_buf_len(buf));

  assert(rv == http2_buf_len(buf));
  assert(1 == ud.frame_recv_cb_called);

  assert(0 == session.remote_settings.header_table_size);
  assert(16381 == session.remote_settings.initial_window_size);
  assert(0 == session.hd_deflater.ctx.hd_table.len);

  http2_bufs_reset(&bufs);

  http2_bufs_free(&bufs);
  http2_session_del(session);
}

void test_http2_session_recv_too_large_frame_length(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  ubyte buf[HTTP2_FRAME_HDLEN];
  http2_outbound_item *item;
  http2_frame_hd hd;

  /* Initial max frame size is HTTP2_MAX_FRAME_SIZE_MIN */
  http2_frame_hd_init(&hd, HTTP2_MAX_FRAME_SIZE_MIN + 1, HTTP2_HEADERS,
                        FrameFlags.NONE, 1);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));

  http2_session_server_new(&session, &callbacks, NULL);

  http2_frame_pack_frame_hd(buf, &hd);

  assert(sizeof(buf) == http2_session_mem_recv(session, buf, sizeof(buf)));

  item = http2_session_get_next_ob_item(session);

  assert(item != NULL);
  assert(HTTP2_GOAWAY == item.frame.hd.type);

  http2_session_del(session);
}

void test_http2_session_continue(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  const http2_nv nv1[] = {MAKE_NV(":method", "GET"), MAKE_NV(":path", "/")};
  const http2_nv nv2[] = {MAKE_NV("user-agent", "nghttp2/1.0.0"),
                            MAKE_NV("alpha", "bravo")};
  http2_bufs bufs;
  http2_buf *buf;
  size_t framelen1, framelen2;
  size_t rv;
  ubyte buffer[4096];
  http2_buf databuf;
  http2_frame frame;
  http2_nv *nva;
  size_t nvlen;
  const http2_frame *recv_frame;
  http2_frame_hd data_hd;
  http2_hd_deflater deflater;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);
  http2_buf_wrap_init(&databuf, buffer, sizeof(buffer));

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_data_chunk_recv_callback = pause_on_data_chunk_recv_callback;
  callbacks.on_header_callback = pause_on_header_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;

  http2_session_server_new(&session, &callbacks, &user_data);
  /* disable strict HTTP layering checks */
  session.opt_flags |= HTTP2_OPTMASK_NO_HTTP_MESSAGING;

  http2_hd_deflate_init(&deflater, mem);

  /* Make 2 HEADERS frames */
  nvlen = ARRLEN(nv1);
  http2_nv_array_copy(&nva, nv1, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 1,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_headers_free(&frame.headers, mem);

  buf = &bufs.head.buf;
  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  framelen1 = http2_buf_len(buf);
  databuf.last = http2_cpymem(databuf.last, buf.pos, http2_buf_len(buf));

  nvlen = ARRLEN(nv2);
  http2_nv_array_copy(&nva, nv2, nvlen, mem);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 3,
                             HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  http2_bufs_reset(&bufs);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);
  assert(http2_bufs_len(&bufs) > 0);

  http2_frame_headers_free(&frame.headers, mem);

  assert(http2_bufs_len(&bufs) == http2_buf_len(buf));

  framelen2 = http2_buf_len(buf);
  databuf.last = http2_cpymem(databuf.last, buf.pos, http2_buf_len(buf));

  /* Receive 1st HEADERS and pause */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv =
      http2_session_mem_recv(session, databuf.pos, http2_buf_len(&databuf));

  assert(rv >= 0);
  databuf.pos += rv;

  recv_frame = user_data.frame;
  assert(HTTP2_HEADERS == recv_frame.hd.type);
  assert(framelen1 - HTTP2_FRAME_HDLEN == recv_frame.hd.length);

  assert(1 == user_data.begin_headers_cb_called);
  assert(1 == user_data.header_cb_called);

  assert(http2_nv_equal(&nv1[0], &user_data.nv));

  /* get 2nd header field */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv =
      http2_session_mem_recv(session, databuf.pos, http2_buf_len(&databuf));

  assert(rv >= 0);
  databuf.pos += rv;

  assert(0 == user_data.begin_headers_cb_called);
  assert(1 == user_data.header_cb_called);

  assert(http2_nv_equal(&nv1[1], &user_data.nv));

  /* will call end_headers_callback and receive 2nd HEADERS and pause */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv =
      http2_session_mem_recv(session, databuf.pos, http2_buf_len(&databuf));

  assert(rv >= 0);
  databuf.pos += rv;

  recv_frame = user_data.frame;
  assert(HTTP2_HEADERS == recv_frame.hd.type);
  assert(framelen2 - HTTP2_FRAME_HDLEN == recv_frame.hd.length);

  assert(1 == user_data.begin_headers_cb_called);
  assert(1 == user_data.header_cb_called);

  assert(http2_nv_equal(&nv2[0], &user_data.nv));

  /* get 2nd header field */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  rv =
      http2_session_mem_recv(session, databuf.pos, http2_buf_len(&databuf));

  assert(rv >= 0);
  databuf.pos += rv;

  assert(0 == user_data.begin_headers_cb_called);
  assert(1 == user_data.header_cb_called);

  assert(http2_nv_equal(&nv2[1], &user_data.nv));

  /* No input data, frame_recv_callback is called */
  user_data.begin_headers_cb_called = 0;
  user_data.header_cb_called = 0;
  user_data.frame_recv_cb_called = 0;
  rv =
      http2_session_mem_recv(session, databuf.pos, http2_buf_len(&databuf));

  assert(rv >= 0);
  databuf.pos += rv;

  assert(0 == user_data.begin_headers_cb_called);
  assert(0 == user_data.header_cb_called);
  assert(1 == user_data.frame_recv_cb_called);

  /* Receive DATA */
  http2_frame_hd_init(&data_hd, 16, HTTP2_DATA, FrameFlags.NONE, 1);

  http2_buf_reset(&databuf);
  http2_frame_pack_frame_hd(databuf.pos, &data_hd);

  /* Intentionally specify larger buffer size to see pause is kicked
     in. */
  databuf.last = databuf.end;

  user_data.frame_recv_cb_called = 0;
  rv =
      http2_session_mem_recv(session, databuf.pos, http2_buf_len(&databuf));

  assert(16 + HTTP2_FRAME_HDLEN == rv);
  assert(0 == user_data.frame_recv_cb_called);

  /* Next http2_session_mem_recv invokes on_frame_recv_callback and
     pause again in on_data_chunk_recv_callback since we pass same
     DATA frame. */
  user_data.frame_recv_cb_called = 0;
  rv =
      http2_session_mem_recv(session, databuf.pos, http2_buf_len(&databuf));
  assert(16 + HTTP2_FRAME_HDLEN == rv);
  assert(1 == user_data.frame_recv_cb_called);

  /* And finally call on_frame_recv_callback with 0 size input */
  user_data.frame_recv_cb_called = 0;
  rv = http2_session_mem_recv(session, NULL, 0);
  assert(0 == rv);
  assert(1 == user_data.frame_recv_cb_called);

  http2_bufs_free(&bufs);
  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
}

void test_http2_session_add_frame(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  accumulator acc;
  my_user_data user_data;
  http2_outbound_item *item;
  http2_frame *frame;
  http2_nv *nva;
  size_t nvlen;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;

  acc.length = 0;
  user_data.acc = &acc;

  assert(0 == http2_session_client_new(&session, &callbacks, &user_data));

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  nvlen = ARRLEN(reqnv);
  http2_nv_array_copy(&nva, reqnv, nvlen, mem);

  http2_frame_headers_init(
      &frame.headers, FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
      session.next_stream_id, HTTP2_HCAT_REQUEST, NULL, nva, nvlen);

  session.next_stream_id += 2;

  assert(0 == http2_session_add_item(session, item));
  assert(0 == http2_pq_empty(&session.ob_ss_pq));
  assert(0 == http2_session_send(session));
  assert(HTTP2_HEADERS == acc.buf[3]);
  assert((FrameFlags.END_HEADERS | FrameFlags.PRIORITY) == acc.buf[4]);
  /* check stream id */
  assert(1 == http2_get_uint32(&acc.buf[5]));

  http2_session_del(session);
}

void test_http2_session_on_request_headers_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_stream *stream;
  int stream_id = 1;
  http2_nv malformed_nva[] = {MAKE_NV(":path", "\x01")};
  http2_nv *nva;
  size_t nvlen;
  http2_priority_spec pri_spec;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  http2_session_server_new(&session, &callbacks, &user_data);

  http2_priority_spec_init(&pri_spec, 0, 255, 0);

  http2_frame_headers_init(
      &frame.headers, FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
      stream_id, HTTP2_HCAT_REQUEST, &pri_spec, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  assert(0 == http2_session_on_request_headers_received(session, &frame));
  assert(1 == user_data.begin_headers_cb_called);
  stream = http2_session_get_stream(session, stream_id);
  assert(HTTP2_STREAM_OPENING == stream.state);
  assert(255 == stream.weight);

  http2_frame_headers_free(&frame.headers, mem);

  /* More than un-ACKed max concurrent streams leads REFUSED_STREAM */
  session.pending_local_max_concurrent_stream = 1;
  http2_frame_headers_init(&frame.headers,
                             FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
                             3, HTTP2_HCAT_HEADERS, NULL, NULL, 0);
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));
  assert(1 == user_data.invalid_frame_recv_cb_called);
  assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));

  http2_frame_headers_free(&frame.headers, mem);
  session.local_settings.max_concurrent_streams =
      HTTP2_INITIAL_MAX_CONCURRENT_STREAMS;

  /* Stream ID less than or equal to the previouly received request
     HEADERS is just ignored due to race condition */
  http2_frame_headers_init(&frame.headers,
                             FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
                             3, HTTP2_HCAT_HEADERS, NULL, NULL, 0);
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));
  assert(0 == user_data.invalid_frame_recv_cb_called);
  assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));

  http2_frame_headers_free(&frame.headers, mem);

  /* Stream ID is our side and it is idle stream ID, then treat it as
     connection error */
  http2_frame_headers_init(&frame.headers,
                             FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
                             2, HTTP2_HCAT_HEADERS, NULL, NULL, 0);
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));
  assert(1 == user_data.invalid_frame_recv_cb_called);
  assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);

  http2_frame_headers_free(&frame.headers, mem);

  http2_session_del(session);

  /* Check malformed headers. The library accept it. */
  http2_session_server_new(&session, &callbacks, &user_data);

  nvlen = ARRLEN(malformed_nva);
  http2_nv_array_copy(&nva, malformed_nva, nvlen, mem);
  http2_frame_headers_init(&frame.headers,
                             FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
                             1, HTTP2_HCAT_HEADERS, NULL, nva, nvlen);
  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(0 == http2_session_on_request_headers_received(session, &frame));
  assert(1 == user_data.begin_headers_cb_called);
  assert(0 == user_data.invalid_frame_recv_cb_called);

  http2_frame_headers_free(&frame.headers, mem);

  http2_session_del(session);

  /* Check client side */
  http2_session_client_new(&session, &callbacks, &user_data);

  /* Receiving peer's idle stream ID is subject to connection error */
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 2,
                             HTTP2_HCAT_REQUEST, NULL, NULL, 0);

  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));
  assert(1 == user_data.invalid_frame_recv_cb_called);
  assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);

  http2_frame_headers_free(&frame.headers, mem);

  http2_session_del(session);

  http2_session_client_new(&session, &callbacks, &user_data);

  /* Receiving our's idle stream ID is subject to connection error */
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 1,
                             HTTP2_HCAT_REQUEST, NULL, NULL, 0);

  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));
  assert(1 == user_data.invalid_frame_recv_cb_called);
  assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);

  http2_frame_headers_free(&frame.headers, mem);

  http2_session_del(session);

  http2_session_client_new(&session, &callbacks, &user_data);

  session.next_stream_id = 5;

  /* Stream ID which is not idle and not in stream map is just
     ignored */
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 3,
                             HTTP2_HCAT_REQUEST, NULL, NULL, 0);

  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));
  assert(0 == user_data.invalid_frame_recv_cb_called);
  assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));

  http2_frame_headers_free(&frame.headers, mem);

  http2_session_del(session);

  http2_session_server_new(&session, &callbacks, &user_data);

  /* Stream ID which is equal to local_last_stream_id is ok. */
  session.local_last_stream_id = 3;

  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 3,
                             HTTP2_HCAT_REQUEST, NULL, NULL, 0);

  assert(0 == http2_session_on_request_headers_received(session, &frame));

  http2_frame_headers_free(&frame.headers, mem);

  /* If GOAWAY has been sent, new stream is ignored */
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 5,
                             HTTP2_HCAT_REQUEST, NULL, NULL, 0);

  session.goaway_flags |= GoAwayFlags.SENT;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));
  assert(0 == user_data.invalid_frame_recv_cb_called);
  assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));

  http2_frame_headers_free(&frame.headers, mem);

  http2_session_del(session);
}

void test_http2_session_on_response_headers_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_stream *stream;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  http2_session_client_new(&session, &callbacks, &user_data);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 1,
                             HTTP2_HCAT_HEADERS, NULL, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  assert(0 == http2_session_on_response_headers_received(session, &frame,
                                                              stream));
  assert(1 == user_data.begin_headers_cb_called);
  assert(HTTP2_STREAM_OPENED == stream.state);

  http2_frame_headers_free(&frame.headers, mem);
  http2_session_del(session);
}

void test_http2_session_on_headers_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_stream *stream;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  http2_session_client_new(&session, &callbacks, &user_data);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);
  http2_stream_shutdown(stream, HTTP2_SHUT_WR);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 1,
                             HTTP2_HCAT_HEADERS, NULL, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  assert(0 == http2_session_on_headers_received(session, &frame, stream));
  assert(1 == user_data.begin_headers_cb_called);
  assert(HTTP2_STREAM_OPENED == stream.state);

  /* stream closed */
  frame.hd.flags |= FrameFlags.END_STREAM;

  assert(0 == http2_session_on_headers_received(session, &frame, stream));
  assert(2 == user_data.begin_headers_cb_called);

  /* Check to see when HTTP2_STREAM_CLOSING, incoming HEADERS is
     discarded. */
  stream = http2_session_open_stream(session, 3, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_CLOSING, NULL);
  frame.hd.stream_id = 3;
  frame.hd.flags = FrameFlags.END_HEADERS;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_headers_received(session, &frame, stream));
  /* See no counters are updated */
  assert(2 == user_data.begin_headers_cb_called);
  assert(0 == user_data.invalid_frame_recv_cb_called);

  /* Server initiated stream */
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  /* half closed (remote) */
  frame.hd.flags = FrameFlags.END_HEADERS | FrameFlags.END_STREAM;
  frame.hd.stream_id = 2;

  assert(0 == http2_session_on_headers_received(session, &frame, stream));
  assert(3 == user_data.begin_headers_cb_called);
  assert(HTTP2_STREAM_OPENING == stream.state);

  http2_stream_shutdown(stream, HTTP2_SHUT_RD);

  /* Further reception of HEADERS is subject to stream error */
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_headers_received(session, &frame, stream));
  assert(1 == user_data.invalid_frame_recv_cb_called);

  http2_frame_headers_free(&frame.headers, mem);

  http2_session_del(session);
}

void test_http2_session_on_push_response_headers_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_stream *stream;
  http2_outbound_item *item;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  http2_session_client_new(&session, &callbacks, &user_data);
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 2,
                             HTTP2_HCAT_HEADERS, NULL, NULL, 0);
  /* http2_session_on_push_response_headers_received assumes
     stream's state is HTTP2_STREAM_RESERVED and session.server is
     0. */

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  assert(0 == http2_session_on_push_response_headers_received(
                     session, &frame, stream));
  assert(1 == user_data.begin_headers_cb_called);
  assert(HTTP2_STREAM_OPENED == stream.state);
  assert(1 == session.num_incoming_streams);
  assert(0 == (stream.flags & HTTP2_STREAM_FLAG_PUSH));

  /* If un-ACKed max concurrent streams limit is exceeded,
     RST_STREAMed */
  session.pending_local_max_concurrent_stream = 1;
  stream = http2_session_open_stream(session, 4, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  frame.hd.stream_id = 4;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_response_headers_received(session, &frame,
                                                              stream));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);
  assert(HTTP2_REFUSED_STREAM == item.frame.rst_stream.error_code);
  assert(1 == session.num_incoming_streams);

  assert(0 == http2_session_send(session));
  assert(1 == session.num_incoming_streams);

  /* If ACKed max concurrent streams limit is exceeded, GOAWAY is
     issued */
  session.local_settings.max_concurrent_streams = 1;

  stream = http2_session_open_stream(session, 6, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  frame.hd.stream_id = 6;

  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_response_headers_received(session, &frame,
                                                              stream));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_PROTOCOL_ERROR == item.frame.goaway.error_code);
  assert(1 == session.num_incoming_streams);

  http2_frame_headers_free(&frame.headers, mem);
  http2_session_del(session);
}

void test_http2_session_on_priority_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_stream *stream, *dep_stream;
  http2_priority_spec pri_spec;
  http2_outbound_item *item;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  http2_session_server_new(&session, &callbacks, &user_data);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  http2_priority_spec_init(&pri_spec, 0, 2, 0);

  http2_frame_priority_init(&frame.priority, 1, &pri_spec);

  /* depend on stream 0 */
  assert(0 == http2_session_on_priority_received(session, &frame));

  assert(2 == stream.weight);

  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  dep_stream = http2_session_open_stream(session, 3, HTTP2_STREAM_FLAG_NONE,
                                           &pri_spec_default,
                                           HTTP2_STREAM_OPENING, NULL);

  frame.hd.stream_id = 2;

  /* using dependency stream */
  http2_priority_spec_init(&frame.priority.pri_spec, 3, 1, 0);

  assert(0 == http2_session_on_priority_received(session, &frame));
  assert(dep_stream == stream.dep_prev);

  /* PRIORITY against idle stream */

  frame.hd.stream_id = 100;

  assert(0 == http2_session_on_priority_received(session, &frame));

  stream = http2_session_get_stream_raw(session, frame.hd.stream_id);

  assert(HTTP2_STREAM_IDLE == stream.state);
  assert(dep_stream == stream.dep_prev);

  http2_frame_priority_free(&frame.priority);
  http2_session_del(session);

  /* Check dep_stream_id == stream_id case */
  http2_session_server_new(&session, &callbacks, &user_data);
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENED, NULL);

  http2_priority_spec_init(&pri_spec, 1, 0, 0);

  http2_frame_priority_init(&frame.priority, 1, &pri_spec);

  assert(0 == http2_session_on_priority_received(session, &frame));

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_GOAWAY == item.frame.hd.type);

  http2_frame_priority_free(&frame.priority);
  http2_session_del(session);
}

void test_http2_session_on_rst_stream_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  http2_session_server_new(&session, &callbacks, &user_data);
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  http2_frame_rst_stream_init(&frame.rst_stream, 1, HTTP2_PROTOCOL_ERROR);

  assert(0 == http2_session_on_rst_stream_received(session, &frame));
  assert(NULL == http2_session_get_stream(session, 1));

  http2_frame_rst_stream_free(&frame.rst_stream);
  http2_session_del(session);
}

void test_http2_session_on_settings_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_stream *stream1, *stream2;
  http2_frame frame;
  const size_t niv = 5;
  http2_settings_entry iv[255];
  http2_outbound_item *item;
  http2_nv nv = MAKE_NV(":authority", "example.org");
  http2_mem *mem;

  mem = http2_mem_default();

  iv[0].settings_id = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 50;

  iv[1].settings_id = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[1].value = 1000000009;

  iv[2].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[2].value = 64 * 1024;

  iv[3].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[3].value = 1024;

  iv[4].settings_id = HTTP2_SETTINGS_ENABLE_PUSH;
  iv[4].value = 0;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, &user_data);
  session.remote_settings.initial_window_size = 16 * 1024;

  stream1 = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                        &pri_spec_default,
                                        HTTP2_STREAM_OPENING, NULL);
  stream2 = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                        &pri_spec_default,
                                        HTTP2_STREAM_OPENING, NULL);
  /* Set window size for each streams and will see how settings
     updates these values */
  stream1.remote_window_size = 16 * 1024;
  stream2.remote_window_size = -48 * 1024;

  http2_frame_settings_init(&frame.settings, FrameFlags.NONE,
                              dup_iv(iv, niv), niv);

  assert(0 == http2_session_on_settings_received(session, &frame, 0));
  assert(1000000009 == session.remote_settings.max_concurrent_streams);
  assert(64 * 1024 == session.remote_settings.initial_window_size);
  assert(1024 == session.remote_settings.header_table_size);
  assert(0 == session.remote_settings.enable_push);

  assert(64 * 1024 == stream1.remote_window_size);
  assert(0 == stream2.remote_window_size);

  frame.settings.iv[2].value = 16 * 1024;

  assert(0 == http2_session_on_settings_received(session, &frame, 0));

  assert(16 * 1024 == stream1.remote_window_size);
  assert(-48 * 1024 == stream2.remote_window_size);

  assert(16 * 1024 == http2_session_get_stream_remote_window_size(
                             session, stream1.stream_id));
  assert(0 == http2_session_get_stream_remote_window_size(
                     session, stream2.stream_id));

  http2_frame_settings_free(&frame.settings, mem);

  http2_session_del(session);

  /* Check ACK with niv > 0 */
  http2_session_server_new(&session, &callbacks, NULL);
  http2_frame_settings_init(&frame.settings, FrameFlags.ACK, dup_iv(iv, 1),
                              1);
  /* Specify inflight_iv deliberately */
  session.inflight_iv = frame.settings.iv;
  session.inflight_niv = frame.settings.niv;

  assert(0 == http2_session_on_settings_received(session, &frame, 0));
  item = http2_session_get_next_ob_item(session);
  assert(item != NULL);
  assert(HTTP2_GOAWAY == item.frame.hd.type);

  session.inflight_iv = NULL;
  session.inflight_niv = -1;

  http2_frame_settings_free(&frame.settings, mem);
  http2_session_del(session);

  /* Check ACK against no inflight SETTINGS */
  http2_session_server_new(&session, &callbacks, NULL);
  http2_frame_settings_init(&frame.settings, FrameFlags.ACK, NULL, 0);

  assert(0 == http2_session_on_settings_received(session, &frame, 0));
  item = http2_session_get_next_ob_item(session);
  assert(item != NULL);
  assert(HTTP2_GOAWAY == item.frame.hd.type);

  http2_frame_settings_free(&frame.settings, mem);
  http2_session_del(session);

  /* Check that 2 SETTINGS_HEADER_TABLE_SIZE 0 and 4096 are included
     and header table size is once cleared to 0. */
  http2_session_client_new(&session, &callbacks, NULL);

  http2_submit_request(session, NULL, &nv, 1, NULL, NULL);

  http2_session_send(session);

  assert(session.hd_deflater.ctx.hd_table.len > 0);

  iv[0].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 0;

  iv[1].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[1].value = 2048;

  http2_frame_settings_init(&frame.settings, FrameFlags.NONE, dup_iv(iv, 2),
                              2);

  assert(0 == http2_session_on_settings_received(session, &frame, 0));

  assert(0 == session.hd_deflater.ctx.hd_table.len);
  assert(2048 == session.hd_deflater.ctx.hd_table_bufsize_max);
  assert(2048 == session.remote_settings.header_table_size);

  http2_frame_settings_free(&frame.settings, mem);
  http2_session_del(session);

  /* Check too large SETTINGS_MAX_FRAME_SIZE */
  http2_session_server_new(&session, &callbacks, NULL);

  iv[0].settings_id = HTTP2_SETTINGS_MAX_FRAME_SIZE;
  iv[0].value = HTTP2_MAX_FRAME_SIZE_MAX + 1;

  http2_frame_settings_init(&frame.settings, FrameFlags.NONE, dup_iv(iv, 1),
                              1);

  assert(0 == http2_session_on_settings_received(session, &frame, 0));

  item = http2_session_get_next_ob_item(session);

  assert(item != NULL);
  assert(HTTP2_GOAWAY == item.frame.hd.type);

  http2_frame_settings_free(&frame.settings, mem);
  http2_session_del(session);
}

void test_http2_session_on_push_promise_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_stream *stream, *promised_stream;
  http2_outbound_item *item;
  http2_nv malformed_nva[] = {MAKE_NV(":path", "\x01")};
  http2_nv *nva;
  size_t nvlen;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_begin_headers_callback = on_begin_headers_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  http2_session_client_new(&session, &callbacks, &user_data);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);
  http2_frame_push_promise_init(&frame.push_promise, FrameFlags.END_HEADERS,
                                  1, 2, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  assert(0 == http2_session_on_push_promise_received(session, &frame));

  assert(1 == user_data.begin_headers_cb_called);
  promised_stream = http2_session_get_stream(session, 2);
  assert(HTTP2_STREAM_RESERVED == promised_stream.state);
  assert(2 == session.last_recv_stream_id);

  /* Attempt to PUSH_PROMISE against half close (remote) */
  http2_stream_shutdown(stream, HTTP2_SHUT_RD);
  frame.push_promise.promised_stream_id = 4;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_promise_received(session, &frame));

  assert(0 == user_data.begin_headers_cb_called);
  assert(1 == user_data.invalid_frame_recv_cb_called);
  assert(NULL == http2_session_get_stream(session, 4));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);
  assert(4 == item.frame.hd.stream_id);
  assert(HTTP2_PROTOCOL_ERROR == item.frame.rst_stream.error_code);
  assert(0 == http2_session_send(session));
  assert(4 == session.last_recv_stream_id);

  /* Attempt to PUSH_PROMISE against stream in closing state */
  stream.shut_flags = HTTP2_SHUT_NONE;
  stream.state = HTTP2_STREAM_CLOSING;
  frame.push_promise.promised_stream_id = 6;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_promise_received(session, &frame));

  assert(0 == user_data.begin_headers_cb_called);
  assert(NULL == http2_session_get_stream(session, 6));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);
  assert(6 == item.frame.hd.stream_id);
  assert(HTTP2_REFUSED_STREAM == item.frame.rst_stream.error_code);
  assert(0 == http2_session_send(session));

  /* Attempt to PUSH_PROMISE against non-existent stream */
  frame.hd.stream_id = 3;
  frame.push_promise.promised_stream_id = 8;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_promise_received(session, &frame));

  assert(0 == user_data.begin_headers_cb_called);
  assert(NULL == http2_session_get_stream(session, 8));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(0 == item.frame.hd.stream_id);
  assert(HTTP2_PROTOCOL_ERROR == item.frame.goaway.error_code);
  assert(0 == http2_session_send(session));

  http2_session_del(session);

  http2_session_client_new(&session, &callbacks, &user_data);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  /* Same ID twice */
  stream.state = HTTP2_STREAM_OPENING;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_promise_received(session, &frame));

  assert(0 == user_data.begin_headers_cb_called);
  assert(NULL == http2_session_get_stream(session, 8));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_PROTOCOL_ERROR == item.frame.goaway.error_code);
  assert(0 == http2_session_send(session));

  /* After GOAWAY, PUSH_PROMISE will be discarded */
  frame.push_promise.promised_stream_id = 10;

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_promise_received(session, &frame));

  assert(0 == user_data.begin_headers_cb_called);
  assert(NULL == http2_session_get_stream(session, 10));
  assert(NULL == http2_session_get_next_ob_item(session));

  http2_frame_push_promise_free(&frame.push_promise, mem);
  http2_session_del(session);

  http2_session_client_new(&session, &callbacks, &user_data);

  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  /* Attempt to PUSH_PROMISE against reserved (remote) stream */
  http2_frame_push_promise_init(&frame.push_promise, FrameFlags.END_HEADERS,
                                  2, 4, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_promise_received(session, &frame));

  assert(0 == user_data.begin_headers_cb_called);
  assert(1 == user_data.invalid_frame_recv_cb_called);

  http2_frame_push_promise_free(&frame.push_promise, mem);
  http2_session_del(session);

  /* Disable PUSH */
  http2_session_client_new(&session, &callbacks, &user_data);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  session.local_settings.enable_push = 0;

  http2_frame_push_promise_init(&frame.push_promise, FrameFlags.END_HEADERS,
                                  1, 2, NULL, 0);

  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_push_promise_received(session, &frame));

  assert(0 == user_data.begin_headers_cb_called);
  assert(1 == user_data.invalid_frame_recv_cb_called);

  http2_frame_push_promise_free(&frame.push_promise, mem);
  http2_session_del(session);

  /* Check malformed headers. We accept malformed headers */
  http2_session_client_new(&session, &callbacks, &user_data);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);
  nvlen = ARRLEN(malformed_nva);
  http2_nv_array_copy(&nva, malformed_nva, nvlen, mem);
  http2_frame_push_promise_init(&frame.push_promise, FrameFlags.END_HEADERS,
                                  1, 2, nva, nvlen);
  user_data.begin_headers_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;
  assert(0 == http2_session_on_push_promise_received(session, &frame));

  assert(1 == user_data.begin_headers_cb_called);
  assert(0 == user_data.invalid_frame_recv_cb_called);

  http2_frame_push_promise_free(&frame.push_promise, mem);
  http2_session_del(session);
}

void test_http2_session_on_ping_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_outbound_item *top;
  const ubyte opaque_data[] = "01234567";

  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;

  http2_session_client_new(&session, &callbacks, &user_data);
  http2_frame_ping_init(&frame.ping, FrameFlags.ACK, opaque_data);

  assert(0 == http2_session_on_ping_received(session, &frame));
  assert(1 == user_data.frame_recv_cb_called);

  /* Since this ping frame has PONG flag set, no further action is
     performed. */
  assert(NULL == http2_session_get_ob_pq_top(session));

  /* Clear the flag, and receive it again */
  frame.hd.flags = FrameFlags.NONE;

  assert(0 == http2_session_on_ping_received(session, &frame));
  assert(2 == user_data.frame_recv_cb_called);
  top = http2_session_get_ob_pq_top(session);
  assert(HTTP2_PING == top.frame.hd.type);
  assert(FrameFlags.ACK == top.frame.hd.flags);
  assert(memcmp(opaque_data, top.frame.ping.opaque_data, 8) == 0);

  http2_frame_ping_free(&frame.ping);
  http2_session_del(session);
}

void test_http2_session_on_goaway_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  int i;
  http2_mem *mem;

  mem = http2_mem_default();
  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;

  http2_session_client_new(&session, &callbacks, &user_data);

  for (i = 1; i <= 7; ++i) {
    open_stream(session, i);
  }

  http2_frame_goaway_init(&frame.goaway, 3, HTTP2_PROTOCOL_ERROR, NULL, 0);

  user_data.stream_close_cb_called = 0;

  assert(0 == http2_session_on_goaway_received(session, &frame));

  assert(1 == user_data.frame_recv_cb_called);
  assert(3 == session.remote_last_stream_id);
  /* on_stream_close should be callsed for 2 times (stream 5 and 7) */
  assert(2 == user_data.stream_close_cb_called);

  assert(NULL != http2_session_get_stream(session, 1));
  assert(NULL != http2_session_get_stream(session, 2));
  assert(NULL != http2_session_get_stream(session, 3));
  assert(NULL != http2_session_get_stream(session, 4));
  assert(NULL == http2_session_get_stream(session, 5));
  assert(NULL != http2_session_get_stream(session, 6));
  assert(NULL == http2_session_get_stream(session, 7));

  http2_frame_goaway_free(&frame.goaway, mem);
  http2_session_del(session);
}

void test_http2_session_on_window_update_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_frame frame;
  http2_stream *stream;
  http2_outbound_item *data_item;
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
  user_data.frame_recv_cb_called = 0;
  user_data.invalid_frame_recv_cb_called = 0;

  http2_session_client_new(&session, &callbacks, &user_data);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);

  data_item = create_data_ob_item();

  assert(0 == http2_stream_attach_item(stream, data_item, session));

  http2_frame_window_update_init(&frame.window_update, FrameFlags.NONE, 1,
                                   16 * 1024);

  assert(0 == http2_session_on_window_update_received(session, &frame));
  assert(1 == user_data.frame_recv_cb_called);
  assert(HTTP2_INITIAL_WINDOW_SIZE + 16 * 1024 ==
            stream.remote_window_size);

  assert(0 ==
            http2_stream_defer_item(
                stream, HTTP2_STREAM_FLAG_DEFERRED_FLOW_CONTROL, session));

  assert(0 == http2_session_on_window_update_received(session, &frame));
  assert(2 == user_data.frame_recv_cb_called);
  assert(HTTP2_INITIAL_WINDOW_SIZE + 16 * 1024 * 2 ==
            stream.remote_window_size);
  assert(0 == (stream.flags & HTTP2_STREAM_FLAG_DEFERRED_ALL));

  http2_frame_window_update_free(&frame.window_update);

  /* Receiving WINDOW_UPDATE on reserved (remote) stream is a
     connection error */
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);

  http2_frame_window_update_init(&frame.window_update, FrameFlags.NONE, 2,
                                   4096);

  assert(!(session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
  assert(0 == http2_session_on_window_update_received(session, &frame));
  assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);

  http2_frame_window_update_free(&frame.window_update);

  http2_session_del(session);

  /* Receiving WINDOW_UPDATE on reserved (local) stream is allowed */
  http2_session_server_new(&session, &callbacks, &user_data);

  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);

  http2_frame_window_update_init(&frame.window_update, FrameFlags.NONE, 2,
                                   4096);

  assert(0 == http2_session_on_window_update_received(session, &frame));
  assert(!(session.goaway_flags & GoAwayFlags.TERM_ON_SEND));

  assert(HTTP2_INITIAL_WINDOW_SIZE + 4096 == stream.remote_window_size);

  http2_frame_window_update_free(&frame.window_update);

  http2_session_del(session);
}

void test_http2_session_on_data_received(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_outbound_item *top;
  http2_stream *stream;
  http2_frame frame;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));

  http2_session_client_new(&session, &callbacks, &user_data);
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  frame.hd = FrameHeader(4096, HTTP2_DATA, FrameFlags.NONE, 2);

  assert(0 == http2_session_on_data_received(session, &frame));
  assert(0 == stream.shut_flags);

  frame.hd.flags = FrameFlags.END_STREAM;

  assert(0 == http2_session_on_data_received(session, &frame));
  assert(HTTP2_SHUT_RD == stream.shut_flags);

  /* If HTTP2_STREAM_CLOSING state, DATA frame is discarded. */
  stream = http2_session_open_stream(session, 4, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_CLOSING, NULL);

  frame.hd.flags = FrameFlags.NONE;
  frame.hd.stream_id = 4;

  assert(0 == http2_session_on_data_received(session, &frame));
  assert(NULL == http2_session_get_ob_pq_top(session));

  /* Check INVALID_STREAM case: DATA frame with stream ID which does
     not exist. */

  frame.hd.stream_id = 6;

  assert(0 == http2_session_on_data_received(session, &frame));
  top = http2_session_get_ob_pq_top(session);
  /* DATA against nonexistent stream is just ignored for now */
  assert(top == NULL);
  /* assert(HTTP2_RST_STREAM == top.frame.hd.type); */
  /* assert(HTTP2_PROTOCOL_ERROR == top.frame.rst_stream.error_code); */

  http2_session_del(session);
}

void test_http2_session_send_headers_start_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_frame *frame;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS,
                             session.next_stream_id, HTTP2_HCAT_REQUEST,
                             NULL, NULL, 0);
  session.next_stream_id += 2;

  http2_session_add_item(session, item);
  assert(0 == http2_session_send(session));
  stream = http2_session_get_stream(session, 1);
  assert(HTTP2_STREAM_OPENING == stream.state);

  http2_session_del(session);
}

void test_http2_session_send_headers_reply(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_frame *frame;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  assert(0 == http2_session_client_new(&session, &callbacks, NULL));
  http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 2,
                             HTTP2_HCAT_HEADERS, NULL, NULL, 0);
  http2_session_add_item(session, item);
  assert(0 == http2_session_send(session));
  stream = http2_session_get_stream(session, 2);
  assert(HTTP2_STREAM_OPENED == stream.state);

  http2_session_del(session);
}

void test_http2_session_send_headers_frame_size_error(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_frame *frame;
  http2_nv *nva;
  size_t nvlen;
  size_t vallen = HTTP2_HD_MAX_NV;
  http2_nv nv[28];
  size_t nnv = ARRLEN(nv);
  size_t i;
  my_user_data ud;
  http2_mem *mem;

  mem = http2_mem_default();

  for (i = 0; i < nnv; ++i) {
    nv[i].name = (ubyte *)"header";
    nv[i].namelen = strlen((const char *)nv[i].name);
    nv[i].value = malloc(vallen + 1);
    memset(nv[i].value, '0' + (int)i, vallen);
    nv[i].value[vallen] = '\0';
    nv[i].valuelen = vallen;
    nv[i].flags = HTTP2_NV_FLAG_NONE;
  }

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;

  http2_session_client_new(&session, &callbacks, &ud);
  nvlen = nnv;
  http2_nv_array_copy(&nva, nv, nvlen, mem);

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS,
                             session.next_stream_id, HTTP2_HCAT_REQUEST,
                             NULL, nva, nvlen);

  session.next_stream_id += 2;

  http2_session_add_item(session, item);

  ud.frame_not_send_cb_called = 0;

  assert(0 == http2_session_send(session));

  assert(1 == ud.frame_not_send_cb_called);
  assert(HTTP2_HEADERS == ud.not_sent_frame_type);
  assert(HTTP2_ERR_FRAME_SIZE_ERROR == ud.not_sent_error);

  for (i = 0; i < nnv; ++i) {
    free(nv[i].value);
  }
  http2_session_del(session);
}

void test_http2_session_send_headers_push_reply(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_frame *frame;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  assert(0 == http2_session_server_new(&session, &callbacks, NULL));
  http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_RESERVED, NULL);

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 2,
                             HTTP2_HCAT_HEADERS, NULL, NULL, 0);
  http2_session_add_item(session, item);
  assert(0 == session.num_outgoing_streams);
  assert(0 == http2_session_send(session));
  assert(1 == session.num_outgoing_streams);
  stream = http2_session_get_stream(session, 2);
  assert(HTTP2_STREAM_OPENED == stream.state);
  assert(0 == (stream.flags & HTTP2_STREAM_FLAG_PUSH));
  http2_session_del(session);
}

void test_http2_session_send_rst_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_outbound_item *item;
  http2_frame *frame;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  http2_session_client_new(&session, &callbacks, &user_data);
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_rst_stream_init(&frame.rst_stream, 1, HTTP2_PROTOCOL_ERROR);
  http2_session_add_item(session, item);
  assert(0 == http2_session_send(session));

  assert(NULL == http2_session_get_stream(session, 1));

  http2_session_del(session);
}

void test_http2_session_send_push_promise(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_frame *frame;
  http2_stream *stream;
  http2_settings_entry iv;
  my_user_data ud;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;

  http2_session_server_new(&session, &callbacks, &ud);
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_push_promise_init(&frame.push_promise,
                                  FrameFlags.END_HEADERS, 1,
                                  session.next_stream_id, NULL, 0);

  session.next_stream_id += 2;

  http2_session_add_item(session, item);

  assert(0 == http2_session_send(session));
  stream = http2_session_get_stream(session, 2);
  assert(HTTP2_STREAM_RESERVED == stream.state);

  /* Received ENABLE_PUSH = 0 */
  iv.settings_id = HTTP2_SETTINGS_ENABLE_PUSH;
  iv.value = 0;
  frame = malloc(sizeof(http2_frame));
  http2_frame_settings_init(&frame.settings, FrameFlags.NONE,
                              dup_iv(&iv, 1), 1);
  http2_session_on_settings_received(session, frame, 1);
  http2_frame_settings_free(&frame.settings, mem);
  free(frame);

  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_push_promise_init(&frame.push_promise,
                                  FrameFlags.END_HEADERS, 1, -1, NULL, 0);
  http2_session_add_item(session, item);

  ud.frame_not_send_cb_called = 0;
  assert(0 == http2_session_send(session));

  assert(1 == ud.frame_not_send_cb_called);
  assert(HTTP2_PUSH_PROMISE == ud.not_sent_frame_type);
  assert(HTTP2_ERR_PUSH_DISABLED == ud.not_sent_error);

  http2_session_del(session);

  /* PUSH_PROMISE from client is error */
  http2_session_client_new(&session, &callbacks, &ud);
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  item = malloc(sizeof(http2_outbound_item));

  http2_session_outbound_item_init(session, item);

  frame = &item.frame;

  http2_frame_push_promise_init(&frame.push_promise,
                                  FrameFlags.END_HEADERS, 1, -1, NULL, 0);
  http2_session_add_item(session, item);

  assert(0 == http2_session_send(session));
  assert(NULL == http2_session_get_stream(session, 3));

  http2_session_del(session);
}

void test_http2_session_is_my_stream_id(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  http2_session_server_new(&session, &callbacks, NULL);

  assert(0 == http2_session_is_my_stream_id(session, 0));
  assert(0 == http2_session_is_my_stream_id(session, 1));
  assert(1 == http2_session_is_my_stream_id(session, 2));

  http2_session_del(session);

  http2_session_client_new(&session, &callbacks, NULL);

  assert(0 == http2_session_is_my_stream_id(session, 0));
  assert(1 == http2_session_is_my_stream_id(session, 1));
  assert(0 == http2_session_is_my_stream_id(session, 2));

  http2_session_del(session);
}

void test_http2_session_upgrade(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  ubyte settings_payload[128];
  size_t settings_payloadlen;
  http2_settings_entry iv[16];
  http2_stream *stream;
  http2_outbound_item *item;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  iv[0].settings_id = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 1;
  iv[1].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 4095;
  settings_payloadlen = http2_pack_settings_payload(
      settings_payload, sizeof(settings_payload), iv, 2);

  /* Check client side */
  http2_session_client_new(&session, &callbacks, NULL);
  assert(0 == http2_session_upgrade(session, settings_payload,
                                         settings_payloadlen, &callbacks));
  stream = http2_session_get_stream(session, 1);
  assert(stream != NULL);
  assert(&callbacks == stream.stream_user_data);
  assert(HTTP2_SHUT_WR == stream.shut_flags);
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_SETTINGS == item.frame.hd.type);
  assert(2 == item.frame.settings.niv);
  assert(HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS ==
            item.frame.settings.iv[0].settings_id);
  assert(1 == item.frame.settings.iv[0].value);
  assert(HTTP2_SETTINGS_INITIAL_WINDOW_SIZE ==
            item.frame.settings.iv[1].settings_id);
  assert(4095 == item.frame.settings.iv[1].value);

  /* Call http2_session_upgrade() again is error */
  assert(HTTP2_ERR_PROTO ==
            http2_session_upgrade(session, settings_payload,
                                    settings_payloadlen, &callbacks));
  http2_session_del(session);

  /* Check server side */
  http2_session_server_new(&session, &callbacks, NULL);
  assert(0 == http2_session_upgrade(session, settings_payload,
                                         settings_payloadlen, &callbacks));
  stream = http2_session_get_stream(session, 1);
  assert(stream != NULL);
  assert(NULL == stream.stream_user_data);
  assert(HTTP2_SHUT_RD == stream.shut_flags);
  assert(NULL == http2_session_get_next_ob_item(session));
  assert(1 == session.remote_settings.max_concurrent_streams);
  assert(4095 == session.remote_settings.initial_window_size);
  /* Call http2_session_upgrade() again is error */
  assert(HTTP2_ERR_PROTO ==
            http2_session_upgrade(session, settings_payload,
                                    settings_payloadlen, &callbacks));
  http2_session_del(session);

  /* Empty SETTINGS is OK */
  settings_payloadlen = http2_pack_settings_payload(
      settings_payload, sizeof(settings_payload), NULL, 0);

  http2_session_client_new(&session, &callbacks, NULL);
  assert(0 == http2_session_upgrade(session, settings_payload,
                                         settings_payloadlen, NULL));
  http2_session_del(session);
}

void test_http2_session_reprioritize_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_stream *stream;
  http2_stream *dep_stream;
  http2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  http2_priority_spec_init(&pri_spec, 0, 10, 0);

  http2_session_reprioritize_stream(session, stream, &pri_spec);

  assert(10 == stream.weight);
  assert(NULL == stream.dep_prev);

  /* If depenency to idle stream which is not in depdenency tree yet */

  http2_priority_spec_init(&pri_spec, 3, 99, 0);

  http2_session_reprioritize_stream(session, stream, &pri_spec);

  assert(99 == stream.weight);
  assert(3 == stream.dep_prev.stream_id);

  dep_stream = http2_session_get_stream_raw(session, 3);

  assert(DEFAULT_WEIGHT == dep_stream.weight);

  dep_stream = open_stream(session, 3);

  /* Change weight */
  pri_spec.weight = 128;

  http2_session_reprioritize_stream(session, stream, &pri_spec);

  assert(128 == stream.weight);
  assert(dep_stream == stream.dep_prev);

  /* Test circular dependency; stream 1 is first removed and becomes
     root.  Then stream 3 depends on it. */
  http2_priority_spec_init(&pri_spec, 1, 1, 0);

  http2_session_reprioritize_stream(session, dep_stream, &pri_spec);

  assert(1 == dep_stream.weight);
  assert(stream == dep_stream.dep_prev);

  /* Making priority to closed stream will result in default
     priority */
  session.last_recv_stream_id = 9;

  http2_priority_spec_init(&pri_spec, 5, 5, 0);

  http2_session_reprioritize_stream(session, stream, &pri_spec);

  assert(DEFAULT_WEIGHT == stream.weight);

  http2_session_del(session);
}

void test_http2_session_reprioritize_stream_with_idle_stream_dep(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;
  http2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  session.pending_local_max_concurrent_stream = 1;

  http2_priority_spec_init(&pri_spec, 101, 10, 0);

  http2_session_reprioritize_stream(session, stream, &pri_spec);

  /* idle stream is not counteed to max concurrent streams */

  assert(10 == stream.weight);
  assert(101 == stream.dep_prev.stream_id);

  stream = http2_session_get_stream_raw(session, 101);

  assert(DEFAULT_WEIGHT == stream.weight);

  http2_session_del(session);
}

void test_http2_submit_data(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  my_user_data ud;
  http2_frame *frame;
  http2_frame_hd hd;
  http2_active_outbound_item *aob;
  http2_bufs *framebufs;
  http2_buf *buf;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = HTTP2_DATA_PAYLOADLEN * 2;
  assert(0 == http2_session_client_new(&session, &callbacks, &ud));
  aob = &session.aob;
  framebufs = &aob.framebufs;

  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(
      0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));

  ud.block_count = 0;
  assert(0 == http2_session_send(session));
  frame = &aob.item.frame;

  buf = &framebufs.head.buf;
  http2_frame_unpack_frame_hd(&hd, buf.pos);

  assert(FrameFlags.NONE == hd.flags);
  assert(FrameFlags.NONE == frame.hd.flags);
  /* aux_data.data.flags has these flags */
  assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);

  http2_session_del(session);
}

void test_http2_submit_data_read_length_too_large(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  my_user_data ud;
  http2_frame *frame;
  http2_frame_hd hd;
  http2_active_outbound_item *aob;
  http2_bufs *framebufs;
  http2_buf *buf;
  size_t payloadlen;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.read_length_callback = too_large_data_source_length_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = HTTP2_DATA_PAYLOADLEN * 2;
  assert(0 == http2_session_client_new(&session, &callbacks, &ud));
  aob = &session.aob;
  framebufs = &aob.framebufs;

  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(
      0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));

  ud.block_count = 0;
  assert(0 == http2_session_send(session));
  frame = &aob.item.frame;

  buf = &framebufs.head.buf;
  http2_frame_unpack_frame_hd(&hd, buf.pos);

  assert(FrameFlags.NONE == hd.flags);
  assert(FrameFlags.NONE == frame.hd.flags);
  assert(16384 == hd.length)
  /* aux_data.data.flags has these flags */
  assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);

  http2_session_del(session);

  /* Check that buffers are expanded */
  assert(0 == http2_session_client_new(&session, &callbacks, &ud));

  ud.data_source_length = HTTP2_MAX_FRAME_SIZE_MAX;

  session.remote_settings.max_frame_size = HTTP2_MAX_FRAME_SIZE_MAX;

  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(
      0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));

  ud.block_count = 0;
  assert(0 == http2_session_send(session));

  aob = &session.aob;

  frame = &aob.item.frame;

  framebufs = &aob.framebufs;

  buf = &framebufs.head.buf;
  http2_frame_unpack_frame_hd(&hd, buf.pos);

  payloadlen = http2_min(HTTP2_INITIAL_CONNECTION_WINDOW_SIZE,
                           HTTP2_INITIAL_WINDOW_SIZE);

  assert(HTTP2_FRAME_HDLEN + 1 + payloadlen ==
            (size_t)http2_buf_cap(buf));
  assert(FrameFlags.NONE == hd.flags);
  assert(FrameFlags.NONE == frame.hd.flags);
  assert(payloadlen == hd.length);
  /* aux_data.data.flags has these flags */
  assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);

  http2_session_del(session);
}

void test_http2_submit_data_read_length_smallest(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  my_user_data ud;
  http2_frame *frame;
  http2_frame_hd hd;
  http2_active_outbound_item *aob;
  http2_bufs *framebufs;
  http2_buf *buf;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.read_length_callback = smallest_length_data_source_length_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = HTTP2_DATA_PAYLOADLEN * 2;
  assert(0 == http2_session_client_new(&session, &callbacks, &ud));
  aob = &session.aob;
  framebufs = &aob.framebufs;

  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(
      0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));

  ud.block_count = 0;
  assert(0 == http2_session_send(session));
  frame = &aob.item.frame;

  buf = &framebufs.head.buf;
  http2_frame_unpack_frame_hd(&hd, buf.pos);

  assert(FrameFlags.NONE == hd.flags);
  assert(FrameFlags.NONE == frame.hd.flags);
  assert(1 == hd.length)
  /* aux_data.data.flags has these flags */
  assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);

  http2_session_del(session);
}

static size_t submit_data_twice_data_source_read_callback(
    http2_session *session, int stream_id, ubyte *buf,
    size_t len, uint *data_flags, http2_data_source *source,
    void *user_data) {
  *data_flags |= HTTP2_DATA_FLAG_EOF;
  return http2_min(len, 16);
}

static int submit_data_twice_on_frame_send_callback(http2_session *session,
                                                    const http2_frame *frame,
                                                    void *user_data) {
  static int called = 0;
  int rv;
  DataProvider data_prd;

  if (called == 0) {
    called = 1;

    data_prd.read_callback = submit_data_twice_data_source_read_callback;

    rv = http2_submit_data(session, FrameFlags.END_STREAM,
                             frame.hd.stream_id, &data_prd);
    assert(0 == rv);
  }

  return 0;
}

void test_http2_submit_data_twice(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  my_user_data ud;
  accumulator acc;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.on_frame_send_callback = submit_data_twice_on_frame_send_callback;

  data_prd.read_callback = submit_data_twice_data_source_read_callback;

  acc.length = 0;
  ud.acc = &acc;

  assert(0 == http2_session_client_new(&session, &callbacks, &ud));

  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  assert(0 == http2_submit_data(session, FrameFlags.NONE, 1, &data_prd));

  assert(0 == http2_session_send(session));

  /* We should have sent 2 DATA frame with 16 bytes payload each */
  assert(HTTP2_FRAME_HDLEN * 2 + 16 * 2 == acc.length);

  http2_session_del(session);
}

void test_http2_submit_request_with_data(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  my_user_data ud;
  http2_outbound_item *item;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64 * 1024 - 1;
  assert(0 == http2_session_client_new(&session, &callbacks, &ud));
  assert(1 == http2_submit_request(session, NULL, reqnv, ARRLEN(reqnv),
                                        &data_prd, NULL));
  item = http2_session_get_next_ob_item(session);
  assert(ARRLEN(reqnv) == item.frame.headers.nvlen);
  assert_nv_equal(reqnv, item.frame.headers.nva, item.frame.headers.nvlen);
  assert(0 == http2_session_send(session));
  assert(0 == ud.data_source_length);

  http2_session_del(session);
}

void test_http2_submit_request_without_data(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  accumulator acc;
  DataProvider data_prd = {{-1}, NULL};
  http2_outbound_item *item;
  my_user_data ud;
  http2_frame frame;
  http2_hd_inflater inflater;
  nva_out out;
  http2_bufs bufs;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  assert(0 == http2_session_client_new(&session, &callbacks, &ud));

  http2_hd_inflate_init(&inflater, mem);
  assert(1 == http2_submit_request(session, NULL, reqnv, ARRLEN(reqnv),
                                        &data_prd, NULL));
  item = http2_session_get_next_ob_item(session);
  assert(ARRLEN(reqnv) == item.frame.headers.nvlen);
  assert_nv_equal(reqnv, item.frame.headers.nva, item.frame.headers.nvlen);
  assert(item.frame.hd.flags & FrameFlags.END_STREAM);

  assert(0 == http2_session_send(session));
  assert(0 == unpack_frame(&frame, acc.buf, acc.length));

  http2_bufs_add(&bufs, acc.buf, acc.length);
  inflate_hd(&inflater, &out, &bufs, HTTP2_FRAME_HDLEN);

  assert(ARRLEN(reqnv) == out.nvlen);
  assert_nv_equal(reqnv, out.nva, out.nvlen);
  http2_frame_headers_free(&frame.headers, mem);
  nva_out_reset(&out);

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
  http2_session_del(session);
}

void test_http2_submit_response_with_data(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  my_user_data ud;
  http2_outbound_item *item;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 64 * 1024 - 1;
  assert(0 == http2_session_server_new(&session, &callbacks, &ud));
  http2_session_open_stream(session, 1, FrameFlags.END_STREAM,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(0 == http2_submit_response(session, 1, resnv, ARRLEN(resnv),
                                         &data_prd));
  item = http2_session_get_next_ob_item(session);
  assert(ARRLEN(resnv) == item.frame.headers.nvlen);
  assert_nv_equal(resnv, item.frame.headers.nva, item.frame.headers.nvlen);
  assert(0 == http2_session_send(session));
  assert(0 == ud.data_source_length);

  http2_session_del(session);
}

void test_http2_submit_response_without_data(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  accumulator acc;
  DataProvider data_prd = {{-1}, NULL};
  http2_outbound_item *item;
  my_user_data ud;
  http2_frame frame;
  http2_hd_inflater inflater;
  nva_out out;
  http2_bufs bufs;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  assert(0 == http2_session_server_new(&session, &callbacks, &ud));

  http2_hd_inflate_init(&inflater, mem);
  http2_session_open_stream(session, 1, FrameFlags.END_STREAM,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(0 == http2_submit_response(session, 1, resnv, ARRLEN(resnv),
                                         &data_prd));
  item = http2_session_get_next_ob_item(session);
  assert(ARRLEN(resnv) == item.frame.headers.nvlen);
  assert_nv_equal(resnv, item.frame.headers.nva, item.frame.headers.nvlen);
  assert(item.frame.hd.flags & FrameFlags.END_STREAM);

  assert(0 == http2_session_send(session));
  assert(0 == unpack_frame(&frame, acc.buf, acc.length));

  http2_bufs_add(&bufs, acc.buf, acc.length);
  inflate_hd(&inflater, &out, &bufs, HTTP2_FRAME_HDLEN);

  assert(ARRLEN(resnv) == out.nvlen);
  assert_nv_equal(resnv, out.nva, out.nvlen);

  nva_out_reset(&out);
  http2_bufs_free(&bufs);
  http2_frame_headers_free(&frame.headers, mem);
  http2_hd_inflate_free(&inflater);
  http2_session_del(session);
}

void test_http2_submit_headers_start_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  assert(0 == http2_session_client_new(&session, &callbacks, NULL));
  assert(1 == http2_submit_headers(session, FrameFlags.END_STREAM, -1,
                                        NULL, reqnv, ARRLEN(reqnv), NULL));
  item = http2_session_get_next_ob_item(session);
  assert(ARRLEN(reqnv) == item.frame.headers.nvlen);
  assert_nv_equal(reqnv, item.frame.headers.nva, item.frame.headers.nvlen);
  assert((FrameFlags.END_HEADERS | FrameFlags.END_STREAM) ==
            item.frame.hd.flags);
  assert(0 == (item.frame.hd.flags & FrameFlags.PRIORITY));

  http2_session_del(session);
}

void test_http2_submit_headers_reply(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_outbound_item *item;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  assert(0 == http2_session_server_new(&session, &callbacks, &ud));
  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1,
                                        NULL, resnv, ARRLEN(resnv), NULL));
  item = http2_session_get_next_ob_item(session);
  assert(ARRLEN(resnv) == item.frame.headers.nvlen);
  assert_nv_equal(resnv, item.frame.headers.nva, item.frame.headers.nvlen);
  assert((FrameFlags.END_STREAM | FrameFlags.END_HEADERS) ==
            item.frame.hd.flags);

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  /* The transimission will be canceled because the stream 1 is not
     open. */
  assert(0 == http2_session_send(session));
  assert(0 == ud.frame_send_cb_called);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1,
                                        NULL, resnv, ARRLEN(resnv), NULL));
  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_send_cb_called);
  assert(HTTP2_HEADERS == ud.sent_frame_type);
  assert(stream.shut_flags & HTTP2_SHUT_WR);

  http2_session_del(session);
}

void test_http2_submit_headers_push_reply(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_stream *stream;
  int foo;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  assert(0 == http2_session_server_new(&session, &callbacks, &ud));
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  assert(0 == http2_submit_headers(session, FrameFlags.NONE, 2, NULL,
                                        resnv, ARRLEN(resnv), &foo));

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_send_cb_called);
  assert(HTTP2_HEADERS == ud.sent_frame_type);
  assert(HTTP2_STREAM_OPENED == stream.state);
  assert(&foo == stream.stream_user_data);

  http2_session_del(session);

  /* Sending HEADERS from client against stream in reserved state is
     error */
  assert(0 == http2_session_client_new(&session, &callbacks, &ud));
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  assert(0 == http2_submit_headers(session, FrameFlags.NONE, 2, NULL,
                                        reqnv, ARRLEN(reqnv), NULL));

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  assert(0 == http2_session_send(session));
  assert(0 == ud.frame_send_cb_called);

  http2_session_del(session);
}

void test_http2_submit_headers(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_outbound_item *item;
  http2_stream *stream;
  accumulator acc;
  http2_frame frame;
  http2_hd_inflater inflater;
  nva_out out;
  http2_bufs bufs;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  acc.length = 0;
  ud.acc = &acc;
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  assert(0 == http2_session_client_new(&session, &callbacks, &ud));

  http2_hd_inflate_init(&inflater, mem);
  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1,
                                        NULL, reqnv, ARRLEN(reqnv), NULL));
  item = http2_session_get_next_ob_item(session);
  assert(ARRLEN(reqnv) == item.frame.headers.nvlen);
  assert_nv_equal(reqnv, item.frame.headers.nva, item.frame.headers.nvlen);
  assert((FrameFlags.END_STREAM | FrameFlags.END_HEADERS) ==
            item.frame.hd.flags);

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  /* The transimission will be canceled because the stream 1 is not
     open. */
  assert(0 == http2_session_send(session));
  assert(0 == ud.frame_send_cb_called);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1,
                                        NULL, reqnv, ARRLEN(reqnv), NULL));
  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_send_cb_called);
  assert(HTTP2_HEADERS == ud.sent_frame_type);
  assert(stream.shut_flags & HTTP2_SHUT_WR);

  assert(0 == unpack_frame(&frame, acc.buf, acc.length));

  http2_bufs_add(&bufs, acc.buf, acc.length);
  inflate_hd(&inflater, &out, &bufs, HTTP2_FRAME_HDLEN);

  assert(ARRLEN(reqnv) == out.nvlen);
  assert_nv_equal(reqnv, out.nva, out.nvlen);

  nva_out_reset(&out);
  http2_bufs_free(&bufs);
  http2_frame_headers_free(&frame.headers, mem);

  http2_hd_inflate_free(&inflater);
  http2_session_del(session);
}

void test_http2_submit_headers_continuation(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_nv nv[] = {
      MAKE_NV("h1", ""), MAKE_NV("h1", ""), MAKE_NV("h1", ""),
      MAKE_NV("h1", ""), MAKE_NV("h1", ""), MAKE_NV("h1", ""),
      MAKE_NV("h1", ""),
  };
  http2_outbound_item *item;
  ubyte data[4096];
  size_t i;
  my_user_data ud;

  memset(data, '0', sizeof(data));
  for (i = 0; i < ARRLEN(nv); ++i) {
    nv[i].valuelen = sizeof(data);
    nv[i].value = data;
  }

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  assert(0 == http2_session_client_new(&session, &callbacks, &ud));
  assert(1 == http2_submit_headers(session, FrameFlags.END_STREAM, -1,
                                        NULL, nv, ARRLEN(nv), NULL));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_HEADERS == item.frame.hd.type);
  assert((FrameFlags.END_STREAM | FrameFlags.END_HEADERS) ==
            item.frame.hd.flags);
  assert(0 == (item.frame.hd.flags & FrameFlags.PRIORITY));

  ud.frame_send_cb_called = 0;
  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_send_cb_called);

  http2_session_del(session);
}

void test_http2_submit_priority(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;
  my_user_data ud;
  http2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;

  http2_session_client_new(&session, &callbacks, &ud);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  http2_priority_spec_init(&pri_spec, 0, 3, 0);

  /* depends on stream 0 */
  assert(0 == http2_submit_priority(session, 1, &pri_spec));
  assert(0 == http2_session_send(session));
  assert(3 == stream.weight);

  /* submit against idle stream */
  assert(0 == http2_submit_priority(session, 3, &pri_spec));

  ud.frame_send_cb_called = 0;
  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_send_cb_called);

  http2_session_del(session);
}

void test_http2_submit_settings(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_outbound_item *item;
  http2_frame *frame;
  http2_settings_entry iv[7];
  http2_frame ack_frame;
  const int UNKNOWN_ID = 1000000007;
  http2_mem *mem;

  mem = http2_mem_default();

  iv[0].settings_id = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = 5;

  iv[1].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 16 * 1024;

  iv[2].settings_id = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[2].value = 50;

  iv[3].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[3].value = 0;

  iv[4].settings_id = UNKNOWN_ID;
  iv[4].value = 999;

  iv[5].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[5].value = (uint)HTTP2_MAX_WINDOW_SIZE + 1;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  http2_session_server_new(&session, &callbacks, &ud);

  assert(HTTP2_ERR_INVALID_ARGUMENT ==
            http2_submit_settings(session, FrameFlags.NONE, iv, 6));

  /* Make sure that local settings are not changed */
  assert(HTTP2_INITIAL_MAX_CONCURRENT_STREAMS ==
            session.local_settings.max_concurrent_streams);
  assert(HTTP2_INITIAL_WINDOW_SIZE ==
            session.local_settings.initial_window_size);

  /* Now sends without 6th one */
  assert(0 == http2_submit_settings(session, FrameFlags.NONE, iv, 5));

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_SETTINGS == item.frame.hd.type);

  frame = &item.frame;
  assert(5 == frame.settings.niv);
  assert(5 == frame.settings.iv[0].value);
  assert(HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS ==
            frame.settings.iv[0].settings_id);

  assert(16 * 1024 == frame.settings.iv[1].value);
  assert(HTTP2_SETTINGS_INITIAL_WINDOW_SIZE ==
            frame.settings.iv[1].settings_id);

  assert(UNKNOWN_ID == frame.settings.iv[4].settings_id);
  assert(999 == frame.settings.iv[4].value);

  ud.frame_send_cb_called = 0;
  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_send_cb_called);

  assert(50 == session.pending_local_max_concurrent_stream);

  http2_frame_settings_init(&ack_frame.settings, FrameFlags.ACK, NULL, 0);
  assert(0 == http2_session_on_settings_received(session, &ack_frame, 0));
  http2_frame_settings_free(&ack_frame.settings, mem);

  assert(16 * 1024 == session.local_settings.initial_window_size);
  assert(0 == session.hd_inflater.ctx.hd_table_bufsize_max);
  assert(50 == session.local_settings.max_concurrent_streams);
  assert(HTTP2_INITIAL_MAX_CONCURRENT_STREAMS ==
            session.pending_local_max_concurrent_stream);

  http2_session_del(session);
}

void test_http2_submit_settings_update_local_window_size(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_settings_entry iv[4];
  http2_stream *stream;
  http2_frame ack_frame;
  http2_mem *mem;

  mem = http2_mem_default();
  http2_frame_settings_init(&ack_frame.settings, FrameFlags.ACK, NULL, 0);

  iv[0].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[0].value = 16 * 1024;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);
  stream.local_window_size = HTTP2_INITIAL_WINDOW_SIZE + 100;
  stream.recv_window_size = 32768;

  stream = http2_session_open_stream(session, 3, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);

  assert(0 == http2_submit_settings(session, FrameFlags.NONE, iv, 1));
  assert(0 == http2_session_send(session));
  assert(0 == http2_session_on_settings_received(session, &ack_frame, 0));

  stream = http2_session_get_stream(session, 1);
  assert(0 == stream.recv_window_size);
  assert(16 * 1024 + 100 == stream.local_window_size);

  stream = http2_session_get_stream(session, 3);
  assert(16 * 1024 == stream.local_window_size);

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(32768 == item.frame.window_update.window_size_increment);

  http2_session_del(session);

  /* Check overflow case */
  iv[0].value = 128 * 1024;
  http2_session_server_new(&session, &callbacks, NULL);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);
  stream.local_window_size = HTTP2_MAX_WINDOW_SIZE;

  assert(0 == http2_submit_settings(session, FrameFlags.NONE, iv, 1));
  assert(0 == http2_session_send(session));
  assert(0 == http2_session_on_settings_received(session, &ack_frame, 0));

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_FLOW_CONTROL_ERROR == item.frame.goaway.error_code);

  http2_session_del(session);
  http2_frame_settings_free(&ack_frame.settings, mem);
}

void test_http2_submit_push_promise(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;

  assert(0 == http2_session_server_new(&session, &callbacks, &ud));
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(2 == http2_submit_push_promise(session, FrameFlags.NONE, 1,
                                             reqnv, ARRLEN(reqnv), &ud));

  ud.frame_send_cb_called = 0;
  ud.sent_frame_type = 0;
  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_send_cb_called);
  assert(HTTP2_PUSH_PROMISE == ud.sent_frame_type);
  stream = http2_session_get_stream(session, 2);
  assert(HTTP2_STREAM_RESERVED == stream.state);
  assert(&ud == http2_session_get_stream_user_data(session, 2));

  /* submit PUSH_PROMISE while associated stream is not opened */
  assert(4 == http2_submit_push_promise(session, FrameFlags.NONE, 3,
                                             reqnv, ARRLEN(reqnv), &ud));

  ud.frame_not_send_cb_called = 0;

  assert(0 == http2_session_send(session));
  assert(1 == ud.frame_not_send_cb_called);
  assert(HTTP2_PUSH_PROMISE == ud.not_sent_frame_type);

  stream = http2_session_get_stream(session, 4);

  assert(NULL == stream);

  http2_session_del(session);
}

void test_http2_submit_window_update(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_outbound_item *item;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, &ud);
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);
  stream.recv_window_size = 4096;

  assert(0 ==
            http2_submit_window_update(session, FrameFlags.NONE, 2, 1024));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(1024 == item.frame.window_update.window_size_increment);
  assert(0 == http2_session_send(session));
  assert(3072 == stream.recv_window_size);

  assert(0 ==
            http2_submit_window_update(session, FrameFlags.NONE, 2, 4096));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(4096 == item.frame.window_update.window_size_increment);
  assert(0 == http2_session_send(session));
  assert(0 == stream.recv_window_size);

  assert(0 ==
            http2_submit_window_update(session, FrameFlags.NONE, 2, 4096));
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(4096 == item.frame.window_update.window_size_increment);
  assert(0 == http2_session_send(session));
  assert(0 == stream.recv_window_size);

  assert(0 ==
            http2_submit_window_update(session, FrameFlags.NONE, 2, 0));
  /* It is ok if stream is closed or does not exist at the call
     time */
  assert(0 ==
            http2_submit_window_update(session, FrameFlags.NONE, 4, 4096));

  http2_session_del(session);
}

void test_http2_submit_window_update_local_window_size(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);
  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);
  stream.recv_window_size = 4096;

  assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2,
                                              stream.recv_window_size + 1));
  assert(HTTP2_INITIAL_WINDOW_SIZE + 1 == stream.local_window_size);
  assert(0 == stream.recv_window_size);
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(4097 == item.frame.window_update.window_size_increment);

  assert(0 == http2_session_send(session));

  /* Let's decrement local window size */
  stream.recv_window_size = 4096;
  assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2,
                                              -stream.local_window_size / 2));
  assert(32768 == stream.local_window_size);
  assert(-28672 == stream.recv_window_size);
  assert(32768 == stream.recv_reduction);

  item = http2_session_get_next_ob_item(session);
  assert(item == NULL);

  /* Increase local window size */
  assert(0 ==
            http2_submit_window_update(session, FrameFlags.NONE, 2, 16384));
  assert(49152 == stream.local_window_size);
  assert(-12288 == stream.recv_window_size);
  assert(16384 == stream.recv_reduction);
  assert(NULL == http2_session_get_next_ob_item(session));

  assert(HTTP2_ERR_FLOW_CONTROL ==
            http2_submit_window_update(session, FrameFlags.NONE, 2,
                                         HTTP2_MAX_WINDOW_SIZE));

  assert(0 == http2_session_send(session));

  /* Check connection-level flow control */
  session.recv_window_size = 4096;
  assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 0,
                                              session.recv_window_size + 1));
  assert(HTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 1 ==
            session.local_window_size);
  assert(0 == session.recv_window_size);
  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(4097 == item.frame.window_update.window_size_increment);

  assert(0 == http2_session_send(session));

  /* Go decrement part */
  session.recv_window_size = 4096;
  assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 0,
                                              -session.local_window_size / 2));
  assert(32768 == session.local_window_size);
  assert(-28672 == session.recv_window_size);
  assert(32768 == session.recv_reduction);
  item = http2_session_get_next_ob_item(session);
  assert(item == NULL);

  /* Increase local window size */
  assert(0 ==
            http2_submit_window_update(session, FrameFlags.NONE, 0, 16384));
  assert(49152 == session.local_window_size);
  assert(-12288 == session.recv_window_size);
  assert(16384 == session.recv_reduction);
  assert(NULL == http2_session_get_next_ob_item(session));

  assert(HTTP2_ERR_FLOW_CONTROL ==
            http2_submit_window_update(session, FrameFlags.NONE, 0,
                                         HTTP2_MAX_WINDOW_SIZE));

  http2_session_del(session);
}

void test_http2_submit_shutdown_notice(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  assert(0 == http2_submit_shutdown_notice(session));

  ud.frame_send_cb_called = 0;

  http2_session_send(session);

  assert(1 == ud.frame_send_cb_called);
  assert(HTTP2_GOAWAY == ud.sent_frame_type);
  assert((1u << 31) - 1 == session.local_last_stream_id);

  /* After another GOAWAY, http2_submit_shutdown_notice() is
     noop. */
  assert(0 == http2_session_terminate_session(session, HTTP2_NO_ERROR));

  ud.frame_send_cb_called = 0;

  http2_session_send(session);

  assert(1 == ud.frame_send_cb_called);
  assert(HTTP2_GOAWAY == ud.sent_frame_type);
  assert(0 == session.local_last_stream_id);

  assert(0 == http2_submit_shutdown_notice(session));

  ud.frame_send_cb_called = 0;
  ud.frame_not_send_cb_called = 0;

  http2_session_send(session);

  assert(0 == ud.frame_send_cb_called);
  assert(0 == ud.frame_not_send_cb_called);

  http2_session_del(session);

  /* Using http2_submit_shutdown_notice() with client side session
     is error */
  http2_session_client_new(&session, &callbacks, NULL);

  assert(HTTP2_ERR_INVALID_STATE ==
            http2_submit_shutdown_notice(session));

  http2_session_del(session);
}

void test_http2_submit_invalid_nv(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_nv empty_name_nv[] = {MAKE_NV("Version", "HTTP/1.1"),
                                MAKE_NV("", "empty name")};

  /* Now invalid header name/value pair in HTTP/1.1 is accepted in
     nghttp2 */

  memset(&callbacks, 0, sizeof(http2_session_callbacks));

  assert(0 == http2_session_server_new(&session, &callbacks, NULL));

  /* http2_submit_request */
  assert(0 < http2_submit_request(session, NULL, empty_name_nv,
                                       ARRLEN(empty_name_nv), NULL, NULL));

  /* http2_submit_response */
  assert(0 == http2_submit_response(session, 2, empty_name_nv,
                                         ARRLEN(empty_name_nv), NULL));

  /* http2_submit_headers */
  assert(0 < http2_submit_headers(session, FrameFlags.NONE, -1, NULL,
                                       empty_name_nv, ARRLEN(empty_name_nv),
                                       NULL));

  /* http2_submit_push_promise */
  open_stream(session, 1);

  assert(0 < http2_submit_push_promise(session, FrameFlags.NONE, 1,
                                            empty_name_nv,
                                            ARRLEN(empty_name_nv), NULL));

  http2_session_del(session);
}

void test_http2_session_open_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;
  http2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  http2_session_server_new(&session, &callbacks, NULL);

  http2_priority_spec_init(&pri_spec, 0, 245, 0);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, HTTP2_STREAM_OPENED, NULL);
  assert(1 == session.num_incoming_streams);
  assert(0 == session.num_outgoing_streams);
  assert(HTTP2_STREAM_OPENED == stream.state);
  assert(245 == stream.weight);
  assert(NULL == stream.dep_prev);
  assert(HTTP2_SHUT_NONE == stream.shut_flags);

  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);
  assert(1 == session.num_incoming_streams);
  assert(1 == session.num_outgoing_streams);
  assert(NULL == stream.dep_prev);
  assert(DEFAULT_WEIGHT == stream.weight);
  assert(HTTP2_SHUT_NONE == stream.shut_flags);

  stream = http2_session_open_stream(session, 4, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  assert(1 == session.num_incoming_streams);
  assert(1 == session.num_outgoing_streams);
  assert(NULL == stream.dep_prev);
  assert(DEFAULT_WEIGHT == stream.weight);
  assert(HTTP2_SHUT_RD == stream.shut_flags);

  http2_priority_spec_init(&pri_spec, 1, 17, 1);

  stream = http2_session_open_stream(session, 3, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, HTTP2_STREAM_OPENED, NULL);
  assert(17 == stream.weight);
  assert(1 == stream.dep_prev.stream_id);

  /* Dependency to idle stream */
  http2_priority_spec_init(&pri_spec, 1000000007, 240, 1);

  stream = http2_session_open_stream(session, 5, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, HTTP2_STREAM_OPENED, NULL);
  assert(240 == stream.weight);
  assert(1000000007 == stream.dep_prev.stream_id);

  stream = http2_session_get_stream_raw(session, 1000000007);

  assert(DEFAULT_WEIGHT == stream.weight);
  assert(NULL != stream.root_next);

  /* Dependency to closed stream which is not in dependency tree */
  session.last_recv_stream_id = 7;

  http2_priority_spec_init(&pri_spec, 7, 10, 0);

  stream = http2_session_open_stream(session, 9, FrameFlags.NONE, &pri_spec,
                                       HTTP2_STREAM_OPENED, NULL);

  assert(DEFAULT_WEIGHT == stream.weight);

  http2_session_del(session);

  http2_session_client_new(&session, &callbacks, NULL);
  stream = http2_session_open_stream(session, 4, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);
  assert(0 == session.num_incoming_streams);
  assert(0 == session.num_outgoing_streams);
  assert(NULL == stream.dep_prev);
  assert(DEFAULT_WEIGHT == stream.weight);
  assert(HTTP2_SHUT_WR == stream.shut_flags);

  http2_session_del(session);
}

void test_http2_session_open_stream_with_idle_stream_dep(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;
  http2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  http2_session_server_new(&session, &callbacks, NULL);

  /* Dependency to idle stream */
  http2_priority_spec_init(&pri_spec, 101, 245, 0);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, HTTP2_STREAM_OPENED, NULL);

  assert(245 == stream.weight);
  assert(101 == stream.dep_prev.stream_id);

  stream = http2_session_get_stream_raw(session, 101);

  assert(HTTP2_STREAM_IDLE == stream.state);
  assert(DEFAULT_WEIGHT == stream.weight);

  http2_priority_spec_init(&pri_spec, 211, 1, 0);

  /* stream 101 was already created as idle. */
  stream = http2_session_open_stream(session, 101, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec, HTTP2_STREAM_OPENED, NULL);

  assert(1 == stream.weight);
  assert(211 == stream.dep_prev.stream_id);

  stream = http2_session_get_stream_raw(session, 211);

  assert(HTTP2_STREAM_IDLE == stream.state);
  assert(DEFAULT_WEIGHT == stream.weight);

  http2_session_del(session);
}

void test_http2_session_get_next_ob_item(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_priority_spec pri_spec;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);
  session.remote_settings.max_concurrent_streams = 2;

  assert(NULL == http2_session_get_next_ob_item(session));
  http2_submit_ping(session, FrameFlags.NONE, NULL);
  assert(HTTP2_PING ==
            http2_session_get_next_ob_item(session).frame.hd.type);

  http2_submit_request(session, NULL, NULL, 0, NULL, NULL);
  assert(HTTP2_PING ==
            http2_session_get_next_ob_item(session).frame.hd.type);

  assert(0 == http2_session_send(session));
  assert(NULL == http2_session_get_next_ob_item(session));

  /* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  http2_priority_spec_init(&pri_spec, 0, HTTP2_MAX_WEIGHT, 0);

  http2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);
  assert(HTTP2_HEADERS ==
            http2_session_get_next_ob_item(session).frame.hd.type);
  assert(0 == http2_session_send(session));

  http2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);
  assert(NULL == http2_session_get_next_ob_item(session));

  session.remote_settings.max_concurrent_streams = 3;

  assert(HTTP2_HEADERS ==
            http2_session_get_next_ob_item(session).frame.hd.type);

  http2_session_del(session);
}

void test_http2_session_pop_next_ob_item(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_outbound_item *item;
  http2_priority_spec pri_spec;
  http2_stream *stream;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);
  session.remote_settings.max_concurrent_streams = 1;

  assert(NULL == http2_session_pop_next_ob_item(session));

  http2_submit_ping(session, FrameFlags.NONE, NULL);

  http2_priority_spec_init(&pri_spec, 0, 254, 0);

  http2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);

  item = http2_session_pop_next_ob_item(session);
  assert(HTTP2_PING == item.frame.hd.type);
  http2_outbound_item_free(item, mem);
  free(item);

  item = http2_session_pop_next_ob_item(session);
  assert(HTTP2_HEADERS == item.frame.hd.type);
  http2_outbound_item_free(item, mem);
  free(item);

  assert(NULL == http2_session_pop_next_ob_item(session));

  /* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  /* In-flight outgoing stream */
  http2_session_open_stream(session, 4, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  http2_priority_spec_init(&pri_spec, 0, HTTP2_MAX_WEIGHT, 0);

  http2_submit_request(session, &pri_spec, NULL, 0, NULL, NULL);
  http2_submit_response(session, 1, NULL, 0, NULL);

  item = http2_session_pop_next_ob_item(session);
  assert(HTTP2_HEADERS == item.frame.hd.type);
  assert(1 == item.frame.hd.stream_id);

  stream = http2_session_get_stream(session, 1);

  http2_stream_detach_item(stream, session);

  http2_outbound_item_free(item, mem);
  free(item);

  assert(NULL == http2_session_pop_next_ob_item(session));

  session.remote_settings.max_concurrent_streams = 2;

  item = http2_session_pop_next_ob_item(session);
  assert(HTTP2_HEADERS == item.frame.hd.type);
  http2_outbound_item_free(item, mem);
  free(item);

  http2_session_del(session);

  /* Check that push reply HEADERS are queued into ob_ss_pq */
  http2_session_server_new(&session, &callbacks, NULL);
  session.remote_settings.max_concurrent_streams = 0;
  http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_RESERVED, NULL);
  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 2,
                                        NULL, NULL, 0, NULL));
  assert(NULL == http2_session_pop_next_ob_item(session));
  assert(1 == http2_pq_size(&session.ob_ss_pq));
  http2_session_del(session);
}

void test_http2_session_reply_fail(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = fail_send_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;
  ud.data_source_length = 4 * 1024;
  assert(0 == http2_session_server_new(&session, &callbacks, &ud));
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  assert(0 == http2_submit_response(session, 1, NULL, 0, &data_prd));
  assert(HTTP2_ERR_CALLBACK_FAILURE == http2_session_send(session));
  http2_session_del(session);
}

void test_http2_session_max_concurrent_streams(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_frame frame;
  http2_outbound_item *item;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENED, NULL);

  /* Check un-ACKed SETTINGS_MAX_CONCURRENT_STREAMS */
  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 3,
                             HTTP2_HCAT_HEADERS, NULL, NULL, 0);
  session.pending_local_max_concurrent_stream = 1;

  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));

  item = http2_session_get_ob_pq_top(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);
  assert(HTTP2_REFUSED_STREAM == item.frame.rst_stream.error_code);

  assert(0 == http2_session_send(session));

  /* Check ACKed SETTINGS_MAX_CONCURRENT_STREAMS */
  session.local_settings.max_concurrent_streams = 1;
  frame.hd.stream_id = 5;

  assert(HTTP2_ERR_IGN_HEADER_BLOCK ==
            http2_session_on_request_headers_received(session, &frame));

  item = http2_session_get_ob_pq_top(session);
  assert(HTTP2_GOAWAY == item.frame.hd.type);
  assert(HTTP2_PROTOCOL_ERROR == item.frame.goaway.error_code);

  http2_frame_headers_free(&frame.headers, mem);
  http2_session_del(session);
}

/*
 * Check that on_stream_close_callback is called when server pushed
 * HEADERS have FrameFlags.END_STREAM.
 */
void test_http2_session_stream_close_on_headers_push(void) {
  /* http2_session *session; */
  /* http2_session_callbacks callbacks; */
  /* const char *nv[] = { NULL }; */
  /* my_user_data ud; */
  /* http2_frame frame; */

  /* memset(&callbacks, 0, sizeof(http2_session_callbacks)); */
  /* callbacks.on_stream_close_callback = */
  /*   no_stream_user_data_stream_close_callback; */
  /* ud.stream_close_cb_called = 0; */

  /* http2_session_client_new(&session, HTTP2_PROTO_SPDY2, &callbacks, &ud);
   */
  /* http2_session_open_stream(session, 1, HTTP2_CTRL_FLAG_NONE, 3, */
  /*                             HTTP2_STREAM_OPENING, NULL); */
  /* http2_frame_syn_stream_init(&frame.syn_stream, HTTP2_PROTO_SPDY2, */
  /*                               HTTP2_CTRL_FLAG_FIN | */
  /*                               HTTP2_CTRL_FLAG_UNIDIRECTIONAL, */
  /*                               2, 1, 3, dup_nv(nv)); */

  /* assert(0 == http2_session_on_request_headers_received(session,
   * &frame)); */

  /* http2_frame_syn_stream_free(&frame.syn_stream); */
  /* http2_session_del(session); */
}

void test_http2_session_stop_data_with_rst_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  DataProvider data_prd;
  http2_frame frame;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = HTTP2_DATA_PAYLOADLEN * 4;

  http2_session_server_new(&session, &callbacks, &ud);
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);
  http2_submit_response(session, 1, NULL, 0, &data_prd);

  ud.block_count = 2;
  /* Sends response HEADERS + DATA[0] */
  assert(0 == http2_session_send(session));
  assert(HTTP2_DATA == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  assert(ud.data_source_length == HTTP2_DATA_PAYLOADLEN * 2);

  http2_frame_rst_stream_init(&frame.rst_stream, 1, HTTP2_CANCEL);
  assert(0 == http2_session_on_rst_stream_received(session, &frame));
  http2_frame_rst_stream_free(&frame.rst_stream);

  /* Big enough number to send all DATA frames potentially. */
  ud.block_count = 100;
  /* Nothing will be sent in the following call. */
  assert(0 == http2_session_send(session));
  /* With RST_STREAM, stream is canceled and further DATA on that
     stream are not sent. */
  assert(ud.data_source_length == HTTP2_DATA_PAYLOADLEN * 2);

  assert(NULL == http2_session_get_stream(session, 1));

  http2_session_del(session);
}

void test_http2_session_defer_data(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  DataProvider data_prd;
  http2_outbound_item *item;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.send_callback = block_count_send_callback;
  data_prd.read_callback = defer_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = HTTP2_DATA_PAYLOADLEN * 4;

  http2_session_server_new(&session, &callbacks, &ud);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  session.remote_window_size = 1 << 20;
  stream.remote_window_size = 1 << 20;

  http2_submit_response(session, 1, NULL, 0, &data_prd);

  ud.block_count = 1;
  /* Sends HEADERS reply */
  assert(0 == http2_session_send(session));
  assert(HTTP2_HEADERS == ud.sent_frame_type);
  /* No data is read */
  assert(ud.data_source_length == HTTP2_DATA_PAYLOADLEN * 4);

  ud.block_count = 1;
  http2_submit_ping(session, FrameFlags.NONE, NULL);
  /* Sends PING */
  assert(0 == http2_session_send(session));
  assert(HTTP2_PING == ud.sent_frame_type);

  /* Resume deferred DATA */
  assert(0 == http2_session_resume_data(session, 1));
  item = (http2_outbound_item *)http2_pq_top(&session.ob_da_pq);
  item.aux_data.data.data_prd.read_callback =
      fixed_length_data_source_read_callback;
  ud.block_count = 1;
  /* Reads 2 DATA chunks */
  assert(0 == http2_session_send(session));
  assert(ud.data_source_length == HTTP2_DATA_PAYLOADLEN * 2);

  /* Deferred again */
  item.aux_data.data.data_prd.read_callback = defer_data_source_read_callback;
  /* This is needed since 16KiB block is already read and waiting to be
     sent. No read_callback invocation. */
  ud.block_count = 1;
  assert(0 == http2_session_send(session));
  assert(ud.data_source_length == HTTP2_DATA_PAYLOADLEN * 2);

  /* Resume deferred DATA */
  assert(0 == http2_session_resume_data(session, 1));
  item = (http2_outbound_item *)http2_pq_top(&session.ob_da_pq);
  item.aux_data.data.data_prd.read_callback =
      fixed_length_data_source_read_callback;
  ud.block_count = 1;
  /* Reads 2 16KiB blocks */
  assert(0 == http2_session_send(session));
  assert(ud.data_source_length == 0);

  http2_session_del(session);
}

void test_http2_session_flow_control(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  DataProvider data_prd;
  http2_frame frame;
  http2_stream *stream;
  int new_initial_window_size;
  http2_settings_entry iv[1];
  http2_frame settings_frame;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = fixed_bytes_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = 128 * 1024;
  /* Use smaller emission count so that we can check outbound flow
     control window calculation is correct. */
  ud.fixed_sendlen = 2 * 1024;

  /* Initial window size to 64KiB - 1*/
  http2_session_client_new(&session, &callbacks, &ud);
  /* Change it to 64KiB for easy calculation */
  session.remote_window_size = 64 * 1024;
  session.remote_settings.initial_window_size = 64 * 1024;

  http2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);

  /* Sends 64KiB - 1 data */
  assert(0 == http2_session_send(session));
  assert(64 * 1024 == ud.data_source_length);

  /* Back 32KiB in stream window */
  http2_frame_window_update_init(&frame.window_update, FrameFlags.NONE, 1,
                                   32 * 1024);
  http2_session_on_window_update_received(session, &frame);

  /* Send nothing because of connection-level window */
  assert(0 == http2_session_send(session));
  assert(64 * 1024 == ud.data_source_length);

  /* Back 32KiB in connection-level window */
  frame.hd.stream_id = 0;
  http2_session_on_window_update_received(session, &frame);

  /* Sends another 32KiB data */
  assert(0 == http2_session_send(session));
  assert(32 * 1024 == ud.data_source_length);

  stream = http2_session_get_stream(session, 1);
  /* Change initial window size to 16KiB. The window_size becomes
     negative. */
  new_initial_window_size = 16 * 1024;
  stream.remote_window_size =
      new_initial_window_size - (session.remote_settings.initial_window_size -
                                 stream.remote_window_size);
  session.remote_settings.initial_window_size = new_initial_window_size;
  assert(-48 * 1024 == stream.remote_window_size);

  /* Back 48KiB to stream window */
  frame.hd.stream_id = 1;
  frame.window_update.window_size_increment = 48 * 1024;
  http2_session_on_window_update_received(session, &frame);

  /* Nothing is sent because window_size is 0 */
  assert(0 == http2_session_send(session));
  assert(32 * 1024 == ud.data_source_length);

  /* Back 16KiB in stream window */
  frame.hd.stream_id = 1;
  frame.window_update.window_size_increment = 16 * 1024;
  http2_session_on_window_update_received(session, &frame);

  /* Back 24KiB in connection-level window */
  frame.hd.stream_id = 0;
  frame.window_update.window_size_increment = 24 * 1024;
  http2_session_on_window_update_received(session, &frame);

  /* Sends another 16KiB data */
  assert(0 == http2_session_send(session));
  assert(16 * 1024 == ud.data_source_length);

  /* Increase initial window size to 32KiB */
  iv[0].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[0].value = 32 * 1024;

  http2_frame_settings_init(&settings_frame.settings, FrameFlags.NONE,
                              dup_iv(iv, 1), 1);
  http2_session_on_settings_received(session, &settings_frame, 1);
  http2_frame_settings_free(&settings_frame.settings, mem);

  /* Sends another 8KiB data */
  assert(0 == http2_session_send(session));
  assert(8 * 1024 == ud.data_source_length);

  /* Back 8KiB in connection-level window */
  frame.hd.stream_id = 0;
  frame.window_update.window_size_increment = 8 * 1024;
  http2_session_on_window_update_received(session, &frame);

  /* Sends last 8KiB data */
  assert(0 == http2_session_send(session));
  assert(0 == ud.data_source_length);
  assert(http2_session_get_stream(session, 1).shut_flags &
            HTTP2_SHUT_WR);

  http2_frame_window_update_free(&frame.window_update);
  http2_session_del(session);
}

void test_http2_session_flow_control_data_recv(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  ubyte data[64 * 1024 + 16];
  http2_frame_hd hd;
  http2_outbound_item *item;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  /* Initial window size to 64KiB - 1*/
  http2_session_client_new(&session, &callbacks, NULL);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);

  session.next_stream_id = 3;

  http2_stream_shutdown(stream, HTTP2_SHUT_WR);

  session.local_window_size = HTTP2_MAX_PAYLOADLEN;
  stream.local_window_size = HTTP2_MAX_PAYLOADLEN;

  /* Create DATA frame */
  memset(data, 0, sizeof(data));
  http2_frame_hd_init(&hd, HTTP2_MAX_PAYLOADLEN, HTTP2_DATA,
                        FrameFlags.END_STREAM, 1);

  http2_frame_pack_frame_hd(data, &hd);
  assert(HTTP2_MAX_PAYLOADLEN + HTTP2_FRAME_HDLEN ==
            http2_session_mem_recv(session, data, HTTP2_MAX_PAYLOADLEN +
                                                        HTTP2_FRAME_HDLEN));

  item = http2_session_get_next_ob_item(session);
  /* Since this is the last frame, stream-level WINDOW_UPDATE is not
     issued, but connection-level is. */
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(0 == item.frame.hd.stream_id);
  assert(HTTP2_MAX_PAYLOADLEN ==
            item.frame.window_update.window_size_increment);

  assert(0 == http2_session_send(session));

  /* Receive DATA for closed stream. They are still subject to under
     connection-level flow control, since this situation arises when
     RST_STREAM is issued by the remote, but the local side keeps
     sending DATA frames. Without calculating connection-level window,
     the subsequent flow control gets confused. */
  assert(HTTP2_MAX_PAYLOADLEN + HTTP2_FRAME_HDLEN ==
            http2_session_mem_recv(session, data, HTTP2_MAX_PAYLOADLEN +
                                                        HTTP2_FRAME_HDLEN));

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_WINDOW_UPDATE == item.frame.hd.type);
  assert(0 == item.frame.hd.stream_id);
  assert(HTTP2_MAX_PAYLOADLEN ==
            item.frame.window_update.window_size_increment);

  http2_session_del(session);
}

void test_http2_session_flow_control_data_with_padding_recv(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  ubyte data[1024];
  http2_frame_hd hd;
  http2_stream *stream;
  http2_option *option;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_option_new(&option);
  /* Disable auto window update so that we can check padding is
     consumed automatically */
  http2_option_set_no_auto_window_update(option, 1);

  /* Initial window size to 64KiB - 1*/
  http2_session_client_new2(&session, &callbacks, NULL, option);

  http2_option_del(option);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);

  /* Create DATA frame */
  memset(data, 0, sizeof(data));
  http2_frame_hd_init(&hd, 357, HTTP2_DATA,
                        FrameFlags.END_STREAM | FrameFlags.PADDED, 1);

  http2_frame_pack_frame_hd(data, &hd);
  /* Set Pad Length field, which itself is padding */
  data[HTTP2_FRAME_HDLEN] = 255;

  assert(
      (size_t)(HTTP2_FRAME_HDLEN + hd.length) ==
      http2_session_mem_recv(session, data, HTTP2_FRAME_HDLEN + hd.length));

  assert((int)hd.length == session.recv_window_size);
  assert((int)hd.length == stream.recv_window_size);
  assert(256 == session.consumed_size);
  assert(256 == stream.consumed_size);

  http2_session_del(session);
}

void test_http2_session_data_read_temporal_failure(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  DataProvider data_prd;
  http2_frame frame;
  http2_stream *stream;
  size_t data_size = 128 * 1024;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.data_source_length = data_size;

  /* Initial window size is 64KiB - 1 */
  http2_session_client_new(&session, &callbacks, &ud);
  http2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);

  /* Sends HTTP2_INITIAL_WINDOW_SIZE data, assuming, it is equal to
     or smaller than HTTP2_INITIAL_CONNECTION_WINDOW_SIZE */
  assert(0 == http2_session_send(session));
  assert(data_size - HTTP2_INITIAL_WINDOW_SIZE == ud.data_source_length);

  stream = http2_session_get_stream(session, 1);
  assert(http2_stream_check_deferred_by_flow_control(stream));
  assert(HTTP2_DATA == stream.item.frame.hd.type);

  stream.item.aux_data.data.data_prd.read_callback =
      temporal_failure_data_source_read_callback;

  /* Back HTTP2_INITIAL_WINDOW_SIZE to both connection-level and
     stream-wise window */
  http2_frame_window_update_init(&frame.window_update, FrameFlags.NONE, 1,
                                   HTTP2_INITIAL_WINDOW_SIZE);
  http2_session_on_window_update_received(session, &frame);
  frame.hd.stream_id = 0;
  http2_session_on_window_update_received(session, &frame);
  http2_frame_window_update_free(&frame.window_update);

  /* Sending data will fail (soft fail) and treated as stream error */
  ud.frame_send_cb_called = 0;
  assert(0 == http2_session_send(session));
  assert(data_size - HTTP2_INITIAL_WINDOW_SIZE == ud.data_source_length);

  assert(1 == ud.frame_send_cb_called);
  assert(HTTP2_RST_STREAM == ud.sent_frame_type);

  data_prd.read_callback = fail_data_source_read_callback;
  http2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);
  /* Sending data will fail (hard fail) and session tear down */
  assert(HTTP2_ERR_CALLBACK_FAILURE == http2_session_send(session));

  http2_session_del(session);
}

void test_http2_session_on_stream_close(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_stream_close_callback = on_stream_close_callback;
  user_data.stream_close_cb_called = 0;

  http2_session_client_new(&session, &callbacks, &user_data);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       &user_data);
  assert(stream != NULL);
  assert(http2_session_close_stream(session, 1, HTTP2_NO_ERROR) == 0);
  assert(user_data.stream_close_cb_called == 1);
  http2_session_del(session);
}

void test_http2_session_on_ctrl_not_send(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data user_data;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
  callbacks.send_callback = null_send_callback;
  user_data.frame_not_send_cb_called = 0;
  user_data.not_sent_frame_type = 0;
  user_data.not_sent_error = 0;

  http2_session_server_new(&session, &callbacks, &user_data);
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, &user_data);

  /* Check response HEADERS */
  /* Send bogus stream ID */
  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 3,
                                        NULL, NULL, 0, NULL));
  assert(0 == http2_session_send(session));
  assert(1 == user_data.frame_not_send_cb_called);
  assert(HTTP2_HEADERS == user_data.not_sent_frame_type);
  assert(HTTP2_ERR_STREAM_CLOSED == user_data.not_sent_error);

  user_data.frame_not_send_cb_called = 0;
  /* Shutdown transmission */
  stream.shut_flags |= HTTP2_SHUT_WR;
  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1,
                                        NULL, NULL, 0, NULL));
  assert(0 == http2_session_send(session));
  assert(1 == user_data.frame_not_send_cb_called);
  assert(HTTP2_HEADERS == user_data.not_sent_frame_type);
  assert(HTTP2_ERR_STREAM_SHUT_WR == user_data.not_sent_error);

  stream.shut_flags = HTTP2_SHUT_NONE;
  user_data.frame_not_send_cb_called = 0;
  /* Queue RST_STREAM */
  assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1,
                                        NULL, NULL, 0, NULL));
  assert(0 == http2_submit_rst_stream(session, FrameFlags.NONE, 1,
                                           HTTP2_INTERNAL_ERROR));
  assert(0 == http2_session_send(session));
  assert(1 == user_data.frame_not_send_cb_called);
  assert(HTTP2_HEADERS == user_data.not_sent_frame_type);
  assert(HTTP2_ERR_STREAM_CLOSING == user_data.not_sent_error);

  http2_session_del(session);

  /* Check request HEADERS */
  user_data.frame_not_send_cb_called = 0;
  assert(http2_session_client_new(&session, &callbacks, &user_data) == 0);
  /* Maximum Stream ID is reached */
  session.next_stream_id = (1u << 31) + 1;
  assert(HTTP2_ERR_STREAM_ID_NOT_AVAILABLE ==
            http2_submit_headers(session, FrameFlags.END_STREAM, -1, NULL,
                                   NULL, 0, NULL));

  user_data.frame_not_send_cb_called = 0;
  /* GOAWAY received */
  session.goaway_flags |= GoAwayFlags.RECV;
  session.next_stream_id = 9;

  assert(0 < http2_submit_headers(session, FrameFlags.END_STREAM, -1,
                                       NULL, NULL, 0, NULL));
  assert(0 == http2_session_send(session));
  assert(1 == user_data.frame_not_send_cb_called);
  assert(HTTP2_HEADERS == user_data.not_sent_frame_type);
  assert(HTTP2_ERR_START_STREAM_NOT_ALLOWED == user_data.not_sent_error);

  http2_session_del(session);
}

void test_http2_session_get_outbound_queue_size(void) {
  http2_session *session;
  http2_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  assert(0 == http2_session_client_new(&session, &callbacks, NULL));
  assert(0 == http2_session_get_outbound_queue_size(session));

  assert(0 == http2_submit_ping(session, FrameFlags.NONE, NULL));
  assert(1 == http2_session_get_outbound_queue_size(session));

  assert(0 == http2_submit_goaway(session, FrameFlags.NONE, 2,
                                       HTTP2_NO_ERROR, NULL, 0));
  assert(2 == http2_session_get_outbound_queue_size(session));

  http2_session_del(session);
}

void test_http2_session_get_effective_local_window_size(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  assert(0 == http2_session_client_new(&session, &callbacks, NULL));

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default, HTTP2_STREAM_OPENED,
                                       NULL);

  assert(HTTP2_INITIAL_CONNECTION_WINDOW_SIZE ==
            http2_session_get_effective_local_window_size(session));
  assert(0 == http2_session_get_effective_recv_data_length(session));

  assert(HTTP2_INITIAL_WINDOW_SIZE ==
            http2_session_get_stream_effective_local_window_size(session, 1));
  assert(0 ==
            http2_session_get_stream_effective_recv_data_length(session, 1));

  /* Check connection flow control */
  session.recv_window_size = 100;
  http2_submit_window_update(session, FrameFlags.NONE, 0, 1100);

  assert(HTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 1000 ==
            http2_session_get_effective_local_window_size(session));
  assert(0 == http2_session_get_effective_recv_data_length(session));

  http2_submit_window_update(session, FrameFlags.NONE, 0, -50);
  /* Now session.recv_window_size = -50 */
  assert(HTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 950 ==
            http2_session_get_effective_local_window_size(session));
  assert(0 == http2_session_get_effective_recv_data_length(session));

  session.recv_window_size += 50;
  /* Now session.recv_window_size = 0 */
  http2_submit_window_update(session, FrameFlags.NONE, 0, 100);
  assert(HTTP2_INITIAL_CONNECTION_WINDOW_SIZE + 1050 ==
            http2_session_get_effective_local_window_size(session));
  assert(50 == http2_session_get_effective_recv_data_length(session));

  /* Check stream flow control */
  stream.recv_window_size = 100;
  http2_submit_window_update(session, FrameFlags.NONE, 1, 1100);

  assert(HTTP2_INITIAL_WINDOW_SIZE + 1000 ==
            http2_session_get_stream_effective_local_window_size(session, 1));
  assert(0 ==
            http2_session_get_stream_effective_recv_data_length(session, 1));

  http2_submit_window_update(session, FrameFlags.NONE, 1, -50);
  /* Now stream.recv_window_size = -50 */
  assert(HTTP2_INITIAL_WINDOW_SIZE + 950 ==
            http2_session_get_stream_effective_local_window_size(session, 1));
  assert(0 ==
            http2_session_get_stream_effective_recv_data_length(session, 1));

  stream.recv_window_size += 50;
  /* Now stream.recv_window_size = 0 */
  http2_submit_window_update(session, FrameFlags.NONE, 1, 100);
  assert(HTTP2_INITIAL_WINDOW_SIZE + 1050 ==
            http2_session_get_stream_effective_local_window_size(session, 1));
  assert(50 ==
            http2_session_get_stream_effective_recv_data_length(session, 1));

  http2_session_del(session);
}

void test_http2_session_set_option(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_option *option;

  http2_option_new(&option);

  http2_option_set_no_auto_window_update(option, 1);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  http2_session_client_new2(&session, &callbacks, NULL, option);

  assert(session.opt_flags & HTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE);

  http2_session_del(session);

  http2_option_set_peer_max_concurrent_streams(option, 100);

  http2_session_client_new2(&session, &callbacks, NULL, option);

  assert(100 == session.remote_settings.max_concurrent_streams);
  http2_session_del(session);

  http2_option_del(option);
}

void test_http2_session_data_backoff_by_high_pri_frame(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  DataProvider data_prd;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  data_prd.read_callback = fixed_length_data_source_read_callback;

  ud.frame_send_cb_called = 0;
  ud.data_source_length = HTTP2_DATA_PAYLOADLEN * 4;

  http2_session_client_new(&session, &callbacks, &ud);
  http2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);

  session.remote_window_size = 1 << 20;

  ud.block_count = 2;
  /* Sends request HEADERS + DATA[0] */
  assert(0 == http2_session_send(session));

  stream = http2_session_get_stream(session, 1);
  stream.remote_window_size = 1 << 20;

  assert(HTTP2_DATA == ud.sent_frame_type);
  /* data for DATA[1] is read from data_prd but it is not sent */
  assert(ud.data_source_length == HTTP2_DATA_PAYLOADLEN * 2);

  http2_submit_ping(session, FrameFlags.NONE, NULL);
  ud.block_count = 2;
  /* Sends DATA[1] + PING, PING is interleaved in DATA sequence */
  assert(0 == http2_session_send(session));
  assert(HTTP2_PING == ud.sent_frame_type);
  /* data for DATA[2] is read from data_prd but it is not sent */
  assert(ud.data_source_length == HTTP2_DATA_PAYLOADLEN);

  ud.block_count = 2;
  /* Sends DATA[2..3] */
  assert(0 == http2_session_send(session));

  assert(stream.shut_flags & HTTP2_SHUT_WR);

  http2_session_del(session);
}

static void check_session_recv_data_with_padding(http2_bufs *bufs,
                                                 size_t datalen) {
  http2_session *session;
  my_user_data ud;
  http2_session_callbacks callbacks;
  ubyte *in;
  size_t inlen;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_frame_recv_callback = on_frame_recv_callback;
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  http2_session_server_new(&session, &callbacks, &ud);

  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  inlen = http2_bufs_remove(bufs, &in);

  ud.frame_recv_cb_called = 0;
  ud.data_chunk_len = 0;

  assert((size_t)inlen == http2_session_mem_recv(session, in, inlen));

  assert(1 == ud.frame_recv_cb_called);
  assert(datalen == ud.data_chunk_len);

  free(in);
  http2_session_del(session);
}

void test_http2_session_pack_data_with_padding(void) {
  http2_session *session;
  my_user_data ud;
  http2_session_callbacks callbacks;
  DataProvider data_prd;
  http2_frame *frame;
  size_t datalen = 55;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = block_count_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.select_padding_callback = select_padding_callback;

  data_prd.read_callback = fixed_length_data_source_read_callback;

  http2_session_client_new(&session, &callbacks, &ud);

  ud.padlen = 63;

  http2_submit_request(session, NULL, NULL, 0, &data_prd, NULL);
  ud.block_count = 1;
  ud.data_source_length = datalen;
  /* Sends HEADERS */
  assert(0 == http2_session_send(session));
  assert(HTTP2_HEADERS == ud.sent_frame_type);

  frame = &session.aob.item.frame;

  assert(ud.padlen == frame.data.padlen);
  assert(frame.hd.flags & FrameFlags.PADDED);

  /* Check reception of this DATA frame */
  check_session_recv_data_with_padding(&session.aob.framebufs, datalen);

  http2_session_del(session);
}

void test_http2_session_pack_headers_with_padding(void) {
  http2_session *session, *sv_session;
  accumulator acc;
  my_user_data ud;
  http2_session_callbacks callbacks;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.select_padding_callback = select_padding_callback;
  callbacks.on_frame_recv_callback = on_frame_recv_callback;

  acc.length = 0;
  ud.acc = &acc;

  http2_session_client_new(&session, &callbacks, &ud);
  http2_session_server_new(&sv_session, &callbacks, &ud);

  ud.padlen = 163;

  assert(1 == http2_submit_request(session, NULL, reqnv, ARRLEN(reqnv),
                                        NULL, NULL));
  assert(0 == http2_session_send(session));

  assert(acc.length < HTTP2_MAX_PAYLOADLEN);
  ud.frame_recv_cb_called = 0;
  assert((size_t)acc.length ==
            http2_session_mem_recv(sv_session, acc.buf, acc.length));
  assert(1 == ud.frame_recv_cb_called);
  assert(NULL == http2_session_get_next_ob_item(sv_session));

  http2_session_del(sv_session);
  http2_session_del(session);
}

void test_http2_pack_settings_payload(void) {
  http2_settings_entry iv[2];
  ubyte buf[64];
  size_t len;
  http2_settings_entry *resiv;
  size_t resniv;
  http2_mem *mem;

  mem = http2_mem_default();

  iv[0].settings_id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  iv[0].value = 1023;
  iv[1].settings_id = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = 4095;

  len = http2_pack_settings_payload(buf, sizeof(buf), iv, 2);
  assert(2 * HTTP2_FRAME_SETTINGS_ENTRY_LENGTH == len);
  assert(0 == http2_frame_unpack_settings_payload2(&resiv, &resniv, buf,
                                                        len, mem));
  assert(2 == resniv);
  assert(HTTP2_SETTINGS_HEADER_TABLE_SIZE == resiv[0].settings_id);
  assert(1023 == resiv[0].value);
  assert(HTTP2_SETTINGS_INITIAL_WINDOW_SIZE == resiv[1].settings_id);
  assert(4095 == resiv[1].value);

  free(resiv);

  len = http2_pack_settings_payload(buf, 9 /* too small */, iv, 2);
  assert(HTTP2_ERR_INSUFF_BUFSIZE == len);
}

#define check_stream_dep_sib(STREAM, DEP_PREV, DEP_NEXT, SIB_PREV, SIB_NEXT)   \
  do {                                                                         \
    assert(DEP_PREV == STREAM.dep_prev);                                   \
    assert(DEP_NEXT == STREAM.dep_next);                                   \
    assert(SIB_PREV == STREAM.sib_prev);                                   \
    assert(SIB_NEXT == STREAM.sib_next);                                   \
  } while (0)

/* http2_stream_dep_add() and its families functions should be
   tested in http2_stream_test.c, but it is easier to use
   http2_session_open_stream().  Therefore, we test them here. */
void test_http2_session_stream_dep_add(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a, *b, *c, *d, *e;

  memset(&callbacks, 0, sizeof(callbacks));

  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);

  c = open_stream_with_dep(session, 5, a);
  b = open_stream_with_dep(session, 3, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c
   *    |
   *    d
   */

  assert(4 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(DEFAULT_WEIGHT * 2 == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, c);
  check_stream_dep_sib(c, NULL, d, b, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  assert(4 == session.roots.num_streams);
  assert(a == session.roots.head);
  assert(NULL == a.root_next);

  e = open_stream_with_dep_excl(session, 9, a);

  /* a
   * |
   * e
   * |
   * b--c
   *    |
   *    d
   */

  assert(5 == a.num_substreams);
  assert(4 == e.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(DEFAULT_WEIGHT == a.sum_dep_weight);
  assert(DEFAULT_WEIGHT * 2 == e.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);

  check_stream_dep_sib(a, NULL, e, NULL, NULL);
  check_stream_dep_sib(e, a, b, NULL, NULL);
  check_stream_dep_sib(b, e, NULL, NULL, c);
  check_stream_dep_sib(c, NULL, d, b, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  assert(5 == session.roots.num_streams);
  assert(a == session.roots.head);
  assert(NULL == a.root_next);

  http2_session_del(session);
}

void test_http2_session_stream_dep_remove(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a, *b, *c, *d, *e, *f;

  memset(&callbacks, 0, sizeof(callbacks));

  /* Remove root */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * c--b
   * |
   * d
   */

  http2_stream_dep_remove(a);

  /* becomes:
   * b    c
   *      |
   *      d
   */

  assert(1 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(0 == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);

  check_stream_dep_sib(a, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(c, NULL, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  assert(3 == session.roots.num_streams);
  assert(b == session.roots.head);
  assert(c == b.root_next);
  assert(NULL == c.root_next);

  http2_session_del(session);

  /* Remove left most stream */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * c--b
   * |
   * d
   */

  http2_stream_dep_remove(b);

  /* becomes:
   * a
   * |
   * c
   * |
   * d
   */

  assert(3 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(DEFAULT_WEIGHT == a.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(0 == b.sum_dep_weight);

  check_stream_dep_sib(a, NULL, c, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(c, a, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  assert(3 == session.roots.num_streams);
  assert(a == session.roots.head);
  assert(NULL == a.root_next);

  http2_session_del(session);

  /* Remove right most stream */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * c--b
   * |
   * d
   */

  http2_stream_dep_remove(c);

  /* becomes:
   * a
   * |
   * d--b
   */

  assert(3 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(1 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(DEFAULT_WEIGHT * 2 == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(0 == c.sum_dep_weight);

  check_stream_dep_sib(a, NULL, d, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, d, NULL);
  check_stream_dep_sib(c, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(d, a, NULL, NULL, b);

  http2_session_del(session);

  /* Remove middle stream */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, a);
  e = open_stream_with_dep(session, 9, c);
  f = open_stream_with_dep(session, 11, c);

  /* a
   * |
   * d--c--b
   *    |
   *    f--e
   */

  assert(6 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(3 == c.num_substreams);
  assert(1 == d.num_substreams);
  assert(1 == e.num_substreams);
  assert(1 == f.num_substreams);

  assert(DEFAULT_WEIGHT * 3 == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT * 2 == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(0 == e.sum_dep_weight);
  assert(0 == f.sum_dep_weight);

  http2_stream_dep_remove(c);

  /* becomes:
   * a
   * |
   * d--f--e--b
   */

  assert(5 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(1 == c.num_substreams);
  assert(1 == d.num_substreams);
  assert(1 == e.num_substreams);
  assert(1 == f.num_substreams);

  /* c's weight 16 is distributed evenly to e and f.  Each weight of e
     and f becomes 8. */
  assert(DEFAULT_WEIGHT * 2 + 8 * 2 == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(0 == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(0 == e.sum_dep_weight);
  assert(0 == f.sum_dep_weight);

  check_stream_dep_sib(a, NULL, d, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, e, NULL);
  check_stream_dep_sib(c, NULL, NULL, NULL, NULL);
  check_stream_dep_sib(e, NULL, NULL, f, b);
  check_stream_dep_sib(f, NULL, NULL, d, e);
  check_stream_dep_sib(d, a, NULL, NULL, f);

  http2_session_del(session);
}

void test_http2_session_stream_dep_add_subtree(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a, *b, *c, *d, *e, *f;

  memset(&callbacks, 0, sizeof(callbacks));

  /* dep_stream has dep_next */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  e = open_stream(session, 9);
  f = open_stream_with_dep(session, 11, e);

  /* a         e
   * |         |
   * c--b      f
   * |
   * d
   */

  http2_stream_dep_add_subtree(a, e, session);

  /* becomes
   * a
   * |
   * e--c--b
   * |  |
   * f  d
   */

  assert(6 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);
  assert(2 == e.num_substreams);
  assert(1 == f.num_substreams);

  assert(DEFAULT_WEIGHT * 3 == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(DEFAULT_WEIGHT == e.sum_dep_weight);
  assert(0 == f.sum_dep_weight);

  check_stream_dep_sib(a, NULL, e, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, c, NULL);
  check_stream_dep_sib(c, NULL, d, e, b);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);
  check_stream_dep_sib(e, a, f, NULL, c);
  check_stream_dep_sib(f, e, NULL, NULL, NULL);

  http2_session_del(session);

  /* dep_stream has dep_next and now we insert subtree */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  e = open_stream(session, 9);
  f = open_stream_with_dep(session, 11, e);

  /* a         e
   * |         |
   * c--b      f
   * |
   * d
   */

  http2_stream_dep_insert_subtree(a, e, session);

  /* becomes
   * a
   * |
   * e
   * |
   * f--c--b
   *    |
   *    d
   */

  assert(6 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);
  assert(5 == e.num_substreams);
  assert(1 == f.num_substreams);

  assert(DEFAULT_WEIGHT == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(DEFAULT_WEIGHT * 3 == e.sum_dep_weight);
  assert(0 == f.sum_dep_weight);

  check_stream_dep_sib(a, NULL, e, NULL, NULL);
  check_stream_dep_sib(e, a, f, NULL, NULL);
  check_stream_dep_sib(f, e, NULL, NULL, c);
  check_stream_dep_sib(b, NULL, NULL, c, NULL);
  check_stream_dep_sib(c, NULL, d, f, b);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  http2_session_del(session);
}

void test_http2_session_stream_dep_remove_subtree(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a, *b, *c, *d, *e;

  memset(&callbacks, 0, sizeof(callbacks));

  /* Remove left most stream */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * c--b
   * |
   * d
   */

  http2_stream_dep_remove_subtree(c);

  /* becomes
   * a  c
   * |  |
   * b  d
   */

  assert(2 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(DEFAULT_WEIGHT == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, NULL);
  check_stream_dep_sib(c, NULL, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  http2_session_del(session);

  /* Remove right most stream */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * c--b
   * |
   * d
   */

  http2_stream_dep_remove_subtree(b);

  /* becomes
   * a  b
   * |
   * c
   * |
   * d
   */

  assert(3 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(DEFAULT_WEIGHT == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);

  check_stream_dep_sib(a, NULL, c, NULL, NULL);
  check_stream_dep_sib(c, a, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);
  check_stream_dep_sib(b, NULL, NULL, NULL, NULL);

  http2_session_del(session);

  /* Remove middle stream */
  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  e = open_stream_with_dep(session, 9, a);
  c = open_stream_with_dep(session, 5, a);
  b = open_stream_with_dep(session, 3, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * b--c--e
   *    |
   *    d
   */

  http2_stream_dep_remove_subtree(c);

  /* becomes
   * a     c
   * |     |
   * b--e  d
   */

  assert(3 == a.num_substreams);
  assert(1 == b.num_substreams);
  assert(1 == e.num_substreams);
  assert(2 == c.num_substreams);
  assert(1 == d.num_substreams);

  assert(DEFAULT_WEIGHT * 2 == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(0 == e.sum_dep_weight);

  check_stream_dep_sib(a, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, e);
  check_stream_dep_sib(e, NULL, NULL, b, NULL);
  check_stream_dep_sib(c, NULL, d, NULL, NULL);
  check_stream_dep_sib(d, c, NULL, NULL, NULL);

  http2_session_del(session);
}

void test_http2_session_stream_dep_all_your_stream_are_belong_to_us(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a, *b, *c, *d;

  memset(&callbacks, 0, sizeof(callbacks));

  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);

  c = open_stream(session, 5);

  /* a     c
   * |
   * b
   */

  http2_stream_dep_remove_subtree(c);
  assert(0 ==
            http2_stream_dep_all_your_stream_are_belong_to_us(c, session));

  /*
   * c
   * |
   * a
   * |
   * b
   */

  assert(3 == c.num_substreams);
  assert(2 == a.num_substreams);
  assert(1 == b.num_substreams);

  assert(DEFAULT_WEIGHT == c.sum_dep_weight);
  assert(DEFAULT_WEIGHT == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);

  check_stream_dep_sib(c, NULL, a, NULL, NULL);
  check_stream_dep_sib(a, c, b, NULL, NULL);
  check_stream_dep_sib(b, a, NULL, NULL, NULL);

  http2_session_del(session);

  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);

  b = open_stream(session, 3);

  c = open_stream(session, 5);

  /*
   * a  b   c
   */

  http2_stream_dep_remove_subtree(c);
  assert(0 ==
            http2_stream_dep_all_your_stream_are_belong_to_us(c, session));

  /*
   * c
   * |
   * b--a
   */

  assert(3 == c.num_substreams);
  assert(1 == a.num_substreams);
  assert(1 == b.num_substreams);

  assert(DEFAULT_WEIGHT * 2 == c.sum_dep_weight);
  assert(0 == b.sum_dep_weight);
  assert(0 == a.sum_dep_weight);

  check_stream_dep_sib(c, NULL, b, NULL, NULL);
  check_stream_dep_sib(b, c, NULL, NULL, a);
  check_stream_dep_sib(a, NULL, NULL, b, NULL);

  http2_session_del(session);

  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);

  c = open_stream(session, 5);
  d = open_stream_with_dep(session, 7, c);

  /* a     c
   * |     |
   * b     d
   */

  http2_stream_dep_remove_subtree(c);
  assert(0 ==
            http2_stream_dep_all_your_stream_are_belong_to_us(c, session));

  /*
   * c
   * |
   * a--d
   * |
   * b
   */

  assert(4 == c.num_substreams);
  assert(1 == d.num_substreams);
  assert(2 == a.num_substreams);
  assert(1 == b.num_substreams);

  assert(DEFAULT_WEIGHT * 2 == c.sum_dep_weight);
  assert(0 == d.sum_dep_weight);
  assert(DEFAULT_WEIGHT == a.sum_dep_weight);
  assert(0 == b.sum_dep_weight);

  check_stream_dep_sib(c, NULL, a, NULL, NULL);
  check_stream_dep_sib(d, NULL, NULL, a, NULL);
  check_stream_dep_sib(a, c, b, NULL, d);
  check_stream_dep_sib(b, a, NULL, NULL, NULL);

  http2_session_del(session);
}

void test_http2_session_stream_attach_item(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a, *b, *c, *d;
  http2_outbound_item *da, *db, *dc, *dd;

  memset(&callbacks, 0, sizeof(callbacks));

  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  /* a
   * |
   * c--b
   * |
   * d
   */

  db = create_data_ob_item();

  http2_stream_attach_item(b, db, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);

  assert(16 == b.effective_weight);

  assert(16 == a.sum_norest_weight);

  assert(1 == db.queued);

  dc = create_data_ob_item();

  http2_stream_attach_item(c, dc, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);

  assert(16 * 16 / 32 == b.effective_weight);
  assert(16 * 16 / 32 == c.effective_weight);

  assert(32 == a.sum_norest_weight);

  assert(1 == dc.queued);

  da = create_data_ob_item();

  http2_stream_attach_item(a, da, session);

  assert(HTTP2_STREAM_DPRI_TOP == a.dpri);
  assert(HTTP2_STREAM_DPRI_REST == b.dpri);
  assert(HTTP2_STREAM_DPRI_REST == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);

  assert(16 == a.effective_weight);

  assert(1 == da.queued);

  http2_stream_detach_item(a, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);

  assert(16 * 16 / 32 == b.effective_weight);
  assert(16 * 16 / 32 == c.effective_weight);

  dd = create_data_ob_item();

  http2_stream_attach_item(d, dd, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == c.dpri);
  assert(HTTP2_STREAM_DPRI_REST == d.dpri);

  assert(16 * 16 / 32 == b.effective_weight);
  assert(16 * 16 / 32 == c.effective_weight);

  assert(0 == dd.queued);

  http2_stream_detach_item(c, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_REST == d.dpri);

  assert(16 * 16 / 16 == b.effective_weight);

  assert(0 == dd.queued);

  http2_stream_detach_item(b, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == d.dpri);

  assert(16 * 16 / 16 == d.effective_weight);

  assert(1 == dd.queued);

  http2_session_del(session);
}

void test_http2_session_stream_attach_item_subtree(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a, *b, *c, *d, *e, *f;
  http2_outbound_item *db, *dd, *de;

  memset(&callbacks, 0, sizeof(callbacks));

  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  b = open_stream_with_dep(session, 3, a);
  c = open_stream_with_dep(session, 5, a);
  d = open_stream_with_dep(session, 7, c);

  e = open_stream(session, 9);
  f = open_stream_with_dep(session, 11, e);
  /*
   * a        e
   * |        |
   * c--b     f
   * |
   * d
   */

  de = create_data_ob_item();

  http2_stream_attach_item(e, de, session);

  db = create_data_ob_item();

  http2_stream_attach_item(b, db, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  assert(16 == b.effective_weight);
  assert(16 == e.effective_weight);

  /* Insert subtree e under a */

  http2_stream_dep_remove_subtree(e);
  http2_stream_dep_insert_subtree(a, e, session);

  /*
   * a
   * |
   * e
   * |
   * f--c--b
   *    |
   *    d
   */

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_REST == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  assert(16 == e.effective_weight);

  /* Remove subtree b */

  http2_stream_dep_remove_subtree(b);

  http2_stream_dep_make_root(b, session);

  /*
   * a       b
   * |
   * e
   * |
   * f--c
   *    |
   *    d
   */

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  assert(16 == b.effective_weight);
  assert(16 == e.effective_weight);

  /* Remove subtree a */

  http2_stream_dep_remove_subtree(a);

  http2_stream_dep_make_root(a, session);

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  /* Remove subtree c */

  http2_stream_dep_remove_subtree(c);

  http2_stream_dep_make_root(c, session);

  /*
   * a       b     c
   * |             |
   * e             d
   * |
   * f
   */

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == d.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  dd = create_data_ob_item();

  http2_stream_attach_item(d, dd, session);

  /* Add subtree c to a */

  http2_stream_dep_remove_subtree(c);
  http2_stream_dep_add_subtree(a, c, session);

  /*
   * a       b
   * |
   * c--e
   * |  |
   * d  f
   */

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_REST == d.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  assert(16 == b.effective_weight);
  assert(16 * 16 / 16 == e.effective_weight);

  assert(32 == a.sum_norest_weight);
  assert(16 == c.sum_norest_weight);

  /* Insert b under a */

  http2_stream_dep_remove_subtree(b);
  http2_stream_dep_insert_subtree(a, b, session);

  /*
   * a
   * |
   * b
   * |
   * e--c
   * |  |
   * f  d
   */

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_REST == d.dpri);
  assert(HTTP2_STREAM_DPRI_REST == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  assert(16 == b.effective_weight);

  assert(16 == a.sum_norest_weight);
  assert(0 == b.sum_norest_weight);

  /* Remove subtree b */

  http2_stream_dep_remove_subtree(b);
  http2_stream_dep_make_root(b, session);

  /*
   * b       a
   * |
   * e--c
   * |  |
   * f  d
   */

  assert(HTTP2_STREAM_DPRI_NO_ITEM == a.dpri);
  assert(HTTP2_STREAM_DPRI_TOP == b.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == c.dpri);
  assert(HTTP2_STREAM_DPRI_REST == d.dpri);
  assert(HTTP2_STREAM_DPRI_REST == e.dpri);
  assert(HTTP2_STREAM_DPRI_NO_ITEM == f.dpri);

  assert(0 == a.sum_norest_weight);
  assert(0 == b.sum_norest_weight);

  http2_session_del(session);
}

void test_http2_session_keep_closed_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  const size_t max_concurrent_streams = 5;
  http2_settings_entry iv = {HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
                               max_concurrent_streams};
  size_t i;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  http2_submit_settings(session, FrameFlags.NONE, &iv, 1);

  for (i = 0; i < max_concurrent_streams; ++i) {
    open_stream(session, (int)i * 2 + 1);
  }

  assert(0 == session.num_closed_streams);

  http2_session_close_stream(session, 1, HTTP2_NO_ERROR);

  assert(1 == session.num_closed_streams);
  assert(1 == session.closed_stream_tail.stream_id);
  assert(session.closed_stream_tail == session.closed_stream_head);

  http2_session_close_stream(session, 5, HTTP2_NO_ERROR);

  assert(2 == session.num_closed_streams);
  assert(5 == session.closed_stream_tail.stream_id);
  assert(1 == session.closed_stream_head.stream_id);
  assert(session.closed_stream_head ==
            session.closed_stream_tail.closed_prev);
  assert(NULL == session.closed_stream_tail.closed_next);
  assert(session.closed_stream_tail ==
            session.closed_stream_head.closed_next);
  assert(NULL == session.closed_stream_head.closed_prev);

  open_stream(session, 11);

  assert(1 == session.num_closed_streams);
  assert(5 == session.closed_stream_tail.stream_id);
  assert(session.closed_stream_tail == session.closed_stream_head);
  assert(NULL == session.closed_stream_head.closed_prev);
  assert(NULL == session.closed_stream_head.closed_next);

  open_stream(session, 13);

  assert(0 == session.num_closed_streams);
  assert(NULL == session.closed_stream_tail);
  assert(NULL == session.closed_stream_head);

  http2_session_del(session);
}

void test_http2_session_keep_idle_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  const size_t max_concurrent_streams = 1;
  http2_settings_entry iv = {HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
                               max_concurrent_streams};
  int i;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  http2_submit_settings(session, FrameFlags.NONE, &iv, 1);

  /* We at least allow 2 idle streams even if max concurrent streams
     is very low. */
  for (i = 0; i < 2; ++i) {
    http2_session_open_stream(session, i * 2 + 1, HTTP2_STREAM_FLAG_NONE,
                                &pri_spec_default, HTTP2_STREAM_IDLE, NULL);
  }

  assert(2 == session.num_idle_streams);

  assert(1 == session.idle_stream_head.stream_id);
  assert(3 == session.idle_stream_tail.stream_id);

  http2_session_open_stream(session, 5, FrameFlags.NONE, &pri_spec_default,
                              HTTP2_STREAM_IDLE, NULL);

  assert(2 == session.num_idle_streams);

  assert(3 == session.idle_stream_head.stream_id);
  assert(5 == session.idle_stream_tail.stream_id);

  http2_session_del(session);
}

void test_http2_session_detach_idle_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  int i;
  http2_stream *stream;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  for (i = 1; i <= 3; ++i) {
    http2_session_open_stream(session, i, HTTP2_STREAM_FLAG_NONE,
                                &pri_spec_default, HTTP2_STREAM_IDLE, NULL);
  }

  assert(3 == session.num_idle_streams);

  /* Detach middle stream */
  stream = http2_session_get_stream_raw(session, 2);

  assert(session.idle_stream_head == stream.closed_prev);
  assert(session.idle_stream_tail == stream.closed_next);
  assert(stream == session.idle_stream_head.closed_next);
  assert(stream == session.idle_stream_tail.closed_prev);

  http2_session_detach_idle_stream(session, stream);

  assert(2 == session.num_idle_streams);

  assert(NULL == stream.closed_prev);
  assert(NULL == stream.closed_next);

  assert(session.idle_stream_head ==
            session.idle_stream_tail.closed_prev);
  assert(session.idle_stream_tail ==
            session.idle_stream_head.closed_next);

  /* Detach head stream */
  stream = session.idle_stream_head;

  http2_session_detach_idle_stream(session, stream);

  assert(1 == session.num_idle_streams);

  assert(session.idle_stream_head == session.idle_stream_tail);
  assert(NULL == session.idle_stream_head.closed_prev);
  assert(NULL == session.idle_stream_head.closed_next);

  /* Detach last stream */

  stream = session.idle_stream_head;

  http2_session_detach_idle_stream(session, stream);

  assert(0 == session.num_idle_streams);

  assert(NULL == session.idle_stream_head);
  assert(NULL == session.idle_stream_tail);

  for (i = 4; i <= 5; ++i) {
    http2_session_open_stream(session, i, HTTP2_STREAM_FLAG_NONE,
                                &pri_spec_default, HTTP2_STREAM_IDLE, NULL);
  }

  assert(2 == session.num_idle_streams);

  /* Detach tail stream */

  stream = session.idle_stream_tail;

  http2_session_detach_idle_stream(session, stream);

  assert(1 == session.num_idle_streams);

  assert(session.idle_stream_head == session.idle_stream_tail);
  assert(NULL == session.idle_stream_head.closed_prev);
  assert(NULL == session.idle_stream_head.closed_next);

  http2_session_del(session);
}

void test_http2_session_large_dep_tree(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  size_t i;
  http2_stream *dep_stream = NULL;
  http2_stream *root_stream;
  int stream_id;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  stream_id = 1;
  for (i = 0; i < HTTP2_MAX_DEP_TREE_LENGTH; ++i) {
    dep_stream = open_stream_with_dep(session, stream_id, dep_stream);
    stream_id += 2;
  }

  root_stream = http2_session_get_stream(session, 1);

  /* Check that last dep_stream must be part of tree */
  assert(http2_stream_dep_subtree_find(root_stream, dep_stream));

  dep_stream = open_stream_with_dep(session, stream_id, dep_stream);

  /* We exceeded HTTP2_MAX_DEP_TREE_LENGTH limit.  dep_stream is now
     root node and has no descendants. */
  assert(!http2_stream_dep_subtree_find(root_stream, dep_stream));
  assert(http2_stream_in_dep_tree(dep_stream));

  http2_session_del(session);
}

void test_http2_session_graceful_shutdown(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  open_stream(session, 301);
  open_stream(session, 302);
  open_stream(session, 309);
  open_stream(session, 311);
  open_stream(session, 319);

  assert(0 == http2_submit_shutdown_notice(session));

  ud.frame_send_cb_called = 0;

  assert(0 == http2_session_send(session));

  assert(1 == ud.frame_send_cb_called);
  assert((1u << 31) - 1 == session.local_last_stream_id);

  assert(0 == http2_submit_goaway(session, FrameFlags.NONE, 311,
                                       HTTP2_NO_ERROR, NULL, 0));

  ud.frame_send_cb_called = 0;
  ud.stream_close_cb_called = 0;

  assert(0 == http2_session_send(session));

  assert(1 == ud.frame_send_cb_called);
  assert(311 == session.local_last_stream_id);
  assert(1 == ud.stream_close_cb_called);

  assert(0 ==
            http2_session_terminate_session2(session, 301, HTTP2_NO_ERROR));

  ud.frame_send_cb_called = 0;
  ud.stream_close_cb_called = 0;

  assert(0 == http2_session_send(session));

  assert(1 == ud.frame_send_cb_called);
  assert(301 == session.local_last_stream_id);
  assert(2 == ud.stream_close_cb_called);

  assert(NULL != http2_session_get_stream(session, 301));
  assert(NULL != http2_session_get_stream(session, 302));
  assert(NULL == http2_session_get_stream(session, 309));
  assert(NULL == http2_session_get_stream(session, 311));
  assert(NULL == http2_session_get_stream(session, 319));

  http2_session_del(session);
}

void test_http2_session_on_header_temporal_failure(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  my_user_data ud;
  http2_bufs bufs;
  http2_buf *buf;
  http2_hd_deflater deflater;
  http2_nv nv[] = {MAKE_NV("alpha", "bravo"), MAKE_NV("charlie", "delta")};
  http2_nv *nva;
  size_t hdpos;
  size_t rv;
  http2_frame frame;
  http2_frame_hd hd;
  http2_outbound_item *item;
  http2_mem *mem;

  mem = http2_mem_default();
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.on_header_callback = temporal_failure_on_header_callback;

  http2_session_server_new(&session, &callbacks, &ud);

  frame_pack_bufs_init(&bufs);

  http2_hd_deflate_init(&deflater, mem);

  http2_nv_array_copy(&nva, reqnv, ARRLEN(reqnv), mem);

  http2_frame_headers_init(&frame.headers, FrameFlags.END_STREAM, 1,
                             HTTP2_HCAT_REQUEST, NULL, nva, ARRLEN(reqnv));
  http2_frame_pack_headers(&bufs, &frame.headers, &deflater);
  http2_frame_headers_free(&frame.headers, mem);

  /* We are going to create CONTINUATION.  First serialize header
     block, and then frame header. */
  hdpos = http2_bufs_len(&bufs);

  buf = &bufs.head.buf;
  buf.last += HTTP2_FRAME_HDLEN;

  http2_hd_deflate_hd_bufs(&deflater, &bufs, &nv[1], 1);

  http2_frame_hd_init(&hd,
                        http2_bufs_len(&bufs) - hdpos - HTTP2_FRAME_HDLEN,
                        HTTP2_CONTINUATION, FrameFlags.END_HEADERS, 1);

  http2_frame_pack_frame_hd(&buf.pos[hdpos], &hd);

  rv = http2_session_mem_recv(session, buf.pos, http2_bufs_len(&bufs));

  assert(rv == http2_bufs_len(&bufs));

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  /* Make sure no header decompression error occurred */
  assert(GoAwayFlags.NONE == session.goaway_flags);

  http2_bufs_free(&bufs);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
}

void test_http2_session_recv_client_preface(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_option *option;
  size_t rv;
  http2_frame ping_frame;
  ubyte buf[16];

  memset(&callbacks, 0, sizeof(callbacks));

  http2_option_new(&option);
  http2_option_set_recv_client_preface(option, 1);

  /* Check success case */
  http2_session_server_new2(&session, &callbacks, NULL, option);

  assert(session.opt_flags & HTTP2_OPTMASK_RECV_CLIENT_PREFACE);

  rv = http2_session_mem_recv(
      session, (const ubyte *)HTTP2_CLIENT_CONNECTION_PREFACE,
      HTTP2_CLIENT_CONNECTION_PREFACE_LEN);

  assert(rv == HTTP2_CLIENT_CONNECTION_PREFACE_LEN);
  assert(HTTP2_IB_READ_FIRST_SETTINGS == session.iframe.state);

  /* Receiving PING is error because we want SETTINGS. */
  http2_frame_ping_init(&ping_frame.ping, FrameFlags.NONE, NULL);

  http2_frame_pack_frame_hd(buf, &ping_frame.ping.hd);

  rv = http2_session_mem_recv(session, buf, HTTP2_FRAME_HDLEN);
  assert(HTTP2_FRAME_HDLEN == rv);
  assert(HTTP2_IB_IGN_ALL == session.iframe.state);
  assert(0 == session.iframe.payloadleft);

  http2_frame_ping_free(&ping_frame.ping);

  http2_session_del(session);

  /* Check bad case */
  http2_session_server_new2(&session, &callbacks, NULL, option);

  /* Feed preface with one byte less */
  rv = http2_session_mem_recv(
      session, (const ubyte *)HTTP2_CLIENT_CONNECTION_PREFACE,
      HTTP2_CLIENT_CONNECTION_PREFACE_LEN - 1);

  assert(rv == HTTP2_CLIENT_CONNECTION_PREFACE_LEN - 1);
  assert(HTTP2_IB_READ_CLIENT_PREFACE == session.iframe.state);
  assert(1 == session.iframe.payloadleft);

  rv = http2_session_mem_recv(session, (const ubyte *)"\0", 1);

  assert(HTTP2_ERR_BAD_PREFACE == rv);

  http2_session_del(session);

  http2_option_del(option);
}

void test_http2_session_delete_data_item(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *a;
  DataProvider prd;

  memset(&callbacks, 0, sizeof(callbacks));

  http2_session_server_new(&session, &callbacks, NULL);

  a = open_stream(session, 1);
  open_stream_with_dep(session, 3, a);

  /* We don't care about these members, since we won't send data */
  prd.source.ptr = NULL;
  prd.read_callback = fail_data_source_read_callback;

  /* This data item will be marked as TOP */
  assert(0 == http2_submit_data(session, FrameFlags.NONE, 1, &prd));
  /* This data item will be marked as REST */
  assert(0 == http2_submit_data(session, FrameFlags.NONE, 3, &prd));

  http2_session_del(session);
}

void test_http2_session_open_idle_stream(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;
  http2_stream *opened_stream;
  http2_priority_spec pri_spec;
  http2_frame frame;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));

  http2_session_server_new(&session, &callbacks, NULL);

  http2_priority_spec_init(&pri_spec, 0, 3, 0);

  http2_frame_priority_init(&frame.priority, 1, &pri_spec);

  assert(0 == http2_session_on_priority_received(session, &frame));

  stream = http2_session_get_stream_raw(session, 1);

  assert(HTTP2_STREAM_IDLE == stream.state);
  assert(NULL == stream.closed_prev);
  assert(NULL == stream.closed_next);
  assert(1 == session.num_idle_streams);
  assert(session.idle_stream_head == stream);
  assert(session.idle_stream_tail == stream);

  opened_stream = http2_session_open_stream(
      session, 1, HTTP2_STREAM_FLAG_NONE, &pri_spec_default,
      HTTP2_STREAM_OPENING, NULL);

  assert(stream == opened_stream);
  assert(HTTP2_STREAM_OPENING == stream.state);
  assert(0 == session.num_idle_streams);
  assert(NULL == session.idle_stream_head);
  assert(NULL == session.idle_stream_tail);

  http2_frame_priority_free(&frame.priority);

  http2_session_del(session);
}

void test_http2_session_cancel_reserved_remote(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;
  http2_frame frame;
  http2_nv *nva;
  size_t nvlen;
  http2_hd_deflater deflater;
  http2_mem *mem;
  http2_bufs bufs;
  size_t rv;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  stream = http2_session_open_stream(session, 2, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_RESERVED, NULL);

  session.last_recv_stream_id = 2;

  http2_submit_rst_stream(session, FrameFlags.NONE, 2, HTTP2_CANCEL);

  assert(HTTP2_STREAM_CLOSING == stream.state);

  assert(0 == http2_session_send(session));

  nvlen = ARRLEN(resnv);
  http2_nv_array_copy(&nva, resnv, nvlen, mem);

  http2_frame_headers_init(&frame.headers, FrameFlags.END_HEADERS, 2,
                             HTTP2_HCAT_PUSH_RESPONSE, NULL, nva, nvlen);
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  /* stream is not dangling, so assign NULL */
  stream = NULL;

  /* No RST_STREAM or GOAWAY is generated since stream should be in
     HTTP2_STREAM_CLOSING and push response should be ignored. */
  assert(0 == http2_pq_size(&session.ob_pq));

  /* Check that we can receive push response HEADERS while RST_STREAM
     is just queued. */
  http2_session_open_stream(session, 4, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_RESERVED, NULL);

  session.last_recv_stream_id = 4;

  http2_submit_rst_stream(session, FrameFlags.NONE, 2, HTTP2_CANCEL);

  http2_bufs_reset(&bufs);

  frame.hd.stream_id = 4;
  rv = http2_frame_pack_headers(&bufs, &frame.headers, &deflater);

  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(1 == http2_pq_size(&session.ob_pq));

  http2_frame_headers_free(&frame.headers, mem);

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);

  http2_bufs_free(&bufs);
}

void test_http2_session_reset_pending_headers(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_stream *stream;
  int stream_id;
  my_user_data ud;

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;
  callbacks.on_frame_send_callback = on_frame_send_callback;
  callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;

  http2_session_client_new(&session, &callbacks, &ud);

  stream_id = http2_submit_request(session, NULL, NULL, 0, NULL, NULL);
  assert(stream_id >= 1);

  http2_submit_rst_stream(session, FrameFlags.NONE, stream_id,
                            HTTP2_CANCEL);

  session.remote_settings.max_concurrent_streams = 0;

  /* RST_STREAM cancels pending HEADERS and is not actually sent. */
  ud.frame_send_cb_called = 0;
  assert(0 == http2_session_send(session));

  assert(0 == ud.frame_send_cb_called);

  stream = http2_session_get_stream(session, stream_id);

  assert(NULL == stream);

  /* See HEADERS is not sent.  on_stream_close is called just like
     transmission failure. */
  session.remote_settings.max_concurrent_streams = 1;

  ud.frame_not_send_cb_called = 0;
  ud.stream_close_error_code = 0;
  assert(0 == http2_session_send(session));

  assert(1 == ud.frame_not_send_cb_called);
  assert(HTTP2_HEADERS == ud.not_sent_frame_type);
  assert(HTTP2_CANCEL == ud.stream_close_error_code);

  stream = http2_session_get_stream(session, stream_id);

  assert(NULL == stream);

  http2_session_del(session);
}

static void check_http2_http_recv_headers_fail(
    http2_session *session, http2_hd_deflater *deflater, int stream_id,
    int stream_state, const http2_nv *nva, size_t nvlen) {
  http2_mem *mem;
  size_t rv;
  http2_outbound_item *item;
  http2_bufs bufs;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  if (stream_state != -1) {
    http2_session_open_stream(session, stream_id, HTTP2_STREAM_FLAG_NONE,
                                &pri_spec_default, stream_state, NULL);
  }

  rv = pack_headers(&bufs, deflater, stream_id, FrameFlags.END_HEADERS, nva,
                    nvlen, mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_free(&bufs);
}

void test_http2_http_mandatory_headers(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_hd_deflater deflater;
  http2_mem *mem;
  /* test case for response */
  const http2_nv nostatus_resnv[] = {MAKE_NV("server", "foo")};
  const http2_nv dupstatus_resnv[] = {MAKE_NV(":status", "200"),
                                        MAKE_NV(":status", "200")};
  const http2_nv badpseudo_resnv[] = {MAKE_NV(":status", "200"),
                                        MAKE_NV(":scheme", "https")};
  const http2_nv latepseudo_resnv[] = {MAKE_NV("server", "foo"),
                                         MAKE_NV(":status", "200")};
  const http2_nv badstatus_resnv[] = {MAKE_NV(":status", "2000")};
  const http2_nv badcl_resnv[] = {MAKE_NV(":status", "200"),
                                    MAKE_NV("content-length", "-1")};
  const http2_nv dupcl_resnv[] = {MAKE_NV(":status", "200"),
                                    MAKE_NV("content-length", "0"),
                                    MAKE_NV("content-length", "0")};
  const http2_nv badhd_resnv[] = {MAKE_NV(":status", "200"),
                                    MAKE_NV("connection", "close")};

  /* test case for request */
  const http2_nv nopath_reqnv[] = {MAKE_NV(":scheme", "https"),
                                     MAKE_NV(":method", "GET"),
                                     MAKE_NV(":authority", "localhost")};
  const http2_nv earlyconnect_reqnv[] = {
      MAKE_NV(":method", "CONNECT"), MAKE_NV(":scheme", "https"),
      MAKE_NV(":path", "/"), MAKE_NV(":authority", "localhost")};
  const http2_nv lateconnect_reqnv[] = {
      MAKE_NV(":scheme", "https"), MAKE_NV(":path", "/"),
      MAKE_NV(":method", "CONNECT"), MAKE_NV(":authority", "localhost")};
  const http2_nv duppath_reqnv[] = {
      MAKE_NV(":scheme", "https"), MAKE_NV(":method", "GET"),
      MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
      MAKE_NV(":path", "/")};
  const http2_nv badcl_reqnv[] = {
      MAKE_NV(":scheme", "https"), MAKE_NV(":method", "POST"),
      MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
      MAKE_NV("content-length", "-1")};
  const http2_nv dupcl_reqnv[] = {
      MAKE_NV(":scheme", "https"),        MAKE_NV(":method", "POST"),
      MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
      MAKE_NV("content-length", "0"),     MAKE_NV("content-length", "0")};
  const http2_nv badhd_reqnv[] = {
      MAKE_NV(":scheme", "https"), MAKE_NV(":method", "GET"),
      MAKE_NV(":authority", "localhost"), MAKE_NV(":path", "/"),
      MAKE_NV("connection", "close")};

  mem = http2_mem_default();

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  /* response header lacks :status */
  check_http2_http_recv_headers_fail(session, &deflater, 1,
                                       HTTP2_STREAM_OPENING, nostatus_resnv,
                                       ARRLEN(nostatus_resnv));

  /* response header has 2 :status */
  check_http2_http_recv_headers_fail(session, &deflater, 3,
                                       HTTP2_STREAM_OPENING, dupstatus_resnv,
                                       ARRLEN(dupstatus_resnv));

  /* response header has bad pseudo header :scheme */
  check_http2_http_recv_headers_fail(session, &deflater, 5,
                                       HTTP2_STREAM_OPENING, badpseudo_resnv,
                                       ARRLEN(badpseudo_resnv));

  /* response header has :status after regular header field */
  check_http2_http_recv_headers_fail(session, &deflater, 7,
                                       HTTP2_STREAM_OPENING, latepseudo_resnv,
                                       ARRLEN(latepseudo_resnv));

  /* response header has bad status code */
  check_http2_http_recv_headers_fail(session, &deflater, 9,
                                       HTTP2_STREAM_OPENING, badstatus_resnv,
                                       ARRLEN(badstatus_resnv));

  /* response header has bad content-length */
  check_http2_http_recv_headers_fail(session, &deflater, 11,
                                       HTTP2_STREAM_OPENING, badcl_resnv,
                                       ARRLEN(badcl_resnv));

  /* response header has multiple content-length */
  check_http2_http_recv_headers_fail(session, &deflater, 13,
                                       HTTP2_STREAM_OPENING, dupcl_resnv,
                                       ARRLEN(dupcl_resnv));

  /* response header has disallowed header field */
  check_http2_http_recv_headers_fail(session, &deflater, 15,
                                       HTTP2_STREAM_OPENING, badhd_resnv,
                                       ARRLEN(badhd_resnv));

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);

  /* check server side */
  http2_session_server_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  /* request header has no :path */
  check_http2_http_recv_headers_fail(session, &deflater, 1, -1, nopath_reqnv,
                                       ARRLEN(nopath_reqnv));

  /* request header has CONNECT method, but followed by :path */
  check_http2_http_recv_headers_fail(session, &deflater, 3, -1,
                                       earlyconnect_reqnv,
                                       ARRLEN(earlyconnect_reqnv));

  /* request header has CONNECT method following :path */
  check_http2_http_recv_headers_fail(
      session, &deflater, 5, -1, lateconnect_reqnv, ARRLEN(lateconnect_reqnv));

  /* request header has multiple :path */
  check_http2_http_recv_headers_fail(session, &deflater, 7, -1, duppath_reqnv,
                                       ARRLEN(duppath_reqnv));

  /* request header has bad content-length */
  check_http2_http_recv_headers_fail(session, &deflater, 9, -1, badcl_reqnv,
                                       ARRLEN(badcl_reqnv));

  /* request header has multiple content-length */
  check_http2_http_recv_headers_fail(session, &deflater, 11, -1, dupcl_reqnv,
                                       ARRLEN(dupcl_reqnv));

  /* request header has disallowed header field */
  check_http2_http_recv_headers_fail(session, &deflater, 13, -1, badhd_reqnv,
                                       ARRLEN(badhd_reqnv));

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);
}

void test_http2_http_content_length(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_hd_deflater deflater;
  http2_mem *mem;
  http2_bufs bufs;
  size_t rv;
  http2_stream *stream;
  const http2_nv cl_resnv[] = {MAKE_NV(":status", "200"),
                                 MAKE_NV("te", "trailers"),
                                 MAKE_NV("content-length", "9000000000")};
  const http2_nv cl_reqnv[] = {
      MAKE_NV(":path", "/"),        MAKE_NV(":method", "PUT"),
      MAKE_NV(":scheme", "https"),  MAKE_NV("te", "trailers"),
      MAKE_NV("host", "localhost"), MAKE_NV("content-length", "9000000000")};

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, cl_resnv,
                    ARRLEN(cl_resnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);
  assert(NULL == http2_session_get_next_ob_item(session));
  assert(9000000000LL == stream.content_length);
  assert(200 == stream.status_code);

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);

  http2_bufs_reset(&bufs);

  /* check server side */
  http2_session_server_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, cl_reqnv,
                    ARRLEN(cl_reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  stream = http2_session_get_stream(session, 1);

  assert(NULL == http2_session_get_next_ob_item(session));
  assert(9000000000LL == stream.content_length);

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);

  http2_bufs_free(&bufs);
}

void test_http2_http_content_length_mismatch(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_hd_deflater deflater;
  http2_mem *mem;
  http2_bufs bufs;
  size_t rv;
  const http2_nv cl_reqnv[] = {
      MAKE_NV(":path", "/"), MAKE_NV(":method", "PUT"),
      MAKE_NV(":authority", "localhost"), MAKE_NV(":scheme", "https"),
      MAKE_NV("content-length", "20")};
  http2_outbound_item *item;
  http2_frame_hd hd;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  /* header says content-length: 20, but HEADERS has END_STREAM flag set */
  rv = pack_headers(&bufs, &deflater, 1,
                    FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
                    cl_reqnv, ARRLEN(cl_reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  /* header says content-length: 20, but DATA has 0 byte */
  rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS, cl_reqnv,
                    ARRLEN(cl_reqnv), mem);
  assert(0 == rv);

  http2_frame_hd_init(&hd, 0, HTTP2_DATA, FrameFlags.END_STREAM, 3);
  http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
  bufs.head.buf.last += HTTP2_FRAME_HDLEN;

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  /* header says content-length: 20, but DATA has 21 bytes */
  rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS, cl_reqnv,
                    ARRLEN(cl_reqnv), mem);
  assert(0 == rv);

  http2_frame_hd_init(&hd, 21, HTTP2_DATA, FrameFlags.END_STREAM, 5);
  http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
  bufs.head.buf.last += HTTP2_FRAME_HDLEN + 21;

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);

  http2_bufs_free(&bufs);
}

void test_http2_http_non_final_response(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_hd_deflater deflater;
  http2_mem *mem;
  http2_bufs bufs;
  size_t rv;
  const http2_nv nonfinal_resnv[] = {
      MAKE_NV(":status", "100"),
  };
  http2_outbound_item *item;
  http2_frame_hd hd;
  http2_stream *stream;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  /* non-final HEADERS with END_STREAM is illegal */
  stream = http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  rv = pack_headers(&bufs, &deflater, 1,
                    FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
                    nonfinal_resnv, ARRLEN(nonfinal_resnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  /* non-final HEADERS followed by non-empty DATA is illegal */
  stream = http2_session_open_stream(session, 3, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS,
                    nonfinal_resnv, ARRLEN(nonfinal_resnv), mem);
  assert(0 == rv);

  http2_frame_hd_init(&hd, 10, HTTP2_DATA, FrameFlags.END_STREAM, 3);
  http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
  bufs.head.buf.last += HTTP2_FRAME_HDLEN + 10;

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);
  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  /* non-final HEADERS followed by empty DATA (without END_STREAM) is
     ok */
  stream = http2_session_open_stream(session, 5, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS,
                    nonfinal_resnv, ARRLEN(nonfinal_resnv), mem);
  assert(0 == rv);

  http2_frame_hd_init(&hd, 0, HTTP2_DATA, FrameFlags.NONE, 5);
  http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
  bufs.head.buf.last += HTTP2_FRAME_HDLEN;

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(NULL == http2_session_get_next_ob_item(session));

  http2_bufs_reset(&bufs);

  /* non-final HEADERS followed by empty DATA (with END_STREAM) is
     illegal */
  stream = http2_session_open_stream(session, 7, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  rv = pack_headers(&bufs, &deflater, 7, FrameFlags.END_HEADERS,
                    nonfinal_resnv, ARRLEN(nonfinal_resnv), mem);
  assert(0 == rv);

  http2_frame_hd_init(&hd, 0, HTTP2_DATA, FrameFlags.END_STREAM, 7);
  http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
  bufs.head.buf.last += HTTP2_FRAME_HDLEN;

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  /* non-final HEADERS followed by final HEADERS is OK */
  stream = http2_session_open_stream(session, 9, HTTP2_STREAM_FLAG_NONE,
                                       &pri_spec_default,
                                       HTTP2_STREAM_OPENING, NULL);

  rv = pack_headers(&bufs, &deflater, 9, FrameFlags.END_HEADERS,
                    nonfinal_resnv, ARRLEN(nonfinal_resnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  http2_bufs_reset(&bufs);

  rv = pack_headers(&bufs, &deflater, 9, FrameFlags.END_HEADERS, resnv,
                    ARRLEN(resnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(NULL == http2_session_get_next_ob_item(session));

  http2_bufs_reset(&bufs);

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);

  http2_bufs_free(&bufs);
}

void test_http2_http_trailer_headers(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_hd_deflater deflater;
  http2_mem *mem;
  http2_bufs bufs;
  size_t rv;
  const http2_nv trailer_reqnv[] = {
      MAKE_NV("foo", "bar"),
  };
  http2_outbound_item *item;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_server_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  /* good trailer header */
  rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, reqnv,
                    ARRLEN(reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  http2_bufs_reset(&bufs);

  rv = pack_headers(&bufs, &deflater, 1,
                    FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
                    trailer_reqnv, ARRLEN(trailer_reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(NULL == http2_session_get_next_ob_item(session));

  http2_bufs_reset(&bufs);

  /* trailer header without END_STREAM is illegal */
  rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS, reqnv,
                    ARRLEN(reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  http2_bufs_reset(&bufs);

  rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS,
                    trailer_reqnv, ARRLEN(trailer_reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  /* trailer header including pseudo header field is illegal */
  rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS, reqnv,
                    ARRLEN(reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  http2_bufs_reset(&bufs);

  rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS, reqnv,
                    ARRLEN(reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_RST_STREAM == item.frame.hd.type);

  assert(0 == http2_session_send(session));

  http2_bufs_reset(&bufs);

  http2_hd_deflate_free(&deflater);

  http2_session_del(session);

  http2_bufs_free(&bufs);
}

void test_http2_http_ignore_content_length(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_hd_deflater deflater;
  http2_mem *mem;
  http2_bufs bufs;
  size_t rv;
  const http2_nv cl_resnv[] = {MAKE_NV(":status", "304"),
                                 MAKE_NV("content-length", "20")};
  const http2_nv conn_reqnv[] = {MAKE_NV(":authority", "localhost"),
                                   MAKE_NV(":method", "CONNECT"),
                                   MAKE_NV("content-length", "999999")};
  http2_stream *stream;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  /* If status 304, content-length must be ignored */
  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  rv = pack_headers(&bufs, &deflater, 1,
                    FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
                    cl_resnv, ARRLEN(cl_resnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(NULL == http2_session_get_next_ob_item(session));

  http2_bufs_reset(&bufs);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);

  /* If request method is CONNECT, content-length must be ignored */
  http2_session_server_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, conn_reqnv,
                    ARRLEN(conn_reqnv), mem);

  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(NULL == http2_session_get_next_ob_item(session));

  stream = http2_session_get_stream(session, 1);

  assert(-1 == stream.content_length);
  assert((stream.http_flags & HTTP2_HTTP_FLAG_METH_CONNECT) > 0);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
  http2_bufs_free(&bufs);
}

void test_http2_http_record_request_method(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  const http2_nv conn_reqnv[] = {MAKE_NV(":method", "CONNECT"),
                                   MAKE_NV(":authority", "localhost")};
  const http2_nv conn_resnv[] = {MAKE_NV(":status", "200"),
                                   MAKE_NV("content-length", "9999")};
  http2_stream *stream;
  size_t rv;
  http2_bufs bufs;
  http2_hd_deflater deflater;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  http2_session_client_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  assert(1 == http2_submit_request(session, NULL, conn_reqnv,
                                        ARRLEN(conn_reqnv), NULL, NULL));

  assert(0 == http2_session_send(session));

  stream = http2_session_get_stream(session, 1);

  assert(HTTP2_HTTP_FLAG_METH_CONNECT == stream.http_flags);

  rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, conn_resnv,
                    ARRLEN(conn_resnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert((HTTP2_HTTP_FLAG_METH_CONNECT & stream.http_flags) > 0);
  assert(-1 == stream.content_length);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
  http2_bufs_free(&bufs);
}

void test_http2_http_push_promise(void) {
  http2_session *session;
  http2_session_callbacks callbacks;
  http2_hd_deflater deflater;
  http2_mem *mem;
  http2_bufs bufs;
  size_t rv;
  http2_stream *stream;
  const http2_nv bad_reqnv[] = {MAKE_NV(":method", "GET")};
  http2_outbound_item *item;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  memset(&callbacks, 0, sizeof(http2_session_callbacks));
  callbacks.send_callback = null_send_callback;

  /* good PUSH_PROMISE case */
  http2_session_client_new(&session, &callbacks, NULL);

  http2_hd_deflate_init(&deflater, mem);

  http2_session_open_stream(session, 1, HTTP2_STREAM_FLAG_NONE,
                              &pri_spec_default, HTTP2_STREAM_OPENING, NULL);

  rv = pack_push_promise(&bufs, &deflater, 1, FrameFlags.END_HEADERS, 2,
                         reqnv, ARRLEN(reqnv), mem);
  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(NULL == http2_session_get_next_ob_item(session));

  stream = http2_session_get_stream(session, 2);
  assert(NULL != stream);

  http2_bufs_reset(&bufs);

  rv = pack_headers(&bufs, &deflater, 2, FrameFlags.END_HEADERS, resnv,
                    ARRLEN(resnv), mem);

  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  assert(NULL == http2_session_get_next_ob_item(session));

  assert(200 == stream.status_code);

  http2_bufs_reset(&bufs);

  /* PUSH_PROMISE lacks mandatory header */
  rv = pack_push_promise(&bufs, &deflater, 1, FrameFlags.END_HEADERS, 4,
                         bad_reqnv, ARRLEN(bad_reqnv), mem);

  assert(0 == rv);

  rv = http2_session_mem_recv(session, bufs.head.buf.pos,
                                http2_buf_len(&bufs.head.buf));

  assert(http2_buf_len(&bufs.head.buf) == rv);

  item = http2_session_get_next_ob_item(session);

  assert(HTTP2_RST_STREAM == item.frame.hd.type);
  assert(4 == item.frame.hd.stream_id);

  http2_bufs_reset(&bufs);

  http2_hd_deflate_free(&deflater);
  http2_session_del(session);
  http2_bufs_free(&bufs);
}
