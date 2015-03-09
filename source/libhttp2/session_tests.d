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
module libhttp2.session_tests;
import libhttp2.session;
import libhttp2.policy;
import libhttp2.frame;
import libhttp2.types;
import libhttp2.buffers;

struct accumulator {
	ubyte[65535] buf;
	size_t length;
}

struct scripted_data_feed {
	ubyte[8192] data;
	ubyte *datamark;
	ubyte *datalimit;
	size_t[8192] feedseq;
	size_t seqidx;
}

struct my_user_data {
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
	const Frame* frame;
	size_t fixed_sendlen;
	int header_cb_called;
	int begin_headers_cb_called;
	HeaderField hf;
	size_t data_chunk_len;
	size_t padlen;
	int begin_frame_cb_called;
}

static const HeaderField[] reqhf = [HeaderField(":method", "GET"), HeaderField(":path", "/"), HeaderField(":scheme", "https"), HeaderField(":authority", "localhost")
];

static const HeaderField[] reshf = [HeaderField(":status", "200")];

static void scripted_data_feed_init2(scripted_data_feed *df, Buffers bufs) 
{
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

static size_t null_send_callback(Session session, const ubyte *data, size_t len, int flags, void *user_data) 
{
	return len;
}

static size_t fail_send_callback(Session session, const ubyte *data, size_t len, int flags, void *user_data) 
{
	return ErrorCode.CALLBACK_FAILURE;
}

static size_t fixed_bytes_send_callback(Session session, const ubyte *data, size_t len, int flags, void *user_data) 
{
	size_t fixed_sendlen = ((my_user_data *)user_data).fixed_sendlen;
	return fixed_sendlen < len ? fixed_sendlen : len;
}

static size_t scripted_recv_callback(Session session,
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

static size_t eof_recv_callback(Session session, ubyte *data, size_t len, int flags, void *user_data) 
{
	return ErrorCode.EOF;
}

static size_t accumulator_send_callback(Session session, const ubyte *buf, size_t len, int flags, void *user_data) 
{
	accumulator *acc = (cast(my_user_data *)user_data).acc;
	assert(acc.length + len < sizeof(acc.buf));
	memcpy(acc.buf + acc.length, buf, len);
	acc.length += len;
	return len;
}

static int on_begin_frame_callback(Session session, const http2_frame_hd *hd, void *user_data) 
{
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.begin_frame_cb_called;
	return 0;
}

static int on_frame_recv_callback(Session session, const http2_frame *frame, void *user_data) 
{
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.frame_recv_cb_called;
	ud.recv_frame_type = frame.hd.type;
	return 0;
}

static int on_invalid_frame_recv_callback(Session session, const http2_frame *frame,	http2_error_code error_code, void *user_data) 
{
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.invalid_frame_recv_cb_called;
	return 0;
}

static int on_frame_send_callback(Session session, const http2_frame *frame, void *user_data) 
{
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.frame_send_cb_called;
	ud.sent_frame_type = frame.hd.type;
	return 0;
}

static int on_frame_not_send_callback(Session session, const http2_frame *frame, int lib_error, void *user_data)
{
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.frame_not_send_cb_called;
	ud.not_sent_frame_type = frame.hd.type;
	ud.not_sent_error = lib_error;
	return 0;
}

static int on_data_chunk_recv_callback(Session session, ubyte flags, int stream_id, const ubyte *data, size_t len, void *user_data) 
{
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.data_chunk_recv_cb_called;
	ud.data_chunk_len = len;
	return 0;
}

static int pause_on_data_chunk_recv_callback(Session session, ubyte flags, int stream_id, const ubyte *data, size_t len, void *user_data)
{
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.data_chunk_recv_cb_called;
	return ErrorCode.PAUSE;
}

static size_t select_padding_callback(Session session,
	const http2_frame *frame,
	size_t max_payloadlen, void *user_data) {
	my_user_data *ud = cast(my_user_data *)user_data;
	return http2_min(max_payloadlen, frame.hd.length + ud.padlen);
}

static size_t too_large_data_source_length_callback(
	Session session, ubyte frame_type, int stream_id,
	int session_remote_window_size,
	int stream_remote_window_size, uint remote_max_frame_size,
	void *user_data) {
	return MAX_FRAME_SIZE_MAX + 1;
}

static size_t smallest_length_data_source_length_callback(
	Session session, ubyte frame_type, int stream_id,
	int session_remote_window_size,
	int stream_remote_window_size, uint remote_max_frame_size,
	void *user_data) {
	return 1;
}

static size_t fixed_length_data_source_read_callback(
	Session session, int stream_id, ubyte *buf,
	size_t len, uint *data_flags, http2_data_source *source,
	void *user_data) {
	my_user_data *ud = cast(my_user_data *)user_data;
	size_t wlen;
	if (len < ud.data_source_length) {
		wlen = len;
	} else {
		wlen = ud.data_source_length;
	}
	ud.data_source_length -= wlen;
	if (ud.data_source_length == 0) {
		*data_flags |= DataFlags.EOF;
	}
	return wlen;
}

static size_t temporal_failure_data_source_read_callback(
	Session session, int stream_id, ubyte *buf,
	size_t len, uint *data_flags, http2_data_source *source,
	void *user_data) {
	return ErrorCode.TEMPORAL_CALLBACK_FAILURE;
}

static size_t fail_data_source_read_callback(Session session,
	int stream_id,
	ubyte *buf, size_t len,
	uint *data_flags,
	http2_data_source *source,
	void *user_data) {
	return ErrorCode.CALLBACK_FAILURE;
}

static size_t block_count_send_callback(Session session, in ubyte[] data, int flags, void *user_data) {
	my_user_data *ud = cast(my_user_data *)user_data;
	size_t r;
	if (ud.block_count == 0) {
		r = ErrorCode.WOULDBLOCK;
	} else {
		--ud.block_count;
		r = len;
	}
	return r;
}

static int on_header_callback(Session session,
	const http2_frame *frame, const ubyte *name,
	size_t namelen, const ubyte *value,
	size_t valuelen, ubyte flags,
	void *user_data) {
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.header_cb_called;
	ud.hf.name = (ubyte *)name;
	ud.hf.namelen = namelen;
	ud.hf.value = (ubyte *)value;
	ud.hf.valuelen = valuelen;
	
	ud.frame = frame;
	return 0;
}

static int pause_on_header_callback(Session session,
	const http2_frame *frame,
	const ubyte *name, size_t namelen,
	const ubyte *value, size_t valuelen,
	ubyte flags, void *user_data) {
	on_header_callback(session, frame, name, namelen, value, valuelen, flags,
		user_data);
	return ErrorCode.PAUSE;
}

static int temporal_failure_on_header_callback(
	Session session, const http2_frame *frame, const ubyte *name,
	size_t namelen, const ubyte *value, size_t valuelen, ubyte flags,
	void *user_data) {
	on_header_callback(session, frame, name, namelen, value, valuelen, flags,
		user_data);
	return ErrorCode.TEMPORAL_CALLBACK_FAILURE;
}

static int on_begin_headers_callback(Session session,
	const http2_frame *frame,
	void *user_data) {
	my_user_data *ud = cast(my_user_data *)user_data;
	++ud.begin_headers_cb_called;
	return 0;
}

static size_t defer_data_source_read_callback(Session session,
	int stream_id,
	ubyte *buf, size_t len,
	uint *data_flags,
	http2_data_source *source,
	void *user_data) {
	return ErrorCode.DEFERRED;
}

static int on_stream_close_callback(Session session, int stream_id,	http2_error_code error_code, void *user_data)
{
	my_user_data *my_data = cast(my_user_data *)user_data;
	++my_data.stream_close_cb_called;
	my_data.stream_close_error_code = error_code;
	
	return 0;
}

static http2_settings_entry *dup_iv(const http2_settings_entry *iv, size_t niv) 
{
	return http2_frame_iv_copy(iv, niv, http2_mem_default());
}

static PrioritySpec pri_spec_default;

void test_http2_session_recv(void) {
	Session session;
	Policy callbacks;
	scripted_data_feed df;
	my_user_data user_data;
	Buffers bufs;
	size_t framelen;
	Frame frame;
	size_t i;
	OutboundItem item;
	HeaderField[] hfa;
	Deflater deflater;
	int rv;

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.recv_callback = scripted_recv_callback;
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.on_begin_frame_callback = on_begin_frame_callback;
	
	user_data.df = &df;
	
	session = new Session(SERVER, callbacks, user_data);
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, null, hfa, hfa.length);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	
	scripted_data_feed_init2(&df, &bufs);
	
	framelen = http2_bufs_len(&bufs);
	
	/* Send 1 byte per each read */
	for (i = 0; i < framelen; ++i) {
		df.feedseq[i] = 1;
	}
	
	http2_frame_headers_free(frame.headers, mem);
	
	user_data.frame_recv_cb_called = 0;
	user_data.begin_frame_cb_called = 0;
	
	while (cast(size_t)df.seqidx < framelen) {
		assert(0 == session.recv());
	}
	assert(1 == user_data.frame_recv_cb_called);
	assert(1 == user_data.begin_frame_cb_called);
	
	bufs.reset();
	
	/* Receive PRIORITY */
	frame.priority = Priority(5, pri_spec_default);
	
	rv = http2_frame_pack_priority(&bufs, &frame.priority);
	
	assert(0 == rv);
	
	http2_frame_priority_free(frame.priority);
	
	scripted_data_feed_init2(&df, &bufs);
	
	user_data.frame_recv_cb_called = 0;
	user_data.begin_frame_cb_called = 0;
	
	assert(0 == session.recv());
	assert(1 == user_data.frame_recv_cb_called);
	assert(1 == user_data.begin_frame_cb_called);
	
	bufs.reset();
	
	deflater.free();
	session.free();
	
	/* Some tests for frame too large */
	session = new Session(SERVER, callbacks, user_data);
	
	/* Receive PING with too large payload */
	http2_frame_ping_init(frame.ping, FrameFlags.NONE, null);
	
	rv = http2_frame_pack_ping(&bufs, &frame.ping);
	
	assert(0 == rv);
	
	/* Add extra 16 bytes */
	http2_bufs_seek_last_present(&bufs);
	assert(http2_buf_len(&bufs.cur.buf) >= 16);
	
	bufs.cur.buf.last += 16;
	http2_put_uint32be(
		bufs.cur.buf.pos,
		cast(uint)(((frame.hd.length + 16) << 8) + bufs.cur.buf.pos[3]));
	
	http2_frame_ping_free(frame.ping);
	
	scripted_data_feed_init2(&df, &bufs);
	user_data.frame_recv_cb_called = 0;
	user_data.begin_frame_cb_called = 0;
	
	assert(0 == session.recv());
	assert(0 == user_data.frame_recv_cb_called);
	assert(0 == user_data.begin_frame_cb_called);
	
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.FRAME_SIZE_ERROR == item.frame.goaway.error_code);
	assert(0 == session.send());
	
	bufs.free();
	session.free();
}

void test_http2_session_recv_invalid_stream_id(void) {
	Session session;
	Policy callbacks;
	scripted_data_feed df;
	my_user_data user_data;
	Buffers bufs;
	Frame frame;
	Deflater deflater;
	int rv;

	HeaderField[] hfa;	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.recv_callback = scripted_recv_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	user_data.df = &df;
	user_data.invalid_frame_recv_cb_called = 0;
	session = new Session(SERVER, callbacks, user_data);
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 2,
		HeadersCategory.HEADERS, null, hfa, hfa.length);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	scripted_data_feed_init2(&df, &bufs);
	http2_frame_headers_free(frame.headers, mem);
	
	assert(0 == session.recv());
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_http2_session_recv_invalid_frame(void) {
	Session session;
	Policy callbacks;
	scripted_data_feed df;
	my_user_data user_data;
	Buffers bufs;
	Frame frame;
	HeaderField[] hfa;
	Deflater deflater;
	int rv;

	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.recv_callback = scripted_recv_callback;
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	
	user_data.df = &df;
	user_data.frame_send_cb_called = 0;
	session = new Session(SERVER, callbacks, user_data);
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 1,
		HeadersCategory.HEADERS, null, hfa, hfa.length);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	scripted_data_feed_init2(&df, &bufs);
	
	assert(0 == session.recv());
	assert(0 == session.send());
	assert(0 == user_data.frame_send_cb_called);
	
	/* Receive exactly same bytes of HEADERS is treated as error, because it has
   * pseudo headers and without END_STREAM flag set */
	scripted_data_feed_init2(&df, &bufs);
	
	assert(0 == session.recv());
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.RST_STREAM == user_data.sent_frame_type);
	
	bufs.free();
	http2_frame_headers_free(frame.headers, mem);
	
	deflater.free();
	session.free();
}

void test_http2_session_recv_eof(void) {
	Session session;
	Policy callbacks;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.recv_callback = eof_recv_callback;
	
	session = new Session(CLIENT, callbacks, null);
	assert(ErrorCode.EOF == session.recv());
	
	session.free();
}

void test_http2_session_recv_data(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	ubyte[8092] data;
	size_t rv;
	OutboundItem item;
	Stream stream;
	http2_frame_hd hd;
	int i;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	
	session = new Session(CLIENT, callbacks, ud);
	
	/* Create DATA frame with length 4KiB */
	memset(data, 0, sizeof(data));
	hd.length = 4096;
	hd.type = FrameType.DATA;
	hd.flags = FrameFlags.NONE;
	hd.stream_id = 1;
	http2_frame_pack_frame_hd(data, &hd);
	
	/* stream 1 is not opened, so it must be responded with connection
     error.  This is not mandated by the spec */
	ud.data_chunk_recv_cb_called = 0;
	ud.frame_recv_cb_called = 0;
	rv = session.memRecv(data, FRAME_HDLEN + 4096);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(0 == ud.data_chunk_recv_cb_called);
	assert(0 == ud.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.free();
	
	session = new Session(CLIENT, callbacks, ud);
	
	/* Create stream 1 with CLOSING state. DATA is ignored. */
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.CLOSING, null);
	/* Set initial window size 16383 to check stream flow control,
     isolating it from the conneciton flow control */
	stream.local_window_size = 16383;
	
	ud.data_chunk_recv_cb_called = 0;
	ud.frame_recv_cb_called = 0;
	rv = session.memRecv(data, FRAME_HDLEN + 4096);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(0 == ud.data_chunk_recv_cb_called);
	assert(0 == ud.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(null == item);
	
	/* This is normal case. DATA is acceptable. */
	stream.state = StreamState.OPENED;
	
	ud.data_chunk_recv_cb_called = 0;
	ud.frame_recv_cb_called = 0;
	rv = session.memRecv(data, FRAME_HDLEN + 4096);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(1 == ud.data_chunk_recv_cb_called);
	assert(1 == ud.frame_recv_cb_called);
	
	assert(null == session.getNextOutboundItem());
	
	ud.data_chunk_recv_cb_called = 0;
	ud.frame_recv_cb_called = 0;
	rv = session.memRecv(data, FRAME_HDLEN + 4096);
	assert(FRAME_HDLEN + 4096 == rv);
	
	/* Now we got data more than initial-window-size / 2, WINDOW_UPDATE
     must be queued */
	assert(1 == ud.data_chunk_recv_cb_called);
	assert(1 == ud.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(1 == item.frame.window_update.hd.stream_id);
	assert(0 == session.send());
	
	/* Set initial window size to 1MiB, so that we can check connection
     flow control individually */
	stream.local_window_size = 1 << 20;
	/* Connection flow control takes into account DATA which is received
     in the error condition. We have received 4096 * 4 bytes of
     DATA. Additional 4 DATA frames, connection flow control will kick
     in. */
	for (i = 0; i < 5; ++i) {
		rv = session.memRecv(data, FRAME_HDLEN + 4096);
		assert(FRAME_HDLEN + 4096 == rv);
	}
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(0 == item.frame.window_update.hd.stream_id);
	assert(0 == session.send());
	
	/* Reception of DATA with stream ID = 0 causes connection error */
	hd.length = 4096;
	hd.type = FrameType.DATA;
	hd.flags = FrameFlags.NONE;
	hd.stream_id = 0;
	http2_frame_pack_frame_hd(data, &hd);
	
	ud.data_chunk_recv_cb_called = 0;
	ud.frame_recv_cb_called = 0;
	rv = session.memRecv(data, FRAME_HDLEN + 4096);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(0 == ud.data_chunk_recv_cb_called);
	assert(0 == ud.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	
	session.free();
}

void test_http2_session_recv_continuation(void) {
	Session session;
	Policy callbacks;
	HeaderField[] hfa;
	Frame frame;
	Buffers bufs;
	http2_buf *buf;
	size_t rv;
	my_user_data ud;
	Deflater deflater;
	ubyte data[1024];
	size_t datalen;
	http2_frame_hd cont_hd;
	PrioritySpec pri_spec;

	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_header_callback = on_header_callback;
	callbacks.on_begin_headers_callback = on_begin_headers_callback;
	callbacks.on_begin_frame_callback = on_begin_frame_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* Make 1 HEADERS and insert CONTINUATION header */
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.NONE, 1,
		HeadersCategory.HEADERS, null, hfa, hfa.length);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	/* make sure that all data is in the first buf */
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	http2_frame_headers_free(frame.headers, mem);
	
	/* HEADERS's payload is 1 byte */
	memcpy(data, buf.pos, FRAME_HDLEN + 1);
	datalen = FRAME_HDLEN + 1;
	buf.pos += FRAME_HDLEN + 1;
	
	http2_put_uint32be(data, (1 << 8) + data[3]);
	
	/* First CONTINUATION, 2 bytes */
	http2_frame_hd_init(&cont_hd, 2, FrameType.CONTINUATION, FrameFlags.NONE,
		1);
	
	http2_frame_pack_frame_hd(data + datalen, &cont_hd);
	datalen += FRAME_HDLEN;
	
	memcpy(data + datalen, buf.pos, cont_hd.length);
	datalen += cont_hd.length;
	buf.pos += cont_hd.length;
	
	/* Second CONTINUATION, rest of the bytes */
	http2_frame_hd_init(&cont_hd, http2_buf_len(buf), FrameType.CONTINUATION,
		FrameFlags.END_HEADERS, 1);
	
	http2_frame_pack_frame_hd(data + datalen, &cont_hd);
	datalen += FRAME_HDLEN;
	
	memcpy(data + datalen, buf.pos, cont_hd.length);
	datalen += cont_hd.length;
	buf.pos += cont_hd.length;
	
	assert(0 == http2_buf_len(buf));
	
	ud.header_cb_called = 0;
	ud.begin_frame_cb_called = 0;
	
	rv = session.memRecv(data, datalen);
	assert(cast(size_t)datalen == rv);
	assert(4 == ud.header_cb_called);
	assert(3 == ud.begin_frame_cb_called);
	
	deflater.free();
	session.free();
	
	/* Expecting CONTINUATION, but get the other frame */
	http2_session_server_new(&session, &callbacks, &ud);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* HEADERS without END_HEADERS flag */
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.NONE, 1,
		HeadersCategory.HEADERS, null, hfa, hfa.length);
	bufs.reset();
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_headers_free(frame.headers, mem);
	
	/* make sure that all data is in the first buf */
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	memcpy(data, buf.pos, http2_buf_len(buf));
	datalen = http2_buf_len(buf);
	
	/* Followed by PRIORITY */
	http2_priority_spec_default_init(pri_spec);
	
	frame.priority = Priority(1, pri_spec);
	bufs.reset();
	
	rv = http2_frame_pack_priority(&bufs, &frame.priority);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	memcpy(data + datalen, buf.pos, http2_buf_len(buf));
	datalen += http2_buf_len(buf);
	
	ud.begin_headers_cb_called = 0;
	rv = session.memRecv(data, datalen);
	assert(cast(size_t)datalen == rv);
	
	assert(1 == ud.begin_headers_cb_called);
	assert(FrameType.GOAWAY == session.getNextOutboundItem().frame.hd.type);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_http2_session_recv_headers_with_priority(void) {
	Session session;
	Policy callbacks;
	HeaderField[] hfa;
	Frame frame;
	Buffers bufs;
	http2_buf *buf;
	size_t rv;
	my_user_data ud;
	Deflater deflater;
	OutboundItem item;
	PrioritySpec pri_spec;
	Stream stream;

	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	session.openStream(1);
	
	/* With FrameFlags.PRIORITY without exclusive flag set */
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	
	pri_spec = PrioritySpec(1, 99, 0);
	
	http2_frame_headers_init(frame.headers,
		FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		3, HeadersCategory.HEADERS, pri_spec, hfa, hfa.length);
	
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_headers_free(frame.headers, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	ud.frame_recv_cb_called = 0;
	
	rv = session.memRecv(buf.pos, http2_buf_len(buf));
	
	assert(http2_buf_len(buf) == rv);
	assert(1 == ud.frame_recv_cb_called);
	
	stream = session.getStream(3);
	
	assert(99 == stream.weight);
	assert(1 == stream.dep_prev.stream_id);
	
	bufs.reset();
	
	/* With FrameFlags.PRIORITY, but cut last 1 byte to make it
     invalid. */
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	
	pri_spec = PrioritySpec(0, 99, 0);
	
	http2_frame_headers_init(frame.headers,
		FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		5, HeadersCategory.HEADERS, pri_spec, hfa, hfa.length);
	
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > FRAME_HDLEN + 5);
	
	http2_frame_headers_free(frame.headers, mem);
	
	buf = &bufs.head.buf;
	/* Make payload shorter than required length to store priority
     group */
	http2_put_uint32be(buf.pos, (4 << 8) + buf.pos[3]);
	
	ud.frame_recv_cb_called = 0;
	
	rv = session.memRecv(buf.pos, http2_buf_len(buf));
	
	assert(http2_buf_len(buf) == rv);
	assert(0 == ud.frame_recv_cb_called);
	
	stream = session.getStream(5);
	
	assert(null == stream);
	
	item = session.getNextOutboundItem();
	assert(null != item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.FRAME_SIZE_ERROR == item.frame.goaway.error_code);
	
	bufs.reset();
	
	deflater.free();
	session.free();
	
	/* Check dep_stream_id == stream_id */
	http2_session_server_new(&session, &callbacks, &ud);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	
	pri_spec = PrioritySpec(1, 0, 0);
	
	http2_frame_headers_init(frame.headers,
		FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		1, HeadersCategory.HEADERS, pri_spec, hfa, hfa.length);
	
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_headers_free(frame.headers, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	ud.frame_recv_cb_called = 0;
	
	rv = session.memRecv(buf.pos, http2_buf_len(buf));
	
	assert(http2_buf_len(buf) == rv);
	assert(0 == ud.frame_recv_cb_called);
	
	stream = session.getStream(1);
	
	assert(null == stream);
	
	item = session.getNextOutboundItem();
	assert(null != item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	
	bufs.reset();
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_http2_session_recv_premature_headers(void) {
	Session session;
	Policy callbacks;
	HeaderField[] hfa;
	Frame frame;
	Buffers bufs;
	http2_buf *buf;
	size_t rv;
	my_user_data ud;
	Deflater deflater;
	OutboundItem item;

	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 1,
		HeadersCategory.HEADERS, null, hfa, hfa.length);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_headers_free(frame.headers, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	/* Intentionally feed payload cutting last 1 byte off */
	http2_put_uint32be(buf.pos,
		cast(uint)(((frame.hd.length - 1) << 8) + buf.pos[3]));
	rv = session.memRecv(buf.pos, http2_buf_len(buf) - 1);
	
	assert(cast(size_t)(http2_buf_len(buf) - 1) == rv);
	
	item = session.getNextOutboundItem();
	assert(null != item);
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(FrameError.COMPRESSION_ERROR == item.frame.rst_stream.error_code);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_http2_session_recv_unknown_frame(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	ubyte data[16384];
	size_t datalen;
	http2_frame_hd hd;
	size_t rv;
	
	http2_frame_hd_init(&hd, 16000, 99, FrameFlags.NONE, 0);
	
	http2_frame_pack_frame_hd(data, &hd);
	datalen = FRAME_HDLEN + hd.length;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	ud.frame_recv_cb_called = 0;
	
	/* Unknown frame must be ignored */
	rv = session.memRecv(data, datalen);
	
	assert(rv == cast(size_t)datalen);
	assert(0 == ud.frame_recv_cb_called);
	assert(null == session.getNextOutboundItem());
	
	session.free();
}

void test_http2_session_recv_unexpected_continuation(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	ubyte data[16384];
	size_t datalen;
	http2_frame_hd hd;
	size_t rv;
	OutboundItem item;
	
	http2_frame_hd_init(&hd, 16000, FrameType.CONTINUATION,
		FrameFlags.END_HEADERS, 1);
	
	http2_frame_pack_frame_hd(data, &hd);
	datalen = FRAME_HDLEN + hd.length;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	session.openStream(1);
	
	ud.frame_recv_cb_called = 0;
	
	/* unexpected CONTINUATION must be treated as connection error */
	rv = session.memRecv(data, datalen);
	
	assert(rv == cast(size_t)datalen);
	assert(0 == ud.frame_recv_cb_called);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.free();
}

void test_http2_session_recv_settings_header_table_size(void) {
	Session session;
	Policy callbacks;
	Frame frame;
	Buffers bufs;
	http2_buf *buf;
	size_t rv;
	my_user_data ud;
	Setting[3] iv;
	HeaderField hf = HeaderField(":authority", "example.org");

	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, ud);
	
	iv[0].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[0].value = 3000;
	
	iv[1].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[1].value = 16384;
	
	http2_frame_settings_init(frame.settings, FrameFlags.NONE, dup_iv(iv, 2),
		2);
	
	rv = http2_frame_pack_settings(&bufs, &frame.settings);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_settings_free(frame.settings, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	ud.frame_recv_cb_called = 0;
	
	rv = session.memRecv(buf.pos, http2_buf_len(buf));
	
	assert(rv == http2_buf_len(buf));
	assert(1 == ud.frame_recv_cb_called);
	
	assert(3000 == session.remote_settings.header_table_size);
	assert(16384 == session.remote_settings.initial_window_size);
	
	bufs.reset();
	
	/* 2 SETTINGS_HEADER_TABLE_SIZE */
	iv[0].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[0].value = 3001;
	
	iv[1].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[1].value = 16383;
	
	iv[2].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[2].value = 3001;
	
	http2_frame_settings_init(frame.settings, FrameFlags.NONE, dup_iv(iv, 3),
		3);
	
	rv = http2_frame_pack_settings(&bufs, &frame.settings);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_settings_free(frame.settings, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	ud.frame_recv_cb_called = 0;
	
	rv = session.memRecv(buf.pos, http2_buf_len(buf));
	
	assert(rv == http2_buf_len(buf));
	assert(1 == ud.frame_recv_cb_called);
	
	assert(3001 == session.remote_settings.header_table_size);
	assert(16383 == session.remote_settings.initial_window_size);
	
	bufs.reset();
	
	/* 2 SETTINGS_HEADER_TABLE_SIZE; first entry clears dynamic header
     table. */
	
	http2_submit_request(session, null, &nv, 1, null, null);
	session.send();
	
	assert(0 < session.hd_deflater.ctx.hd_table.len);
	
	iv[0].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[0].value = 0;
	
	iv[1].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[1].value = 16382;
	
	iv[2].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[2].value = 4096;
	
	http2_frame_settings_init(frame.settings, FrameFlags.NONE, dup_iv(iv, 3),
		3);
	
	rv = http2_frame_pack_settings(&bufs, &frame.settings);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_settings_free(frame.settings, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	ud.frame_recv_cb_called = 0;
	
	rv = session.memRecv(buf.pos, http2_buf_len(buf));
	
	assert(rv == http2_buf_len(buf));
	assert(1 == ud.frame_recv_cb_called);
	
	assert(4096 == session.remote_settings.header_table_size);
	assert(16382 == session.remote_settings.initial_window_size);
	assert(0 == session.hd_deflater.ctx.hd_table.len);
	
	bufs.reset();
	
	/* 2 SETTINGS_HEADER_TABLE_SIZE; second entry clears dynamic header
     table. */
	
	http2_submit_request(session, null, &nv, 1, null, null);
	session.send();
	
	assert(0 < session.hd_deflater.ctx.hd_table.len);
	
	iv[0].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[0].value = 3000;
	
	iv[1].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[1].value = 16381;
	
	iv[2].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[2].value = 0;
	
	http2_frame_settings_init(frame.settings, FrameFlags.NONE, dup_iv(iv, 3),
		3);
	
	rv = http2_frame_pack_settings(&bufs, &frame.settings);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_settings_free(frame.settings, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	ud.frame_recv_cb_called = 0;
	
	rv = session.memRecv(buf.pos, http2_buf_len(buf));
	
	assert(rv == http2_buf_len(buf));
	assert(1 == ud.frame_recv_cb_called);
	
	assert(0 == session.remote_settings.header_table_size);
	assert(16381 == session.remote_settings.initial_window_size);
	assert(0 == session.hd_deflater.ctx.hd_table.len);
	
	bufs.reset();
	
	bufs.free();
	session.free();
}

void test_http2_session_recv_too_large_frame_length(void) {
	Session session;
	Policy callbacks;
	ubyte[FRAME_HDLEN] buf;
	OutboundItem item;
	http2_frame_hd hd;
	
	/* Initial max frame size is MAX_FRAME_SIZE_MIN */
	http2_frame_hd_init(&hd, MAX_FRAME_SIZE_MIN + 1, FrameType.HEADERS, FrameFlags.NONE, 1);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	
	session = new Session(SERVER, callbacks, null);
	
	http2_frame_pack_frame_hd(buf, &hd);
	
	assert(sizeof(buf) == session.memRecv(buf, sizeof(buf)));
	
	item = session.getNextOutboundItem();
	
	assert(item != null);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.free();
}

void test_http2_session_continue(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	const HeaderField[] hf1 = [HeaderField(":method", "GET"), HeaderField(":path", "/")];
	const HeaderField[] hf2 = [HeaderField("user-agent", "nghttp2/1.0.0"),
		HeaderField("alpha", "bravo")];
	Buffers bufs;
	http2_buf *buf;
	size_t framelen1, framelen2;
	size_t rv;
	ubyte buffer[4096];
	http2_buf databuf;
	Frame frame;
	HeaderField[] hfa;
	
	const http2_frame *recv_frame;
	http2_frame_hd data_hd;
	Deflater deflater;

	

	frame_pack_bufs_init(&bufs);
	http2_buf_wrap_init(&databuf, buffer, sizeof(buffer));
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.on_data_chunk_recv_callback = pause_on_data_chunk_recv_callback;
	callbacks.on_header_callback = pause_on_header_callback;
	callbacks.on_begin_headers_callback = on_begin_headers_callback;
	
	session = new Session(SERVER, callbacks, user_data);
	/* disable strict HTTP layering checks */
	session.opt_flags |= OptionsMask.NO_HTTP_MESSAGING;
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* Make 2 HEADERS frames */
	hfa.length = ARRLEN(hf1);
	http2_nv_array_copy(hfa, hf1, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 1,
		HeadersCategory.HEADERS, null, hfa, hfa.length);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_headers_free(frame.headers, mem);
	
	buf = &bufs.head.buf;
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	framelen1 = http2_buf_len(buf);
	databuf.last = http2_cpymem(databuf.last, buf.pos, http2_buf_len(buf));
	
	hfa.length = ARRLEN(hf2);
	http2_nv_array_copy(hfa, hf2, hfa.length, mem);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 3,
		HeadersCategory.HEADERS, null, hfa, hfa.length);
	bufs.reset();
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(http2_bufs_len(&bufs) > 0);
	
	http2_frame_headers_free(frame.headers, mem);
	
	assert(http2_bufs_len(&bufs) == http2_buf_len(buf));
	
	framelen2 = http2_buf_len(buf);
	databuf.last = http2_cpymem(databuf.last, buf.pos, http2_buf_len(buf));
	
	/* Receive 1st HEADERS and pause */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv =
		session.memRecv(databuf.pos, http2_buf_len(&databuf));
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	recv_frame = user_data.frame;
	assert(FrameType.HEADERS == recv_frame.hd.type);
	assert(framelen1 - FRAME_HDLEN == recv_frame.hd.length);
	
	assert(1 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	
	assert(http2_nv_equal(&hf1[0], &user_data.hf));
	
	/* get 2nd header field */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv =
		session.memRecv(databuf.pos, http2_buf_len(&databuf));
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	
	assert(http2_nv_equal(&hf1[1], &user_data.hf));
	
	/* will call end_headers_callback and receive 2nd HEADERS and pause */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv =
		session.memRecv(databuf.pos, http2_buf_len(&databuf));
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	recv_frame = user_data.frame;
	assert(FrameType.HEADERS == recv_frame.hd.type);
	assert(framelen2 - FRAME_HDLEN == recv_frame.hd.length);
	
	assert(1 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	
	assert(http2_nv_equal(&hf2[0], &user_data.hf));
	
	/* get 2nd header field */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv =
		session.memRecv(databuf.pos, http2_buf_len(&databuf));
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	
	assert(http2_nv_equal(&hf2[1], &user_data.hf));
	
	/* No input data, frame_recv_callback is called */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	user_data.frame_recv_cb_called = 0;
	rv =
		session.memRecv(databuf.pos, http2_buf_len(&databuf));
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(0 == user_data.header_cb_called);
	assert(1 == user_data.frame_recv_cb_called);
	
	/* Receive DATA */
	http2_frame_hd_init(&data_hd, 16, FrameType.DATA, FrameFlags.NONE, 1);
	
	http2_buf_reset(&databuf);
	http2_frame_pack_frame_hd(databuf.pos, &data_hd);
	
	/* Intentionally specify larger buffer size to see pause is kicked
     in. */
	databuf.last = databuf.end;
	
	user_data.frame_recv_cb_called = 0;
	rv =
		session.memRecv(databuf.pos, http2_buf_len(&databuf));
	
	assert(16 + FRAME_HDLEN == rv);
	assert(0 == user_data.frame_recv_cb_called);
	
	/* Next http2_session_mem_recv invokes on_frame_recv_callback and
     pause again in on_data_chunk_recv_callback since we pass same
     DATA frame. */
	user_data.frame_recv_cb_called = 0;
	rv =
		session.memRecv(databuf.pos, http2_buf_len(&databuf));
	assert(16 + FRAME_HDLEN == rv);
	assert(1 == user_data.frame_recv_cb_called);
	
	/* And finally call on_frame_recv_callback with 0 size input */
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(null, 0);
	assert(0 == rv);
	assert(1 == user_data.frame_recv_cb_called);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_http2_session_add_frame(void) {
	Session session;
	Policy callbacks;
	accumulator acc;
	my_user_data user_data;
	OutboundItem item;
	Frame* frame;
	HeaderField[] hfa;
	

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = accumulator_send_callback;
	
	acc.length = 0;
	user_data.acc = &acc;
	
	assert(0 == session = new Session(CLIENT, callbacks, user_data));
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	hfa.length = ARRLEN(reqhf);
	http2_nv_array_copy(hfa, reqhf, hfa.length, mem);
	
	http2_frame_headers_init(
		&frame.headers, FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		session.next_stream_id, HeadersCategory.REQUEST, null, hfa, hfa.length);
	
	session.next_stream_id += 2;
	
	assert(0 == http2_session_add_item(session, item));
	assert(0 == http2_pq_empty(&session.ob_ss_pq));
	assert(0 == session.send());
	assert(FrameType.HEADERS == acc.buf[3]);
	assert((FrameFlags.END_HEADERS | FrameFlags.PRIORITY) == acc.buf[4]);
	/* check stream id */
	assert(1 == http2_get_uint32(&acc.buf[5]));
	
	session.free();
}

void test_http2_session_on_request_headers_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	Stream stream;
	int stream_id = 1;
	HeaderField[] malformed_nva = [HeaderField(":path", "\x01")];
	HeaderField[] hfa;
	
	PrioritySpec pri_spec;

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_begin_headers_callback = on_begin_headers_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	session = new Session(SERVER, callbacks, user_data);
	
	pri_spec = PrioritySpec(0, 255, 0);
	
	http2_frame_headers_init(
		&frame.headers, FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		stream_id, HeadersCategory.REQUEST, pri_spec, null, 0);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	assert(0 == session.onRequestHeaders(frame));
	assert(1 == user_data.begin_headers_cb_called);
	stream = session.getStream(stream_id);
	assert(StreamState.OPENING == stream.state);
	assert(255 == stream.weight);
	
	http2_frame_headers_free(frame.headers, mem);
	
	/* More than un-ACKed max concurrent streams leads REFUSED_STREAM */
	session.pending_local_max_concurrent_stream = 1;
	http2_frame_headers_init(frame.headers,
		FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		3, HeadersCategory.HEADERS, null, null, 0);
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	http2_frame_headers_free(frame.headers, mem);
	session.local_settings.max_concurrent_streams = INITIAL_MAX_CONCURRENT_STREAMS;
	
	/* Stream ID less than or equal to the previouly received request
     HEADERS is just ignored due to race condition */
	http2_frame_headers_init(frame.headers,
		FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		3, HeadersCategory.HEADERS, null, null, 0);
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(0 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	http2_frame_headers_free(frame.headers, mem);
	
	/* Stream ID is our side and it is idle stream ID, then treat it as
     connection error */
	http2_frame_headers_init(frame.headers,
		FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		2, HeadersCategory.HEADERS, null, null, 0);
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	http2_frame_headers_free(frame.headers, mem);
	
	session.free();
	
	/* Check malformed headers. The library accept it. */
	session = new Session(SERVER, callbacks, user_data);
	
	hfa.length = ARRLEN(malformed_nva);
	http2_nv_array_copy(hfa, malformed_nva, hfa.length, mem);
	http2_frame_headers_init(frame.headers,
		FrameFlags.END_HEADERS | FrameFlags.PRIORITY,
		1, HeadersCategory.HEADERS, null, hfa, hfa.length);
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(0 == session.onRequestHeaders(frame));
	assert(1 == user_data.begin_headers_cb_called);
	assert(0 == user_data.invalid_frame_recv_cb_called);
	
	http2_frame_headers_free(frame.headers, mem);
	
	session.free();
	
	/* Check client side */
	session = new Session(CLIENT, callbacks, user_data);
	
	/* Receiving peer's idle stream ID is subject to connection error */
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 2,
		HeadersCategory.REQUEST, null, null, 0);
	
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	http2_frame_headers_free(frame.headers, mem);
	
	session.free();
	
	session = new Session(CLIENT, callbacks, user_data);
	
	/* Receiving our's idle stream ID is subject to connection error */
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 1,
		HeadersCategory.REQUEST, null, null, 0);
	
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	http2_frame_headers_free(frame.headers, mem);
	
	session.free();
	
	session = new Session(CLIENT, callbacks, user_data);
	
	session.next_stream_id = 5;
	
	/* Stream ID which is not idle and not in stream map is just
     ignored */
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 3,
		HeadersCategory.REQUEST, null, null, 0);
	
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(0 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	http2_frame_headers_free(frame.headers, mem);
	
	session.free();
	
	session = new Session(SERVER, callbacks, user_data);
	
	/* Stream ID which is equal to local_last_stream_id is ok. */
	session.local_last_stream_id = 3;
	
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 3,
		HeadersCategory.REQUEST, null, null, 0);
	
	assert(0 == session.onRequestHeaders(frame));
	
	http2_frame_headers_free(frame.headers, mem);
	
	/* If GOAWAY has been sent, new stream is ignored */
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 5,
		HeadersCategory.REQUEST, null, null, 0);
	
	session.goaway_flags |= GoAwayFlags.SENT;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(0 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	http2_frame_headers_free(frame.headers, mem);
	
	session.free();
}

void test_http2_session_on_response_headers_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	Stream stream;

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_begin_headers_callback = on_begin_headers_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	session = new Session(CLIENT, callbacks, user_data);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, null, null, 0);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	assert(0 == onResponseHeaders(frame, stream));
	assert(1 == user_data.begin_headers_cb_called);
	assert(StreamState.OPENED == stream.state);
	
	http2_frame_headers_free(frame.headers, mem);
	session.free();
}

void test_http2_session_on_headers_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	Stream stream;

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_begin_headers_callback = on_begin_headers_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	session = new Session(CLIENT, callbacks, user_data);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.shutdown(ShutdownFlag.WR);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 1,
		HeadersCategory.HEADERS, null, null, 0);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	assert(0 == session.onHeaders(frame, stream));
	assert(1 == user_data.begin_headers_cb_called);
	assert(StreamState.OPENED == stream.state);
	
	/* stream closed */
	frame.hd.flags |= FrameFlags.END_STREAM;
	
	assert(0 == session.onHeaders(frame, stream));
	assert(2 == user_data.begin_headers_cb_called);
	
	/* Check to see when StreamState.CLOSING, incoming HEADERS is discarded. */
	stream = session.openStream(3, StreamFlags.NONE, pri_spec_default, StreamState.CLOSING, null);
	frame.hd.stream_id = 3;
	frame.hd.flags = FrameFlags.END_HEADERS;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onHeaders(frame, stream));
	/* See no counters are updated */
	assert(2 == user_data.begin_headers_cb_called);
	assert(0 == user_data.invalid_frame_recv_cb_called);
	
	/* Server initiated stream */
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);

	/* half closed (remote) */
	frame.hd.flags = FrameFlags.END_HEADERS | FrameFlags.END_STREAM;
	frame.hd.stream_id = 2;
	
	assert(0 == session.onHeaders(frame, stream));
	assert(3 == user_data.begin_headers_cb_called);
	assert(StreamState.OPENING == stream.state);
	
	stream.shutdown(ShutdownFlag.RD);
	
	/* Further reception of HEADERS is subject to stream error */
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onHeaders(frame, stream));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	http2_frame_headers_free(frame.headers, mem);
	
	session.free();
}

void test_http2_session_on_push_response_headers_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	Stream stream;
	OutboundItem item;

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_begin_headers_callback = on_begin_headers_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	session = new Session(CLIENT, callbacks, user_data);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 2,
		HeadersCategory.HEADERS, null, null, 0);
	/* session.onPushResponseHeaders assumes stream's state is StreamState.RESERVED and session.server is 0. */
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	assert(0 == session.onPushResponseHeaders(frame, stream));
	assert(1 == user_data.begin_headers_cb_called);
	assert(StreamState.OPENED == stream.state);
	assert(1 == session.num_incoming_streams);
	assert(0 == (stream.flags & StreamFlags.PUSH));
	
	/* If un-ACKed max concurrent streams limit is exceeded,
     RST_STREAMed */
	session.pending_local_max_concurrent_stream = 1;
	stream = session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	frame.hd.stream_id = 4;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushResponseHeaders(frame, stream));
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(FrameError.REFUSED_STREAM == item.frame.rst_stream.error_code);
	assert(1 == session.num_incoming_streams);
	
	assert(0 == session.send());
	assert(1 == session.num_incoming_streams);
	
	/* If ACKed max concurrent streams limit is exceeded, GOAWAY is
     issued */
	session.local_settings.max_concurrent_streams = 1;
	
	stream = session.openStream(6, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	frame.hd.stream_id = 6;
	
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushResponseHeaders(&frame, stream));
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	assert(1 == session.num_incoming_streams);
	
	http2_frame_headers_free(frame.headers, mem);
	session.free();
}

void test_http2_session_on_priority_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	Stream stream, dep_stream;
	PrioritySpec pri_spec;
	OutboundItem item;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	session = new Session(SERVER, callbacks, user_data);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, 2, 0);
	
	frame.priority = Priority(1, pri_spec);
	
	/* depend on stream 0 */
	assert(0 == http2_session_on_priority_received(session, &frame));
	
	assert(2 == stream.weight);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	dep_stream = session.openStream(3, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	frame.hd.stream_id = 2;
	
	/* using dependency stream */
	http2_priority_spec_init(frame.priority.pri_spec, 3, 1, 0);
	
	assert(0 == http2_session_on_priority_received(session, &frame));
	assert(dep_stream == stream.dep_prev);
	
	/* PRIORITY against idle stream */
	
	frame.hd.stream_id = 100;
	
	assert(0 == http2_session_on_priority_received(session, &frame));
	
	stream = http2_session_get_stream_raw(session, frame.hd.stream_id);
	
	assert(StreamState.IDLE == stream.state);
	assert(dep_stream == stream.dep_prev);
	
	http2_frame_priority_free(frame.priority);
	session.free();
	
	/* Check dep_stream_id == stream_id case */
	session = new Session(SERVER, callbacks, user_data);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	pri_spec = PrioritySpec(1, 0, 0);
	
	frame.priority = Priority(1, pri_spec);
	
	assert(0 == http2_session_on_priority_received(session, &frame));
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	http2_frame_priority_free(frame.priority);
	session.free();
}

void test_http2_session_on_rst_stream_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	session = new Session(SERVER, callbacks, user_data);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	http2_frame_rst_stream_init(frame.rst_stream, 1, FrameError.PROTOCOL_ERROR);
	
	assert(0 == session.onRstStream(frame));
	assert(null == session.getStream(1));
	
	http2_frame_rst_stream_free(frame.rst_stream);
	session.free();
}

void test_http2_session_on_settings_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Stream stream1, stream2;
	Frame frame;
	const size_t niv = 5;
	Setting[255] iv;
	OutboundItem item;
	HeaderField hf = HeaderField(":authority", "example.org");

	

	
	iv[0].settings_id = SETTINGS_MAX_CONCURRENT_STREAMS;
	iv[0].value = 50;
	
	iv[1].settings_id = SETTINGS_MAX_CONCURRENT_STREAMS;
	iv[1].value = 1000000009;
	
	iv[2].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[2].value = 64 * 1024;
	
	iv[3].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[3].value = 1024;
	
	iv[4].settings_id = Setting.ENABLE_PUSH;
	iv[4].value = 0;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, user_data);
	session.remote_settings.initial_window_size = 16 * 1024;
	
	stream1 = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	stream2 = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	/* Set window size for each streams and will see how settings updates these values */
	stream1.remote_window_size = 16 * 1024;
	stream2.remote_window_size = -48 * 1024;
	
	http2_frame_settings_init(frame.settings, FrameFlags.NONE,
		dup_iv(iv, niv), niv);
	
	assert(0 == session.onSettings(&frame, 0));
	assert(1000000009 == session.remote_settings.max_concurrent_streams);
	assert(64 * 1024 == session.remote_settings.initial_window_size);
	assert(1024 == session.remote_settings.header_table_size);
	assert(0 == session.remote_settings.enable_push);
	
	assert(64 * 1024 == stream1.remote_window_size);
	assert(0 == stream2.remote_window_size);
	
	frame.settings.iva[2].value = 16 * 1024;
	
	assert(0 == session.onSettings(&frame, 0));
	
	assert(16 * 1024 == stream1.remote_window_size);
	assert(-48 * 1024 == stream2.remote_window_size);
	
	assert(16 * 1024 == http2_session_get_stream_remote_window_size(
			session, stream1.stream_id));
	assert(0 == http2_session_get_stream_remote_window_size(
			session, stream2.stream_id));
	
	http2_frame_settings_free(frame.settings, mem);
	
	session.free();
	
	/* Check ACK with niv > 0 */
	session = new Session(SERVER, callbacks, null);
	http2_frame_settings_init(frame.settings, FrameFlags.ACK, dup_iv(iv, 1),
		1);
	/* Specify inflight_iv deliberately */
	session.inflight_iv = frame.settings.iva;
	
	assert(0 == session.onSettings(&frame, 0));
	item = session.getNextOutboundItem();
	assert(item != null);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.inflight_iv = null;
	session.inflight_niv = -1;
	
	http2_frame_settings_free(frame.settings, mem);
	session.free();
	
	/* Check ACK against no inflight SETTINGS */
	session = new Session(SERVER, callbacks, null);
	http2_frame_settings_init(frame.settings, FrameFlags.ACK, null, 0);
	
	assert(0 == session.onSettings(&frame, 0));
	item = session.getNextOutboundItem();
	assert(item != null);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	http2_frame_settings_free(frame.settings, mem);
	session.free();
	
	/* Check that 2 SETTINGS_HEADER_TABLE_SIZE 0 and 4096 are included
     and header table size is once cleared to 0. */
	session = new Session(CLIENT, callbacks, null);
	
	http2_submit_request(session, null, &nv, 1, null, null);
	
	session.send();
	
	assert(session.hd_deflater.ctx.hd_table.len > 0);
	
	iv[0].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[0].value = 0;
	
	iv[1].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[1].value = 2048;
	
	http2_frame_settings_init(frame.settings, FrameFlags.NONE, dup_iv(iv, 2),
		2);
	
	assert(0 == session.onSettings(&frame, 0));
	
	assert(0 == session.hd_deflater.ctx.hd_table.len);
	assert(2048 == session.hd_deflater.ctx.hd_table_bufsize_max);
	assert(2048 == session.remote_settings.header_table_size);
	
	http2_frame_settings_free(frame.settings, mem);
	session.free();
	
	/* Check too large SETTINGS_MAX_FRAME_SIZE */
	session = new Session(SERVER, callbacks, null);
	
	iv[0].settings_id = Setting.MAX_FRAME_SIZE;
	iv[0].value = MAX_FRAME_SIZE_MAX + 1;
	
	http2_frame_settings_init(frame.settings, FrameFlags.NONE, dup_iv(iv, 1),
		1);
	
	assert(0 == session.onSettings(&frame, 0));
	
	item = session.getNextOutboundItem();
	
	assert(item != null);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	http2_frame_settings_free(frame.settings, mem);
	session.free();
}

void test_http2_session_on_push_promise_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	Stream stream, promised_stream;
	OutboundItem item;
	HeaderField[] malformed_nva = [HeaderField(":path", "\x01")];
	HeaderField[] hfa;
	

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_begin_headers_callback = on_begin_headers_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	session = new Session(CLIENT, callbacks, user_data);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	http2_frame_push_promise_init(frame.push_promise, FrameFlags.END_HEADERS, 1, 2, null, 0);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	assert(0 == http2_session_on_push_promise_received(session, &frame));
	
	assert(1 == user_data.begin_headers_cb_called);
	promised_stream = session.getStream(2);
	assert(StreamState.RESERVED == promised_stream.state);
	assert(2 == session.last_recv_stream_id);
	
	/* Attempt to PUSH_PROMISE against half close (remote) */
	stream.shutdown(ShutdownFlag.RD);
	frame.push_promise.promised_stream_id = 4;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		http2_session_on_push_promise_received(session, &frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(null == session.getStream(4));
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(4 == item.frame.hd.stream_id);
	assert(FrameError.PROTOCOL_ERROR == item.frame.rst_stream.error_code);
	assert(0 == session.send());
	assert(4 == session.last_recv_stream_id);
	
	/* Attempt to PUSH_PROMISE against stream in closing state */
	stream.shut_flags = ShutdownFlag.NONE;
	stream.state = StreamState.CLOSING;
	frame.push_promise.promised_stream_id = 6;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		http2_session_on_push_promise_received(session, &frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(null == session.getStream(6));
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(6 == item.frame.hd.stream_id);
	assert(FrameError.REFUSED_STREAM == item.frame.rst_stream.error_code);
	assert(0 == session.send());
	
	/* Attempt to PUSH_PROMISE against non-existent stream */
	frame.hd.stream_id = 3;
	frame.push_promise.promised_stream_id = 8;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		http2_session_on_push_promise_received(session, &frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(null == session.getStream(8));
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(0 == item.frame.hd.stream_id);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	assert(0 == session.send());
	
	session.free();
	
	session = new Session(CLIENT, callbacks, user_data);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	/* Same ID twice */
	stream.state = StreamState.OPENING;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		http2_session_on_push_promise_received(session, &frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(null == session.getStream(8));
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	assert(0 == session.send());
	
	/* After GOAWAY, PUSH_PROMISE will be discarded */
	frame.push_promise.promised_stream_id = 10;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		http2_session_on_push_promise_received(session, &frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(null == session.getStream(10));
	assert(null == session.getNextOutboundItem());
	
	http2_frame_push_promise_free(frame.push_promise, mem);
	session.free();
	
	session = new Session(CLIENT, callbacks, user_data);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	/* Attempt to PUSH_PROMISE against reserved (remote) stream */
	http2_frame_push_promise_init(frame.push_promise, FrameFlags.END_HEADERS, 2, 4, null, 0);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == http2_session_on_push_promise_received(session, &frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	http2_frame_push_promise_free(frame.push_promise, mem);
	session.free();
	
	/* Disable PUSH */
	session = new Session(CLIENT, callbacks, user_data);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	session.local_settings.enable_push = 0;
	
	http2_frame_push_promise_init(frame.push_promise, FrameFlags.END_HEADERS,
		1, 2, null, 0);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		http2_session_on_push_promise_received(session, &frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	http2_frame_push_promise_free(frame.push_promise, mem);
	session.free();
	
	/* Check malformed headers. We accept malformed headers */
	session = new Session(CLIENT, callbacks, user_data);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	hfa.length = ARRLEN(malformed_nva);
	http2_nv_array_copy(hfa, malformed_nva, hfa.length, mem);
	http2_frame_push_promise_init(frame.push_promise, FrameFlags.END_HEADERS,
		1, 2, hfa, hfa.length);
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(0 == http2_session_on_push_promise_received(session, &frame));
	
	assert(1 == user_data.begin_headers_cb_called);
	assert(0 == user_data.invalid_frame_recv_cb_called);
	
	http2_frame_push_promise_free(frame.push_promise, mem);
	session.free();
}

void test_http2_session_on_ping_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	http2_outbound_item *top;
	const ubyte opaque_data[] = "01234567";
	
	user_data.frame_recv_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	
	session = new Session(CLIENT, callbacks, user_data);
	http2_frame_ping_init(frame.ping, FrameFlags.ACK, opaque_data);
	
	assert(0 == http2_session_on_ping_received(session, &frame));
	assert(1 == user_data.frame_recv_cb_called);
	
	/* Since this ping frame has PONG flag set, no further action is
     performed. */
	assert(null == session.ob_pq_top);
	
	/* Clear the flag, and receive it again */
	frame.hd.flags = FrameFlags.NONE;
	
	assert(0 == http2_session_on_ping_received(session, &frame));
	assert(2 == user_data.frame_recv_cb_called);
	top = session.ob_pq_top;
	assert(FrameType.PING == top.frame.hd.type);
	assert(FrameFlags.ACK == top.frame.hd.flags);
	assert(memcmp(opaque_data, top.frame.ping.opaque_data, 8) == 0);
	
	http2_frame_ping_free(frame.ping);
	session.free();
}

void test_http2_session_on_goaway_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	int i;

	

	user_data.frame_recv_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	callbacks.on_stream_close_callback = on_stream_close_callback;
	
	session = new Session(CLIENT, callbacks, user_data);
	
	for (i = 1; i <= 7; ++i) {
		session.openStream(i);
	}
	
	http2_frame_goaway_init(frame.goaway, 3, FrameError.PROTOCOL_ERROR, null, 0);
	
	user_data.stream_close_cb_called = 0;
	
	assert(0 == http2_session_on_goaway_received(session, &frame));
	
	assert(1 == user_data.frame_recv_cb_called);
	assert(3 == session.remote_last_stream_id);
	/* on_stream_close should be callsed for 2 times (stream 5 and 7) */
	assert(2 == user_data.stream_close_cb_called);
	
	assert(null != session.getStream(1));
	assert(null != session.getStream(2));
	assert(null != session.getStream(3));
	assert(null != session.getStream(4));
	assert(null == session.getStream(5));
	assert(null != session.getStream(6));
	assert(null == session.getStream(7));
	
	http2_frame_goaway_free(frame.goaway, mem);
	session.free();
}

void test_http2_session_on_window_update_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Frame frame;
	Stream stream;
	http2_outbound_item *data_item;
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.on_invalid_frame_recv_callback = on_invalid_frame_recv_callback;
	user_data.frame_recv_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	session = new Session(CLIENT, callbacks, user_data);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	data_item = create_data_ob_item();
	
	assert(0 == attachItem(stream, data_item, session));
	
	http2_frame_window_update_init(frame.window_update, FrameFlags.NONE, 1,
		16 * 1024);
	
	assert(0 == http2_session_on_window_update_received(session, &frame));
	assert(1 == user_data.frame_recv_cb_called);
	assert(INITIAL_WINDOW_SIZE + 16 * 1024 == stream.remote_window_size);
	
	assert(0 == deferItem(stream, StreamFlags.DEFERRED_FLOW_CONTROL, session));
	
	assert(0 == http2_session_on_window_update_received(session, &frame));
	assert(2 == user_data.frame_recv_cb_called);
	assert(INITIAL_WINDOW_SIZE + 16 * 1024 * 2 ==
		stream.remote_window_size);
	assert(0 == (stream.flags & StreamFlags.DEFERRED_ALL));
	
	http2_frame_window_update_free(frame.window_update);
	
	/* Receiving WINDOW_UPDATE on reserved (remote) stream is a connection error */
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	http2_frame_window_update_init(frame.window_update, FrameFlags.NONE, 2, 4096);
	
	assert(!(session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	assert(0 == http2_session_on_window_update_received(session, &frame));
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	http2_frame_window_update_free(frame.window_update);
	
	session.free();
	
	/* Receiving WINDOW_UPDATE on reserved (local) stream is allowed */
	session = new Session(SERVER, callbacks, user_data);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	http2_frame_window_update_init(frame.window_update, FrameFlags.NONE, 2,
		4096);
	
	assert(0 == http2_session_on_window_update_received(session, &frame));
	assert(!(session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	assert(INITIAL_WINDOW_SIZE + 4096 == stream.remote_window_size);
	
	http2_frame_window_update_free(frame.window_update);
	
	session.free();
}

void test_http2_session_on_data_received(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	http2_outbound_item *top;
	Stream stream;
	Frame frame;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	
	session = new Session(CLIENT, callbacks, user_data);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	frame.hd = FrameHeader(4096, FrameType.DATA, FrameFlags.NONE, 2);
	
	assert(0 == http2_session_on_data_received(session, &frame));
	assert(0 == stream.shut_flags);
	
	frame.hd.flags = FrameFlags.END_STREAM;
	
	assert(0 == http2_session_on_data_received(session, &frame));
	assert(ShutdownFlag.RD == stream.shut_flags);
	
	/* If StreamState.CLOSING state, DATA frame is discarded. */
	stream = session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.CLOSING, null);
	
	frame.hd.flags = FrameFlags.NONE;
	frame.hd.stream_id = 4;
	
	assert(0 == http2_session_on_data_received(session, &frame));
	assert(null == session.ob_pq_top);
	
	/* Check INVALID_STREAM case: DATA frame with stream ID which does
     not exist. */
	
	frame.hd.stream_id = 6;
	
	assert(0 == http2_session_on_data_received(session, &frame));
	top = session.ob_pq_top;
	/* DATA against nonexistent stream is just ignored for now */
	assert(top == null);
	/* assert(FrameType.RST_STREAM == top.frame.hd.type); */
	/* assert(FrameError.PROTOCOL_ERROR == top.frame.rst_stream.error_code);
	 */
	session.free();
}

void test_http2_session_send_headers_start_stream(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	
	item = Mem.alloc!OutboundItem(session);

	frame = &item.frame;
	
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS,
		session.next_stream_id, HeadersCategory.REQUEST,
		null, null, 0);
	session.next_stream_id += 2;
	
	http2_session_add_item(session, item);
	assert(0 == session.send());
	stream = session.getStream(1);
	assert(StreamState.OPENING == stream.state);
	
	session.free();
}

void test_http2_session_send_headers_reply(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 2,
		HeadersCategory.HEADERS, null, null, 0);
	http2_session_add_item(session, item);
	assert(0 == session.send());
	stream = session.getStream(2);
	assert(StreamState.OPENED == stream.state);
	
	session.free();
}

void test_http2_session_send_headers_frame_size_error(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	Frame* frame;
	HeaderField[] hfa;
	
	size_t vallen = MAX_HF_LEN;
	HeaderField hf[28];
	size_t nnv = ARRLEN(nv);
	size_t i;
	my_user_data ud;

	

	
	for (i = 0; i < nnv; ++i) {
		nv[i].name = (ubyte *)"header";
		nv[i].namelen = strlen((const char *)nv[i].name);
		nv[i].value = malloc(vallen + 1);
		memset(nv[i].value, '0' + (int)i, vallen);
		nv[i].value[vallen] = '\0';
		nv[i].valuelen = vallen;
		nv[i].flags = HeaderFlag.NONE;
	}
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
	
	session = new Session(CLIENT, callbacks, ud);
	hfa.length = nnv;
	http2_nv_array_copy(hfa, nv, hfa.length, mem);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS,
		session.next_stream_id, HeadersCategory.REQUEST,
		null, hfa, hfa.length);
	
	session.next_stream_id += 2;
	
	http2_session_add_item(session, item);
	
	ud.frame_not_send_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == ud.frame_not_send_cb_called);
	assert(FrameType.HEADERS == ud.not_sent_frame_type);
	assert(ErrorCode.FRAME_SIZE_ERROR == ud.not_sent_error);
	
	for (i = 0; i < nnv; ++i) {
		free(nv[i].value);
	}
	session.free();
}

void test_http2_session_send_headers_push_reply(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	assert(0 == http2_session_server_new(&session, &callbacks, null));
	session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 2,
		HeadersCategory.HEADERS, null, null, 0);
	http2_session_add_item(session, item);
	assert(0 == session.num_outgoing_streams);
	assert(0 == session.send());
	assert(1 == session.num_outgoing_streams);
	stream = session.getStream(2);
	assert(StreamState.OPENED == stream.state);
	assert(0 == (stream.flags & StreamFlags.PUSH));
	session.free();
}

void test_http2_session_send_rst_stream(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	OutboundItem item;
	Frame* frame;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	session = new Session(CLIENT, callbacks, user_data);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_rst_stream_init(frame.rst_stream, 1, FrameError.PROTOCOL_ERROR);
	http2_session_add_item(session, item);
	assert(0 == session.send());
	
	assert(null == session.getStream(1));
	
	session.free();
}

void test_http2_session_send_push_promise(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;
	Setting iv;
	my_user_data ud;

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_push_promise_init(frame.push_promise,
		FrameFlags.END_HEADERS, 1,
		session.next_stream_id, null, 0);
	
	session.next_stream_id += 2;
	
	http2_session_add_item(session, item);
	
	assert(0 == session.send());
	stream = session.getStream(2);
	assert(StreamState.RESERVED == stream.state);
	
	/* Received ENABLE_PUSH = 0 */
	iv.settings_id = Setting.ENABLE_PUSH;
	iv.value = 0;
	frame = malloc(sizeof(http2_frame));
	http2_frame_settings_init(frame.settings, FrameFlags.NONE,
		dup_iv(&iv, 1), 1);
	session.onSettings(frame, 1);
	http2_frame_settings_free(frame.settings, mem);
	free(frame);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_push_promise_init(frame.push_promise,
		FrameFlags.END_HEADERS, 1, -1, null, 0);
	http2_session_add_item(session, item);
	
	ud.frame_not_send_cb_called = 0;
	assert(0 == session.send());
	
	assert(1 == ud.frame_not_send_cb_called);
	assert(FrameType.PUSH_PROMISE == ud.not_sent_frame_type);
	assert(ErrorCode.PUSH_DISABLED == ud.not_sent_error);
	
	session.free();
	
	/* PUSH_PROMISE from client is error */
	session = new Session(CLIENT, callbacks, ud);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	http2_frame_push_promise_init(frame.push_promise,
		FrameFlags.END_HEADERS, 1, -1, null, 0);
	http2_session_add_item(session, item);
	
	assert(0 == session.send());
	assert(null == session.getStream(3));
	
	session.free();
}

void test_http2_session_is_my_stream_id(void) {
	Session session;
	Policy callbacks;
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	session = new Session(SERVER, callbacks, null);
	
	assert(0 == isMyStreamId(0));
	assert(0 == isMyStreamId(1));
	assert(1 == isMyStreamId(2));
	
	session.free();
	
	session = new Session(CLIENT, callbacks, null);
	
	assert(0 == isMyStreamId(0));
	assert(1 == isMyStreamId(1));
	assert(0 == isMyStreamId(2));
	
	session.free();
}

void test_http2_session_upgrade(void) {
	Session session;
	Policy callbacks;
	ubyte settings_payload[128];
	size_t settings_payloadlen;
	Setting[16] iv;
	Stream stream;
	OutboundItem item;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	iv[0].settings_id = SETTINGS_MAX_CONCURRENT_STREAMS;
	iv[0].value = 1;
	iv[1].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[1].value = 4095;
	settings_payloadlen = http2_pack_settings_payload(
		settings_payload, sizeof(settings_payload), iv, 2);
	
	/* Check client side */
	session = new Session(CLIENT, callbacks, null);
	assert(0 == http2_session_upgrade(session, settings_payload,
			settings_payloadlen, &callbacks));
	stream = session.getStream(1);
	assert(stream != null);
	assert(&callbacks == stream.stream_user_data);
	assert(ShutdownFlag.WR == stream.shut_flags);
	item = session.getNextOutboundItem();
	assert(FrameType.SETTINGS == item.frame.hd.type);
	assert(2 == item.frame.settings.niv);
	assert(SETTINGS_MAX_CONCURRENT_STREAMS == item.frame.settings.iva[0].settings_id);
	assert(1 == item.frame.settings.iva[0].value);
	assert(Setting.INITIAL_WINDOW_SIZE == item.frame.settings.iva[1].settings_id);
	assert(4095 == item.frame.settings.iva[1].value);
	
	/* Call http2_session_upgrade() again is error */
	assert(ErrorCode.PROTO ==
		http2_session_upgrade(session, settings_payload,
			settings_payloadlen, &callbacks));
	session.free();
	
	/* Check server side */
	session = new Session(SERVER, callbacks, null);
	assert(0 == http2_session_upgrade(session, settings_payload,
			settings_payloadlen, &callbacks));
	stream = session.getStream(1);
	assert(stream != null);
	assert(null == stream.stream_user_data);
	assert(ShutdownFlag.RD == stream.shut_flags);
	assert(null == session.getNextOutboundItem());
	assert(1 == session.remote_settings.max_concurrent_streams);
	assert(4095 == session.remote_settings.initial_window_size);
	/* Call http2_session_upgrade() again is error */
	assert(ErrorCode.PROTO ==
		http2_session_upgrade(session, settings_payload,
			settings_payloadlen, &callbacks));
	session.free();
	
	/* Empty SETTINGS is OK */
	settings_payloadlen = http2_pack_settings_payload(
		settings_payload, sizeof(settings_payload), null, 0);
	
	session = new Session(CLIENT, callbacks, null);
	assert(0 == http2_session_upgrade(session, settings_payload,
			settings_payloadlen, null));
	session.free();
}

void test_http2_session_reprioritize_stream(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	Stream stream;
	Stream dep_stream;
	PrioritySpec pri_spec;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = block_count_send_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, 10, 0);
	
	http2_session_reprioritize_stream(session, stream, pri_spec);
	
	assert(10 == stream.weight);
	assert(null == stream.dep_prev);
	
	/* If depenency to idle stream which is not in depdenency tree yet */
	
	pri_spec = PrioritySpec(3, 99, 0);
	
	http2_session_reprioritize_stream(session, stream, pri_spec);
	
	assert(99 == stream.weight);
	assert(3 == stream.dep_prev.stream_id);
	
	dep_stream = http2_session_get_stream_raw(session, 3);
	
	assert(DEFAULT_WEIGHT == dep_stream.weight);
	
	dep_stream = session.openStream(3);
	
	/* Change weight */
	pri_spec.weight = 128;
	
	http2_session_reprioritize_stream(session, stream, pri_spec);
	
	assert(128 == stream.weight);
	assert(dep_stream == stream.dep_prev);
	
	/* Test circular dependency; stream 1 is first removed and becomes
     root.  Then stream 3 depends on it. */
	pri_spec = PrioritySpec(1, 1, 0);
	
	http2_session_reprioritize_stream(session, dep_stream, pri_spec);
	
	assert(1 == dep_stream.weight);
	assert(stream == dep_stream.dep_prev);
	
	/* Making priority to closed stream will result in default
     priority */
	session.last_recv_stream_id = 9;
	
	pri_spec = PrioritySpec(5, 5, 0);
	
	http2_session_reprioritize_stream(session, stream, pri_spec);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
}

void test_http2_session_reprioritize_stream_with_idle_stream_dep(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	PrioritySpec pri_spec;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = block_count_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	session.pending_local_max_concurrent_stream = 1;
	
	pri_spec = PrioritySpec(101, 10, 0);
	
	http2_session_reprioritize_stream(session, stream, pri_spec);
	
	/* idle stream is not counteed to max concurrent streams */
	
	assert(10 == stream.weight);
	assert(101 == stream.dep_prev.stream_id);
	
	stream = http2_session_get_stream_raw(session, 101);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
}

void test_http2_submit_data(void) {
	Session session;
	Policy callbacks;
	DataProvider data_prd;
	my_user_data ud;
	Frame* frame;
	http2_frame_hd hd;
	http2_active_outbound_item *aob;
	Buffers framebufs;
	http2_buf *buf;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = block_count_send_callback;
	
	data_prd.read_callback = fixed_length_data_source_read_callback;
	ud.data_source_length = DATA_PAYLOADLEN * 2;
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	aob = &session.aob;
	framebufs = &aob.framebufs;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));
	
	ud.block_count = 0;
	assert(0 == session.send());
	frame = &aob.item.frame;
	
	buf = &framebufs.head.buf;
	http2_frame_unpack_frame_hd(&hd, buf.pos);
	
	assert(FrameFlags.NONE == hd.flags);
	assert(FrameFlags.NONE == frame.hd.flags);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
}

void test_http2_submit_data_read_length_too_large(void) {
	Session session;
	Policy callbacks;
	DataProvider data_prd;
	my_user_data ud;
	Frame* frame;
	http2_frame_hd hd;
	http2_active_outbound_item *aob;
	Buffers framebufs;
	http2_buf *buf;
	size_t payloadlen;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = block_count_send_callback;
	callbacks.read_length_callback = too_large_data_source_length_callback;
	
	data_prd.read_callback = fixed_length_data_source_read_callback;
	ud.data_source_length = DATA_PAYLOADLEN * 2;
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	aob = &session.aob;
	framebufs = &aob.framebufs;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));
	
	ud.block_count = 0;
	assert(0 == session.send());
	frame = &aob.item.frame;
	
	buf = &framebufs.head.buf;
	http2_frame_unpack_frame_hd(&hd, buf.pos);
	
	assert(FrameFlags.NONE == hd.flags);
	assert(FrameFlags.NONE == frame.hd.flags);
	assert(16384 == hd.length);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
	
	/* Check that buffers are expanded */
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	
	ud.data_source_length = MAX_FRAME_SIZE_MAX;
	
	session.remote_settings.max_frame_size = MAX_FRAME_SIZE_MAX;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));
	
	ud.block_count = 0;
	assert(0 == session.send());
	
	aob = &session.aob;
	
	frame = &aob.item.frame;
	
	framebufs = &aob.framebufs;
	
	buf = &framebufs.head.buf;
	http2_frame_unpack_frame_hd(&hd, buf.pos);
	
	payloadlen = http2_min(INITIAL_CONNECTION_WINDOW_SIZE,
		INITIAL_WINDOW_SIZE);
	
	assert(FRAME_HDLEN + 1 + payloadlen == cast(size_t)http2_buf_cap(buf));
	assert(FrameFlags.NONE == hd.flags);
	assert(FrameFlags.NONE == frame.hd.flags);
	assert(payloadlen == hd.length);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
}

void test_http2_submit_data_read_length_smallest(void) {
	Session session;
	Policy callbacks;
	DataProvider data_prd;
	my_user_data ud;
	Frame* frame;
	http2_frame_hd hd;
	http2_active_outbound_item *aob;
	Buffers framebufs;
	http2_buf *buf;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = block_count_send_callback;
	callbacks.read_length_callback = smallest_length_data_source_length_callback;
	
	data_prd.read_callback = fixed_length_data_source_read_callback;
	ud.data_source_length = DATA_PAYLOADLEN * 2;
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	aob = &session.aob;
	framebufs = &aob.framebufs;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == http2_submit_data(session, FrameFlags.END_STREAM, 1, &data_prd));
	
	ud.block_count = 0;
	assert(0 == session.send());
	frame = &aob.item.frame;
	
	buf = &framebufs.head.buf;
	http2_frame_unpack_frame_hd(&hd, buf.pos);
	
	assert(FrameFlags.NONE == hd.flags);
	assert(FrameFlags.NONE == frame.hd.flags);
	assert(1 == hd.length);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
}

static size_t submit_data_twice_data_source_read_callback(Session session, int stream_id, ubyte *buf, size_t len, uint *data_flags, http2_data_source *source, void *user_data) {
	*data_flags |= DataFlags.EOF;
	return http2_min(len, 16);
}

static int submit_data_twice_on_frame_send_callback(Session session,
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
	Session session;
	Policy callbacks;
	DataProvider data_prd;
	my_user_data ud;
	accumulator acc;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = accumulator_send_callback;
	callbacks.on_frame_send_callback = submit_data_twice_on_frame_send_callback;
	
	data_prd.read_callback = submit_data_twice_data_source_read_callback;
	
	acc.length = 0;
	ud.acc = &acc;
	
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	assert(0 == http2_submit_data(session, FrameFlags.NONE, 1, &data_prd));
	
	assert(0 == session.send());
	
	/* We should have sent 2 DATA frame with 16 bytes payload each */
	assert(FRAME_HDLEN * 2 + 16 * 2 == acc.length);
	
	session.free();
}

void test_http2_submit_request_with_data(void) {
	Session session;
	Policy callbacks;
	DataProvider data_prd;
	my_user_data ud;
	OutboundItem item;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	data_prd.read_callback = fixed_length_data_source_read_callback;
	ud.data_source_length = 64 * 1024 - 1;
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	assert(1 == http2_submit_request(session, null, reqhf, ARRLEN(reqhf),
			&data_prd, null));
	item = session.getNextOutboundItem();
	assert(ARRLEN(reqhf) == item.frame.headers.hflen);
	assert_nv_equal(reqhf, item.frame.headers.hfa, item.frame.headers.hflen);
	assert(0 == session.send());
	assert(0 == ud.data_source_length);
	
	session.free();
}

void test_http2_submit_request_without_data(void) {
	Session session;
	Policy callbacks;
	accumulator acc;
	DataProvider data_prd = DataProvider(-1, null);
	OutboundItem item;
	my_user_data ud;
	Frame frame;
	Inflater inflater = Inflater(true);
	nva_out out;
	Buffers bufs;

	

	frame_pack_bufs_init(&bufs);
	
	nva_out_init(&out);
	acc.length = 0;
	ud.acc = &acc;
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = accumulator_send_callback;
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	
	http2_hd_inflate_init(&inflater, mem);
	assert(1 == http2_submit_request(session, null, reqhf, ARRLEN(reqhf),
			&data_prd, null));
	item = session.getNextOutboundItem();
	assert(ARRLEN(reqhf) == item.frame.headers.hflen);
	assert_nv_equal(reqhf, item.frame.headers.hfa, item.frame.headers.hflen);
	assert(item.frame.hd.flags & FrameFlags.END_STREAM);
	
	assert(0 == session.send());
	assert(0 == unpack_frame(frame, acc.buf, acc.length));
	
	http2_bufs_add(&bufs, acc.buf, acc.length);
	inflate_hd(&inflater, &out, &bufs, FRAME_HDLEN);
	
	assert(ARRLEN(reqhf) == out.hflen);
	assert_nv_equal(reqhf, out.hfa, out.hflen);
	http2_frame_headers_free(frame.headers, mem);
	nva_out_reset(&out);
	
	bufs.free();
	http2_hd_inflate_free(&inflater);
	session.free();
}

void test_http2_submit_response_with_data(void) {
	Session session;
	Policy callbacks;
	DataProvider data_prd;
	my_user_data ud;
	OutboundItem item;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	data_prd.read_callback = fixed_length_data_source_read_callback;
	ud.data_source_length = 64 * 1024 - 1;
	assert(0 == http2_session_server_new(&session, &callbacks, &ud));
	session.openStream(1, FrameFlags.END_STREAM, pri_spec_default, StreamState.OPENING, null);
	assert(0 == http2_submit_response(session, 1, reshf, ARRLEN(reshf), &data_prd));
	item = session.getNextOutboundItem();
	assert(ARRLEN(reshf) == item.frame.headers.hflen);
	assert_nv_equal(reshf, item.frame.headers.hfa, item.frame.headers.hflen);
	assert(0 == session.send());
	assert(0 == ud.data_source_length);
	
	session.free();
}

void test_http2_submit_response_without_data(void) {
	Session session;
	Policy callbacks;
	accumulator acc;
	DataProvider data_prd = DataProvider(-1, null);
	OutboundItem item;
	my_user_data ud;
	Frame frame;
	Inflater inflater = Inflater(true);
	nva_out out;
	Buffers bufs;

	

	frame_pack_bufs_init(&bufs);
	
	nva_out_init(&out);
	acc.length = 0;
	ud.acc = &acc;
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = accumulator_send_callback;
	assert(0 == http2_session_server_new(&session, &callbacks, &ud));
	
	http2_hd_inflate_init(&inflater, mem);
	session.openStream(1, FrameFlags.END_STREAM, pri_spec_default, StreamState.OPENING, null);
	assert(0 == http2_submit_response(session, 1, reshf, ARRLEN(reshf),
			&data_prd));
	item = session.getNextOutboundItem();
	assert(ARRLEN(reshf) == item.frame.headers.hflen);
	assert_nv_equal(reshf, item.frame.headers.hfa, item.frame.headers.hflen);
	assert(item.frame.hd.flags & FrameFlags.END_STREAM);
	
	assert(0 == session.send());
	assert(0 == unpack_frame(frame, acc.buf, acc.length));
	
	http2_bufs_add(&bufs, acc.buf, acc.length);
	inflate_hd(&inflater, &out, &bufs, FRAME_HDLEN);
	
	assert(ARRLEN(reshf) == out.hflen);
	assert_nv_equal(reshf, out.hfa, out.hflen);
	
	nva_out_reset(&out);
	bufs.free();
	http2_frame_headers_free(frame.headers, mem);
	http2_hd_inflate_free(&inflater);
	session.free();
}

void test_http2_submit_headers_start_stream(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	session = new Session(CLIENT, callbacks, null);
	assert(1 == http2_submit_headers(session, FrameFlags.END_STREAM, -1, null, reqhf, ARRLEN(reqhf), null));
	item = session.getNextOutboundItem();
	assert(ARRLEN(reqhf) == item.frame.headers.hflen);
	assert_nv_equal(reqhf, item.frame.headers.hfa, item.frame.headers.hflen);
	assert((FrameFlags.END_HEADERS | FrameFlags.END_STREAM) == item.frame.hd.flags);
	assert(0 == (item.frame.hd.flags & FrameFlags.PRIORITY));
	
	session.free();
}

void test_http2_submit_headers_reply(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	OutboundItem item;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	
	assert(0 == http2_session_server_new(&session, &callbacks, &ud));
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1, null, reshf, ARRLEN(reshf), null));
	item = session.getNextOutboundItem();
	assert(ARRLEN(reshf) == item.frame.headers.hflen);
	assert_nv_equal(reshf, item.frame.headers.hfa, item.frame.headers.hflen);
	assert((FrameFlags.END_STREAM | FrameFlags.END_HEADERS) == item.frame.hd.flags);
	
	ud.frame_send_cb_called = 0;
	ud.sent_frame_type = 0;
	/* The transimission will be canceled because the stream 1 is not
     open. */
	assert(0 == session.send());
	assert(0 == ud.frame_send_cb_called);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1, null, reshf, ARRLEN(reshf), null));
	assert(0 == session.send());
	assert(1 == ud.frame_send_cb_called);
	assert(FrameType.HEADERS == ud.sent_frame_type);
	assert(stream.shut_flags & ShutdownFlag.WR);
	
	session.free();
}

void test_http2_submit_headers_push_reply(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	Stream stream;
	int foo;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	
	assert(0 == http2_session_server_new(&session, &callbacks, &ud));
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == http2_submit_headers(session, FrameFlags.NONE, 2, null, reshf, ARRLEN(reshf), &foo));
	
	ud.frame_send_cb_called = 0;
	ud.sent_frame_type = 0;
	assert(0 == session.send());
	assert(1 == ud.frame_send_cb_called);
	assert(FrameType.HEADERS == ud.sent_frame_type);
	assert(StreamState.OPENED == stream.state);
	assert(&foo == stream.stream_user_data);

	session.free();
	
	/* Sending HEADERS from client against stream in reserved state is
     error */
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == http2_submit_headers(session, FrameFlags.NONE, 2, null, reqhf, ARRLEN(reqhf), null));
	
	ud.frame_send_cb_called = 0;
	ud.sent_frame_type = 0;
	assert(0 == session.send());
	assert(0 == ud.frame_send_cb_called);
	
	session.free();
}

void test_http2_submit_headers(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	OutboundItem item;
	Stream stream;
	accumulator acc;
	Frame frame;
	Inflater inflater = Inflater(true);
	nva_out out;
	Buffers bufs;

	

	frame_pack_bufs_init(&bufs);
	
	nva_out_init(&out);
	acc.length = 0;
	ud.acc = &acc;
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = accumulator_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	
	http2_hd_inflate_init(&inflater, mem);
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1,
			null, reqhf, ARRLEN(reqhf), null));
	item = session.getNextOutboundItem();
	assert(ARRLEN(reqhf) == item.frame.headers.hflen);
	assert_nv_equal(reqhf, item.frame.headers.hfa, item.frame.headers.hflen);
	assert((FrameFlags.END_STREAM | FrameFlags.END_HEADERS) ==
		item.frame.hd.flags);
	
	ud.frame_send_cb_called = 0;
	ud.sent_frame_type = 0;
	/* The transimission will be canceled because the stream 1 is not
     open. */
	assert(0 == session.send());
	assert(0 == ud.frame_send_cb_called);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1, null, reqhf, ARRLEN(reqhf), null));
	assert(0 == session.send());
	assert(1 == ud.frame_send_cb_called);
	assert(FrameType.HEADERS == ud.sent_frame_type);
	assert(stream.shut_flags & ShutdownFlag.WR);
	
	assert(0 == unpack_frame(frame, acc.buf, acc.length));
	
	http2_bufs_add(&bufs, acc.buf, acc.length);
	inflate_hd(&inflater, &out, &bufs, FRAME_HDLEN);
	
	assert(ARRLEN(reqhf) == out.hflen);
	assert_nv_equal(reqhf, out.hfa, out.hflen);
	
	nva_out_reset(&out);
	bufs.free();
	http2_frame_headers_free(frame.headers, mem);
	
	http2_hd_inflate_free(&inflater);
	session.free();
}

void test_http2_submit_headers_continuation(void) {
	Session session;
	Policy callbacks;
	HeaderField[] hf = [HeaderField("h1", ""), HeaderField("h1", ""), HeaderField("h1", ""), HeaderField("h1", ""), 
		HeaderField("h1", ""), HeaderField("h1", ""), HeaderField("h1", "")];
	OutboundItem item;
	ubyte[4096] data;
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
	
	assert(0 == session = new Session(CLIENT, callbacks, ud));
	assert(1 == http2_submit_headers(session, FrameFlags.END_STREAM, -1,
			null, nv, ARRLEN(nv), null));
	item = session.getNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	assert((FrameFlags.END_STREAM | FrameFlags.END_HEADERS) ==
		item.frame.hd.flags);
	assert(0 == (item.frame.hd.flags & FrameFlags.PRIORITY));
	
	ud.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(1 == ud.frame_send_cb_called);
	
	session.free();
}

void test_http2_submit_priority(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	my_user_data ud;
	PrioritySpec pri_spec;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	
	session = new Session(CLIENT, callbacks, ud);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, 3, 0);
	
	/* depends on stream 0 */
	assert(0 == http2_submit_priority(session, 1, pri_spec));
	assert(0 == session.send());
	assert(3 == stream.weight);
	
	/* submit against idle stream */
	assert(0 == http2_submit_priority(session, 3, pri_spec));
	
	ud.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(1 == ud.frame_send_cb_called);
	
	session.free();
}

void test_http2_submit_settings(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	OutboundItem item;
	Frame* frame;
	Setting[7] iv;
	Frame ack_frame;
	const int UNKNOWN_ID = 1000000007;

	

	
	iv[0].settings_id = SETTINGS_MAX_CONCURRENT_STREAMS;
	iv[0].value = 5;
	
	iv[1].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[1].value = 16 * 1024;
	
	iv[2].settings_id = SETTINGS_MAX_CONCURRENT_STREAMS;
	iv[2].value = 50;
	
	iv[3].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[3].value = 0;
	
	iv[4].settings_id = UNKNOWN_ID;
	iv[4].value = 999;
	
	iv[5].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[5].value = cast(uint)MAX_WINDOW_SIZE + 1;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	http2_session_server_new(&session, &callbacks, &ud);
	
	assert(ErrorCode.INVALID_ARGUMENT ==
		http2_submit_settings(session, FrameFlags.NONE, iv, 6));
	
	/* Make sure that local settings are not changed */
	assert(INITIAL_MAX_CONCURRENT_STREAMS ==
		session.local_settings.max_concurrent_streams);
	assert(INITIAL_WINDOW_SIZE ==
		session.local_settings.initial_window_size);
	
	/* Now sends without 6th one */
	assert(0 == http2_submit_settings(session, FrameFlags.NONE, iv, 5));
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.SETTINGS == item.frame.hd.type);
	
	frame = &item.frame;
	assert(5 == frame.settings.niv);
	assert(5 == frame.settings.iva[0].value);
	assert(SETTINGS_MAX_CONCURRENT_STREAMS ==
		frame.settings.iva[0].settings_id);
	
	assert(16 * 1024 == frame.settings.iva[1].value);
	assert(Setting.INITIAL_WINDOW_SIZE ==
		frame.settings.iva[1].settings_id);
	
	assert(UNKNOWN_ID == frame.settings.iva[4].settings_id);
	assert(999 == frame.settings.iva[4].value);
	
	ud.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(1 == ud.frame_send_cb_called);
	
	assert(50 == session.pending_local_max_concurrent_stream);
	
	http2_frame_settings_init(&ack_frame.settings, FrameFlags.ACK, null, 0);
	assert(0 == session.onSettings(&ack_frame, 0));
	http2_frame_settings_free(&ack_frame.settings, mem);
	
	assert(16 * 1024 == session.local_settings.initial_window_size);
	assert(0 == session.hd_inflater.ctx.hd_table_bufsize_max);
	assert(50 == session.local_settings.max_concurrent_streams);
	assert(INITIAL_MAX_CONCURRENT_STREAMS ==
		session.pending_local_max_concurrent_stream);
	
	session.free();
}

void test_http2_submit_settings_update_local_window_size(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	Setting[4] iv;
	Stream stream;
	Frame ack_frame;

	

	http2_frame_settings_init(&ack_frame.settings, FrameFlags.ACK, null, 0);
	
	iv[0].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[0].value = 16 * 1024;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.local_window_size = INITIAL_WINDOW_SIZE + 100;
	stream.recv_window_size = 32768;

	stream = session.openStream(3, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	assert(0 == http2_submit_settings(session, FrameFlags.NONE, iv, 1));
	assert(0 == session.send());
	assert(0 == session.onSettings(&ack_frame, 0));
	
	stream = session.getStream(1);
	assert(0 == stream.recv_window_size);
	assert(16 * 1024 + 100 == stream.local_window_size);
	
	stream = session.getStream(3);
	assert(16 * 1024 == stream.local_window_size);
	
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(32768 == item.frame.window_update.window_size_increment);
	
	session.free();
	
	/* Check overflow case */
	iv[0].value = 128 * 1024;
	session = new Session(SERVER, callbacks, null);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.local_window_size = MAX_WINDOW_SIZE;
	
	assert(0 == http2_submit_settings(session, FrameFlags.NONE, iv, 1));
	assert(0 == session.send());
	assert(0 == session.onSettings(&ack_frame, 0));
	
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.FLOW_CONTROL_ERROR == item.frame.goaway.error_code);
	
	session.free();
	http2_frame_settings_free(&ack_frame.settings, mem);
}

void test_http2_submit_push_promise(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
	
	assert(0 == http2_session_server_new(&session, &callbacks, &ud));
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(2 == http2_submit_push_promise(session, FrameFlags.NONE, 1, reqhf, ARRLEN(reqhf), &ud));
	
	ud.frame_send_cb_called = 0;
	ud.sent_frame_type = 0;
	assert(0 == session.send());
	assert(1 == ud.frame_send_cb_called);
	assert(FrameType.PUSH_PROMISE == ud.sent_frame_type);
	stream = session.getStream(2);
	assert(StreamState.RESERVED == stream.state);
	assert(&ud == http2_session_get_stream_user_data(session, 2));
	
	/* submit PUSH_PROMISE while associated stream is not opened */
	assert(4 == http2_submit_push_promise(session, FrameFlags.NONE, 3, reqhf, ARRLEN(reqhf), &ud));
	
	ud.frame_not_send_cb_called = 0;
	
	assert(0 == session.send());
	assert(1 == ud.frame_not_send_cb_called);
	assert(FrameType.PUSH_PROMISE == ud.not_sent_frame_type);
	
	stream = session.getStream(4);
	
	assert(null == stream);
	
	session.free();
}

void test_http2_submit_window_update(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	OutboundItem item;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, ud);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.recv_window_size = 4096;
	
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2, 1024));
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(1024 == item.frame.window_update.window_size_increment);
	assert(0 == session.send());
	assert(3072 == stream.recv_window_size);
	
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2, 4096));
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4096 == item.frame.window_update.window_size_increment);
	assert(0 == session.send());
	assert(0 == stream.recv_window_size);
	
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2, 4096));
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4096 == item.frame.window_update.window_size_increment);
	assert(0 == session.send());
	assert(0 == stream.recv_window_size);
	
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2, 0));
	/* It is ok if stream is closed or does not exist at the call
     time */
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 4, 4096));
	
	session.free();
}

void test_http2_submit_window_update_local_window_size(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.recv_window_size = 4096;
	
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2, stream.recv_window_size + 1));
	assert(INITIAL_WINDOW_SIZE + 1 == stream.local_window_size);
	assert(0 == stream.recv_window_size);
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4097 == item.frame.window_update.window_size_increment);
	
	assert(0 == session.send());
	
	/* Let's decrement local window size */
	stream.recv_window_size = 4096;
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2, -stream.local_window_size / 2));
	assert(32768 == stream.local_window_size);
	assert(-28672 == stream.recv_window_size);
	assert(32768 == stream.recv_reduction);

	item = session.getNextOutboundItem();
	assert(item == null);
	
	/* Increase local window size */
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 2, 16384));
	assert(49152 == stream.local_window_size);
	assert(-12288 == stream.recv_window_size);
	assert(16384 == stream.recv_reduction);
	assert(null == session.getNextOutboundItem());
	
	assert(ErrorCode.FLOW_CONTROL == http2_submit_window_update(session, FrameFlags.NONE, 2, MAX_WINDOW_SIZE));
	
	assert(0 == session.send());
	
	/* Check connection-level flow control */
	session.recv_window_size = 4096;
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 0,
			session.recv_window_size + 1));
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 1 ==
		session.local_window_size);
	assert(0 == session.recv_window_size);
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4097 == item.frame.window_update.window_size_increment);
	
	assert(0 == session.send());
	
	/* Go decrement part */
	session.recv_window_size = 4096;
	assert(0 == http2_submit_window_update(session, FrameFlags.NONE, 0,
			-session.local_window_size / 2));
	assert(32768 == session.local_window_size);
	assert(-28672 == session.recv_window_size);
	assert(32768 == session.recv_reduction);
	item = session.getNextOutboundItem();
	assert(item == null);
	
	/* Increase local window size */
	assert(0 ==
		http2_submit_window_update(session, FrameFlags.NONE, 0, 16384));
	assert(49152 == session.local_window_size);
	assert(-12288 == session.recv_window_size);
	assert(16384 == session.recv_reduction);
	assert(null == session.getNextOutboundItem());
	
	assert(ErrorCode.FLOW_CONTROL ==
		http2_submit_window_update(session, FrameFlags.NONE, 0,
			MAX_WINDOW_SIZE));
	
	session.free();
}

void test_http2_submit_shutdown_notice(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	assert(0 == http2_submit_shutdown_notice(session));
	
	ud.frame_send_cb_called = 0;
	
	session.send();
	
	assert(1 == ud.frame_send_cb_called);
	assert(FrameType.GOAWAY == ud.sent_frame_type);
	assert((1u << 31) - 1 == session.local_last_stream_id);
	
	/* After another GOAWAY, http2_submit_shutdown_notice() is
     noop. */
	assert(0 == http2_session_terminate_session(session, FrameError.NO_ERROR));
	
	ud.frame_send_cb_called = 0;
	
	session.send();
	
	assert(1 == ud.frame_send_cb_called);
	assert(FrameType.GOAWAY == ud.sent_frame_type);
	assert(0 == session.local_last_stream_id);
	
	assert(0 == http2_submit_shutdown_notice(session));
	
	ud.frame_send_cb_called = 0;
	ud.frame_not_send_cb_called = 0;
	
	session.send();
	
	assert(0 == ud.frame_send_cb_called);
	assert(0 == ud.frame_not_send_cb_called);
	
	session.free();
	
	/* Using http2_submit_shutdown_notice() with client side session is error */
	session = new Session(CLIENT, callbacks, null);
	
	assert(ErrorCode.INVALID_STATE ==
		http2_submit_shutdown_notice(session));
	
	session.free();
}

void test_http2_submit_invalid_nv(void) {
	Session session;
	Policy callbacks;
	HeaderField[] empty_name_nv = [HeaderField("Version", "HTTP/1.1"), HeaderField("", "empty name")];
	
	/* Now invalid header field from HTTP/1.1 is accepted in libhttp2 */
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	
	assert(0 == http2_session_server_new(&session, &callbacks, null));
	
	/* http2_submit_request */
	assert(0 < http2_submit_request(session, null, empty_name_nv,
			ARRLEN(empty_name_nv), null, null));
	
	/* http2_submit_response */
	assert(0 == http2_submit_response(session, 2, empty_name_nv,
			ARRLEN(empty_name_nv), null));
	
	/* http2_submit_headers */
	assert(0 < http2_submit_headers(session, FrameFlags.NONE, -1, null,
			empty_name_nv, ARRLEN(empty_name_nv),
			null));
	
	/* http2_submit_push_promise */
	session.openStream(1);
	
	assert(0 < http2_submit_push_promise(session, FrameFlags.NONE, 1, empty_name_nv, ARRLEN(empty_name_nv), null));
	
	session.free();
}

void test_http2_session_open_stream(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	PrioritySpec pri_spec;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	session = new Session(SERVER, callbacks, null);
	
	pri_spec = PrioritySpec(0, 245, 0);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	assert(1 == session.num_incoming_streams);
	assert(0 == session.num_outgoing_streams);
	assert(StreamState.OPENED == stream.state);
	assert(245 == stream.weight);
	assert(null == stream.dep_prev);
	assert(ShutdownFlag.NONE == stream.shut_flags);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(1 == session.num_incoming_streams);
	assert(1 == session.num_outgoing_streams);
	assert(null == stream.dep_prev);
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(ShutdownFlag.NONE == stream.shut_flags);

	stream = session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(1 == session.num_incoming_streams);
	assert(1 == session.num_outgoing_streams);
	assert(null == stream.dep_prev);
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(ShutdownFlag.RD == stream.shut_flags);
	
	pri_spec = PrioritySpec(1, 17, 1);
	
	stream = session.openStream(3, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	assert(17 == stream.weight);
	assert(1 == stream.dep_prev.stream_id);
	
	/* Dependency to idle stream */
	pri_spec = PrioritySpec(1000000007, 240, 1);

	stream = session.openStream(5, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	assert(240 == stream.weight);
	assert(1000000007 == stream.dep_prev.stream_id);
	
	stream = http2_session_get_stream_raw(session, 1000000007);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(null != stream.root_next);
	
	/* Dependency to closed stream which is not in dependency tree */
	session.last_recv_stream_id = 7;
	
	pri_spec = PrioritySpec(7, 10, 0);
	
	stream = session.openStream(9, FrameFlags.NONE, pri_spec, StreamState.OPENED, null);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
	
	session = new Session(CLIENT, callbacks, null);
	stream = session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == session.num_incoming_streams);
	assert(0 == session.num_outgoing_streams);
	assert(null == stream.dep_prev);
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(ShutdownFlag.WR == stream.shut_flags);
	
	session.free();
}

void test_http2_session_open_stream_with_idle_stream_dep(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	PrioritySpec pri_spec;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	session = new Session(SERVER, callbacks, null);
	
	/* Dependency to idle stream */
	pri_spec = PrioritySpec(101, 245, 0);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	
	assert(245 == stream.weight);
	assert(101 == stream.dep_prev.stream_id);
	
	stream = http2_session_get_stream_raw(session, 101);
	
	assert(StreamState.IDLE == stream.state);
	assert(DEFAULT_WEIGHT == stream.weight);
	
	pri_spec = PrioritySpec(211, 1, 0);
	
	/* stream 101 was already created as idle. */
	stream = session.openStream(101, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	
	assert(1 == stream.weight);
	assert(211 == stream.dep_prev.stream_id);

	stream = http2_session_get_stream_raw(session, 211);
	
	assert(StreamState.IDLE == stream.state);
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
}

void test_http2_session_get_next_ob_item(void) {
	Session session;
	Policy callbacks;
	PrioritySpec pri_spec;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	session.remote_settings.max_concurrent_streams = 2;
	
	assert(null == session.getNextOutboundItem());
	http2_submit_ping(session, FrameFlags.NONE, null);
	assert(FrameType.PING == session.getNextOutboundItem().frame.hd.type);
	
	http2_submit_request(session, null, null, 0, null, null);
	assert(FrameType.PING == session.getNextOutboundItem().frame.hd.type);
	
	assert(0 == session.send());
	assert(null == session.getNextOutboundItem());
	
	/* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, MAX_WEIGHT, 0);

	http2_submit_request(session, pri_spec, null, 0, null, null);
	assert(FrameType.HEADERS == session.getNextOutboundItem().frame.hd.type);
	assert(0 == session.send());
	
	http2_submit_request(session, pri_spec, null, 0, null, null);
	assert(null == session.getNextOutboundItem());
	
	session.remote_settings.max_concurrent_streams = 3;
	
	assert(FrameType.HEADERS == session.getNextOutboundItem().frame.hd.type);

	session.free();
}

void test_http2_session_pop_next_ob_item(void) {
	Session session;
	Policy callbacks;
	OutboundItem item;
	PrioritySpec pri_spec;
	Stream stream;

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	session.remote_settings.max_concurrent_streams = 1;
	
	assert(null == session.popNextOutboundItem());
	
	http2_submit_ping(session, FrameFlags.NONE, null);
	
	pri_spec = PrioritySpec(0, 254, 0);
	
	http2_submit_request(session, pri_spec, null, 0, null, null);
	
	item = session.popNextOutboundItem();
	assert(FrameType.PING == item.frame.hd.type);
	http2_outbound_item_free(item, mem);
	free(item);
	
	item = session.popNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	http2_outbound_item_free(item, mem);
	free(item);
	
	assert(null == session.popNextOutboundItem());
	
	/* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	/* In-flight outgoing stream */
	session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);

	pri_spec = PrioritySpec(0, MAX_WEIGHT, 0);
	
	http2_submit_request(session, pri_spec, null, 0, null, null);
	http2_submit_response(session, 1, null, 0, null);
	
	item = session.popNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	assert(1 == item.frame.hd.stream_id);
	
	stream = session.getStream(1);
	
	detachItem(stream, session);
	
	http2_outbound_item_free(item, mem);
	free(item);
	
	assert(null == session.popNextOutboundItem());
	
	session.remote_settings.max_concurrent_streams = 2;
	
	item = session.popNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	http2_outbound_item_free(item, mem);
	free(item);
	
	session.free();
	
	/* Check that push reply HEADERS are queued into ob_ss_pq */
	session = new Session(SERVER, callbacks, null);
	session.remote_settings.max_concurrent_streams = 0;
	session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 2, null, null, 0, null));
	assert(null == session.popNextOutboundItem());
	assert(1 == http2_pq_size(&session.ob_ss_pq));
	session.free();
}

void test_http2_session_reply_fail(void) {
	Session session;
	Policy callbacks;
	DataProvider data_prd;
	my_user_data ud;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = fail_send_callback;
	
	data_prd.read_callback = fixed_length_data_source_read_callback;
	ud.data_source_length = 4 * 1024;
	assert(0 == http2_session_server_new(&session, &callbacks, &ud));
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == http2_submit_response(session, 1, null, 0, &data_prd));
	assert(ErrorCode.CALLBACK_FAILURE == session.send());
	session.free();
}

void test_http2_session_max_concurrent_streams(void) {
	Session session;
	Policy callbacks;
	Frame frame;
	OutboundItem item;

	

	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	/* Check un-ACKed SETTINGS_MAX_CONCURRENT_STREAMS */
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 3, HeadersCategory.HEADERS, null, null, 0);
	session.pending_local_max_concurrent_stream = 1;
	
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));

	item = session.ob_pq_top;
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(FrameError.REFUSED_STREAM == item.frame.rst_stream.error_code);
	
	assert(0 == session.send());
	
	/* Check ACKed SETTINGS_MAX_CONCURRENT_STREAMS */
	session.local_settings.max_concurrent_streams = 1;
	frame.hd.stream_id = 5;
	
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	
	item = session.ob_pq_top;
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	
	http2_frame_headers_free(frame.headers, mem);
	session.free();
}

void test_http2_session_stop_data_with_rst_stream(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	DataProvider data_prd;
	Frame frame;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.send_callback = block_count_send_callback;
	data_prd.read_callback = fixed_length_data_source_read_callback;
	
	ud.frame_send_cb_called = 0;
	ud.data_source_length = DATA_PAYLOADLEN * 4;

	http2_session_server_new(&session, &callbacks, &ud);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	http2_submit_response(session, 1, null, 0, &data_prd);
	
	ud.block_count = 2;
	/* Sends response HEADERS + DATA[0] */
	assert(0 == session.send());
	assert(FrameType.DATA == ud.sent_frame_type);
	/* data for DATA[1] is read from data_prd but it is not sent */
	assert(ud.data_source_length == DATA_PAYLOADLEN * 2);
	
	http2_frame_rst_stream_init(frame.rst_stream, 1, FrameError.CANCEL);
	assert(0 == session.onRstStream(frame));
	http2_frame_rst_stream_free(frame.rst_stream);
	
	/* Big enough number to send all DATA frames potentially. */
	ud.block_count = 100;
	/* Nothing will be sent in the following call. */
	assert(0 == session.send());
	/* With RST_STREAM, stream is canceled and further DATA on that
     stream are not sent. */
	assert(ud.data_source_length == DATA_PAYLOADLEN * 2);
	
	assert(null == session.getStream(1));
	
	session.free();
}

void test_http2_session_defer_data(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	DataProvider data_prd;
	OutboundItem item;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.send_callback = block_count_send_callback;
	data_prd.read_callback = defer_data_source_read_callback;
	
	ud.frame_send_cb_called = 0;
	ud.data_source_length = DATA_PAYLOADLEN * 4;
	
	http2_session_server_new(&session, &callbacks, &ud);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	session.remote_window_size = 1 << 20;
	stream.remote_window_size = 1 << 20;
	
	http2_submit_response(session, 1, null, 0, &data_prd);
	
	ud.block_count = 1;
	/* Sends HEADERS reply */
	assert(0 == session.send());
	assert(FrameType.HEADERS == ud.sent_frame_type);
	/* No data is read */
	assert(ud.data_source_length == DATA_PAYLOADLEN * 4);
	
	ud.block_count = 1;
	http2_submit_ping(session, FrameFlags.NONE, null);
	/* Sends PING */
	assert(0 == session.send());
	assert(FrameType.PING == ud.sent_frame_type);
	
	/* Resume deferred DATA */
	assert(0 == http2_session_resume_data(session, 1));
	item = (http2_outbound_item *)http2_pq_top(&session.ob_da_pq);
	item.aux_data.data.data_prd.read_callback =
		fixed_length_data_source_read_callback;
	ud.block_count = 1;
	/* Reads 2 DATA chunks */
	assert(0 == session.send());
	assert(ud.data_source_length == DATA_PAYLOADLEN * 2);
	
	/* Deferred again */
	item.aux_data.data.data_prd.read_callback = defer_data_source_read_callback;
	/* This is needed since 16KiB block is already read and waiting to be
     sent. No read_callback invocation. */
	ud.block_count = 1;
	assert(0 == session.send());
	assert(ud.data_source_length == DATA_PAYLOADLEN * 2);
	
	/* Resume deferred DATA */
	assert(0 == http2_session_resume_data(session, 1));
	item = (http2_outbound_item *)http2_pq_top(&session.ob_da_pq);
	item.aux_data.data.data_prd.read_callback =
		fixed_length_data_source_read_callback;
	ud.block_count = 1;
	/* Reads 2 16KiB blocks */
	assert(0 == session.send());
	assert(ud.data_source_length == 0);
	
	session.free();
}

void test_http2_session_flow_control(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	DataProvider data_prd;
	Frame frame;
	Stream stream;
	int new_initial_window_size;
	Setting[1] iv;
	Frame settings_frame;

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
	session = new Session(CLIENT, callbacks, ud);
	/* Change it to 64KiB for easy calculation */
	session.remote_window_size = 64 * 1024;
	session.remote_settings.initial_window_size = 64 * 1024;
	
	http2_submit_request(session, null, null, 0, &data_prd, null);
	
	/* Sends 64KiB - 1 data */
	assert(0 == session.send());
	assert(64 * 1024 == ud.data_source_length);
	
	/* Back 32KiB in stream window */
	http2_frame_window_update_init(frame.window_update, FrameFlags.NONE, 1, 32 * 1024);
	http2_session_on_window_update_received(session, &frame);
	
	/* Send nothing because of connection-level window */
	assert(0 == session.send());
	assert(64 * 1024 == ud.data_source_length);
	
	/* Back 32KiB in connection-level window */
	frame.hd.stream_id = 0;
	http2_session_on_window_update_received(session, &frame);
	
	/* Sends another 32KiB data */
	assert(0 == session.send());
	assert(32 * 1024 == ud.data_source_length);
	
	stream = session.getStream(1);
	/* Change initial window size to 16KiB. The window_size becomes
     negative. */
	new_initial_window_size = 16 * 1024;
	stream.remote_window_size = new_initial_window_size - (session.remote_settings.initial_window_size - stream.remote_window_size);
	session.remote_settings.initial_window_size = new_initial_window_size;
	assert(-48 * 1024 == stream.remote_window_size);
	
	/* Back 48KiB to stream window */
	frame.hd.stream_id = 1;
	frame.window_update.window_size_increment = 48 * 1024;
	http2_session_on_window_update_received(session, &frame);
	
	/* Nothing is sent because window_size is 0 */
	assert(0 == session.send());
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
	assert(0 == session.send());
	assert(16 * 1024 == ud.data_source_length);
	
	/* Increase initial window size to 32KiB */
	iv[0].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[0].value = 32 * 1024;
	
	http2_frame_settings_init(&settings_frame.settings, FrameFlags.NONE, dup_iv(iv, 1), 1);
	session.onSettings(&settings_frame, 1);
	http2_frame_settings_free(&settings_frame.settings, mem);
	
	/* Sends another 8KiB data */
	assert(0 == session.send());
	assert(8 * 1024 == ud.data_source_length);
	
	/* Back 8KiB in connection-level window */
	frame.hd.stream_id = 0;
	frame.window_update.window_size_increment = 8 * 1024;
	http2_session_on_window_update_received(session, &frame);
	
	/* Sends last 8KiB data */
	assert(0 == session.send());
	assert(0 == ud.data_source_length);
	assert(session.getStream(1).shut_flags & ShutdownFlag.WR);
	
	http2_frame_window_update_free(frame.window_update);
	session.free();
}

void test_http2_session_flow_control_data_recv(void) {
	Session session;
	Policy callbacks;
	ubyte data[64 * 1024 + 16];
	http2_frame_hd hd;
	OutboundItem item;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	/* Initial window size to 64KiB - 1*/
	session = new Session(CLIENT, callbacks, null);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	session.next_stream_id = 3;
	
	stream.shutdown(ShutdownFlag.WR);
	
	session.local_window_size = MAX_PAYLOADLEN;
	stream.local_window_size = MAX_PAYLOADLEN;
	
	/* Create DATA frame */
	memset(data, 0, sizeof(data));
	http2_frame_hd_init(&hd, MAX_PAYLOADLEN, FrameType.DATA,
		FrameFlags.END_STREAM, 1);
	
	http2_frame_pack_frame_hd(data, &hd);
	assert(MAX_PAYLOADLEN + FRAME_HDLEN == session.memRecv(data, MAX_PAYLOADLEN + FRAME_HDLEN));
	
	item = session.getNextOutboundItem();
	/* Since this is the last frame, stream-level WINDOW_UPDATE is not
     issued, but connection-level is. */
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(0 == item.frame.hd.stream_id);
	assert(MAX_PAYLOADLEN == item.frame.window_update.window_size_increment);
	
	assert(0 == session.send());

	/* Receive DATA for closed stream. They are still subject to under
     connection-level flow control, since this situation arises when
     RST_STREAM is issued by the remote, but the local side keeps
     sending DATA frames. Without calculating connection-level window,
     the subsequent flow control gets confused. */
	assert(MAX_PAYLOADLEN + FRAME_HDLEN == session.memRecv(data, MAX_PAYLOADLEN + FRAME_HDLEN));
	
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(0 == item.frame.hd.stream_id);
	assert(MAX_PAYLOADLEN == item.frame.window_update.window_size_increment);
	
	session.free();
}

void test_http2_session_flow_control_data_with_padding_recv(void) {
	Session session;
	Policy callbacks;
	ubyte data[1024];
	http2_frame_hd hd;
	Stream stream;
	http2_option *option;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	http2_option_new(&option);
	/* Disable auto window update so that we can check padding is
     consumed automatically */
	http2_option_set_no_auto_window_update(option, 1);
	
	/* Initial window size to 64KiB - 1*/
	http2_session_client_new2(&session, &callbacks, null, option);
	
	http2_option_del(option);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	/* Create DATA frame */
	memset(data, 0, sizeof(data));
	http2_frame_hd_init(&hd, 357, FrameType.DATA, FrameFlags.END_STREAM | FrameFlags.PADDED, 1);
	
	http2_frame_pack_frame_hd(data, &hd);
	/* Set Pad Length field, which itself is padding */
	data[FRAME_HDLEN] = 255;
	
	assert(
		cast(size_t)(FRAME_HDLEN + hd.length) ==
		session.memRecv(data, FRAME_HDLEN + hd.length));
	
	assert((int)hd.length == session.recv_window_size);
	assert((int)hd.length == stream.recv_window_size);
	assert(256 == session.consumed_size);
	assert(256 == stream.consumed_size);
	
	session.free();
}

void test_http2_session_data_read_temporal_failure(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	DataProvider data_prd;
	Frame frame;
	Stream stream;
	size_t data_size = 128 * 1024;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	data_prd.read_callback = fixed_length_data_source_read_callback;
	
	ud.data_source_length = data_size;
	
	/* Initial window size is 64KiB - 1 */
	session = new Session(CLIENT, callbacks, ud);
	http2_submit_request(session, null, null, 0, &data_prd, null);
	
	/* Sends INITIAL_WINDOW_SIZE data, assuming, it is equal to
     or smaller than INITIAL_CONNECTION_WINDOW_SIZE */
	assert(0 == session.send());
	assert(data_size - INITIAL_WINDOW_SIZE == ud.data_source_length);
	
	stream = session.getStream(1);
	assert(stream.isDeferredByFlowControl());
	assert(FrameType.DATA == stream.item.frame.hd.type);
	
	stream.item.aux_data.data.data_prd.read_callback =
		temporal_failure_data_source_read_callback;
	
	/* Back INITIAL_WINDOW_SIZE to both connection-level and
     stream-wise window */
	http2_frame_window_update_init(frame.window_update, FrameFlags.NONE, 1,
		INITIAL_WINDOW_SIZE);
	http2_session_on_window_update_received(session, &frame);
	frame.hd.stream_id = 0;
	http2_session_on_window_update_received(session, &frame);
	http2_frame_window_update_free(frame.window_update);
	
	/* Sending data will fail (soft fail) and treated as stream error */
	ud.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(data_size - INITIAL_WINDOW_SIZE == ud.data_source_length);
	
	assert(1 == ud.frame_send_cb_called);
	assert(FrameType.RST_STREAM == ud.sent_frame_type);
	
	data_prd.read_callback = fail_data_source_read_callback;
	http2_submit_request(session, null, null, 0, &data_prd, null);
	/* Sending data will fail (hard fail) and session tear down */
	assert(ErrorCode.CALLBACK_FAILURE == session.send());
	
	session.free();
}

void test_http2_session_on_stream_close(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_stream_close_callback = on_stream_close_callback;
	user_data.stream_close_cb_called = 0;
	
	session = new Session(CLIENT, callbacks, user_data);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, &user_data);
	assert(stream != null);
	assert(closeStream(1, FrameError.NO_ERROR) == 0);
	assert(user_data.stream_close_cb_called == 1);
	session.free();
}

void test_http2_session_on_ctrl_not_send(void) {
	Session session;
	Policy callbacks;
	my_user_data user_data;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
	callbacks.send_callback = null_send_callback;
	user_data.frame_not_send_cb_called = 0;
	user_data.not_sent_frame_type = 0;
	user_data.not_sent_error = 0;
	
	session = new Session(SERVER, callbacks, user_data);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, &user_data);
	
	/* Check response HEADERS */
	/* Send bogus stream ID */
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 3, null, null, 0, null));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.STREAM_CLOSED == user_data.not_sent_error);
	
	user_data.frame_not_send_cb_called = 0;
	/* Shutdown transmission */
	stream.shut_flags |= ShutdownFlag.WR;
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1, null, null, 0, null));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.STREAM_SHUT_WR == user_data.not_sent_error);
	
	stream.shut_flags = ShutdownFlag.NONE;
	user_data.frame_not_send_cb_called = 0;
	/* Queue RST_STREAM */
	assert(0 == http2_submit_headers(session, FrameFlags.END_STREAM, 1, null, null, 0, null));
	assert(0 == http2_submit_rst_stream(session, FrameFlags.NONE, 1, FrameError.INTERNAL_ERROR));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.STREAM_CLOSING == user_data.not_sent_error);
	
	session.free();
	
	/* Check request HEADERS */
	user_data.frame_not_send_cb_called = 0;
	assert(session = new Session(CLIENT, callbacks, user_data) == 0);
	/* Maximum Stream ID is reached */
	session.next_stream_id = (1u << 31) + 1;
	assert(ErrorCode.STREAM_ID_NOT_AVAILABLE == http2_submit_headers(session, FrameFlags.END_STREAM, -1, null, null, 0, null));
	
	user_data.frame_not_send_cb_called = 0;
	/* GOAWAY received */
	session.goaway_flags |= GoAwayFlags.RECV;
	session.next_stream_id = 9;
	
	assert(0 < http2_submit_headers(session, FrameFlags.END_STREAM, -1, null, null, 0, null));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.START_STREAM_NOT_ALLOWED == user_data.not_sent_error);

	session.free();
}

void test_http2_session_get_outbound_queue_size(void) {
	Session session;
	Policy callbacks;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	session = new Session(CLIENT, callbacks, null);
	assert(0 == http2_session_get_outbound_queue_size(session));

	assert(0 == http2_submit_ping(session, FrameFlags.NONE, null));
	assert(1 == http2_session_get_outbound_queue_size(session));
	
	assert(0 == http2_submit_goaway(session, FrameFlags.NONE, 2, FrameError.NO_ERROR, null, 0));
	assert(2 == http2_session_get_outbound_queue_size(session));
	
	session.free();
}

void test_http2_session_get_effective_local_window_size(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	session = new Session(CLIENT, callbacks, null);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	assert(INITIAL_CONNECTION_WINDOW_SIZE == http2_session_get_effective_local_window_size(session));
	assert(0 == http2_session_get_effective_recv_data_length(session));
	
	assert(INITIAL_WINDOW_SIZE == http2_session_get_stream_effective_local_window_size(session, 1));
	assert(0 == http2_session_get_stream_effective_recv_data_length(session, 1));
	
	/* Check connection flow control */
	session.recv_window_size = 100;
	http2_submit_window_update(session, FrameFlags.NONE, 0, 1100);
	
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 1000 == http2_session_get_effective_local_window_size(session));
	assert(0 == http2_session_get_effective_recv_data_length(session));
	
	http2_submit_window_update(session, FrameFlags.NONE, 0, -50);
	/* Now session.recv_window_size = -50 */
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 950 == http2_session_get_effective_local_window_size(session));
	assert(0 == http2_session_get_effective_recv_data_length(session));

	session.recv_window_size += 50;
	/* Now session.recv_window_size = 0 */
	http2_submit_window_update(session, FrameFlags.NONE, 0, 100);
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 1050 == http2_session_get_effective_local_window_size(session));
	assert(50 == http2_session_get_effective_recv_data_length(session));
	
	/* Check stream flow control */
	stream.recv_window_size = 100;
	http2_submit_window_update(session, FrameFlags.NONE, 1, 1100);
	
	assert(INITIAL_WINDOW_SIZE + 1000 ==
		http2_session_get_stream_effective_local_window_size(session, 1));
	assert(0 ==
		http2_session_get_stream_effective_recv_data_length(session, 1));
	
	http2_submit_window_update(session, FrameFlags.NONE, 1, -50);
	/* Now stream.recv_window_size = -50 */
	assert(INITIAL_WINDOW_SIZE + 950 ==
		http2_session_get_stream_effective_local_window_size(session, 1));
	assert(0 ==
		http2_session_get_stream_effective_recv_data_length(session, 1));
	
	stream.recv_window_size += 50;
	/* Now stream.recv_window_size = 0 */
	http2_submit_window_update(session, FrameFlags.NONE, 1, 100);
	assert(INITIAL_WINDOW_SIZE + 1050 == http2_session_get_stream_effective_local_window_size(session, 1));
	assert(50 == http2_session_get_stream_effective_recv_data_length(session, 1));
	
	session.free();
}

void test_http2_session_set_option(void) {
	Session session;
	Policy callbacks;
	http2_option *option;
	
	http2_option_new(&option);
	
	http2_option_set_no_auto_window_update(option, 1);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	http2_session_client_new2(&session, &callbacks, null, option);
	
	assert(session.opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE);
	
	session.free();
	
	http2_option_set_peer_max_concurrent_streams(option, 100);
	
	http2_session_client_new2(&session, &callbacks, null, option);
	
	assert(100 == session.remote_settings.max_concurrent_streams);
	session.free();
	
	http2_option_del(option);
}

void test_http2_session_data_backoff_by_high_pri_frame(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	DataProvider data_prd;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = block_count_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	data_prd.read_callback = fixed_length_data_source_read_callback;
	
	ud.frame_send_cb_called = 0;
	ud.data_source_length = DATA_PAYLOADLEN * 4;
	
	session = new Session(CLIENT, callbacks, ud);
	http2_submit_request(session, null, null, 0, &data_prd, null);
	
	session.remote_window_size = 1 << 20;
	
	ud.block_count = 2;
	/* Sends request HEADERS + DATA[0] */
	assert(0 == session.send());
	
	stream = session.getStream(1);
	stream.remote_window_size = 1 << 20;
	
	assert(FrameType.DATA == ud.sent_frame_type);
	/* data for DATA[1] is read from data_prd but it is not sent */
	assert(ud.data_source_length == DATA_PAYLOADLEN * 2);
	
	http2_submit_ping(session, FrameFlags.NONE, null);
	ud.block_count = 2;
	/* Sends DATA[1] + PING, PING is interleaved in DATA sequence */
	assert(0 == session.send());
	assert(FrameType.PING == ud.sent_frame_type);
	/* data for DATA[2] is read from data_prd but it is not sent */
	assert(ud.data_source_length == DATA_PAYLOADLEN);
	
	ud.block_count = 2;
	/* Sends DATA[2..3] */
	assert(0 == session.send());
	
	assert(stream.shut_flags & ShutdownFlag.WR);
	
	session.free();
}

static void check_session_recv_data_with_padding(Buffers bufs,
	size_t datalen) {
	Session session;
	my_user_data ud;
	Policy callbacks;
	ubyte *in;
	size_t inlen;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
	http2_session_server_new(&session, &callbacks, &ud);
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	inlen = http2_bufs_remove(bufs, &in);
	
	ud.frame_recv_cb_called = 0;
	ud.data_chunk_len = 0;
	
	assert(cast(size_t)inlen == session.memRecv(in, inlen));
	
	assert(1 == ud.frame_recv_cb_called);
	assert(datalen == ud.data_chunk_len);
	
	free(in);
	session.free();
}

void test_http2_session_pack_data_with_padding(void) {
	Session session;
	my_user_data ud;
	Policy callbacks;
	DataProvider data_prd;
	Frame* frame;
	size_t datalen = 55;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.send_callback = block_count_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.select_padding_callback = select_padding_callback;
	
	data_prd.read_callback = fixed_length_data_source_read_callback;
	
	session = new Session(CLIENT, callbacks, ud);
	
	ud.padlen = 63;
	
	http2_submit_request(session, null, null, 0, &data_prd, null);
	ud.block_count = 1;
	ud.data_source_length = datalen;
	/* Sends HEADERS */
	assert(0 == session.send());
	assert(FrameType.HEADERS == ud.sent_frame_type);
	
	frame = &session.aob.item.frame;
	
	assert(ud.padlen == frame.data.padlen);
	assert(frame.hd.flags & FrameFlags.PADDED);
	
	/* Check reception of this DATA frame */
	check_session_recv_data_with_padding(&session.aob.framebufs, datalen);
	
	session.free();
}

void test_http2_session_pack_headers_with_padding(void) {
	Session session, *sv_session;
	accumulator acc;
	my_user_data ud;
	Policy callbacks;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.send_callback = accumulator_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.select_padding_callback = select_padding_callback;
	callbacks.on_frame_recv_callback = on_frame_recv_callback;
	
	acc.length = 0;
	ud.acc = &acc;
	
	session = new Session(CLIENT, callbacks, ud);
	sv_session = new Session(SERVER, callbacks, ud);
	
	ud.padlen = 163;
	
	assert(1 == http2_submit_request(session, null, reqhf, ARRLEN(reqhf),
			null, null));
	assert(0 == session.send());
	
	assert(acc.length < MAX_PAYLOADLEN);
	ud.frame_recv_cb_called = 0;
	assert(cast(size_t)acc.length == sv_session.memRecv(acc.buf));
	assert(1 == ud.frame_recv_cb_called);
	assert(null == http2_session_get_next_ob_item(sv_session));
	
	sv_session.free();
	session.free();
}

void test_http2_pack_settings_payload(void) {
	Setting[2] iv;
	ubyte[64] buf;
	size_t len;
	http2_settings_entry *resiv;
	size_t resniv;

	iv[0].settings_id = Setting.HEADER_TABLE_SIZE;
	iv[0].value = 1023;
	iv[1].settings_id = Setting.INITIAL_WINDOW_SIZE;
	iv[1].value = 4095;
	
	len = http2_pack_settings_payload(buf, sizeof(buf), iv, 2);
	assert(2 * FRAME_SETTINGS_ENTRY_LENGTH == len);
	assert(0 == http2_frame_unpack_settings_payload2(&resiv, &resniv, buf, len, mem));
	assert(2 == resniv);
	assert(Setting.HEADER_TABLE_SIZE == resiv[0].settings_id);
	assert(1023 == resiv[0].value);
	assert(Setting.INITIAL_WINDOW_SIZE == resiv[1].settings_id);
	assert(4095 == resiv[1].value);
	
	free(resiv);
	
	len = http2_pack_settings_payload(buf, 9 /* too small */, iv, 2);
	assert(ErrorCode.INSUFF_BUFSIZE == len);
}

void checkStreamDependencySiblings(Stream stream, Stream dep_prev, stream dep_next, Stream sib_prev, Stream sib_next) {
	assert(dep_prev == stream.dep_prev);
	assert(dep_next == stream.dep_next);
	assert(sib_prev == stream.sib_prev);
	assert(sib_next == stream.sib_next);
}

/* http2_stream_dep_add() and its families functions should be
   tested in http2_stream_test.c, but it is easier to use
   http2_session_open_stream().  Therefore, we test them here. */
void test_http2_session_stream_dep_add(void) {
	Session session;
	Policy callbacks;
	Stream a, b, c, d, e;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	
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
	
	checkStreamDependencySiblings(a, null, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, c);
	checkStreamDependencySiblings(c, null, d, b, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(4 == session.roots.num_streams);
	assert(a == session.roots.head);
	assert(null == a.root_next);
	
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
	
	checkStreamDependencySiblings(a, null, e, null, null);
	checkStreamDependencySiblings(e, a, b, null, null);
	checkStreamDependencySiblings(b, e, null, null, c);
	checkStreamDependencySiblings(c, null, d, b, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(5 == session.roots.num_streams);
	assert(a == session.roots.head);
	assert(null == a.root_next);
	
	session.free();
}

void test_http2_session_stream_dep_remove(void) {
	Session session;
	Policy callbacks;
	Stream a, b, c, d, e, f;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	/* Remove root */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	a.remove();
	
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
	
	checkStreamDependencySiblings(a, null, null, null, null);
	checkStreamDependencySiblings(b, null, null, null, null);
	checkStreamDependencySiblings(c, null, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(3 == session.roots.num_streams);
	assert(b == session.roots.head);
	assert(c == b.root_next);
	assert(null == c.root_next);
	
	session.free();
	
	/* Remove left most stream */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	b.remove();
	
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
	
	checkStreamDependencySiblings(a, null, c, null, null);
	checkStreamDependencySiblings(b, null, null, null, null);
	checkStreamDependencySiblings(c, a, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(3 == session.roots.num_streams);
	assert(a == session.roots.head);
	assert(null == a.root_next);
	
	session.free();
	
	/* Remove right most stream */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	c.remove();
	
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
	
	checkStreamDependencySiblings(a, null, d, null, null);
	checkStreamDependencySiblings(b, null, null, d, null);
	checkStreamDependencySiblings(c, null, null, null, null);
	checkStreamDependencySiblings(d, a, null, null, b);
	
	session.free();
	
	/* Remove middle stream */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
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
	
	c.remove();
	
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
	
	checkStreamDependencySiblings(a, null, d, null, null);
	checkStreamDependencySiblings(b, null, null, e, null);
	checkStreamDependencySiblings(c, null, null, null, null);
	checkStreamDependencySiblings(e, null, null, f, b);
	checkStreamDependencySiblings(f, null, null, d, e);
	checkStreamDependencySiblings(d, a, null, null, f);
	
	session.free();
}

void test_http2_session_stream_dep_add_subtree(void) {
	Session session;
	Policy callbacks;
	Stream a, b, c, d, e, f;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	/* dep_stream has dep_next */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	e = session.openStream(9);
	f = open_stream_with_dep(session, 11, e);
	
	/* a         e
   * |         |
   * c--b      f
   * |
   * d
   */
	
	addSubtree(a, e, session);
	
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
	
	checkStreamDependencySiblings(a, null, e, null, null);
	checkStreamDependencySiblings(b, null, null, c, null);
	checkStreamDependencySiblings(c, null, d, e, b);
	checkStreamDependencySiblings(d, c, null, null, null);
	checkStreamDependencySiblings(e, a, f, null, c);
	checkStreamDependencySiblings(f, e, null, null, null);
	
	session.free();
	
	/* dep_stream has dep_next and now we insert subtree */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	e = session.openStream(9);
	f = open_stream_with_dep(session, 11, e);
	
	/* a         e
   * |         |
   * c--b      f
   * |
   * d
   */
	
	insertSubtree(a, e, session);
	
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
	
	checkStreamDependencySiblings(a, null, e, null, null);
	checkStreamDependencySiblings(e, a, f, null, null);
	checkStreamDependencySiblings(f, e, null, null, c);
	checkStreamDependencySiblings(b, null, null, c, null);
	checkStreamDependencySiblings(c, null, d, f, b);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	session.free();
}

void test_http2_session_stream_dep_remove_subtree(void) {
	Session session;
	Policy callbacks;
	Stream a, b, c, d, e;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	/* Remove left most stream */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	removeSubtree(c);
	
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
	
	checkStreamDependencySiblings(a, null, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, null);
	checkStreamDependencySiblings(c, null, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	session.free();
	
	/* Remove right most stream */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	removeSubtree(b);
	
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
	
	checkStreamDependencySiblings(a, null, c, null, null);
	checkStreamDependencySiblings(c, a, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	checkStreamDependencySiblings(b, null, null, null, null);
	
	session.free();
	
	/* Remove middle stream */
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
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
	
	removeSubtree(c);
	
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
	
	checkStreamDependencySiblings(a, null, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, e);
	checkStreamDependencySiblings(e, null, null, b, null);
	checkStreamDependencySiblings(c, null, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	session.free();
}

void test_http2_session_stream_dep_make_head_root(void) {
	Session session;
	Policy callbacks;
	Stream a, b, c, d;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	
	c = session.openStream(5);
	
	/* a     c
   * |
   * b
   */
	
	removeSubtree(c);
	assert(0 == c.makeTopmostRoot(session));
	
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
	
	checkStreamDependencySiblings(c, null, a, null, null);
	checkStreamDependencySiblings(a, c, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, null);
	
	session.free();
	
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	
	b = session.openStream(3);
	
	c = session.openStream(5);
	
	/*
   * a  b   c
   */
	
	removeSubtree(c);
	assert(0 == c.makeTopmostRoot(session));
	
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
	
	checkStreamDependencySiblings(c, null, b, null, null);
	checkStreamDependencySiblings(b, c, null, null, a);
	checkStreamDependencySiblings(a, null, null, b, null);
	
	session.free();
	
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	
	c = session.openStream(5);
	d = open_stream_with_dep(session, 7, c);
	
	/* a     c
   * |     |
   * b     d
   */
	
	removeSubtree(c);
	assert(0 == c.makeTopmostRoot(session));
	
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
	
	checkStreamDependencySiblings(c, null, a, null, null);
	checkStreamDependencySiblings(d, null, null, a, null);
	checkStreamDependencySiblings(a, c, b, null, d);
	checkStreamDependencySiblings(b, a, null, null, null);
	
	session.free();
}

void test_http2_session_stream_attach_item(void) {
	Session session;
	Policy callbacks;
	Stream a, b, c, d;
	http2_outbound_item *da, *db, *dc, *dd;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
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
	
	attachItem(b, db, session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	
	assert(16 == b.effective_weight);
	
	assert(16 == a.sum_norest_weight);
	
	assert(1 == db.queued);
	
	dc = create_data_ob_item();
	
	attachItem(c, dc, session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_TOP == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	
	assert(16 * 16 / 32 == b.effective_weight);
	assert(16 * 16 / 32 == c.effective_weight);
	
	assert(32 == a.sum_norest_weight);
	
	assert(1 == dc.queued);
	
	da = create_data_ob_item();
	
	attachItem(a, da, session);
	
	assert(StreamState.DPRI_TOP == a.dpri);
	assert(StreamState.DPRI_REST == b.dpri);
	assert(StreamState.DPRI_REST == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	
	assert(16 == a.effective_weight);
	
	assert(1 == da.queued);
	
	detachItem(a, session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_TOP == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	
	assert(16 * 16 / 32 == b.effective_weight);
	assert(16 * 16 / 32 == c.effective_weight);
	
	dd = create_data_ob_item();
	
	attachItem(d, dd, session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_TOP == c.dpri);
	assert(StreamState.DPRI_REST == d.dpri);
	
	assert(16 * 16 / 32 == b.effective_weight);
	assert(16 * 16 / 32 == c.effective_weight);
	
	assert(0 == dd.queued);
	
	detachItem(c, session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_REST == d.dpri);
	
	assert(16 * 16 / 16 == b.effective_weight);
	
	assert(0 == dd.queued);
	
	detachItem(b, session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_NO_ITEM == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_TOP == d.dpri);
	
	assert(16 * 16 / 16 == d.effective_weight);
	
	assert(1 == dd.queued);
	
	session.free();
}

void test_http2_session_stream_attach_item_subtree(void) {
	Session session;
	Policy callbacks;
	Stream a, b, c, d, e, f;
	http2_outbound_item *db, *dd, *de;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	b = open_stream_with_dep(session, 3, a);
	c = open_stream_with_dep(session, 5, a);
	d = open_stream_with_dep(session, 7, c);
	
	e = session.openStream(9);
	f = open_stream_with_dep(session, 11, e);
	/*
   * a        e
   * |        |
   * c--b     f
   * |
   * d
   */
	
	de = create_data_ob_item();
	
	attachItem(e, de, session);
	
	db = create_data_ob_item();
	
	attachItem(b, db, session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	assert(StreamState.DPRI_TOP == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	assert(16 == b.effective_weight);
	assert(16 == e.effective_weight);
	
	/* Insert subtree e under a */
	
	removeSubtree(e);
	insertSubtree(a, e, session);
	
	/*
   * a
   * |
   * e
   * |
   * f--c--b
   *    |
   *    d
   */
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_REST == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	assert(StreamState.DPRI_TOP == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	assert(16 == e.effective_weight);
	
	/* Remove subtree b */
	
	removeSubtree(b);
	
	b.makeRoot(session);
	
	/*
   * a       b
   * |
   * e
   * |
   * f--c
   *    |
	 *    d
   */
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	assert(StreamState.DPRI_TOP == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	assert(16 == b.effective_weight);
	assert(16 == e.effective_weight);
	
	/* Remove subtree a */
	
	removeSubtree(a);
	
	a.makeRoot(session);
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	assert(StreamState.DPRI_TOP == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	/* Remove subtree c */
	
	removeSubtree(c);
	
	c.makeRoot(session);
	
	/*
   * a       b     c
   * |             |
   * e             d
   * |
   * f
   */
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_NO_ITEM == d.dpri);
	assert(StreamState.DPRI_TOP == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	dd = create_data_ob_item();
	
	attachItem(d, dd, session);
	
	/* Add subtree c to a */
	
	removeSubtree(c);
	addSubtree(a, c, session);
	
	/*
   * a       b
   * |
   * c--e
   * |  |
   * d  f
   */
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_REST == d.dpri);
	assert(StreamState.DPRI_TOP == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	assert(16 == b.effective_weight);
	assert(16 * 16 / 16 == e.effective_weight);
	
	assert(32 == a.sum_norest_weight);
	assert(16 == c.sum_norest_weight);
	
	/* Insert b under a */
	
	removeSubtree(b);
	insertSubtree(a, b, session);
	
	/*
   * a
   * |
   * b
   * |
   * e--c
   * |  |
   * f  d
   */
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_REST == d.dpri);
	assert(StreamState.DPRI_REST == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	assert(16 == b.effective_weight);
	
	assert(16 == a.sum_norest_weight);
	assert(0 == b.sum_norest_weight);
	
	/* Remove subtree b */
	
	removeSubtree(b);
	b.makeRoot(session);
	
	/*
   * b       a
   * |
   * e--c
   * |  |
   * f  d
   */
	
	assert(StreamState.DPRI_NO_ITEM == a.dpri);
	assert(StreamState.DPRI_TOP == b.dpri);
	assert(StreamState.DPRI_NO_ITEM == c.dpri);
	assert(StreamState.DPRI_REST == d.dpri);
	assert(StreamState.DPRI_REST == e.dpri);
	assert(StreamState.DPRI_NO_ITEM == f.dpri);
	
	assert(0 == a.sum_norest_weight);
	assert(0 == b.sum_norest_weight);
	
	session.free();
}

void test_http2_session_keep_closed_stream(void) {
	Session session;
	Policy callbacks;
	const size_t max_concurrent_streams = 5;
	Setting iv = Setting(SETTINGS_MAX_CONCURRENT_STREAMS, max_concurrent_streams);
	size_t i;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	http2_submit_settings(session, FrameFlags.NONE, &iv, 1);
	
	for (i = 0; i < max_concurrent_streams; ++i) {
		session.openStream((int)i * 2 + 1);
	}
	
	assert(0 == session.num_closed_streams);
	
	closeStream(1, FrameError.NO_ERROR);
	
	assert(1 == session.num_closed_streams);
	assert(1 == session.closed_stream_tail.stream_id);
	assert(session.closed_stream_tail == session.closed_stream_head);
	
	closeStream(5, FrameError.NO_ERROR);
	
	assert(2 == session.num_closed_streams);
	assert(5 == session.closed_stream_tail.stream_id);
	assert(1 == session.closed_stream_head.stream_id);
	assert(session.closed_stream_head ==
		session.closed_stream_tail.closed_prev);
	assert(null == session.closed_stream_tail.closed_next);
	assert(session.closed_stream_tail ==
		session.closed_stream_head.closed_next);
	assert(null == session.closed_stream_head.closed_prev);
	
	session.openStream(11);
	
	assert(1 == session.num_closed_streams);
	assert(5 == session.closed_stream_tail.stream_id);
	assert(session.closed_stream_tail == session.closed_stream_head);
	assert(null == session.closed_stream_head.closed_prev);
	assert(null == session.closed_stream_head.closed_next);
	
	session.openStream(13);
	
	assert(0 == session.num_closed_streams);
	assert(null == session.closed_stream_tail);
	assert(null == session.closed_stream_head);
	
	session.free();
}

void test_http2_session_keep_idle_stream(void) {
	Session session;
	Policy callbacks;
	const size_t max_concurrent_streams = 1;
	Setting iv = Setting(SETTINGS_MAX_CONCURRENT_STREAMS, max_concurrent_streams);
	int i;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	http2_submit_settings(session, FrameFlags.NONE, &iv, 1);
	
	/* We at least allow 2 idle streams even if max concurrent streams
     is very low. */
	for (i = 0; i < 2; ++i) {
		session.openStream(i * 2 + 1, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	}

	assert(2 == session.num_idle_streams);
	
	assert(1 == session.idle_stream_head.stream_id);
	assert(3 == session.idle_stream_tail.stream_id);
	
	session.openStream(5, FrameFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	
	assert(2 == session.num_idle_streams);
	
	assert(3 == session.idle_stream_head.stream_id);
	assert(5 == session.idle_stream_tail.stream_id);
	
	session.free();
}

void test_http2_session_detach_idle_stream(void) {
	Session session;
	Policy callbacks;
	int i;
	Stream stream;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	for (i = 1; i <= 3; ++i) {
		session.openStream(i, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	}
	
	assert(3 == session.num_idle_streams);
	
	/* Detach middle stream */
	stream = http2_session_get_stream_raw(session, 2);
	
	assert(session.idle_stream_head == stream.closed_prev);
	assert(session.idle_stream_tail == stream.closed_next);
	assert(stream == session.idle_stream_head.closed_next);
	assert(stream == session.idle_stream_tail.closed_prev);
	
	session.detachIdleStream(stream);
	
	assert(2 == session.num_idle_streams);
	
	assert(null == stream.closed_prev);
	assert(null == stream.closed_next);
	
	assert(session.idle_stream_head ==
		session.idle_stream_tail.closed_prev);
	assert(session.idle_stream_tail ==
		session.idle_stream_head.closed_next);
	
	/* Detach head stream */
	stream = session.idle_stream_head;
	
	session.detachIdleStream(stream);
	
	assert(1 == session.num_idle_streams);
	
	assert(session.idle_stream_head == session.idle_stream_tail);
	assert(null == session.idle_stream_head.closed_prev);
	assert(null == session.idle_stream_head.closed_next);
	
	/* Detach last stream */
	
	stream = session.idle_stream_head;
	
	session.detachIdleStream(stream);
	
	assert(0 == session.num_idle_streams);
	
	assert(null == session.idle_stream_head);
	assert(null == session.idle_stream_tail);
	
	for (i = 4; i <= 5; ++i) {
		session.openStream(i, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	}
	
	assert(2 == session.num_idle_streams);
	
	/* Detach tail stream */
	
	stream = session.idle_stream_tail;
	
	session.detachIdleStream(stream);
	
	assert(1 == session.num_idle_streams);
	
	assert(session.idle_stream_head == session.idle_stream_tail);
	assert(null == session.idle_stream_head.closed_prev);
	assert(null == session.idle_stream_head.closed_next);
	
	session.free();
}

void test_http2_session_large_dep_tree(void) {
	Session session;
	Policy callbacks;
	size_t i;
	Stream dep_stream;
	Stream root_stream;
	int stream_id;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	stream_id = 1;
	for (i = 0; i < MAX_DEP_TREE_LENGTH; ++i) {
		dep_stream = open_stream_with_dep(session, stream_id, dep_stream);
		stream_id += 2;
	}
	
	root_stream = session.getStream(1);
	
	/* Check that last dep_stream must be part of tree */
	assert(root_stream.subtreeContains(dep_stream));
	
	dep_stream = open_stream_with_dep(session, stream_id, dep_stream);
	
	/* We exceeded MAX_DEP_TREE_LENGTH limit.  dep_stream is now
     root node and has no descendants. */
	assert(!root_stream.subtreeContains(dep_stream));
	assert(http2_stream_in_dep_tree(dep_stream));
	
	session.free();
}

void test_http2_session_graceful_shutdown(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.on_stream_close_callback = on_stream_close_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	session.openStream(301);
	session.openStream(302);
	session.openStream(309);
	session.openStream(311);
	session.openStream(319);
	
	assert(0 == http2_submit_shutdown_notice(session));
	
	ud.frame_send_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == ud.frame_send_cb_called);
	assert((1u << 31) - 1 == session.local_last_stream_id);
	
	assert(0 == http2_submit_goaway(session, FrameFlags.NONE, 311,
			FrameError.NO_ERROR, null, 0));
	
	ud.frame_send_cb_called = 0;
	ud.stream_close_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == ud.frame_send_cb_called);
	assert(311 == session.local_last_stream_id);
	assert(1 == ud.stream_close_cb_called);
	
	assert(0 ==
		http2_session_terminate_session2(session, 301, FrameError.NO_ERROR));
	
	ud.frame_send_cb_called = 0;
	ud.stream_close_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == ud.frame_send_cb_called);
	assert(301 == session.local_last_stream_id);
	assert(2 == ud.stream_close_cb_called);
	
	assert(null != session.getStream(301));
	assert(null != session.getStream(302));
	assert(null == session.getStream(309));
	assert(null == session.getStream(311));
	assert(null == session.getStream(319));
	
	session.free();
}

void test_http2_session_on_header_temporal_failure(void) {
	Session session;
	Policy callbacks;
	my_user_data ud;
	Buffers bufs;
	http2_buf *buf;
	Deflater deflater;
	HeaderField[] hf = [HeaderField("alpha", "bravo"), HeaderField("charlie", "delta")];
	HeaderField[] hfa;
	size_t hdpos;
	size_t rv;
	Frame frame;
	http2_frame_hd hd;
	OutboundItem item;

	

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.on_header_callback = temporal_failure_on_header_callback;
	
	http2_session_server_new(&session, &callbacks, &ud);
	
	frame_pack_bufs_init(&bufs);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	http2_nv_array_copy(hfa, reqhf, ARRLEN(reqhf), mem);
	
	http2_frame_headers_init(frame.headers, FrameFlags.END_STREAM, 1,
		HeadersCategory.REQUEST, null, hfa, ARRLEN(reqhf));
	frame.headers.pack(bufs, deflater);
	http2_frame_headers_free(frame.headers, mem);
	
	/* We are going to create CONTINUATION.  First serialize header
     block, and then frame header. */
	hdpos = http2_bufs_len(&bufs);
	
	buf = &bufs.head.buf;
	buf.last += FRAME_HDLEN;
	
	http2_hd_deflate_hd_bufs(&deflater, &bufs, &nv[1], 1);
	
	http2_frame_hd_init(&hd,
		http2_bufs_len(&bufs) - hdpos - FRAME_HDLEN,
		FrameType.CONTINUATION, FrameFlags.END_HEADERS, 1);
	
	http2_frame_pack_frame_hd(&buf.pos[hdpos], &hd);
	
	rv = session.memRecv(buf.pos, http2_bufs_len(&bufs));
	
	assert(rv == http2_bufs_len(&bufs));
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	/* Make sure no header decompression error occurred */
	assert(GoAwayFlags.NONE == session.goaway_flags);
	
	bufs.free();
	
	deflater.free();
	session.free();
}

void test_http2_session_recv_client_preface(void) {
	Session session;
	Policy callbacks;
	http2_option *option;
	size_t rv;
	http2_frame ping_frame;
	ubyte[16] buf;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	http2_option_new(&option);
	http2_option_set_recv_client_preface(option, 1);
	
	/* Check success case */
	http2_session_server_new2(&session, &callbacks, null, option);
	
	assert(session.opt_flags & OptionsMask.RECV_CLIENT_PREFACE);
	
	rv = http2_session_mem_recv(
		session, (const ubyte *)CLIENT_CONNECTION_PREFACE,
		CLIENT_CONNECTION_PREFACE.length);
	
	assert(rv == CLIENT_CONNECTION_PREFACE.length);
	assert(InboundState.READ_FIRST_SETTINGS == session.iframe.state);
	
	/* Receiving PING is error because we want SETTINGS. */
	http2_frame_ping_init(&ping_frame.ping, FrameFlags.NONE, null);
	
	http2_frame_pack_frame_hd(buf, &ping_frame.ping.hd);
	
	rv = session.memRecv(buf, FRAME_HDLEN);
	assert(FRAME_HDLEN == rv);
	assert(InboundState.IGN_ALL == session.iframe.state);
	assert(0 == session.iframe.payloadleft);
	
	http2_frame_ping_free(&ping_frame.ping);
	
	session.free();
	
	/* Check bad case */
	http2_session_server_new2(&session, &callbacks, null, option);
	
	/* Feed preface with one byte less */
	rv = http2_session_mem_recv(
		session, (const ubyte *)CLIENT_CONNECTION_PREFACE,
		CLIENT_CONNECTION_PREFACE.length - 1);
	
	assert(rv == CLIENT_CONNECTION_PREFACE.length - 1);
	assert(InboundState.READ_CLIENT_PREFACE == session.iframe.state);
	assert(1 == session.iframe.payloadleft);
	
	rv = session.memRecv((const ubyte *)"\0", 1);
	
	assert(ErrorCode.BAD_PREFACE == rv);
	
	session.free();
	
	http2_option_del(option);
}

void test_http2_session_delete_data_item(void) {
	Session session;
	Policy callbacks;
	Stream a;
	DataProvider prd;
	
	memset(&callbacks, 0, sizeof(callbacks));
	
	session = new Session(SERVER, callbacks, null);
	
	a = session.openStream(1);
	open_stream_with_dep(session, 3, a);
	
	/* We don't care about these members, since we won't send data */
	prd.source.ptr = null;
	prd.read_callback = fail_data_source_read_callback;
	
	/* This data item will be marked as TOP */
	assert(0 == http2_submit_data(session, FrameFlags.NONE, 1, &prd));
	/* This data item will be marked as REST */
	assert(0 == http2_submit_data(session, FrameFlags.NONE, 3, &prd));
	
	session.free();
}

void test_http2_session_open_idle_stream(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	Stream opened_stream;
	PrioritySpec pri_spec;
	Frame frame;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	
	session = new Session(SERVER, callbacks, null);
	
	pri_spec = PrioritySpec(0, 3, 0);
	
	frame.priority = Priority(1, pri_spec);
	
	assert(0 == http2_session_on_priority_received(session, &frame));
	
	stream = http2_session_get_stream_raw(session, 1);
	
	assert(StreamState.IDLE == stream.state);
	assert(null == stream.closed_prev);
	assert(null == stream.closed_next);
	assert(1 == session.num_idle_streams);
	assert(session.idle_stream_head == stream);
	assert(session.idle_stream_tail == stream);
	
	opened_stream = http2_session_open_stream(
		session, 1, StreamFlags.NONE, pri_spec_default,
		StreamState.OPENING, null);
	
	assert(stream == opened_stream);
	assert(StreamState.OPENING == stream.state);
	assert(0 == session.num_idle_streams);
	assert(null == session.idle_stream_head);
	assert(null == session.idle_stream_tail);
	
	http2_frame_priority_free(frame.priority);
	
	session.free();
}

void test_http2_session_cancel_reserved_remote(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	Frame frame;
	HeaderField[] hfa;
	
	Deflater deflater;

	Buffers bufs;
	size_t rv;
	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	session.last_recv_stream_id = 2;
	
	http2_submit_rst_stream(session, FrameFlags.NONE, 2, FrameError.CANCEL);
	
	assert(StreamState.CLOSING == stream.state);
	
	assert(0 == session.send());
	
	hfa.length = ARRLEN(reshf);
	http2_nv_array_copy(hfa, reshf, hfa.length, mem);
	
	http2_frame_headers_init(frame.headers, FrameFlags.END_HEADERS, 2,
		HeadersCategory.PUSH_RESPONSE, null, hfa, hfa.length);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos, bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	/* stream is not dangling, so assign null */
	stream = null;
	
	/* No RST_STREAM or GOAWAY is generated since stream should be in
     StreamState.CLOSING and push response should be ignored. */
	assert(0 == http2_pq_size(&session.ob_pq));
	
	/* Check that we can receive push response HEADERS while RST_STREAM
     is just queued. */
	session.openStream(4, StreamFlags.NONE,
		pri_spec_default, StreamState.RESERVED, null);
	
	session.last_recv_stream_id = 4;
	
	http2_submit_rst_stream(session, FrameFlags.NONE, 2, FrameError.CANCEL);
	
	bufs.reset();
	
	frame.hd.stream_id = 4;
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(1 == http2_pq_size(&session.ob_pq));
	
	http2_frame_headers_free(frame.headers, mem);
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http2_session_reset_pending_headers(void) {
	Session session;
	Policy callbacks;
	Stream stream;
	int stream_id;
	my_user_data ud;
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	callbacks.on_frame_send_callback = on_frame_send_callback;
	callbacks.on_frame_not_send_callback = on_frame_not_send_callback;
	callbacks.on_stream_close_callback = on_stream_close_callback;
	
	session = new Session(CLIENT, callbacks, ud);
	
	stream_id = http2_submit_request(session, null, null, 0, null, null);
	assert(stream_id >= 1);
	
	http2_submit_rst_stream(session, FrameFlags.NONE, stream_id, FrameError.CANCEL);
	
	session.remote_settings.max_concurrent_streams = 0;
	
	/* RST_STREAM cancels pending HEADERS and is not actually sent. */
	ud.frame_send_cb_called = 0;
	assert(0 == session.send());
	
	assert(0 == ud.frame_send_cb_called);
	
	stream = session.getStream(stream_id);
	
	assert(null == stream);
	
	/* See HEADERS is not sent.  on_stream_close is called just like
     transmission failure. */
	session.remote_settings.max_concurrent_streams = 1;
	
	ud.frame_not_send_cb_called = 0;
	ud.stream_close_error_code = 0;
	assert(0 == session.send());
	
	assert(1 == ud.frame_not_send_cb_called);
	assert(FrameType.HEADERS == ud.not_sent_frame_type);
	assert(FrameError.CANCEL == ud.stream_close_error_code);
	
	stream = session.getStream(stream_id);
	
	assert(null == stream);
	
	session.free();
}

static void check_http2_http_recv_headers_fail(Session session, http2_hd_deflater *deflater, int stream_id, int stream_state, const HeaderField[] hfa, size_t hfa.length) {

	size_t rv;
	OutboundItem item;
	Buffers bufs;

	frame_pack_bufs_init(&bufs);
	
	if (stream_state != -1) {
		session.openStream(stream_id, StreamFlags.NONE, pri_spec_default, stream_state, null);
	}
	
	rv = pack_headers(&bufs, deflater, stream_id, FrameFlags.END_HEADERS, hfa,
		hfa.length, mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.free();
}

void test_http2_http_mandatory_headers(void) {
	Session session;
	Policy callbacks;
	Deflater deflater;

	/* test case for response */
	const HeaderField[] nostatus_reshf = [HeaderField("server", "foo")];
	const HeaderField[] dupstatus_reshf = [HeaderField(":status", "200"), HeaderField(":status", "200")];
	const HeaderField[] badpseudo_reshf = [HeaderField(":status", "200"), HeaderField(":scheme", "https")];
	const HeaderField[] latepseudo_reshf = [HeaderField("server", "foo"), HeaderField(":status", "200")];
	const HeaderField[] badstatus_reshf = [HeaderField(":status", "2000")];
	const HeaderField[] badcl_reshf = [HeaderField(":status", "200"), HeaderField("content-length", "-1")];
	const HeaderField[] dupcl_reshf = [HeaderField(":status", "200"), HeaderField("content-length", "0"), HeaderField("content-length", "0")];
	const HeaderField[] badhd_reshf = [HeaderField(":status", "200"), HeaderField("connection", "close")];
	
	/* test case for request */
	const HeaderField[] nopath_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":method", "GET"), 
		HeaderField(":authority", "localhost")
	];
	const HeaderField[] earlyconnect_reqhf = [
		HeaderField(":method", "CONNECT"), 		HeaderField(":scheme", "https"), 
		HeaderField(":path", "/"), 				HeaderField(":authority", "localhost")];
	const HeaderField[] lateconnect_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":path", "/"), 
		HeaderField(":method", "CONNECT"), 		HeaderField(":authority", "localhost")];
	const HeaderField[] duppath_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":method", "GET"),
		HeaderField(":authority", "localhost"), HeaderField(":path", "/"),
		HeaderField(":path", "/")];
	const HeaderField[] badcl_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":method", "POST"),
		HeaderField(":authority", "localhost"), HeaderField(":path", "/"),
		HeaderField("content-length", "-1")];
	const HeaderField[] dupcl_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":method", "POST"),
		HeaderField(":authority", "localhost"), HeaderField(":path", "/"),
		HeaderField("content-length", "0"), 	HeaderField("content-length", "0")];
	const HeaderField[] badhd_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":method", "GET"), 
		HeaderField(":authority", "localhost"), HeaderField(":path", "/"),
		HeaderField("connection", "close")];

	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* response header lacks :status */
	check_http2_http_recv_headers_fail(session, &deflater, 1,
		StreamState.OPENING, nostatus_reshf,
		ARRLEN(nostatus_reshf));
	
	/* response header has 2 :status */
	check_http2_http_recv_headers_fail(session, &deflater, 3,
		StreamState.OPENING, dupstatus_reshf,
		ARRLEN(dupstatus_reshf));
	
	/* response header has bad pseudo header :scheme */
	check_http2_http_recv_headers_fail(session, &deflater, 5,
		StreamState.OPENING, badpseudo_reshf,
		ARRLEN(badpseudo_reshf));
	
	/* response header has :status after regular header field */
	check_http2_http_recv_headers_fail(session, &deflater, 7,
		StreamState.OPENING, latepseudo_reshf,
		ARRLEN(latepseudo_reshf));
	
	/* response header has bad status code */
	check_http2_http_recv_headers_fail(session, &deflater, 9,
		StreamState.OPENING, badstatus_reshf,
		ARRLEN(badstatus_reshf));
	
	/* response header has bad content-length */
	check_http2_http_recv_headers_fail(session, &deflater, 11,
		StreamState.OPENING, badcl_reshf,
		ARRLEN(badcl_reshf));
	
	/* response header has multiple content-length */
	check_http2_http_recv_headers_fail(session, &deflater, 13,
		StreamState.OPENING, dupcl_reshf,
		ARRLEN(dupcl_reshf));
	
	/* response header has disallowed header field */
	check_http2_http_recv_headers_fail(session, &deflater, 15,
		StreamState.OPENING, badhd_reshf,
		ARRLEN(badhd_reshf));
	
	deflater.free();
	
	session.free();
	
	/* check server side */
	session = new Session(SERVER, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* request header has no :path */
	check_http2_http_recv_headers_fail(session, &deflater, 1, -1, nopath_reqhf,
		ARRLEN(nopath_reqhf));
	
	/* request header has CONNECT method, but followed by :path */
	check_http2_http_recv_headers_fail(session, &deflater, 3, -1,
		earlyconnect_reqhf,
		ARRLEN(earlyconnect_reqhf));
	
	/* request header has CONNECT method following :path */
	check_http2_http_recv_headers_fail(
		session, &deflater, 5, -1, lateconnect_reqhf, ARRLEN(lateconnect_reqhf));
	
	/* request header has multiple :path */
	check_http2_http_recv_headers_fail(session, &deflater, 7, -1, duppath_reqhf,
		ARRLEN(duppath_reqhf));
	
	/* request header has bad content-length */
	check_http2_http_recv_headers_fail(session, &deflater, 9, -1, badcl_reqhf,
		ARRLEN(badcl_reqhf));
	
	/* request header has multiple content-length */
	check_http2_http_recv_headers_fail(session, &deflater, 11, -1, dupcl_reqhf,
		ARRLEN(dupcl_reqhf));
	
	/* request header has disallowed header field */
	check_http2_http_recv_headers_fail(session, &deflater, 13, -1, badhd_reqhf,
		ARRLEN(badhd_reqhf));
	
	deflater.free();
	
	session.free();
}

void test_http2_http_content_length(void) {
	Session session;
	Policy callbacks;
	Deflater deflater;

	Buffers bufs;
	size_t rv;
	Stream stream;
	const HeaderField[] cl_reshf = [HeaderField(":status", "200"),
		HeaderField("te", "trailers"),
		HeaderField("content-length", "9000000000")];
	const HeaderField[] cl_reqhf = [
		HeaderField(":path", "/"),        HeaderField(":method", "PUT"),
			HeaderField(":scheme", "https"),  HeaderField("te", "trailers"),
		HeaderField("host", "localhost"), HeaderField("content-length", "9000000000")];
	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, cl_reshf, ARRLEN(cl_reshf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	assert(null == session.getNextOutboundItem());
	assert(9000000000LL == stream.content_length);
	assert(200 == stream.status_code);
	
	deflater.free();
	
	session.free();
	
	bufs.reset();
	
	/* check server side */
	session = new Session(SERVER, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, cl_reqhf, ARRLEN(cl_reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	stream = session.getStream(1);
	
	assert(null == session.getNextOutboundItem());
	assert(9000000000LL == stream.content_length);
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http2_http_content_length_mismatch(void) {
	Session session;
	Policy callbacks;
	Deflater deflater;

	Buffers bufs;
	size_t rv;
	const HeaderField[] cl_reqhf = [
		HeaderField(":path", "/"), HeaderField(":method", "PUT"),
			HeaderField(":authority", "localhost"), HeaderField(":scheme", "https"),
		HeaderField("content-length", "20")];
	OutboundItem item;
	http2_frame_hd hd;
	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* header says content-length: 20, but HEADERS has END_STREAM flag set */
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS | FrameFlags.END_STREAM, cl_reqhf, ARRLEN(cl_reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* header says content-length: 20, but DATA has 0 byte */
	rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS, cl_reqhf, ARRLEN(cl_reqhf), mem);
	assert(0 == rv);
	
	http2_frame_hd_init(&hd, 0, FrameType.DATA, FrameFlags.END_STREAM, 3);
	http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
	bufs.head.buf.last += FRAME_HDLEN;
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* header says content-length: 20, but DATA has 21 bytes */
	rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS, cl_reqhf, ARRLEN(cl_reqhf), mem);
	assert(0 == rv);
	
	http2_frame_hd_init(&hd, 21, FrameType.DATA, FrameFlags.END_STREAM, 5);
	http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
	bufs.head.buf.last += FRAME_HDLEN + 21;
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http2_http_non_final_response(void) {
	Session session;
	Policy callbacks;
	Deflater deflater;

	Buffers bufs;
	size_t rv;
	const HeaderField[] nonfinal_reshf = [
		HeaderField(":status", "100"),
	];
	OutboundItem item;
	http2_frame_hd hd;
	Stream stream;
	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* non-final HEADERS with END_STREAM is illegal */
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS | FrameFlags.END_STREAM, nonfinal_reshf, ARRLEN(nonfinal_reshf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* non-final HEADERS followed by non-empty DATA is illegal */
	stream = session.openStream(3, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS, nonfinal_reshf, ARRLEN(nonfinal_reshf), mem);
	assert(0 == rv);
	
	http2_frame_hd_init(&hd, 10, FrameType.DATA, FrameFlags.END_STREAM, 3);
	http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
	bufs.head.buf.last += FRAME_HDLEN + 10;
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* non-final HEADERS followed by empty DATA (without END_STREAM) is
     ok */
	stream = session.openStream(5, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS, nonfinal_reshf, ARRLEN(nonfinal_reshf), mem);
	assert(0 == rv);
	
	http2_frame_hd_init(&hd, 0, FrameType.DATA, FrameFlags.NONE, 5);
	http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
	bufs.head.buf.last += FRAME_HDLEN;
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(null == session.getNextOutboundItem());
	
	bufs.reset();
	
	/* non-final HEADERS followed by empty DATA (with END_STREAM) is
     illegal */
	stream = session.openStream(7, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_headers(&bufs, &deflater, 7, FrameFlags.END_HEADERS, nonfinal_reshf, ARRLEN(nonfinal_reshf), mem);
	assert(0 == rv);
	
	http2_frame_hd_init(&hd, 0, FrameType.DATA, FrameFlags.END_STREAM, 7);
	http2_frame_pack_frame_hd(bufs.head.buf.last, &hd);
	bufs.head.buf.last += FRAME_HDLEN;
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* non-final HEADERS followed by final HEADERS is OK */
	stream = session.openStream(9, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_headers(&bufs, &deflater, 9, FrameFlags.END_HEADERS, nonfinal_reshf, ARRLEN(nonfinal_reshf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	rv = pack_headers(&bufs, &deflater, 9, FrameFlags.END_HEADERS, reshf, ARRLEN(reshf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(null == session.getNextOutboundItem());
	
	bufs.reset();
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http2_http_trailer_headers(void) {
	Session session;
	Policy callbacks;
	Deflater deflater;

	Buffers bufs;
	size_t rv;
	const HeaderField[] trailer_reqhf = [
		HeaderField("foo", "bar"),
	];
	OutboundItem item;
	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(SERVER, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* good trailer header */
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, reqhf, ARRLEN(reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS | FrameFlags.END_STREAM, trailer_reqhf, ARRLEN(trailer_reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(null == session.getNextOutboundItem());
	
	bufs.reset();
	
	/* trailer header without END_STREAM is illegal */
	rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS, reqhf, ARRLEN(reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	rv = pack_headers(&bufs, &deflater, 3, FrameFlags.END_HEADERS, trailer_reqhf, ARRLEN(trailer_reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* trailer header including pseudo header field is illegal */
	rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS, reqhf, ARRLEN(reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	rv = pack_headers(&bufs, &deflater, 5, FrameFlags.END_HEADERS, reqhf, ARRLEN(reqhf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http2_http_ignore_content_length(void) {
	Session session;
	Policy callbacks;
	Deflater deflater;

	Buffers bufs;
	size_t rv;
	const HeaderField[] cl_reshf = [HeaderField(":status", "304"), HeaderField("content-length", "20")];
	const HeaderField[] conn_reqhf = [HeaderField(":authority", "localhost"), HeaderField(":method", "CONNECT"), HeaderField("content-length", "999999")];
	Stream stream;
	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* If status 304, content-length must be ignored */
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS | FrameFlags.END_STREAM, cl_reshf, ARRLEN(cl_reshf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(null == session.getNextOutboundItem());
	
	bufs.reset();
	
	deflater.free();
	session.free();
	
	/* If request method is CONNECT, content-length must be ignored */
	session = new Session(SERVER, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, conn_reqhf, ARRLEN(conn_reqhf), mem);
	
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos, bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(null == session.getNextOutboundItem());
	
	stream = session.getStream(1);
	
	assert(-1 == stream.content_length);
	assert((stream.http_flags & HTTPFlags.METH_CONNECT) > 0);
	
	deflater.free();
	session.free();
	bufs.free();
}

void test_http2_http_record_request_method(void) {
	Session session;
	Policy callbacks;
	const HeaderField[] conn_reqhf = [HeaderField(":method", "CONNECT"), HeaderField(":authority", "localhost")];
	const HeaderField[] conn_reshf = [HeaderField(":status", "200"), HeaderField("content-length", "9999")];
	Stream stream;
	size_t rv;
	Buffers bufs;
	Deflater deflater;

	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	session = new Session(CLIENT, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	assert(1 == http2_submit_request(session, null, conn_reqhf,
			ARRLEN(conn_reqhf), null, null));
	
	assert(0 == session.send());
	
	stream = session.getStream(1);
	
	assert(HTTPFlags.METH_CONNECT == stream.http_flags);
	
	rv = pack_headers(&bufs, &deflater, 1, FrameFlags.END_HEADERS, conn_reshf, ARRLEN(conn_reshf), mem);
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert((HTTPFlags.METH_CONNECT & stream.http_flags) > 0);
	assert(-1 == stream.content_length);
	
	deflater.free();
	session.free();
	bufs.free();
}

void test_http2_http_push_promise(void) {
	Session session;
	Policy callbacks;
	Deflater deflater;

	Buffers bufs;
	size_t rv;
	Stream stream;
	const HeaderField[] bad_reqhf = [HeaderField(":method", "GET")];
	OutboundItem item;
	

	frame_pack_bufs_init(&bufs);
	
	memset(&callbacks, 0, sizeof(http2_session_callbacks));
	callbacks.send_callback = null_send_callback;
	
	/* good PUSH_PROMISE case */
	session = new Session(CLIENT, callbacks, null);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	rv = pack_push_promise(&bufs, &deflater, 1, FrameFlags.END_HEADERS, 2, reqhf, ARRLEN(reqhf), mem);
	assert(0 == rv);

	rv = session.memRecv(bufs.head.buf.pos, bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(null == session.getNextOutboundItem());
	
	stream = session.getStream(2);
	assert(null != stream);
	
	bufs.reset();
	
	rv = pack_headers(&bufs, &deflater, 2, FrameFlags.END_HEADERS, reshf, ARRLEN(reshf), mem);
	
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	assert(null == session.getNextOutboundItem());
	
	assert(200 == stream.status_code);
	
	bufs.reset();
	
	/* PUSH_PROMISE lacks mandatory header */
	rv = pack_push_promise(&bufs, &deflater, 1, FrameFlags.END_HEADERS, 4, bad_reqhf, ARRLEN(bad_reqhf), mem);
	
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf.pos,
		bufs.head.buf.length);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(4 == item.frame.hd.stream_id);
	
	bufs.reset();
	
	deflater.free();
	session.free();
	bufs.free();
}
