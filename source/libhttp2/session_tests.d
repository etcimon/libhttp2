/**
 * Session Tests
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.session_tests;

import libhttp2.constants;
static if (TEST_ALL):

import libhttp2.session;
import libhttp2.connector;
import libhttp2.frame;
import libhttp2.types;
import libhttp2.buffers;
import libhttp2.deflater;
import libhttp2.inflater;
import libhttp2.stream;
import libhttp2.tests;
import libhttp2.huffman;
import libhttp2.helpers;

import memutils.refcounted;

import std.algorithm : min, max;
import std.functional : toDelegate;

struct Accumulator {
	ubyte[] opSlice() { return buf[0 .. length]; }

	ubyte[65535] buf;
	size_t length;
}

struct ScriptedDataFeed {
	ubyte[8192] data;
	ubyte* datamark;
	ubyte* datalimit;
	size_t[8192] feedseq;
	size_t seqidx;

	this(Buffers bufs) 
	{
		Buffers.Chain ci;
		Buffer* buf;
		ubyte* ptr;
		size_t len;

		ptr = data.ptr;
		len = 0;
		
		for (ci = bufs.head; ci; ci = ci.next) {
			buf = &ci.buf;
			memcpy(ptr, buf.pos, buf.length);
			ptr += buf.length;
			len += buf.length;
		}
		
		datamark = data.ptr;
		datalimit = data.ptr + len;
		feedseq[0] = len;
	}
}

struct MyUserData {
	this(Session* sess)
	{
		cb_handlers = MyCallbacks(sess, &this);
		datasrc = MyDataSource(&this);
	}
	void opAssign(ref MyUserData other) {
		cb_handlers = other.cb_handlers;
		cb_handlers.user_data = &this;
		datasrc.user_data = &this;
	}

	MyCallbacks cb_handlers;
	MyDataSource datasrc;
	Accumulator* acc;
	ScriptedDataFeed *df;
	int frame_recv_cb_called, invalid_frame_recv_cb_called;
	FrameType recv_frame_type;
	int frame_send_cb_called;
	FrameType sent_frame_type;
	int frame_not_send_cb_called;
	ubyte not_sent_frame_type;
	ErrorCode not_sent_error;
	int stream_close_cb_called;
	FrameError stream_close_error_code;
	int data_source_length;
	int stream_id;
	size_t block_count;
	int data_chunk_recv_cb_called;
	const(Frame)* frame;
	size_t fixed_sendlen;
	int header_cb_called;
	int begin_headers_cb_called;
	HeaderField hf;
	size_t data_chunk_len;
	size_t padlen;
	int begin_frame_cb_called;
}

const HeaderField[] reqhf = [HeaderField(":method", "GET"), HeaderField(":path", "/"), HeaderField(":scheme", "https"), HeaderField(":authority", "localhost")];

const HeaderField[] reshf = [HeaderField(":status", "200")];

alias Callbacks = RefCounted!CallbackConnector;

struct MyCallbacks {
	Session* session;
	MyUserData* user_data;

	static int writeNull(in ubyte[] data) 
	{
		return cast(int)data.length;
	}
	
	static int writeFailure(in ubyte[] data) 
	{
		return ErrorCode.CALLBACK_FAILURE;
	}
	
	int writeFixedBytes(in ubyte[] data) 
	{
		size_t fixed_sendlen = user_data.fixed_sendlen;
		return cast(int)(fixed_sendlen < data.length ? fixed_sendlen : data.length);
	}
	
	int writeToAccumulator(in ubyte[] data) 
	{
		Accumulator *acc = user_data.acc;
		assert(acc.length + data.length < acc.buf.length);
		acc.buf[acc.length .. acc.length + data.length] = data[0 .. $];
		acc.length += data.length;
		return cast(int)data.length;
	}

	int writeWouldBlock(in ubyte[] data) 
	{
		int r;
		if (user_data.block_count == 0) {
			r = ErrorCode.WOULDBLOCK;
		} else {
			--user_data.block_count;
			r = cast(int)data.length;
		}
		return r;
	}

	ErrorCode writeData(in Frame frame, ubyte[] framehd, uint length)
	{
		Accumulator *acc = user_data.acc;

		FrameHeader hd;
		hd.unpack(framehd);
		acc.buf[acc.length .. acc.length + framehd.length] = framehd[0 .. $];

		hd.unpack(acc.buf[acc.length .. acc.length + framehd.length]);

		acc.length += framehd.length; // FRAME_HDLEN

		if (frame.data.padlen)
			acc.buf[acc.length++] = cast(ubyte)(frame.data.padlen - 1);
		acc.length += length;

		if (frame.data.padlen)
			acc.length += frame.data.padlen - 1;

		return ErrorCode.OK;

	}
		
	int readScripted(ubyte[] data) 
	{
		ScriptedDataFeed* df = user_data.df;
		size_t wlen = df.feedseq[df.seqidx] > data.length ? data.length : df.feedseq[df.seqidx];
		data[0 .. wlen] = df.datamark[0 .. wlen];
		df.datamark += wlen;
		df.feedseq[df.seqidx] -= wlen;
		if (df.feedseq[df.seqidx] == 0) {
			++df.seqidx;
		}
		return cast(int)wlen;
	}

	static int readEOF(ubyte[] data) 
	{
		return ErrorCode.EOF;
	}

	bool onFrameHeader(in FrameHeader hd) 
	{
		++user_data.begin_frame_cb_called;
		return true;
	}

	bool onFrame(in Frame frame) 
	{
		++user_data.frame_recv_cb_called;
		user_data.recv_frame_type = frame.hd.type;
		return true;
	}

	bool onInvalidFrame(in Frame frame, FrameError error_code) 
	{
		++user_data.invalid_frame_recv_cb_called;
		return true;
	}

	bool onFrameSent(in Frame frame) 
	{
		++user_data.frame_send_cb_called;
		user_data.sent_frame_type = frame.hd.type;
		return true;
	}

	bool onFrameSentTwice(in Frame frame)
	{
		static bool called;
		ErrorCode rv;
		DataProvider data_prd;
		
		if (!called) {
			called = true;
			
			data_prd = toDelegate(&MyDataSource.readTwice);

			rv = submitData(*session, FrameFlags.END_STREAM, frame.hd.stream_id, data_prd);
			assert(0 == rv);
		}
		
		return true;
	}


	bool onFrameFailure(in Frame frame, ErrorCode lib_error)
	{
		++user_data.frame_not_send_cb_called;
		user_data.not_sent_frame_type = frame.hd.type;
		user_data.not_sent_error = lib_error;
		return true;
	}

	bool onDataChunk(FrameFlags flags, int stream_id, in ubyte[] data, ref bool pause) 
	{
		++user_data.data_chunk_recv_cb_called;
		user_data.data_chunk_len = data.length;
		return true;
	}

	bool onDataChunkPause(FrameFlags flags, int stream_id, in ubyte[] data, ref bool pause) 
	{
		++user_data.data_chunk_recv_cb_called;
		pause = true;
		return true;
	}

	int selectPaddingLength(in Frame frame, int max_payloadlen) 
	{
		return cast(int) min(max_payloadlen, frame.hd.length + user_data.padlen);
	}

	static int tooLargeMaxFrameSize(FrameType frame_type, int stream_id, int session_remote_window_size, int stream_remote_window_size, uint remote_max_frame_size)
	{
		return MAX_FRAME_SIZE_MAX + 1;
	}

	static int smallestMaxFrameSize(FrameType frame_type, int stream_id, int session_remote_window_size, int stream_remote_window_size, uint remote_max_frame_size)
	{
		return 1;
	}

	bool onHeaderField(in Frame frame, in HeaderField hf, ref bool pause, ref bool rst_stream) 
	{
		++user_data.header_cb_called;
		user_data.hf = hf;
		user_data.frame = &frame;
		return true;
	}
	
	bool onHeaderFieldPause(in Frame frame, in HeaderField hf, ref bool pause, ref bool rst_stream) {
		pause = true;
		return onHeaderField(frame, hf, pause, rst_stream);
	}
	
	bool onHeaderFieldRstStream(in Frame frame, in HeaderField hf, ref bool pause, ref bool rst_stream) {
		rst_stream = true;
		return onHeaderField(frame, hf, pause, rst_stream);
	}
	
	bool onHeaders(in Frame frame) {
		++user_data.begin_headers_cb_called;
		return true;
	}
	
	bool onStreamExit(int stream_id, FrameError error_code)
	{
		++user_data.stream_close_cb_called;
		user_data.stream_close_error_code = error_code;
		
		return true;
	}
		
}

struct MyDataSource
{
	MyUserData* user_data;

	int readFixedLength(ubyte[] buf, ref DataFlags data_flags) 
	{
		size_t wlen;
		if (buf.length < user_data.data_source_length) {
			wlen = buf.length;
		} else {
			wlen = user_data.data_source_length;
		}
		user_data.data_source_length -= wlen;
		assert(user_data.data_source_length >= 0);
		if (user_data.data_source_length == 0) {
			data_flags |= DataFlags.EOF;
		}
		return cast(int)wlen;
	}

	int readNoCopy(ubyte[] buf, ref DataFlags data_flags)
	{
		size_t wlen;
		if (buf.length < user_data.data_source_length)
			wlen = buf.length;
		else
			wlen = user_data.data_source_length;

		user_data.data_source_length -= wlen;
		data_flags |= DataFlags.NO_COPY;
		if (user_data.data_source_length == 0)
			data_flags |= DataFlags.EOF;
		return cast(int)wlen;
	}

	static int readRstStream(ubyte[] buf, ref DataFlags data_flags)
	{
		return ErrorCode.TEMPORAL_CALLBACK_FAILURE;
	}

	static int readFailure(ubyte[] buf, ref DataFlags data_flags)
	{
		return ErrorCode.CALLBACK_FAILURE;
	}

	static int readDeferred(ubyte[] buf, ref DataFlags data_flags)
	{
		return ErrorCode.DEFERRED;
	}

	static int readTwice(ubyte[] buf, ref DataFlags data_flags) 
	{
		data_flags |= DataFlags.EOF;
		return min(buf.length, 16);
	}

}

private immutable PrioritySpec pri_spec_default;

void test_session_read() {
	Session session;
	Callbacks callbacks;
	ScriptedDataFeed df;
	MyUserData user_data = MyUserData(&session);
	Buffers bufs = framePackBuffers();
	size_t framelen;
	Frame frame;
	size_t i;
	OutboundItem item;
	HeaderField[] hfa;
	Deflater deflater;
	int rv;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.read_cb = &user_data.cb_handlers.readScripted;
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.on_frame_header_cb = &user_data.cb_handlers.onFrameHeader;
	
	user_data.df = &df;
	
	session = new Session(SERVER, *callbacks);
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
		
	hfa = reqhf.copy();
	frame.headers = Headers(FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, pri_spec_default, hfa);
	rv = frame.headers.pack(bufs, deflater);

	assert(0 == rv);
	
	df = ScriptedDataFeed(bufs);
	
	framelen = bufs.length;
	
	/* Send 1 byte per each read */
	for (i = 0; i < framelen; ++i) {
		df.feedseq[i] = 1;
	}
	
	frame.headers.free();
	
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
	
	frame.priority.pack(bufs);
	
	assert(0 == rv);
	
	frame.priority.free();
	
	df = ScriptedDataFeed(bufs);
	
	user_data.frame_recv_cb_called = 0;
	user_data.begin_frame_cb_called = 0;
	
	assert(0 == session.recv());
	assert(1 == user_data.frame_recv_cb_called);
	assert(1 == user_data.begin_frame_cb_called);
	
	bufs.reset();
	
	deflater.free();
	session.free();
	
	/* Some tests for frame too large */
	session = new Session(SERVER, *callbacks);
	
	/* Receive PING with too large payload */
	frame.ping = Ping(FrameFlags.NONE, null);
	
	frame.ping.pack(bufs);
	
	assert(0 == rv);
	
	/* Add extra 16 bytes */
	bufs.seekLastPresent();
	assert(bufs.cur.buf.length >= 16);
	
	bufs.cur.buf.last += 16;
	write!uint(bufs.cur.buf.pos, cast(uint)(((frame.hd.length + 16) << 8) + bufs.cur.buf.pos[3]));
	
	frame.ping.free();
	
	df = ScriptedDataFeed(bufs);
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

void test_session_read_invalid_stream_id() {
	Session session;
	Callbacks callbacks;
	ScriptedDataFeed df;
	MyUserData user_data = MyUserData(&session);
	Buffers bufs = framePackBuffers();
	Frame frame;
	Deflater deflater;
	int rv;

	HeaderField[] hfa;	

	callbacks.read_cb = &user_data.cb_handlers.readScripted;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	user_data.df = &df;
	user_data.invalid_frame_recv_cb_called = 0;
	session = new Session(SERVER, *callbacks);
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);

	
	hfa = reqhf.copy();
	frame.headers = Headers(FrameFlags.END_HEADERS, 2, HeadersCategory.HEADERS, pri_spec_default, hfa);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	df = ScriptedDataFeed(bufs);
	frame.headers.free();
	
	assert(0 == session.recv());
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_session_read_invalid_frame() {
	Session session;
	Callbacks callbacks;
	ScriptedDataFeed df;
	MyUserData user_data = MyUserData(&session);
	Buffers bufs = framePackBuffers();
	Frame frame;
	HeaderField[] hfa;
	Deflater deflater;
	int rv;	

	callbacks.read_cb = &user_data.cb_handlers.readScripted;
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	
	user_data.df = &df;
	user_data.frame_send_cb_called = 0;
	session = new Session(SERVER, *callbacks);
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	hfa = reqhf.copy();
	frame.headers = Headers(FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, pri_spec_default, hfa);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	df = ScriptedDataFeed(bufs);
	
	assert(0 == session.recv());
	assert(0 == session.send());
	assert(0 == user_data.frame_send_cb_called);
	
	/* Receive exactly same bytes of HEADERS is treated as error, because it has
   * pseudo headers and without END_STREAM flag set */
	df = ScriptedDataFeed(bufs);
	
	assert(0 == session.recv());
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.RST_STREAM == user_data.sent_frame_type);
	
	bufs.free();
	frame.headers.free();
	
	deflater.free();
	session.free();
}

void test_session_read_eof() {
	Session session;
	Callbacks callbacks;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.read_cb = toDelegate(&MyCallbacks.readEOF);
	
	session = new Session(CLIENT, *callbacks);
	assert(ErrorCode.EOF == session.recv());
	
	session.free();
}

void test_session_read_data() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	ubyte[8092] data;
	int rv;
	OutboundItem item;
	Stream stream;
	FrameHeader hd;
	int i;
		
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_data_chunk_cb = &user_data.cb_handlers.onDataChunk;
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	
	session = new Session(CLIENT, *callbacks);
	
	/* Create DATA frame with length 4KiB */
	
	hd.length = 4096;
	hd.type = FrameType.DATA;
	hd.flags = FrameFlags.NONE;
	hd.stream_id = 1;
	hd.pack(data[0 .. $]);
	
	/* stream 1 is not opened, so it must be responded with connection
     error.  This is not mandated by the spec */
	user_data.data_chunk_recv_cb_called = 0;
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(data[0 .. FRAME_HDLEN + 4096]);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(0 == user_data.data_chunk_recv_cb_called);
	assert(0 == user_data.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.free();
	
	session = new Session(CLIENT, *callbacks);
	
	/* Create stream 1 with CLOSING state. DATA is ignored. */
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.CLOSING, null);

	/* Set initial window size 16383 to check stream flow control,
     isolating it from the conneciton flow control */
	stream.localWindowSize = 16383;
	
	user_data.data_chunk_recv_cb_called = 0;
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(data[0 .. FRAME_HDLEN + 4096]);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(0 == user_data.data_chunk_recv_cb_called);
	assert(0 == user_data.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(!item);
	
	/* This is normal case. DATA is acceptable. */
	stream.state = StreamState.OPENED;
	
	user_data.data_chunk_recv_cb_called = 0;
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(data[0 .. FRAME_HDLEN + 4096]);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(1 == user_data.data_chunk_recv_cb_called);
	assert(1 == user_data.frame_recv_cb_called);
	
	//assert(!session.getNextOutboundItem());
	
	user_data.data_chunk_recv_cb_called = 0;
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(data[0 .. FRAME_HDLEN + 4096]);
	assert(FRAME_HDLEN + 4096 == rv);
	
	/* Now we got data more than initial-window-size / 2, WINDOW_UPDATE
     must be queued */
	assert(1 == user_data.data_chunk_recv_cb_called);
	assert(1 == user_data.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(1 == item.frame.window_update.hd.stream_id);
	assert(0 == session.send());
	
	/* Set initial window size to 1MiB, so that we can check connection
     flow control individually */
	stream.localWindowSize = 1 << 20;
	/* Connection flow control takes into account DATA which is received
     in the error condition. We have received 4096 * 4 bytes of
     DATA. Additional 4 DATA frames, connection flow control will kick
     in. */
	for (i = 0; i < 5; ++i) {
		rv = session.memRecv(data[0 .. FRAME_HDLEN + 4096]);
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
	hd.pack(data[0 .. $]);
	
	user_data.data_chunk_recv_cb_called = 0;
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(data[0 .. FRAME_HDLEN + 4096]);
	assert(FRAME_HDLEN + 4096 == rv);
	
	assert(0 == user_data.data_chunk_recv_cb_called);
	assert(0 == user_data.frame_recv_cb_called);
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	
	session.free();
}

void test_session_read_continuation() {
	Session session;
	Callbacks callbacks;
	HeaderField[] hfa;
	Frame frame;
	Buffers bufs = framePackBuffers();
	Buffer* buf;
	int rv;
	MyUserData user_data = MyUserData(&session);
	Deflater deflater;
	ubyte[1024] data;
	size_t datalen;
	FrameHeader cont_hd;
	PrioritySpec pri_spec;
	
	callbacks.on_header_field_cb = &user_data.cb_handlers.onHeaderField;
	callbacks.on_headers_cb = &user_data.cb_handlers.onHeaders;
	callbacks.on_frame_header_cb = &user_data.cb_handlers.onFrameHeader;
	
	session = new Session(SERVER, *callbacks);
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* Make 1 HEADERS and insert CONTINUATION header */	
	hfa = reqhf.copy();
	frame.headers = Headers(FrameFlags.NONE, 1, HeadersCategory.HEADERS, pri_spec_default, hfa);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	/* make sure that all data is in the first buf */
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	frame.headers.free();
	
	/* HEADERS's payload is 1 byte */
	memcpy(data.ptr, buf.pos, FRAME_HDLEN + 1);
	datalen = FRAME_HDLEN + 1;
	buf.pos += FRAME_HDLEN + 1;
	
	write!uint(data.ptr, (1 << 8) + data[3]);
	
	/* First CONTINUATION, 2 bytes */
	cont_hd = FrameHeader(2, FrameType.CONTINUATION, FrameFlags.NONE, 1);
	
	cont_hd.pack(data[datalen .. $]);
	datalen += FRAME_HDLEN;
	
	data[datalen .. cont_hd.length + datalen] = buf.pos[0 .. cont_hd.length];
	datalen += cont_hd.length;
	buf.pos += cont_hd.length;
	
	/* Second CONTINUATION, rest of the bytes */
	cont_hd = FrameHeader(buf.length, FrameType.CONTINUATION, FrameFlags.END_HEADERS, 1);
	
	cont_hd.pack(data[datalen .. $]);
	datalen += FRAME_HDLEN;
	
	data[datalen .. datalen + cont_hd.length] = buf.pos[0 .. cont_hd.length];
	datalen += cont_hd.length;
	buf.pos += cont_hd.length;
	
	assert(0 == buf.length);
	
	user_data.header_cb_called = 0;
	user_data.begin_frame_cb_called = 0;
	
	rv = session.memRecv(data[0 .. datalen]);
	assert(cast(size_t)datalen == rv);
	assert(4 == user_data.header_cb_called, "headers called times: " ~ user_data.header_cb_called.to!string);
	assert(3 == user_data.begin_frame_cb_called);
	
	deflater.free();
	session.free();
	
	/* Expecting CONTINUATION, but get the other frame */
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);

	/* HEADERS without END_HEADERS flag */
	hfa = reqhf.copy();
	frame.headers = Headers(FrameFlags.NONE, 1, HeadersCategory.HEADERS, pri_spec_default, hfa);
	bufs.reset();
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	frame.headers.free();
	
	/* make sure that all data is in the first buf */
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	memcpy(data.ptr, buf.pos, buf.length);
	datalen = buf.length;
	
	/* Followed by PRIORITY */
	pri_spec = pri_spec_default;
	
	frame.priority = Priority(1, pri_spec);
	bufs.reset();
	
	frame.priority.pack(bufs);

	assert(bufs.length > 0);
	
	memcpy(data.ptr + datalen, buf.pos, buf.length);
	datalen += buf.length;
	
	user_data.begin_headers_cb_called = 0;
	rv = session.memRecv(data[0 .. datalen]);
	assert(cast(size_t)datalen == rv);
	
	assert(1 == user_data.begin_headers_cb_called);
	assert(FrameType.GOAWAY == session.getNextOutboundItem().frame.hd.type);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_session_read_headers_with_priority() {
	Session session;
	Callbacks callbacks;
	HeaderField[] hfa;
	Frame frame;
	Buffers bufs = framePackBuffers();
	Buffer* buf;
	int rv;
	MyUserData user_data = MyUserData(&session);
	Deflater deflater;
	OutboundItem item;
	PrioritySpec pri_spec;
	Stream stream;

	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);

	openStream(session, 1);
	
	/* With FrameFlags.PRIORITY without exclusive flag set */
	
	hfa = reqhf.copy();
	pri_spec = PrioritySpec(1, 99, 0);

	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), 3, HeadersCategory.HEADERS, pri_spec, hfa);
	
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	frame.headers.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv((*buf)[]);
	
	assert(buf.length == rv);
	assert(1 == user_data.frame_recv_cb_called);
	
	stream = session.getStream(3);
	
	assert(99 == stream.weight);
	assert(1 == stream.depPrev.id);
	
	bufs.reset();
	
	/* With FrameFlags.PRIORITY, but cut last 1 byte to make it invalid. */
	
	hfa = reqhf.copy();
	
	pri_spec = PrioritySpec(0, 99, 0);
	
	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), 5, HeadersCategory.HEADERS, pri_spec, hfa);
	
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > FRAME_HDLEN + 5);
	
	frame.headers.free();
	
	buf = &bufs.head.buf;
	/* Make payload shorter than required length to store priority
     group */
	write!uint(buf.pos, (4 << 8) + buf.pos[3]);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv((*buf)[]);
	
	assert(buf.length == rv);
	assert(0 == user_data.frame_recv_cb_called);
	
	stream = session.getStream(5);
	
	assert(!stream);
	
	item = session.getNextOutboundItem();
	assert(item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.FRAME_SIZE_ERROR == item.frame.goaway.error_code);
	
	bufs.reset();
	
	deflater.free();
	session.free();
	
	/* Check dep_stream_id == stream_id */
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	
	hfa = reqhf.copy();
	
	pri_spec = PrioritySpec(1, 0, 0);
	
	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), 1, HeadersCategory.HEADERS, pri_spec, hfa);
	
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	frame.headers.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv((*buf)[]);
	
	assert(buf.length == rv);
	assert(0 == user_data.frame_recv_cb_called);
	
	stream = session.getStream(1);
	
	assert(!stream);
	
	item = session.getNextOutboundItem();
	assert(item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	
	bufs.reset();
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_session_read_premature_headers() {
	Session session;
	Callbacks callbacks;
	HeaderField[] hfa;
	Frame frame;
	Buffers bufs = framePackBuffers();
	Buffer* buf;
	int rv;
	MyUserData user_data = MyUserData(&session);
	Deflater deflater;
	OutboundItem item;

	
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	
	hfa = reqhf.copy();
	frame.headers = Headers(FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, pri_spec_default, hfa);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	frame.headers.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	/* Intentionally feed payload cutting last 1 byte off */
	write!uint(buf.pos,cast(uint)(((frame.hd.length - 1) << 8) + buf.pos[3]));
	rv = session.memRecv(buf.pos[0 .. buf.length - 1]);

	assert(cast(size_t)(buf.length - 1) == rv);
	
	item = session.getNextOutboundItem();
	assert(item);
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(FrameError.COMPRESSION_ERROR == item.frame.rst_stream.error_code);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_session_read_unknown_frame() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	ubyte[16384] data;
	size_t datalen;
	FrameHeader hd;
	int rv;
	
	hd = FrameHeader(16000, cast(FrameType)99, FrameFlags.NONE, 0);

	hd.pack(data[0 .. $]);
	datalen = FRAME_HDLEN + hd.length;
	
	
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	
	session = new Session(SERVER, *callbacks);
	
	user_data.frame_recv_cb_called = 0;
	
	/* Unknown frame must be ignored */
	rv = session.memRecv(data[0 .. datalen]);
	
	assert(rv == datalen);
	assert(0 == user_data.frame_recv_cb_called);
	assert(!session.getNextOutboundItem());
	
	session.free();
}

void test_session_read_unexpected_continuation() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	ubyte[16384] data;
	size_t datalen;
	FrameHeader hd;
	int rv;
	OutboundItem item;
	
	hd = FrameHeader(16000, FrameType.CONTINUATION,	FrameFlags.END_HEADERS, 1);
	
	hd.pack(data[0 .. $]);
	datalen = FRAME_HDLEN + hd.length;
	
	
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	
	session = new Session(SERVER, *callbacks);
	
	openStream(session, 1);
	
	user_data.frame_recv_cb_called = 0;
	
	/* unexpected CONTINUATION must be treated as connection error */
	rv = session.memRecv(data[0 .. datalen]);
	
	assert(rv == cast(size_t)datalen);
	assert(0 == user_data.frame_recv_cb_called);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.free();
}

void test_session_read_settings_header_table_size() {
	Session session;
	Callbacks callbacks;
	Frame frame;
	Buffers bufs = framePackBuffers();
	Buffer* buf;
	int rv;
	MyUserData user_data = MyUserData(&session);
	Setting[3] iva;
	HeaderField hf = HeaderField(":authority", "example.org");

	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	
	iva[0].id = Setting.HEADER_TABLE_SIZE;
	iva[0].value = 3000;
	
	iva[1].id = Setting.INITIAL_WINDOW_SIZE;
	iva[1].value = 16384;

	frame.settings = Settings(FrameFlags.NONE, iva[0 .. 2].copy());
	
	frame.settings.pack(bufs);

	assert(bufs.length > 0);
	
	frame.settings.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv((*buf)[]);
	
	assert(rv == buf.length);
	assert(1 == user_data.frame_recv_cb_called);
	
	assert(3000 == session.remote_settings.header_table_size);
	assert(16384 == session.remote_settings.initial_window_size);
	
	bufs.reset();
	
	/* 2 SettingsID.HEADER_TABLE_SIZE */
	iva[0].id = Setting.HEADER_TABLE_SIZE;
	iva[0].value = 3001;
	
	iva[1].id = Setting.INITIAL_WINDOW_SIZE;
	iva[1].value = 16383;
	
	iva[2].id = Setting.HEADER_TABLE_SIZE;
	iva[2].value = 3001;
	
	frame.settings = Settings(FrameFlags.NONE, iva.copy());
	
	frame.settings.pack(bufs);

	assert(bufs.length > 0);
	
	frame.settings.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv((*buf)[]);
	
	assert(rv == buf.length);
	assert(1 == user_data.frame_recv_cb_called);
	
	assert(3001 == session.remote_settings.header_table_size);
	assert(16383 == session.remote_settings.initial_window_size);
	
	bufs.reset();
	
	/* 2 SettingsID.HEADER_TABLE_SIZE; first entry clears dynamic header table. */	
	submitRequest(session, pri_spec_default, (&hf)[0 .. 1], DataProvider.init, null);
	session.send();
	
	assert(0 < session.hd_deflater.ctx.hd_table.length);
	
	iva[0].id = Setting.HEADER_TABLE_SIZE;
	iva[0].value = 0;
	
	iva[1].id = Setting.INITIAL_WINDOW_SIZE;
	iva[1].value = 16382;
	
	iva[2].id = Setting.HEADER_TABLE_SIZE;
	iva[2].value = 4096;
	
	frame.settings = Settings(FrameFlags.NONE, iva.copy());
	
	frame.settings.pack(bufs);

	assert(bufs.length > 0);
	
	frame.settings.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv((*buf)[]);
	
	assert(rv == buf.length);
	assert(1 == user_data.frame_recv_cb_called);
	
	assert(4096 == session.remote_settings.header_table_size);
	assert(16382 == session.remote_settings.initial_window_size);
	assert(0 == session.hd_deflater.ctx.hd_table.length);
	
	bufs.reset();
	
	/* 2 SettingsID.HEADER_TABLE_SIZE; second entry clears dynamic header table. */
	
	submitRequest(session, pri_spec_default, (&hf)[0 .. 1], DataProvider.init, null);
	session.send();
	
	assert(0 < session.hd_deflater.ctx.hd_table.length);
	
	iva[0].id = Setting.HEADER_TABLE_SIZE;
	iva[0].value = 3000;

	iva[1].id = Setting.INITIAL_WINDOW_SIZE;
	iva[1].value = 16381;
	
	iva[2].id = Setting.HEADER_TABLE_SIZE;
	iva[2].value = 0;
	
	frame.settings = Settings(FrameFlags.NONE, iva.copy());
	
	frame.settings.pack(bufs);

	assert(bufs.length > 0);
	
	frame.settings.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv((*buf)[]);
	
	assert(rv == buf.length);
	assert(1 == user_data.frame_recv_cb_called);
	
	assert(0 == session.remote_settings.header_table_size);
	assert(16381 == session.remote_settings.initial_window_size);
	assert(0 == session.hd_deflater.ctx.hd_table.length);
	
	bufs.reset();
	
	bufs.free();
	session.free();
}

void test_session_read_too_large_frame_length() {
	Session session;
	Callbacks callbacks;
	ubyte[FRAME_HDLEN] buf;
	OutboundItem item;
	FrameHeader hd;
	
	/* Initial max frame size is MAX_FRAME_SIZE_MIN */
	hd = FrameHeader(MAX_FRAME_SIZE_MIN + 1, FrameType.HEADERS, FrameFlags.NONE, 1);

	session = new Session(SERVER, *callbacks);
	
	hd.pack(buf);
	
	assert(buf.length == session.memRecv(buf));
	
	item = session.getNextOutboundItem();
	
	assert(item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.free();
}

void test_session_continue() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	const HeaderField[] hf1 = [HeaderField(":method", "GET"), HeaderField(":path", "/")];
	const HeaderField[] hf2 = [HeaderField("user-agent", "nghttp2/1.0.0"), HeaderField("alpha", "bravo")];
	Buffers bufs = framePackBuffers();
	Buffer* buf;
	size_t framelen1, framelen2;
	int rv;
	ubyte[4096] buffer;
	Buffer databuf;
	Frame frame;
	HeaderField[] hfa;
	
	Frame* recv_frame;
	FrameHeader data_hd;
	Deflater deflater;

	databuf = Buffer(buffer);

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.on_data_chunk_cb = &user_data.cb_handlers.onDataChunkPause;
	callbacks.on_header_field_cb = &user_data.cb_handlers.onHeaderFieldPause;
	callbacks.on_headers_cb = &user_data.cb_handlers.onHeaders;
	
	session = new Session(SERVER, *callbacks);
	/* disable strict HTTP layering checks */
	session.opt_flags |= OptionsMask.NO_HTTP_MESSAGING;
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* Make 2 HEADERS frames */
	hfa = hf1.copy();
	frame.headers = Headers(FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, pri_spec_default, hfa);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	frame.headers.free();
	
	buf = &bufs.head.buf;
	assert(bufs.length == buf.length);
	
	framelen1 = buf.length;
	memcpy(databuf.last, buf.pos, buf.length);
	databuf.last += buf.length;
	
	hfa = hf2.copy();
	frame.headers = Headers(FrameFlags.END_HEADERS, 3, HeadersCategory.HEADERS, pri_spec_default, hfa);
	bufs.reset();
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	assert(bufs.length > 0);
	
	frame.headers.free();
	
	assert(bufs.length == buf.length);
	
	framelen2 = buf.length;
	memcpy(databuf.last, buf.pos, buf.length);
	databuf.last += buf.length;

	/* Receive 1st HEADERS and pause */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv = session.memRecv(databuf[]);
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	recv_frame = cast(Frame*)user_data.frame;
	assert(FrameType.HEADERS == recv_frame.hd.type);
	assert(framelen1 - FRAME_HDLEN == recv_frame.hd.length);
	
	assert(1 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	assert(hf1[0] == user_data.hf);
	
	/* get 2nd header field */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv = session.memRecv(databuf[]);
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	
	assert(hf1[1] == user_data.hf);
	
	/* will call end_headers_callback and receive 2nd HEADERS and pause */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv = session.memRecv(databuf[]);
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	recv_frame = cast(Frame*) user_data.frame;
	assert(FrameType.HEADERS == recv_frame.hd.type);
	assert(framelen2 - FRAME_HDLEN == recv_frame.hd.length);
	
	assert(1 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	
	assert(hf2[0] == user_data.hf);
	
	/* get 2nd header field */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	rv = session.memRecv(databuf[]);
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.header_cb_called);
	
	assert(hf2[1] == user_data.hf);
	
	/* No input data, frame_read_cb is called */
	user_data.begin_headers_cb_called = 0;
	user_data.header_cb_called = 0;
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(databuf[]);
	
	assert(rv >= 0);
	databuf.pos += rv;
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(0 == user_data.header_cb_called);
	assert(1 == user_data.frame_recv_cb_called);
	
	/* Receive DATA */
	data_hd = FrameHeader(16, FrameType.DATA, FrameFlags.NONE, 1);
	
	databuf.reset();
	data_hd.pack(databuf.pos[0 .. databuf.available]);
	
	/* Intentionally specify larger buffer size to see pause is kicked in. */
	databuf.last = databuf.end;
	
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(databuf[]);
	
	assert(16 + FRAME_HDLEN == rv);
	assert(0 == user_data.frame_recv_cb_called);
	
	/* Next Session.memRecv invokes on_frame_cb and
       pause again in on_data_chunk_cb since we pass same
       DATA frame. */
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(databuf[]);
	assert(16 + FRAME_HDLEN == rv);
	assert(1 == user_data.frame_recv_cb_called);
	
	/* And finally call on_frame_cb with 0 size input */
	user_data.frame_recv_cb_called = 0;
	rv = session.memRecv(null);
	assert(0 == rv);
	assert(1 == user_data.frame_recv_cb_called);
	
	bufs.free();
	deflater.free();
	session.free();
}

void test_session_add_frame() {
	Session session;
	Callbacks callbacks;
	Accumulator acc;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;
	Frame* frame;
	HeaderField[] hfa;

	callbacks.write_cb = &user_data.cb_handlers.writeToAccumulator;
	
	acc.length = 0;
	user_data.acc = &acc;
	
	session = new Session(CLIENT, *callbacks);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	
	hfa = reqhf.copy();
	
	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), session.next_stream_id, HeadersCategory.REQUEST, pri_spec_default, hfa);
	
	session.next_stream_id += 2;
	
	assert(0 == session.addItem(item));
	assert(0 == session.ob_ss_pq.empty);
	assert(0 == session.send());
	assert(FrameType.HEADERS == acc.buf[3]);
	assert(cast(ubyte)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY) == acc.buf[4]);
	/* check stream id */
	assert(1 == read!uint(&acc.buf[5]));
	session.free();
}

void test_session_on_request_headers_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Stream stream;
	int stream_id = 1;
	HeaderField[] malformed_hfa = [HeaderField(":path", "\x01")];
	HeaderField[] hfa;
	
	PrioritySpec pri_spec;

	callbacks.on_headers_cb = &user_data.cb_handlers.onHeaders;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	session = new Session(SERVER, *callbacks);
	
	pri_spec = PrioritySpec(0, 255, 0);

	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), stream_id, HeadersCategory.REQUEST, pri_spec, null);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	assert(0 == session.onRequestHeaders(frame));
	assert(1 == user_data.begin_headers_cb_called);
	stream = session.getStream(stream_id);
	assert(StreamState.OPENING == stream.state);
	assert(255 == stream.weight);
	
	frame.headers.free();
	
	/* More than un-ACKed max concurrent streams leads REFUSED_STREAM */
	session.pending_local_max_concurrent_stream = 1;
	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), 3, HeadersCategory.HEADERS, pri_spec_default, null);
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	frame.headers.free();
	session.local_settings.max_concurrent_streams = INITIAL_MAX_CONCURRENT_STREAMS;

	/* Stream ID less than or equal to the previouly received request HEADERS is just ignored due to race condition */
	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), 3, HeadersCategory.HEADERS, pri_spec_default, null);
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));
	assert(0 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	frame.headers.free();
	
	/* Stream ID is our side and it is idle stream ID, then treat it as connection error */
	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), 2, HeadersCategory.HEADERS, pri_spec_default, null);
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	frame.headers.free();
	
	session.free();
	
	/* Check malformed headers. The library accept it. */
	session = new Session(SERVER, *callbacks);
	
	hfa = malformed_hfa.copy();

	frame.headers = Headers(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.PRIORITY), 1, HeadersCategory.HEADERS, pri_spec_default, hfa);
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(0 == session.onRequestHeaders(frame));
	assert(1 == user_data.begin_headers_cb_called);
	assert(0 == user_data.invalid_frame_recv_cb_called);
	
	frame.headers.free();
	
	session.free();
	
	/* Check client side */
	session = new Session(CLIENT, *callbacks);
	
	/* Receiving peer's idle stream ID is subject to connection error */
	frame.headers = Headers(FrameFlags.END_HEADERS, 2, HeadersCategory.REQUEST, pri_spec_default, null);
	
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK ==
		session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	frame.headers.free();
	
	session.free();
	
	session = new Session(CLIENT, *callbacks);
	
	/* Receiving our's idle stream ID is subject to connection error */
	frame.headers = Headers(FrameFlags.END_HEADERS, 1, HeadersCategory.REQUEST, pri_spec_default, null);
	
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	frame.headers.free();
	
	session.free();
	
	session = new Session(CLIENT, *callbacks);
	
	session.next_stream_id = 5;
	
	/* Stream ID which is not idle and not in stream map is just ignored */
	frame.headers = Headers(FrameFlags.END_HEADERS, 3, HeadersCategory.REQUEST, pri_spec_default, null);
	
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));
	assert(0 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	frame.headers.free();
	
	session.free();
	
	session = new Session(SERVER, *callbacks);
	
	/* Stream ID which is equal to local_last_stream_id is ok. */
	session.local_last_stream_id = 3;
	
	frame.headers = Headers(FrameFlags.END_HEADERS, 3, HeadersCategory.REQUEST, pri_spec_default, null);
	
	assert(0 == session.onRequestHeaders(frame));
	
	frame.headers.free();
	
	/* If GOAWAY has been sent, new stream is ignored */
	frame.headers = Headers(FrameFlags.END_HEADERS, 5, HeadersCategory.REQUEST, pri_spec_default, null);
	
	session.goaway_flags |= GoAwayFlags.SENT;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));
	assert(0 == user_data.invalid_frame_recv_cb_called);
	assert(0 == (session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	frame.headers.free();
	
	session.free();
}

void test_session_on_response_headers_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Stream stream;

	callbacks.on_headers_cb = &user_data.cb_handlers.onHeaders;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	frame.headers = Headers(FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, pri_spec_default, null);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;

	assert(0 == session.onResponseHeaders(frame, stream));
	assert(1 == user_data.begin_headers_cb_called);
	assert(StreamState.OPENED == stream.state);
	
	frame.headers.free();
	session.free();
}

void test_session_on_headers_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Stream stream;

	callbacks.on_headers_cb = &user_data.cb_handlers.onHeaders;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.shutdown(ShutdownFlag.WR);
	frame.headers = Headers(FrameFlags.END_HEADERS, 1, HeadersCategory.HEADERS, pri_spec_default, null);
	
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
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onHeaders(frame, stream));
	/* See no counters are updated */
	assert(2 == user_data.begin_headers_cb_called);
	assert(0 == user_data.invalid_frame_recv_cb_called);
	
	/* Server initiated stream */
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);

	/* half closed (remote) */
	frame.hd.flags = cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.END_STREAM);
	frame.hd.stream_id = 2;
	
	assert(0 == session.onHeaders(frame, stream));
	assert(3 == user_data.begin_headers_cb_called);
	assert(StreamState.OPENING == stream.state);
	
	stream.shutdown(ShutdownFlag.RD);
	
	/* Further reception of HEADERS is subject to stream error */
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onHeaders(frame, stream));
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	frame.headers.free();
	
	session.free();
}

void test_session_on_push_response_headers_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Stream stream;
	OutboundItem item;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_headers_cb = &user_data.cb_handlers.onHeaders;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	frame.headers = Headers(FrameFlags.END_HEADERS, 2, HeadersCategory.HEADERS, pri_spec_default, null);
	/* session.onPushResponseHeaders assumes stream's state is StreamState.RESERVED and session.server is 0. */
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;

	assert(0 == session.onPushResponseHeaders(frame, stream));
	assert(1 == user_data.begin_headers_cb_called);
	assert(StreamState.OPENED == stream.state);
	assert(1 == session.num_incoming_streams);
	assert(0 == (stream.flags & StreamFlags.PUSH));
	
	/* If un-ACKed max concurrent streams limit is exceeded, RST_STREAMed */
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
	
	/* If ACKed max concurrent streams limit is exceeded, GOAWAY is issued */
	session.local_settings.max_concurrent_streams = 1;
	
	stream = session.openStream(6, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	frame.hd.stream_id = 6;
	
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushResponseHeaders(frame, stream));
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	assert(1 == session.num_incoming_streams);
	
	frame.headers.free();
	session.free();
}

void test_session_on_priority_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Stream stream, dep_stream;
	PrioritySpec pri_spec;
	OutboundItem item;

	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	session = new Session(SERVER, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, 2, 0);
	
	frame.priority = Priority(1, pri_spec);
	
	/* depend on stream 0 */
	assert(0 == session.onPriority(frame));
	
	assert(2 == stream.weight);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	dep_stream = session.openStream(3, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	frame.hd.stream_id = 2;
	
	/* using dependency stream */
	frame.priority.pri_spec = PrioritySpec(3, 1, 0);
	
	assert(0 == session.onPriority(frame));
	assert(dep_stream == stream.depPrev);
	
	/* PRIORITY against idle stream */
	frame.hd.stream_id = 100;
	
	assert(0 == session.onPriority(frame));
	
	stream = session.getStreamRaw(frame.hd.stream_id);
	
	assert(StreamState.IDLE == stream.state);
	assert(dep_stream == stream.depPrev);
	
	frame.priority.free();
	session.free();
	
	/* Check dep_stream_id == stream_id case */
	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	pri_spec = PrioritySpec(1, 0, 0);
	
	frame.priority = Priority(1, pri_spec);
	
	assert(0 == session.onPriority(frame));
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	frame.priority.free();
	session.free();
}

void test_session_on_rst_stream_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	
	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	frame.rst_stream = RstStream(1, FrameError.PROTOCOL_ERROR);
	
	assert(0 == session.onRstStream(frame));
	assert(!session.getStream(1));
	
	frame.rst_stream.free();
	session.free();
}

void test_session_on_settings_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Stream stream1, stream2;
	Frame frame;
	Setting[255] iva;
	OutboundItem item;
	HeaderField hf = HeaderField(":authority", "example.org");

	iva[0].id = Setting.MAX_CONCURRENT_STREAMS;
	iva[0].value = 50;
	
	iva[1].id = Setting.MAX_CONCURRENT_STREAMS;
	iva[1].value = 1000000009;
	
	iva[2].id = Setting.INITIAL_WINDOW_SIZE;
	iva[2].value = 64 * 1024;
	
	iva[3].id = Setting.HEADER_TABLE_SIZE;
	iva[3].value = 1024;
	
	iva[4].id = Setting.ENABLE_PUSH;
	iva[4].value = 0;
		
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	session.remote_settings.initial_window_size = 16 * 1024;
	
	stream1 = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	stream2 = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	/* Set window size for each streams and will see how settings updates these values */
	stream1.remoteWindowSize = 16 * 1024;
	stream2.remoteWindowSize = -48 * 1024;
	
	frame.settings = Settings(FrameFlags.NONE, iva[0 .. 5].copy());
	
	assert(0 == session.onSettings(frame, false));
	assert(1000000009 == session.remote_settings.max_concurrent_streams);
	assert(64 * 1024 == session.remote_settings.initial_window_size);
	assert(1024 == session.remote_settings.header_table_size);
	assert(0 == session.remote_settings.enable_push);
	
	assert(64 * 1024 == stream1.remoteWindowSize);
	assert(0 == stream2.remoteWindowSize);
	
	frame.settings.iva[2].value = 16 * 1024;
	
	assert(0 == session.onSettings(frame, false));
	
	assert(16 * 1024 == stream1.remoteWindowSize);
	assert(-48 * 1024 == stream2.remoteWindowSize);
	
	assert(16 * 1024 == session.getStreamRemoteWindowSize(stream1.id));
	assert(0 == session.getStreamRemoteWindowSize(stream2.id));
	
	frame.settings.free();
	
	session.free();
	
	/* Check ACK with niv > 0 */
	session = new Session(SERVER, *callbacks);
	frame.settings = Settings(FrameFlags.ACK, iva[0 .. 1].copy());
	/* Specify inflight_ivadeliberately */
	session.inflight_iva = frame.settings.iva;
	
	assert(0 == session.onSettings(frame, false));
	item = session.getNextOutboundItem();
	assert(item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	session.inflight_iva = null;
	
	frame.settings.free();
	session.free();
	
	/* Check ACK against no inflight SETTINGS */
	session = new Session(SERVER, *callbacks);
	frame.settings = Settings(FrameFlags.ACK, null);
	
	assert(0 == session.onSettings(frame, false));
	item = session.getNextOutboundItem();
	assert(item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	frame.settings.free();
	session.free();
	
	/* Check that 2 SettingsID.HEADER_TABLE_SIZE 0 and 4096 are included
     and header table size is once cleared to 0. */
	session = new Session(CLIENT, *callbacks);
	
	submitRequest(session, pri_spec_default, (&hf)[0 .. 1], DataProvider.init, null);

	session.send();
	
	assert(session.hd_deflater.ctx.hd_table.length > 0);
	
	iva[0].id = Setting.HEADER_TABLE_SIZE;
	iva[0].value = 0;
	
	iva[1].id = Setting.HEADER_TABLE_SIZE;
	iva[1].value = 2048;
	
	frame.settings = Settings(FrameFlags.NONE, iva[0 .. 2].copy());
	
	assert(0 == session.onSettings(frame, false));
	
	assert(0 == session.hd_deflater.ctx.hd_table.length);
	assert(2048 == session.hd_deflater.ctx.hd_table_bufsize_max);
	assert(2048 == session.remote_settings.header_table_size);
	
	frame.settings.free();
	session.free();
	
	/* Check too large SettingsID.MAX_FRAME_SIZE */
	session = new Session(SERVER, *callbacks);
	
	iva[0].id = Setting.MAX_FRAME_SIZE;
	iva[0].value = MAX_FRAME_SIZE_MAX + 1;
	
	frame.settings = Settings(FrameFlags.NONE, iva[0 .. 1].copy());
	
	assert(0 == session.onSettings(frame, false));

	item = session.getNextOutboundItem();
	
	assert(item);
	assert(FrameType.GOAWAY == item.frame.hd.type);
	
	frame.settings.free();
	session.free();
}

void test_session_on_push_promise_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Stream stream, promised_stream;
	OutboundItem item;
	HeaderField[] malformed_hfa = [HeaderField(":path", "\x01")];
	HeaderField[] hfa;
	Setting iv = Setting(Setting.ENABLE_PUSH, 0);

	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_headers_cb = &user_data.cb_handlers.onHeaders;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 1, 2, null);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	assert(0 == session.onPushPromise(frame));
	
	assert(1 == user_data.begin_headers_cb_called);
	promised_stream = session.getStream(2);
	assert(StreamState.RESERVED == promised_stream.state);
	assert(2 == session.last_recv_stream_id);
	
	/* Attempt to PUSH_PROMISE against half close (remote) */
	stream.shutdown(ShutdownFlag.RD);
	frame.push_promise.promised_stream_id = 4;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.invalid_frame_recv_cb_called);
	assert(!session.getStream(4));
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(4 == item.frame.hd.stream_id);
	assert(FrameError.PROTOCOL_ERROR == item.frame.rst_stream.error_code);
	assert(0 == session.send());
	assert(4 == session.last_recv_stream_id);
	
	/* Attempt to PUSH_PROMISE against stream in closing state */
	stream.shutFlags = ShutdownFlag.NONE;
	stream.state = StreamState.CLOSING;
	frame.push_promise.promised_stream_id = 6;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(!session.getStream(6));
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
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(!session.getStream(8));
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(0 == item.frame.hd.stream_id);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	assert(0 == session.send());
	
	session.free();

	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	/* Same ID twice */
	stream.state = StreamState.OPENING;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(!session.getStream(8));
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	assert(0 == session.send());
	
	/* After GOAWAY, PUSH_PROMISE will be discarded */
	frame.push_promise.promised_stream_id = 10;
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(!session.getStream(10));
	assert(!session.getNextOutboundItem());
	
	frame.push_promise.free();
	session.free();
	
	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	/* Attempt to PUSH_PROMISE against reserved (remote) stream */
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 2, 4, null);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	frame.push_promise.free();
	session.free();
	
	/* Disable PUSH */
	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	session.local_settings.enable_push = 0;
	
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 1, 2, null);
	
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));
	
	assert(0 == user_data.begin_headers_cb_called);
	assert(1 == user_data.invalid_frame_recv_cb_called);
	
	frame.push_promise.free();
	session.free();
	
	/* Check malformed headers. We accept malformed headers */
	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	hfa = malformed_hfa.copy();
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 1, 2, hfa);
	user_data.begin_headers_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	assert(0 == session.onPushPromise(frame));
	
	assert(1 == user_data.begin_headers_cb_called);
	assert(0 == user_data.invalid_frame_recv_cb_called);
	
	frame.push_promise.free();
	session.free();

	// If local_settings.enable_push = 0 is pending, but not acked from peer, incoming
	// PUSH_PROMISE is rejected

	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	// Submit settings with ENABLE_PUSH = 0 (thus disabling push)
	submitSettings(session, (&iv)[0 .. 1]);
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 1, 2, null);
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onPushPromise(frame));

	frame.push_promise.free();
	session.free();

}

void test_session_on_ping_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	OutboundItem top;
	string opaque_data = "01234567";
	
	user_data.frame_recv_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	
	session = new Session(CLIENT, *callbacks);
	frame.ping = Ping(FrameFlags.ACK, cast(ubyte[])opaque_data.ptr[0 .. 8]);
	
	assert(0 == session.onPing(frame));
	assert(1 == user_data.frame_recv_cb_called);
	
	/* Since this ping frame has PONG flag set, no further action is
     performed. */
	assert(!session.ob_pq_top);
	
	/* Clear the flag, and receive it again */
	frame.hd.flags = FrameFlags.NONE;
	
	assert(0 == session.onPing(frame));
	assert(2 == user_data.frame_recv_cb_called);
	top = session.ob_pq_top;
	assert(FrameType.PING == top.frame.hd.type);
	assert(FrameFlags.ACK == top.frame.hd.flags);
	assert(opaque_data == top.frame.ping.opaque_data);
	
	frame.ping.free();
	session.free();
}

void test_session_on_goaway_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	int i;

	user_data.frame_recv_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	callbacks.on_stream_exit_cb = &user_data.cb_handlers.onStreamExit;
	
	session = new Session(CLIENT, *callbacks);
	
	for (i = 1; i <= 7; ++i) {
		openStream(session, i);
	}
	
	frame.goaway = GoAway(3, FrameError.PROTOCOL_ERROR, null);
	
	user_data.stream_close_cb_called = 0;
	
	assert(0 == session.onGoAway(frame));
	
	assert(1 == user_data.frame_recv_cb_called);
	assert(3 == session.remote_last_stream_id);
	/* on_stream_close should be callsed for 2 times (stream 5 and 7) */
	assert(2 == user_data.stream_close_cb_called);
	
	assert(session.getStream(1));
	assert(session.getStream(2));
	assert(session.getStream(3));
	assert(session.getStream(4));
	assert(!session.getStream(5));
	assert(session.getStream(6));
	assert(!session.getStream(7));
	
	frame.goaway.free();
	session.free();

}

void test_session_on_window_update_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Stream stream;
	OutboundItem data_item;
	
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	user_data.frame_recv_cb_called = 0;
	user_data.invalid_frame_recv_cb_called = 0;
	
	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	data_item = createDataOutboundItem();
	
	stream.attachItem(data_item, session);
	
	frame.window_update = WindowUpdate(FrameFlags.NONE, 1, 16 * 1024);

	assert(0 == session.onWindowUpdate(frame));
	assert(1 == user_data.frame_recv_cb_called);
	assert(INITIAL_WINDOW_SIZE + 16 * 1024 == stream.remoteWindowSize);
	
	stream.deferItem(StreamFlags.DEFERRED_FLOW_CONTROL, session);
	
	assert(0 == session.onWindowUpdate(frame));
	assert(2 == user_data.frame_recv_cb_called);
	assert(INITIAL_WINDOW_SIZE + 16 * 1024 * 2 == stream.remoteWindowSize);
	assert(0 == (stream.flags & StreamFlags.DEFERRED_ALL));
	
	frame.window_update.free();
	
	/* Receiving WINDOW_UPDATE on reserved (remote) stream is a connection error */
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	frame.window_update = WindowUpdate(FrameFlags.NONE, 2, 4096);
	
	assert(!(session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	assert(0 == session.onWindowUpdate(frame));
	assert(session.goaway_flags & GoAwayFlags.TERM_ON_SEND);
	
	frame.window_update.free();
	session.free();
	/* Receiving WINDOW_UPDATE on reserved (local) stream is allowed */
	session = new Session(SERVER, *callbacks);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);

	frame.window_update = WindowUpdate(FrameFlags.NONE, 2, 4096);

	assert(0 == session.onWindowUpdate(frame));
	assert(!(session.goaway_flags & GoAwayFlags.TERM_ON_SEND));
	
	assert(INITIAL_WINDOW_SIZE + 4096 == stream.remoteWindowSize);
	
	frame.window_update.free();
	
	session.free();
}

void test_session_on_data_received() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	OutboundItem top;
	Stream stream;
	Frame frame;

	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	frame.hd = FrameHeader(4096, FrameType.DATA, FrameFlags.NONE, 2);
	
	assert(0 == session.onData(frame));
	assert(0 == stream.shutFlags);
	
	frame.hd.flags = FrameFlags.END_STREAM;
	
	assert(0 == session.onData(frame));
	assert(ShutdownFlag.RD == stream.shutFlags);
	
	/* If StreamState.CLOSING state, DATA frame is discarded. */
	stream = session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.CLOSING, null);
	
	frame.hd.flags = FrameFlags.NONE;
	frame.hd.stream_id = 4;
	
	assert(0 == session.onData(frame));
	assert(!session.ob_pq_top);
	
	/* Check INVALID_STREAM case: DATA frame with stream ID which does not exist. */
	
	frame.hd.stream_id = 6;
	
	assert(0 == session.onData(frame));
	top = session.ob_pq_top;
	/* DATA against nonexistent stream is just ignored for now */
	assert(!top);
	/* assert(FrameType.RST_STREAM == top.frame.hd.type); */
	/* assert(FrameError.PROTOCOL_ERROR == top.frame.rst_stream.error_code);
	 */
	session.free();
}

void test_session_write_headers_start_stream() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	
	item = Mem.alloc!OutboundItem(session);

	frame = &item.frame;
	
	frame.headers = Headers(FrameFlags.END_HEADERS,	session.next_stream_id, HeadersCategory.REQUEST, pri_spec_default, null);
	session.next_stream_id += 2;
	
	session.addItem(item);
	assert(0 == session.send());
	stream = session.getStream(1);
	assert(StreamState.OPENING == stream.state);
	
	session.free();
}

void test_session_write_headers_reply() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	frame.headers = Headers(FrameFlags.END_HEADERS, 2, HeadersCategory.HEADERS, pri_spec_default, null);
	session.addItem(item);
	assert(0 == session.send());
	stream = session.getStream(2);
	assert(StreamState.OPENED == stream.state);
	
	session.free();
}

void test_session_write_headers_frame_size_error() {
	import core.stdc.string : memset;

	Session session;
	Callbacks callbacks;
	OutboundItem item;
	Frame* frame;	
	size_t vallen = MAX_HF_LEN;
	HeaderField[] hfa_copy;
	HeaderField[28] hfa;
	MyUserData user_data = MyUserData(&session);

	foreach(size_t i, ref hf; hfa) 
	{
		hf.name = "header";
		char[] value = Mem.alloc!(char[])(vallen + 1);
		memset(value.ptr, '0' + cast(int)i, value.length);
		value[$-1] = '\0';
		hf.value = cast(string)value;
		hf.flag = HeaderFlag.NONE;
	}
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_failure_cb = &user_data.cb_handlers.onFrameFailure;
	
	session = new Session(CLIENT, *callbacks);
	hfa_copy = hfa.ptr[0 .. hfa.length].copy();
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	frame.headers = Headers(cast(FrameFlags)FrameFlags.END_HEADERS,	session.next_stream_id, HeadersCategory.REQUEST, pri_spec_default, hfa_copy);
	
	session.next_stream_id += 2;
	
	session.addItem(item);
	
	user_data.frame_not_send_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.FRAME_SIZE_ERROR == user_data.not_sent_error);
	
	foreach(ref hf; hfa)
	{
		Mem.free(hf.value);
	}
	frame.headers.free();
	session.free();
}

void test_session_write_headers_push_reply() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	frame.headers = Headers(FrameFlags.END_HEADERS, 2, HeadersCategory.HEADERS, pri_spec_default, null);
	session.addItem(item);
	assert(0 == session.num_outgoing_streams);
	assert(0 == session.send());
	assert(1 == session.num_outgoing_streams);
	stream = session.getStream(2);
	assert(StreamState.OPENED == stream.state);
	assert(0 == (stream.flags & StreamFlags.PUSH));
	session.free();
}

void test_session_write_rst_stream() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;
	Frame* frame;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	session = new Session(CLIENT, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	frame.rst_stream = RstStream(1, FrameError.PROTOCOL_ERROR);
	session.addItem(item);
	assert(0 == session.send());
	
	assert(!session.getStream(1));
	
	session.free();
}

void test_session_write_push_promise() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;
	Frame* frame;
	Stream stream;
	Setting iv;
	MyUserData user_data = MyUserData(&session);

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_failure_cb = &user_data.cb_handlers.onFrameFailure;
	
	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 1, session.next_stream_id, null);
	
	session.next_stream_id += 2;
	
	session.addItem(item);
	
	assert(0 == session.send());
	stream = session.getStream(2);
	assert(StreamState.RESERVED == stream.state);
	
	/* Received ENABLE_PUSH = 0 */
	iv.id = Setting.ENABLE_PUSH;
	iv.value = 0;
	frame = Mem.alloc!Frame();
	frame.settings = Settings(FrameFlags.NONE, (&iv)[0 .. 1].copy());
	session.onSettings(*frame, true);
	frame.settings.free();
	Mem.free(frame);
	
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 1, -1, null);
	session.addItem(item);
	
	user_data.frame_not_send_cb_called = 0;
	assert(0 == session.send());
	
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.PUSH_PROMISE == user_data.not_sent_frame_type);
	assert(ErrorCode.PUSH_DISABLED == user_data.not_sent_error);
	
	session.free();
	
	/* PUSH_PROMISE from client is error */
	session = new Session(CLIENT, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	item = Mem.alloc!OutboundItem(session);
	
	frame = &item.frame;
	
	frame.push_promise = PushPromise(FrameFlags.END_HEADERS, 1, -1, null);
	session.addItem(item);
	
	assert(0 == session.send());
	assert(!session.getStream(3));

	session.free();
}

void test_session_is_my_stream_id() {
	Session session;
	Callbacks callbacks;
	
	session = new Session(SERVER, *callbacks);
	
	assert(0 == session.isMyStreamId(0));
	assert(0 == session.isMyStreamId(1));
	assert(1 == session.isMyStreamId(2));
	
	session.free();
	
	session = new Session(CLIENT, *callbacks);
	
	assert(0 == session.isMyStreamId(0));
	assert(1 == session.isMyStreamId(1));
	assert(0 == session.isMyStreamId(2));
	
	session.free();
}

void test_session_upgrade() {
	Session session;
	Callbacks callbacks;
	ubyte[128] settings_payload;
	int settings_payloadlen;
	Setting[16] iva;
	Stream stream;
	OutboundItem item;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	iva[0].id = Setting.MAX_CONCURRENT_STREAMS;
	iva[0].value = 1;
	iva[1].id = Setting.INITIAL_WINDOW_SIZE;
	iva[1].value = 4095;
	settings_payloadlen = packSettingsPayload(settings_payload.ptr[0 .. 128], iva[0 .. 2]);
	
	/* Check client side */
	session = new Session(CLIENT, *callbacks);
	assert(0 == session.upgrade(settings_payload[0 .. settings_payloadlen], &*callbacks));
	stream = session.getStream(1);
	assert(stream !is null);
	assert(&*callbacks == session.getStreamUserData(stream.id));
	assert(ShutdownFlag.WR == stream.shutFlags);
	item = session.getNextOutboundItem();
	assert(FrameType.SETTINGS == item.frame.hd.type);
	assert(2 == item.frame.settings.iva.length);
	assert(Setting.MAX_CONCURRENT_STREAMS == item.frame.settings.iva[0].id);
	assert(1 == item.frame.settings.iva[0].value);
	assert(Setting.INITIAL_WINDOW_SIZE == item.frame.settings.iva[1].id);
	assert(4095 == item.frame.settings.iva[1].value);
	
	/* Call upgrade() again is error */
	assert(ErrorCode.PROTO == session.upgrade(settings_payload[0 .. settings_payloadlen], &*callbacks));
	session.free();

	/* Check server side */
	session = new Session(SERVER, *callbacks);
	assert(0 == session.upgrade(settings_payload[0 .. settings_payloadlen], &*callbacks));
	stream = session.getStream(1);
	assert(stream);
	//assert(!session.getStreamUserData(stream.id));
	assert(ShutdownFlag.RD == stream.shutFlags);
	assert(!session.getNextOutboundItem());
	assert(1 == session.remote_settings.max_concurrent_streams);
	assert(4095 == session.remote_settings.initial_window_size);
	/* Call upgrade() again is error */
	assert(ErrorCode.PROTO == session.upgrade(settings_payload[0 .. settings_payloadlen], &*callbacks));
	session.free();

	/* Empty SETTINGS is OK */
	settings_payloadlen = packSettingsPayload(settings_payload[0 .. 0], null);
	
	session = new Session(CLIENT, *callbacks);
	assert(0 == session.upgrade(settings_payload[0 .. settings_payloadlen]));
	session.free();
}

void test_session_reprioritize_stream() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Stream stream;
	Stream dep_stream;
	PrioritySpec pri_spec;

	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	
	session = new Session(SERVER, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, 10, 0);
	
	session.reprioritizeStream(stream, pri_spec);
	
	assert(10 == stream.weight);
	assert(!stream.depPrev);
	
	/* If depenency to idle stream which is not in depdenency tree yet */
	
	pri_spec = PrioritySpec(3, 99, 0);
	
	session.reprioritizeStream(stream, pri_spec);
	
	assert(99 == stream.weight);
	assert(3 == stream.depPrev.id);
	
	dep_stream = session.getStreamRaw(3);
	
	assert(DEFAULT_WEIGHT == dep_stream.weight);
	
	dep_stream = openStream(session, 3);
	
	/* Change weight */
	pri_spec.weight = 128;
	
	session.reprioritizeStream(stream, pri_spec);
	
	assert(128 == stream.weight);
	assert(dep_stream == stream.depPrev);
	
	/* Test circular dependency; stream 1 is first removed and becomes
     root.  Then stream 3 depends on it. */
	pri_spec = PrioritySpec(1, 1, 0);
	
	session.reprioritizeStream(dep_stream, pri_spec);
	
	assert(1 == dep_stream.weight);
	assert(stream == dep_stream.depPrev);
	
	/* Making priority to closed stream will result in default
     priority */
	session.last_recv_stream_id = 9;
	
	pri_spec = PrioritySpec(5, 5, 0);
	
	session.reprioritizeStream(stream, pri_spec);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
}

void test_session_reprioritize_stream_with_idle_stream_dep() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Stream stream;
	PrioritySpec pri_spec;

	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	
	session = new Session(SERVER, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	session.pending_local_max_concurrent_stream = 1;
	
	pri_spec = PrioritySpec(101, 10, 0);
	
	session.reprioritizeStream(stream, pri_spec);
	
	/* idle stream is not counteed to max concurrent streams */
	
	assert(10 == stream.weight);
	assert(101 == stream.depPrev.id);
	
	stream = session.getStreamRaw(101);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
}

void test_submit_data() {
	Session session;
	Callbacks callbacks;
	DataProvider data_prd;
	MyUserData user_data = MyUserData(&session);
	Frame* frame;
	FrameHeader hd;
	ActiveOutboundItem* aob;
	Buffers framebufs;
	Buffer* buf;

	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	
	data_prd = &user_data.datasrc.readFixedLength;
	user_data.data_source_length = DATA_PAYLOADLEN * 2;
	session = new Session(CLIENT, *callbacks);
	aob = &session.aob;
	framebufs = aob.framebufs;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == submitData(session, FrameFlags.END_STREAM, 1, data_prd));
	
	user_data.block_count = 0;
	assert(0 == session.send());
	frame = &aob.item.frame;
	
	buf = &framebufs.head.buf;
	hd.unpack((*buf)[]);
	
	assert(FrameFlags.NONE == hd.flags);
	assert(FrameFlags.NONE == frame.hd.flags);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
}

void test_submit_data_read_length_too_large() {
	Session session;
	Callbacks callbacks;
	DataProvider data_prd;
	MyUserData user_data = MyUserData(&session);
	Frame* frame;
	FrameHeader hd;
	ActiveOutboundItem* aob;
	Buffers framebufs;
	Buffer* buf;
	size_t payloadlen;
	
	
	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	callbacks.max_frame_size_cb = toDelegate(&MyCallbacks.tooLargeMaxFrameSize);
	
	data_prd = &user_data.datasrc.readFixedLength;
	user_data.data_source_length = DATA_PAYLOADLEN * 2;
	session = new Session(CLIENT, *callbacks);
	aob = &session.aob;
	framebufs = aob.framebufs;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == submitData(session, FrameFlags.END_STREAM, 1, data_prd));
	
	user_data.block_count = 0;
	assert(0 == session.send());
	frame = &aob.item.frame;
	
	buf = &framebufs.head.buf;
	hd.unpack((*buf)[]);
	
	assert(FrameFlags.NONE == hd.flags);
	assert(FrameFlags.NONE == frame.hd.flags);
	assert(16384 == hd.length);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
	
	/* Check that buffers are expanded */
	session = new Session(CLIENT, *callbacks);
	
	user_data.data_source_length = MAX_FRAME_SIZE_MAX;
	
	session.remote_settings.max_frame_size = MAX_FRAME_SIZE_MAX;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == submitData(session, FrameFlags.END_STREAM, 1, data_prd));
	
	user_data.block_count = 0;
	assert(0 == session.send());
	
	aob = &session.aob;
	
	frame = &aob.item.frame;
	
	framebufs = aob.framebufs;
	
	buf = &framebufs.head.buf;
	hd.unpack((*buf)[]);
	
	payloadlen = min(INITIAL_CONNECTION_WINDOW_SIZE, INITIAL_WINDOW_SIZE);
	
	assert(FRAME_HDLEN + 1 + payloadlen == cast(size_t)buf.capacity, "Capacity error, got payloadlen " ~ payloadlen.to!string ~ " and capacity: " ~ buf.capacity.to!string);
	assert(FrameFlags.NONE == hd.flags, "Flag error");
	assert(FrameFlags.NONE == frame.hd.flags);
	assert(payloadlen == hd.length);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
}

void test_submit_data_read_length_smallest() {
	Session session;
	Callbacks callbacks;
	DataProvider data_prd;
	MyUserData user_data = MyUserData(&session);
	Frame* frame;
	FrameHeader hd;
	ActiveOutboundItem* aob;
	Buffers framebufs;
	Buffer* buf;

	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	callbacks.max_frame_size_cb = toDelegate(&MyCallbacks.smallestMaxFrameSize);
	
	data_prd = &user_data.datasrc.readFixedLength;
	user_data.data_source_length = DATA_PAYLOADLEN * 2;
	session = new Session(CLIENT, *callbacks);
	aob = &session.aob;
	framebufs = aob.framebufs;
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == submitData(session, FrameFlags.END_STREAM, 1, data_prd));
	
	user_data.block_count = 0;
	assert(0 == session.send());
	frame = &aob.item.frame;
	
	buf = &framebufs.head.buf;
	hd.unpack((*buf)[]);
	
	assert(FrameFlags.NONE == hd.flags);
	assert(FrameFlags.NONE == frame.hd.flags);
	assert(1 == hd.length);
	/* aux_data.data.flags has these flags */
	assert(FrameFlags.END_STREAM == aob.item.aux_data.data.flags);
	
	session.free();
}

void test_submit_data_twice() {
	Session session;
	Callbacks callbacks;
	DataProvider data_prd;
	MyUserData user_data = MyUserData(&session);
	Accumulator acc;
	
	
	callbacks.write_cb = &user_data.cb_handlers.writeToAccumulator;
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSentTwice;
	
	data_prd = toDelegate(&MyDataSource.readTwice);
	
	acc.length = 0;
	user_data.acc = &acc;
	
	session = new Session(CLIENT, *callbacks);
	
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	assert(0 == submitData(session, FrameFlags.NONE, 1, data_prd));
	
	assert(0 == session.send());
	
	/* We should have sent 2 DATA frame with 16 bytes payload each */
	assert(FRAME_HDLEN * 2 + 16 * 2 == acc.length);
	
	session.free();
}

void test_submit_request_with_data() {
	Session session;
	Callbacks callbacks;
	DataProvider data_prd;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	data_prd = &user_data.datasrc.readFixedLength;
	user_data.data_source_length = 64 * 1024 - 1;
	session = new Session(CLIENT, *callbacks);
	assert(1 == submitRequest(session, pri_spec_default, reqhf, data_prd, null));
	item = session.getNextOutboundItem();
	assert(reqhf.length == item.frame.headers.hfa.length);
	assert(reqhf.equals(item.frame.headers.hfa));
	assert(0 == session.send());
	assert(0 == user_data.data_source_length);
	
	session.free();
}

void test_submit_request_without_data() {
	Session session;
	Callbacks callbacks;
	Accumulator acc;
	DataProvider data_prd = null;
	OutboundItem item;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Inflater inflater = Inflater(true);
	HeaderFields output;
	Buffers bufs = framePackBuffers();

	acc.length = 0;
	user_data.acc = &acc;
	
	callbacks.write_cb = &user_data.cb_handlers.writeToAccumulator;
	session = new Session(CLIENT, *callbacks);

	assert(1 == submitRequest(session, pri_spec_default, reqhf, data_prd, null));
	item = session.getNextOutboundItem();
	assert(reqhf.length == item.frame.headers.hfa.length);
	assert(reqhf.equals(item.frame.headers.hfa));
	assert(item.frame.hd.flags & FrameFlags.END_STREAM);
	
	assert(0 == session.send());
	frame.unpack(acc[]);

	bufs.add(cast(string) acc[]);
	output.inflate(inflater, bufs, FRAME_HDLEN);
	
	assert(reqhf.length == output.length);
	assert(reqhf.equals(output[]));
	frame.headers.free();
	output.reset();
	
	bufs.free();
	inflater.free();
	session.free();
}

void test_submit_response_with_data() {
	Session session;
	Callbacks callbacks;
	DataProvider data_prd;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	data_prd = &user_data.datasrc.readFixedLength;
	user_data.data_source_length = 64 * 1024 - 1;
	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.PUSH, pri_spec_default, StreamState.OPENING, null);
	assert(0 == submitResponse(session, 1, reshf, data_prd));
	item = session.getNextOutboundItem();
	assert(reshf.length == item.frame.headers.hfa.length);
	assert(reshf.equals(item.frame.headers.hfa));
	assert(0 == session.send());
	assert(0 == user_data.data_source_length);
	
	session.free();
}

void test_submit_response_without_data() {
	Session session;
	Callbacks callbacks;
	Accumulator acc;
	DataProvider data_prd = null;
	OutboundItem item;
	MyUserData user_data = MyUserData(&session);
	Frame frame;
	Inflater inflater = Inflater(true);
	HeaderFields output;
	Buffers bufs = framePackBuffers();

	acc.length = 0;
	user_data.acc = &acc;
	
	callbacks.write_cb = &user_data.cb_handlers.writeToAccumulator;
	session = new Session(SERVER, *callbacks);

	session.openStream(1, StreamFlags.PUSH, pri_spec_default, StreamState.OPENING, null);
	assert(0 == submitResponse(session, 1, reshf, data_prd));
	item = session.getNextOutboundItem();
	assert(reshf.length == item.frame.headers.hfa.length);
	assert(reshf.equals(item.frame.headers.hfa));
	assert(item.frame.hd.flags & FrameFlags.END_STREAM);
	
	assert(0 == session.send());
	frame.unpack(acc[]);
	
	bufs.add(cast(string)acc[]);
	output.inflate(inflater, bufs, FRAME_HDLEN);
	
	assert(reshf.length == output.length);
	assert(reshf.equals(output[]));
	
	output.reset();
	bufs.free();
	frame.headers.free();
	inflater.free();
	session.free();
}

void test_submit_headers_start_stream() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;

	session = new Session(CLIENT, *callbacks);
	assert(1 == submitHeaders(session, FrameFlags.END_STREAM, -1, pri_spec_default, reqhf));
	item = session.getNextOutboundItem();
	assert(reqhf.length == item.frame.headers.hfa.length);
	assert(reqhf.equals(item.frame.headers.hfa));
	assert(cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.END_STREAM) == item.frame.hd.flags);
	assert(0 == (item.frame.hd.flags & FrameFlags.PRIORITY));
	
	session.free();
}

void test_submit_headers_reply() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;
	Stream stream;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	
	session = new Session(SERVER, *callbacks);
	submitHeaders(session, FrameFlags.END_STREAM, 1, pri_spec_default, reshf);
	item = session.getNextOutboundItem();
	assert(reshf.length == item.frame.headers.hfa.length);
	assert(reshf.equals(item.frame.headers.hfa));
	assert(cast(FrameFlags)(FrameFlags.END_STREAM | FrameFlags.END_HEADERS) == item.frame.hd.flags);
	
	user_data.frame_send_cb_called = 0;
	user_data.sent_frame_type = FrameType.init;
	/* The transimission will be canceled because the stream 1 is not
     open. */
	assert(0 == session.send());
	assert(0 == user_data.frame_send_cb_called);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	assert(0 == submitHeaders(session, FrameFlags.END_STREAM, 1, pri_spec_default, reshf));
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.HEADERS == user_data.sent_frame_type);
	assert(stream.shutFlags & ShutdownFlag.WR);
	
	session.free();
}

void test_submit_headers_push_reply() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Stream stream;
	int foo;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	
	session = new Session(SERVER, *callbacks);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == submitHeaders(session, FrameFlags.NONE, 2, pri_spec_default, reshf, &foo));
	
	user_data.frame_send_cb_called = 0;
	user_data.sent_frame_type = FrameType.init;
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.HEADERS == user_data.sent_frame_type);
	assert(StreamState.OPENED == stream.state);
	assert(&foo == session.getStreamUserData(stream.id));

	session.free();
	
	/* Sending HEADERS from client against stream in reserved state is
     error */
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == submitHeaders(session, FrameFlags.NONE, 2, pri_spec_default, reqhf, null));
	
	user_data.frame_send_cb_called = 0;
	user_data.sent_frame_type = FrameType.init;
	assert(0 == session.send());
	assert(0 == user_data.frame_send_cb_called);
	
	session.free();
}

void test_submit_headers() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;
	Stream stream;
	Accumulator acc;
	Frame frame;
	Inflater inflater = Inflater(true);
	HeaderFields output;
	Buffers bufs = framePackBuffers();

	acc.length = 0;
	user_data.acc = &acc;
	
	callbacks.write_cb = &user_data.cb_handlers.writeToAccumulator;
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	
	session = new Session(CLIENT, *callbacks);

	assert(0 == submitHeaders(session, FrameFlags.END_STREAM, 1, pri_spec_default, reqhf));
	item = session.getNextOutboundItem();
	assert(reqhf.length == item.frame.headers.hfa.length);
	assert(reqhf.equals(item.frame.headers.hfa));
	assert(cast(FrameFlags)(FrameFlags.END_STREAM | FrameFlags.END_HEADERS) == item.frame.hd.flags);
	
	user_data.frame_send_cb_called = 0;
	user_data.sent_frame_type = FrameType.init;
	/* The transimission will be canceled because the stream 1 is not open. */
	assert(0 == session.send());
	assert(0 == user_data.frame_send_cb_called);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	assert(0 == submitHeaders(session, FrameFlags.END_STREAM, 1, pri_spec_default, reqhf));
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.HEADERS == user_data.sent_frame_type);
	assert(stream.shutFlags & ShutdownFlag.WR);
	
	frame.unpack(acc[]);
	
	bufs.add(cast(string)acc[]);
	output.inflate(inflater, bufs, FRAME_HDLEN);
	
	assert(reqhf.length == output.length);
	assert(reqhf.equals(output[]));
	
	output.reset();
	bufs.free();
	frame.headers.free();
	
	inflater.free();
	session.free();
}

void test_submit_headers_continuation() {
	Session session;
	Callbacks callbacks;
	HeaderField[] hfa = [HeaderField("h1", ""), HeaderField("h1", ""), HeaderField("h1", ""), HeaderField("h1", ""), 
		HeaderField("h1", ""), HeaderField("h1", ""), HeaderField("h1", "")];
	OutboundItem item;
	ubyte[4096] data;
	size_t i;
	MyUserData user_data = MyUserData(&session);

	foreach(ref hf; hfa)
		hf.value = cast(string)data;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	
	session = new Session(CLIENT, *callbacks);
	assert(1 == submitHeaders(session, FrameFlags.END_STREAM, -1, pri_spec_default, hfa, null));
	item = session.getNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	assert(cast(FrameFlags)(FrameFlags.END_STREAM | FrameFlags.END_HEADERS) == item.frame.hd.flags);
	assert(0 == (item.frame.hd.flags & FrameFlags.PRIORITY));
	
	user_data.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	
	session.free();
}

void test_submit_priority() {
	Session session;
	Callbacks callbacks;
	Stream stream;
	MyUserData user_data = MyUserData(&session);
	PrioritySpec pri_spec;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, 3, 0);
	
	/* depends on stream 0 */
	assert(0 == submitPriority(session, 1, pri_spec));
	assert(0 == session.send());
	assert(3 == stream.weight);
	
	/* submit against idle stream */
	assert(0 == submitPriority(session, 3, pri_spec));
	
	user_data.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	
	session.free();
}

void test_submit_settings() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;
	Frame* frame;
	Setting[7] iva;
	Frame ack_frame;
	const int UNKNOWN_ID = 1000000007;
 
	iva[0].id = Setting.MAX_CONCURRENT_STREAMS;
	iva[0].value = 5;
	
	iva[1].id = Setting.INITIAL_WINDOW_SIZE;
	iva[1].value = 16 * 1024;
	
	iva[2].id = Setting.MAX_CONCURRENT_STREAMS;
	iva[2].value = 50;
	
	iva[3].id = Setting.HEADER_TABLE_SIZE;
	iva[3].value = 0;
	
	iva[4].id = cast(ushort)UNKNOWN_ID;
	iva[4].value = 999;
	
	iva[5].id = Setting.INITIAL_WINDOW_SIZE;
	iva[5].value = cast(uint)MAX_WINDOW_SIZE + 1;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	session = new Session(SERVER, *callbacks);

	assert(ErrorCode.INVALID_ARGUMENT == submitSettings(session, iva[0 .. 6]));
	
	/* Make sure that local settings are not changed */
	assert(INITIAL_MAX_CONCURRENT_STREAMS == session.local_settings.max_concurrent_streams);
	assert(INITIAL_WINDOW_SIZE == session.local_settings.initial_window_size);
	
	/* Now sends without 6th one */
	assert(0 == submitSettings(session, iva[0 .. 5]));
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.SETTINGS == item.frame.hd.type);

	frame = &item.frame;
	assert(5 == frame.settings.iva.length);
	assert(5 == frame.settings.iva[0].value);
	assert(Setting.MAX_CONCURRENT_STREAMS == frame.settings.iva[0].id);
	
	assert(16 * 1024 == frame.settings.iva[1].value);
	assert(Setting.INITIAL_WINDOW_SIZE == frame.settings.iva[1].id);
	
	assert(cast(ushort)UNKNOWN_ID == frame.settings.iva[4].id);
	assert(999 == frame.settings.iva[4].value);
	
	user_data.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	
	assert(50 == session.pending_local_max_concurrent_stream);
	
	ack_frame.settings = Settings(FrameFlags.ACK, null);
	assert(0 == session.onSettings(ack_frame, false));
	ack_frame.settings.free();
	
	assert(16 * 1024 == session.local_settings.initial_window_size);
	assert(0 == session.hd_inflater.ctx.hd_table_bufsize_max);
	assert(50 == session.local_settings.max_concurrent_streams);
	assert(INITIAL_MAX_CONCURRENT_STREAMS == session.pending_local_max_concurrent_stream);
	
	session.free();
}

void test_submit_settings_update_local_window_size() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;
	Setting[4] iva;
	Stream stream;
	Frame ack_frame;

	ack_frame.settings = Settings(FrameFlags.ACK, null);
	
	iva[0].id = Setting.INITIAL_WINDOW_SIZE;
	iva[0].value = 16 * 1024;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.localWindowSize = INITIAL_WINDOW_SIZE + 100;
	stream.recvWindowSize = 32768;

	stream = session.openStream(3, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	assert(0 == submitSettings(session, iva[0 .. 1]));
	assert(0 == session.send());
	assert(0 == session.onSettings(ack_frame, false));
	
	stream = session.getStream(1);
	assert(0 == stream.recvWindowSize);
	assert(16 * 1024 + 100 == stream.localWindowSize);
	
	stream = session.getStream(3);
	assert(16 * 1024 == stream.localWindowSize);
	
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(32768 == item.frame.window_update.window_size_increment);
	
	session.free();
	
	/* Check overflow case */
	iva[0].value = 128 * 1024;
	session = new Session(SERVER, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.localWindowSize = MAX_WINDOW_SIZE;
	
	assert(0 == submitSettings(session, iva[0 .. 1]));
	assert(0 == session.send());
	assert(0 == session.onSettings(ack_frame, false));
	
	item = session.getNextOutboundItem();
	assert(FrameType.GOAWAY == item.frame.hd.type, "Expected GoAway frame type, got " ~ item.frame.hd.type.to!string);
	assert(FrameError.FLOW_CONTROL_ERROR == item.frame.goaway.error_code, "Expected a Flow control error, got " ~ item.frame.goaway.error_code.to!string);
	
	session.free();
	ack_frame.settings.free();
}

void test_submit_push_promise() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Stream stream;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.on_frame_failure_cb = &user_data.cb_handlers.onFrameFailure;
	
	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(2 == submitPushPromise(session, 1, reqhf, &user_data));
	
	user_data.frame_send_cb_called = 0;
	user_data.sent_frame_type = FrameType.init;
	assert(0 == session.send());
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.PUSH_PROMISE == user_data.sent_frame_type);
	stream = session.getStream(2);
	assert(StreamState.RESERVED == stream.state);
	assert(&user_data == session.getStreamUserData(2));
	
	/* submit PUSH_PROMISE while associated stream is not opened */
	assert(4 == submitPushPromise(session, 3, reqhf, &user_data));
	
	user_data.frame_not_send_cb_called = 0;
	
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.PUSH_PROMISE == user_data.not_sent_frame_type);
	
	stream = session.getStream(4);
	
	assert(!stream);
	
	session.free();
}

void test_submit_window_update() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	OutboundItem item;
	Stream stream;
	

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.recvWindowSize = 4096;
	
	assert(0 == submitWindowUpdate(session, 2, 1024));
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(1024 == item.frame.window_update.window_size_increment);
	assert(0 == session.send());
	assert(3072 == stream.recvWindowSize);
	
	assert(0 == submitWindowUpdate(session, 2, 4096));
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4096 == item.frame.window_update.window_size_increment);
	assert(0 == session.send());
	assert(0 == stream.recvWindowSize);
	
	assert(0 == submitWindowUpdate(session, 2, 4096));
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4096 == item.frame.window_update.window_size_increment);
	assert(0 == session.send());
	assert(0 == stream.recvWindowSize);
	
	assert(0 == submitWindowUpdate(session, 2, 0));
	/* It is ok if stream is closed or does not exist at the call
     time */
	assert(0 == submitWindowUpdate(session, 4, 4096));
	
	session.free();
}

void test_submit_window_update_local_window_size() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;
	Stream stream;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	stream.recvWindowSize = 4096;
	
	assert(0 == submitWindowUpdate(session, 2, stream.recvWindowSize + 1));
	assert(INITIAL_WINDOW_SIZE + 1 == stream.localWindowSize);
	assert(0 == stream.recvWindowSize);
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4097 == item.frame.window_update.window_size_increment);
	
	assert(0 == session.send());
	
	/* Let's decrement local window size */
	stream.recvWindowSize = 4096;
	assert(0 == submitWindowUpdate(session, 2, -stream.localWindowSize / 2));
	assert(32768 == stream.localWindowSize);
	assert(-28672 == stream.recvWindowSize);
	assert(32768 == stream.recvReduction);

	item = session.getNextOutboundItem();
	assert(!item);
	
	/* Increase local window size */
	assert(0 == submitWindowUpdate(session, 2, 16384));
	assert(49152 == stream.localWindowSize);
	assert(-12288 == stream.recvWindowSize);
	assert(16384 == stream.recvReduction);
	assert(!session.getNextOutboundItem());
	
	assert(ErrorCode.FLOW_CONTROL == submitWindowUpdate(session, 2, MAX_WINDOW_SIZE));
	
	assert(0 == session.send());
	
	/* Check connection-level flow control */
	session.recv_window_size = 4096;
	assert(0 == submitWindowUpdate(session, 0,	session.recv_window_size + 1));
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 1 ==
		session.local_window_size);
	assert(0 == session.recv_window_size);
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(4097 == item.frame.window_update.window_size_increment);
	
	assert(0 == session.send());
	
	/* Go decrement part */
	session.recv_window_size = 4096;
	assert(0 == submitWindowUpdate(session, 0, -session.local_window_size / 2));
	assert(32768 == session.local_window_size);
	assert(-28672 == session.recv_window_size);
	assert(32768 == session.recv_reduction);
	item = session.getNextOutboundItem();
	assert(!item);
	
	/* Increase local window size */
	assert(0 == submitWindowUpdate(session, 0, 16384));
	assert(49152 == session.local_window_size);
	assert(-12288 == session.recv_window_size);
	assert(16384 == session.recv_reduction);
	assert(!session.getNextOutboundItem());
	
	assert(ErrorCode.FLOW_CONTROL == submitWindowUpdate(session, 0, MAX_WINDOW_SIZE));
	
	session.free();
}

void test_submit_shutdown_notice() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);

	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.on_frame_failure_cb = &user_data.cb_handlers.onFrameFailure;
	
	session = new Session(SERVER, *callbacks);
	
	assert(0 == submitShutdownNotice(session));
	
	user_data.frame_send_cb_called = 0;
	
	session.send();
	
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.GOAWAY == user_data.sent_frame_type);
	assert((1u << 31) - 1 == session.local_last_stream_id);
	
	/* After another GOAWAY, submitShutdownNotice() is noop. */
	assert(0 == session.terminateSession(FrameError.NO_ERROR));
	
	user_data.frame_send_cb_called = 0;
	
	session.send();
	
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.GOAWAY == user_data.sent_frame_type);
	assert(0 == session.local_last_stream_id);
	
	assert(0 == submitShutdownNotice(session));
	
	user_data.frame_send_cb_called = 0;
	user_data.frame_not_send_cb_called = 0;
	
	session.send();
	
	assert(0 == user_data.frame_send_cb_called);
	assert(0 == user_data.frame_not_send_cb_called);
	
	session.free();
	
	/* Using submitShutdownNotice() with client side session is error */
	session = new Session(CLIENT, *callbacks);
	
	assert(ErrorCode.INVALID_STATE == submitShutdownNotice(session));
	
	session.free();
}

void test_submit_invalid_hf() {
	Session session;
	Callbacks callbacks;
	HeaderField[] empty_name_hfa = [HeaderField("Version", "HTTP/1.1"), HeaderField("", "empty name")];
	
	/* Now invalid header field from HTTP/1.1 is accepted in libhttp2 */
	session = new Session(SERVER, *callbacks);

	/* submitRequest */
	assert(0 < submitRequest(session, pri_spec_default, empty_name_hfa, DataProvider.init, null));
	
	/* submitResponse */
	assert(0 == submitResponse(session, 2, empty_name_hfa, DataProvider.init));
	
	/* submitHeaders */
	assert(0 < submitHeaders(session, FrameFlags.NONE, -1, pri_spec_default, empty_name_hfa));
	
	/* submitPushPromise */
	openStream(session, 1);
	
	assert(0 < submitPushPromise(session, 1, empty_name_hfa, null));
	
	session.free();
}

void test_session_open_stream() {
	Session session;
	Callbacks callbacks;
	Stream stream;
	PrioritySpec pri_spec;
	
	
	session = new Session(SERVER, *callbacks);
	
	pri_spec = PrioritySpec(0, 245, 0);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	assert(1 == session.num_incoming_streams);
	assert(0 == session.num_outgoing_streams);
	assert(StreamState.OPENED == stream.state);
	assert(245 == stream.weight);
	assert(!stream.depPrev);
	assert(ShutdownFlag.NONE == stream.shutFlags);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(1 == session.num_incoming_streams);
	assert(1 == session.num_outgoing_streams);
	assert(!stream.depPrev);
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(ShutdownFlag.NONE == stream.shutFlags);

	stream = session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(1 == session.num_incoming_streams);
	assert(1 == session.num_outgoing_streams);
	assert(!stream.depPrev);
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(ShutdownFlag.RD == stream.shutFlags);
	
	pri_spec = PrioritySpec(1, 17, 1);
	
	stream = session.openStream(3, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	assert(17 == stream.weight);
	assert(1 == stream.depPrev.id);
	
	/* Dependency to idle stream */
	pri_spec = PrioritySpec(1000000007, 240, 1);

	stream = session.openStream(5, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	assert(240 == stream.weight);
	assert(1000000007 == stream.depPrev.id);
	
	stream = session.getStreamRaw(1000000007);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(stream.rootNext);
	
	/* Dependency to closed stream which is not in dependency tree */
	session.last_recv_stream_id = 7;
	
	pri_spec = PrioritySpec(7, 10, 0);
	
	stream = session.openStream(9, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == session.num_incoming_streams);
	assert(0 == session.num_outgoing_streams);
	assert(!stream.depPrev);
	assert(DEFAULT_WEIGHT == stream.weight);
	assert(ShutdownFlag.WR == stream.shutFlags);
	
	session.free();
}

void test_session_open_stream_with_idle_stream_dep() {
	Session session;
	Callbacks callbacks;
	Stream stream;
	PrioritySpec pri_spec;
	
	
	session = new Session(SERVER, *callbacks);
	
	/* Dependency to idle stream */
	pri_spec = PrioritySpec(101, 245, 0);

	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	
	assert(245 == stream.weight);
	assert(101 == stream.depPrev.id);
	
	stream = session.getStreamRaw(101);
	
	assert(StreamState.IDLE == stream.state);
	assert(DEFAULT_WEIGHT == stream.weight);
	
	pri_spec = PrioritySpec(211, 1, 0);

	/* stream 101 was already created as idle. */
	stream = session.openStream(101, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
	
	assert(1 == stream.weight);
	assert(211 == stream.depPrev.id);

	stream = session.getStreamRaw(211);
	
	assert(StreamState.IDLE == stream.state);
	assert(DEFAULT_WEIGHT == stream.weight);
	
	session.free();
}

void test_session_get_next_ob_item() {
	Session session;
	Callbacks callbacks;
	PrioritySpec pri_spec;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	session.remote_settings.max_concurrent_streams = 2;
	
	assert(!session.getNextOutboundItem());
	submitPing(session, null);
	assert(FrameType.PING == session.getNextOutboundItem().frame.hd.type);
	
	submitRequest(session, pri_spec_default, null, DataProvider.init, null);
	assert(FrameType.PING == session.getNextOutboundItem().frame.hd.type);
	
	assert(0 == session.send());
	assert(!session.getNextOutboundItem());
	
	/* Incoming stream does not affect the number of outgoing max
     concurrent streams. */
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	pri_spec = PrioritySpec(0, MAX_WEIGHT, 0);

	submitRequest(session, pri_spec, null, DataProvider.init, null);
	assert(FrameType.HEADERS == session.getNextOutboundItem().frame.hd.type);
	assert(0 == session.send());
	
	submitRequest(session, pri_spec, null, DataProvider.init, null);
	assert(!session.getNextOutboundItem());
	
	session.remote_settings.max_concurrent_streams = 3;
	
	assert(FrameType.HEADERS == session.getNextOutboundItem().frame.hd.type);

	session.free();
}

void test_session_pop_next_ob_item() {
	Session session;
	Callbacks callbacks;
	OutboundItem item;
	PrioritySpec pri_spec;
	Stream stream;
		
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	session.remote_settings.max_concurrent_streams = 1;
	
	assert(!session.popNextOutboundItem());
	
	submitPing(session, null);
	
	pri_spec = PrioritySpec(0, 254, 0);
	
	submitRequest(session, pri_spec, null, DataProvider.init, null);
	
	item = session.popNextOutboundItem();
	assert(FrameType.PING == item.frame.hd.type);
	item.free();
	Mem.free(item);
	
	item = session.popNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	item.free();
	Mem.free(item);
	
	assert(!session.popNextOutboundItem());
	
	/* Incoming stream does not affect the number of outgoing max concurrent streams. */
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	/* In-flight outgoing stream */
	session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);

	pri_spec = PrioritySpec(0, MAX_WEIGHT, 0);
	
	submitRequest(session, pri_spec, null, DataProvider.init, null);
	submitResponse(session, 1, null, DataProvider.init);
	
	item = session.popNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	assert(1 == item.frame.hd.stream_id);
	
	stream = session.getStream(1);
	
	stream.detachItem(session);
	
	item.free();
	Mem.free(item);
	
	assert(!session.popNextOutboundItem());
	
	session.remote_settings.max_concurrent_streams = 2;
	
	item = session.popNextOutboundItem();
	assert(FrameType.HEADERS == item.frame.hd.type);
	item.free();
	Mem.free(item);
	
	session.free();
	
	/* Check that push reply HEADERS are queued into ob_ss_pq */
	session = new Session(SERVER, *callbacks);
	session.remote_settings.max_concurrent_streams = 0;
	session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	assert(0 == submitHeaders(session, FrameFlags.END_STREAM, 2));
	assert(!session.popNextOutboundItem());
	assert(1 == session.ob_ss_pq.length);
	session.free();
}

void test_session_reply_fail() {
	Session session;
	Callbacks callbacks;
	DataProvider data_prd;
	MyUserData user_data = MyUserData(&session);

	callbacks.write_cb = toDelegate(&MyCallbacks.writeFailure);
	
	data_prd = &user_data.datasrc.readFixedLength;
	user_data.data_source_length = 4 * 1024;
	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	assert(0 == submitResponse(session, 1, null, data_prd));
	assert(ErrorCode.CALLBACK_FAILURE == session.send());
	session.free();
}

void test_session_max_concurrent_streams() {
	Session session;
	Callbacks callbacks;
	Frame frame;
	OutboundItem item;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	/* Check un-ACKed Setting.MAX_CONCURRENT_STREAMS */
	frame.headers = Headers(FrameFlags.END_HEADERS, 3, HeadersCategory.HEADERS, pri_spec_default, null);
	session.pending_local_max_concurrent_stream = 1;
	
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));

	item = session.ob_pq_top;
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(FrameError.REFUSED_STREAM == item.frame.rst_stream.error_code);
	
	assert(0 == session.send());
	
	/* Check ACKed Setting.MAX_CONCURRENT_STREAMS */
	session.local_settings.max_concurrent_streams = 1;
	frame.hd.stream_id = 5;
	
	assert(ErrorCode.IGN_HEADER_BLOCK == session.onRequestHeaders(frame));
	
	item = session.ob_pq_top;
	assert(FrameType.GOAWAY == item.frame.hd.type);
	assert(FrameError.PROTOCOL_ERROR == item.frame.goaway.error_code);
	
	frame.headers.free();
	session.free();
}

void test_session_stop_data_with_rst_stream() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	DataProvider data_prd;
	Frame frame;

	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	data_prd = &user_data.datasrc.readFixedLength;
	
	user_data.frame_send_cb_called = 0;
	user_data.data_source_length = DATA_PAYLOADLEN * 4;

	session = new Session(SERVER, *callbacks);
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	submitResponse(session, 1, null, data_prd);
	
	user_data.block_count = 2;
	/* Sends response HEADERS + DATA[0] */
	assert(0 == session.send());
	assert(FrameType.DATA == user_data.sent_frame_type);
	/* data for DATA[1] is read from data_prd but it is not sent */
	assert(user_data.data_source_length == DATA_PAYLOADLEN * 2);
	
	frame.rst_stream = RstStream(1, FrameError.CANCEL);
	assert(0 == session.onRstStream(frame));
	frame.rst_stream.free();
	
	/* Big enough number to send all DATA frames potentially. */
	user_data.block_count = 100;
	/* Nothing will be sent in the following call. */
	assert(0 == session.send());
	/* With RST_STREAM, stream is canceled and further DATA on that stream are not sent. */
	assert(user_data.data_source_length == DATA_PAYLOADLEN * 2);
	
	assert(!session.getStream(1));
	
	session.free();
}

void test_session_defer_data() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	DataProvider data_prd;
	OutboundItem item;
	Stream stream;
		
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	data_prd = toDelegate(&MyDataSource.readDeferred);
	
	user_data.frame_send_cb_called = 0;
	user_data.data_source_length = DATA_PAYLOADLEN * 4;

	session = new Session(SERVER, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	session.remote_window_size = 1 << 20;
	stream.remoteWindowSize = 1 << 20;
	
	submitResponse(session, 1, null, data_prd);
	
	user_data.block_count = 1;
	/* Sends HEADERS reply */
	assert(0 == session.send());
	assert(FrameType.HEADERS == user_data.sent_frame_type);
	/* No data is read */
	assert(user_data.data_source_length == DATA_PAYLOADLEN * 4);
	
	user_data.block_count = 1;
	submitPing(session, null);
	/* Sends PING */
	assert(0 == session.send());
	assert(FrameType.PING == user_data.sent_frame_type);
	
	/* Resume deferred DATA */
	assert(0 == session.resumeData(1));
	item = session.ob_da_pq.top();
	item.aux_data.data.data_prd = &user_data.datasrc.readFixedLength;
	user_data.block_count = 1;
	/* Reads 2 DATA chunks */
	assert(0 == session.send());
	assert(user_data.data_source_length == DATA_PAYLOADLEN * 2);
	
	/* Deferred again */
	item.aux_data.data.data_prd = toDelegate(&MyDataSource.readDeferred);
	/* This is needed since 16KiB block is already read and waiting to be
     sent. No read_callback invocation. */
	user_data.block_count = 1;
	assert(0 == session.send());
	assert(user_data.data_source_length == DATA_PAYLOADLEN * 2);
	
	/* Resume deferred DATA */
	assert(0 == session.resumeData(1));
	item = session.ob_da_pq.top();
	item.aux_data.data.data_prd = &user_data.datasrc.readFixedLength;
	user_data.block_count = 1;
	/* Reads 2 16KiB blocks */
	assert(0 == session.send());
	assert(user_data.data_source_length == 0);
	
	session.free();
}

void test_session_flow_control() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	DataProvider data_prd;
	Frame frame;
	Stream stream;
	int new_initial_window_size;
	Setting[1] iva;
	Frame settings_frame;
		
	callbacks.write_cb = &user_data.cb_handlers.writeFixedBytes;
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	data_prd = &user_data.datasrc.readFixedLength;
	
	user_data.frame_send_cb_called = 0;
	user_data.data_source_length = 128 * 1024;
	/* Use smaller emission count so that we can check outbound flow
     control window calculation is correct. */
	user_data.fixed_sendlen = 2 * 1024;
	
	/* Initial window size to 64KiB - 1*/
	session = new Session(CLIENT, *callbacks);
	/* Change it to 64KiB for easy calculation */
	session.remote_window_size = 64 * 1024;
	session.remote_settings.initial_window_size = 64 * 1024;
	
	submitRequest(session, pri_spec_default, null, data_prd, null);

	/* Sends 64KiB - 1 data */
	assert(0 == session.send());
	assert(64 * 1024 == user_data.data_source_length, "Wrong data source length: " ~ user_data.data_source_length.to!string);
	
	/* Back 32KiB in stream window */
	frame.window_update = WindowUpdate(FrameFlags.NONE, 1, 32 * 1024);
	session.onWindowUpdate(frame);
	
	/* Send nothing because of connection-level window */
	assert(0 == session.send());
	assert(64 * 1024 == user_data.data_source_length);
	
	/* Back 32KiB in connection-level window */
	frame.hd.stream_id = 0;
	session.onWindowUpdate(frame);
	
	/* Sends another 32KiB data */
	assert(0 == session.send());
	assert(32 * 1024 == user_data.data_source_length);
	
	stream = session.getStream(1);
	/* Change initial window size to 16KiB. The window_size becomes
     negative. */
	new_initial_window_size = 16 * 1024;
	stream.remoteWindowSize = new_initial_window_size - (session.remote_settings.initial_window_size - stream.remoteWindowSize);
	session.remote_settings.initial_window_size = new_initial_window_size;
	assert(-48 * 1024 == stream.remoteWindowSize);
	
	/* Back 48KiB to stream window */
	frame.hd.stream_id = 1;
	frame.window_update.window_size_increment = 48 * 1024;
	session.onWindowUpdate(frame);
	
	/* Nothing is sent because window_size is 0 */
	assert(0 == session.send());
	assert(32 * 1024 == user_data.data_source_length);
	
	/* Back 16KiB in stream window */
	frame.hd.stream_id = 1;
	frame.window_update.window_size_increment = 16 * 1024;
	session.onWindowUpdate(frame);
	
	/* Back 24KiB in connection-level window */
	frame.hd.stream_id = 0;
	frame.window_update.window_size_increment = 24 * 1024;
	session.onWindowUpdate(frame);
	
	/* Sends another 16KiB data */
	assert(0 == session.send());
	assert(16 * 1024 == user_data.data_source_length);
	
	/* Increase initial window size to 32KiB */
	iva[0].id = Setting.INITIAL_WINDOW_SIZE;
	iva[0].value = 32 * 1024;
	
	settings_frame.settings = Settings(FrameFlags.NONE, iva[0 .. 1].copy());
	session.onSettings(settings_frame, true);
	settings_frame.settings.free();
	
	/* Sends another 8KiB data */
	assert(0 == session.send());
	assert(8 * 1024 == user_data.data_source_length);
	
	/* Back 8KiB in connection-level window */
	frame.hd.stream_id = 0;
	frame.window_update.window_size_increment = 8 * 1024;
	session.onWindowUpdate(frame);
	
	/* Sends last 8KiB data */
	assert(0 == session.send());
	assert(0 == user_data.data_source_length);
	assert(session.getStream(1).shutFlags & ShutdownFlag.WR);
	
	frame.window_update.free();
	session.free();
}

void test_session_flow_control_data_recv() {
	Session session;
	Callbacks callbacks;
	ubyte[64 * 1024 + 16] data;
	FrameHeader hd;
	OutboundItem item;
	Stream stream;

	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	/* Initial window size to 64KiB - 1*/
	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	session.next_stream_id = 3;
	
	stream.shutdown(ShutdownFlag.WR);
	
	session.local_window_size = MAX_PAYLOADLEN;
	stream.localWindowSize = MAX_PAYLOADLEN;
	
	/* Create DATA frame */
	
	hd = FrameHeader(MAX_PAYLOADLEN, FrameType.DATA, FrameFlags.END_STREAM, 1);
	
	hd.pack(data[0 .. $]);
	assert(MAX_PAYLOADLEN + FRAME_HDLEN == session.memRecv(data[0 .. MAX_PAYLOADLEN + FRAME_HDLEN]));
	
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
	assert(MAX_PAYLOADLEN + FRAME_HDLEN == session.memRecv(data[0 .. MAX_PAYLOADLEN + FRAME_HDLEN]));
	
	item = session.getNextOutboundItem();
	assert(FrameType.WINDOW_UPDATE == item.frame.hd.type);
	assert(0 == item.frame.hd.stream_id);
	assert(MAX_PAYLOADLEN == item.frame.window_update.window_size_increment);
	
	session.free();
}

void test_session_flow_control_data_with_padding_recv() {
	Session session;
	Callbacks callbacks;
	ubyte[1024] data;
	FrameHeader hd;
	Stream stream;
	Options options;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	/* Disable auto window update so that we can check padding is consumed automatically */
	options.setNoAutoWindowUpdate(1);
	
	/* Initial window size to 64KiB - 1*/
	session = new Session(CLIENT, *callbacks, options);
	
	
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	/* Create DATA frame */
	
	hd = FrameHeader(357, FrameType.DATA, cast(FrameFlags)(FrameFlags.END_STREAM | FrameFlags.PADDED), 1);
	
	hd.pack(data[0 .. $]);
	/* Set Pad Length field, which itself is padding */
	data[FRAME_HDLEN] = 255;
	
	assert(cast(size_t)(FRAME_HDLEN + hd.length) == session.memRecv(data[0 .. FRAME_HDLEN + hd.length]));
	
	assert(cast(int)hd.length == session.recv_window_size);
	assert(cast(int)hd.length == stream.recvWindowSize);
	assert(256 == session.consumed_size);
	assert(256 == stream.consumedSize);
	
	session.free();
}

void test_session_data_read_temporal_failure() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	DataProvider data_prd;
	Frame frame;
	Stream stream;
	int data_size = 128 * 1024;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	data_prd = &user_data.datasrc.readFixedLength;
	
	user_data.data_source_length = data_size;
	
	/* Initial window size is 64KiB - 1 */
	session = new Session(CLIENT, *callbacks);
	submitRequest(session, pri_spec_default, null, data_prd, null);
	
	/* Sends INITIAL_WINDOW_SIZE data, assuming, it is equal to
     or smaller than INITIAL_CONNECTION_WINDOW_SIZE */
	assert(0 == session.send());
	assert(data_size - INITIAL_WINDOW_SIZE == user_data.data_source_length);
	
	stream = session.getStream(1);
	assert(stream.isDeferredByFlowControl());
	assert(FrameType.DATA == stream.item.frame.hd.type);
	
	stream.item.aux_data.data.data_prd = toDelegate(&MyDataSource.readRstStream);
	
	/* Back INITIAL_WINDOW_SIZE to both connection-level and
     stream-wise window */
	frame.window_update = WindowUpdate(FrameFlags.NONE, 1, INITIAL_WINDOW_SIZE);
	session.onWindowUpdate(frame);
	frame.hd.stream_id = 0;
	session.onWindowUpdate(frame);
	frame.window_update.free();

	/* Sending data will fail (soft fail) and treated as stream error */
	user_data.frame_send_cb_called = 0;
	assert(0 == session.send());
	assert(data_size - INITIAL_WINDOW_SIZE == user_data.data_source_length);
	
	assert(1 == user_data.frame_send_cb_called);
	assert(FrameType.RST_STREAM == user_data.sent_frame_type);
	
	data_prd = toDelegate(&MyDataSource.readFailure);

	submitRequest(session, pri_spec_default, null, data_prd, null);
	/* Sending data will fail (hard fail) and session tear down */
	auto send_ret = session.send();
	assert(ErrorCode.CALLBACK_FAILURE == send_ret, "send returned: "~ send_ret.to!string);
	
	session.free();
}

void test_session_on_stream_close() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Stream stream;

	callbacks.on_stream_exit_cb = &user_data.cb_handlers.onStreamExit;
	user_data.stream_close_cb_called = 0;
	
	session = new Session(CLIENT, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, &user_data);
	assert(stream);
	assert(session.closeStream(1, FrameError.NO_ERROR) == 0);
	assert(user_data.stream_close_cb_called == 1);
	session.free();
}

void test_session_on_ctrl_not_send() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Stream stream;
	
	callbacks.on_frame_failure_cb = &user_data.cb_handlers.onFrameFailure;
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	user_data.frame_not_send_cb_called = 0;
	user_data.not_sent_frame_type = FrameType.init;
	user_data.not_sent_error = ErrorCode.OK;
	
	session = new Session(SERVER, *callbacks);
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, &user_data);
	
	/* Check response HEADERS */
	/* Send bogus stream ID */
	assert(0 == submitHeaders(session, FrameFlags.END_STREAM, 3));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.STREAM_CLOSED == user_data.not_sent_error);
	
	user_data.frame_not_send_cb_called = 0;
	/* Shutdown transmission */
	stream.shutFlags = cast(ShutdownFlag)(stream.shutFlags | ShutdownFlag.WR);
	assert(0 == submitHeaders(session, FrameFlags.END_STREAM, 1));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.STREAM_SHUT_WR == user_data.not_sent_error);
	
	stream.shutFlags = ShutdownFlag.NONE;
	user_data.frame_not_send_cb_called = 0;
	/* Queue RST_STREAM */
	assert(0 == submitHeaders(session, FrameFlags.END_STREAM, 1));
	assert(0 == submitRstStream(session, 1, FrameError.INTERNAL_ERROR));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.STREAM_CLOSING == user_data.not_sent_error);
	
	session.free();
	
	/* Check request HEADERS */
	user_data.frame_not_send_cb_called = 0;
	session = new Session(CLIENT, *callbacks);
	/* Maximum Stream ID is reached */
	session.next_stream_id = (1u << 31) + 1;
	assert(ErrorCode.STREAM_ID_NOT_AVAILABLE == submitHeaders(session, FrameFlags.END_STREAM));
	
	user_data.frame_not_send_cb_called = 0;
	/* GOAWAY received */
	session.goaway_flags |= GoAwayFlags.RECV;
	session.next_stream_id = 9;
	
	assert(0 < submitHeaders(session, FrameFlags.END_STREAM));
	assert(0 == session.send());
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(ErrorCode.START_STREAM_NOT_ALLOWED == user_data.not_sent_error);

	session.free();
}

void test_session_get_outbound_queue_size() {
	Session session;
	Callbacks callbacks;

	session = new Session(CLIENT, *callbacks);
	assert(0 == session.getOutboundQueueSize());

	submitPing(session, null);
	assert(1 == session.getOutboundQueueSize());
	
	assert(0 == submitGoAway(session, 2, FrameError.NO_ERROR, null));
	assert(2 == session.getOutboundQueueSize());
	
	session.free();
}

void test_session_get_effective_local_window_size() {
	Session session;
	Callbacks callbacks;
	Stream stream;
	
	session = new Session(CLIENT, *callbacks);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENED, null);
	
	assert(INITIAL_CONNECTION_WINDOW_SIZE == session.getEffectiveLocalWindowSize());
	assert(0 == session.getEffectiveRecvDataLength());
	
	assert(INITIAL_WINDOW_SIZE == session.getStreamEffectiveLocalWindowSize(1));
	assert(0 == session.getStreamEffectiveRecvDataLength(1));
	
	/* Check connection flow control */
	session.recv_window_size = 100;
	submitWindowUpdate(session, 0, 1100);
	
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 1000 == session.getEffectiveLocalWindowSize());
	assert(0 == session.getEffectiveRecvDataLength());
	
	submitWindowUpdate(session, 0, -50);
	/* Now session.recv_window_size = -50 */
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 950 == session.getEffectiveLocalWindowSize());
	assert(0 == session.getEffectiveRecvDataLength());

	session.recv_window_size += 50;
	/* Now session.recv_window_size = 0 */
	submitWindowUpdate(session, 0, 100);
	assert(INITIAL_CONNECTION_WINDOW_SIZE + 1050 == session.getEffectiveLocalWindowSize());
	assert(50 == session.getEffectiveRecvDataLength());
	
	/* Check stream flow control */
	stream.recvWindowSize = 100;
	submitWindowUpdate(session, 1, 1100);
	
	assert(INITIAL_WINDOW_SIZE + 1000 == session.getStreamEffectiveLocalWindowSize(1));
	assert(0 == session.getStreamEffectiveRecvDataLength(1));

	submitWindowUpdate(session, 1, -50);
	/* Now stream.recvWindowSize = -50 */
	assert(INITIAL_WINDOW_SIZE + 950 == session.getStreamEffectiveLocalWindowSize(1));
	assert(0 == session.getStreamEffectiveRecvDataLength(1));
	
	stream.recvWindowSize += 50;
	/* Now stream.recvWindowSize = 0 */
	submitWindowUpdate(session, 1, 100);
	assert(INITIAL_WINDOW_SIZE + 1050 == session.getStreamEffectiveLocalWindowSize(1));
	assert(50 == session.getStreamEffectiveRecvDataLength(1));
	
	session.free();
}

void test_session_set_option() {
	Session session;
	Callbacks callbacks;
	Options options;

	options.setNoAutoWindowUpdate(1);
	
	
	session = new Session(CLIENT, *callbacks, options);
	
	assert(session.opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE);
	
	session.free();
	
	options.setPeerMaxConcurrentStreams(100);
	
	session = new Session(CLIENT, *callbacks, options);
	
	assert(100 == session.remote_settings.max_concurrent_streams);
	session.free();

}

void test_session_data_backoff_by_high_pri_frame() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	DataProvider data_prd;
	Stream stream;
	
	
	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	data_prd = &user_data.datasrc.readFixedLength;
	
	user_data.frame_send_cb_called = 0;
	user_data.data_source_length = DATA_PAYLOADLEN * 4;
	
	session = new Session(CLIENT, *callbacks);
	submitRequest(session, pri_spec_default, null, data_prd, null);
	
	session.remote_window_size = 1 << 20;
	
	user_data.block_count = 2;
	/* Sends request HEADERS + DATA[0] */
	assert(0 == session.send());
	
	stream = session.getStream(1);
	stream.remoteWindowSize = 1 << 20;
	
	assert(FrameType.DATA == user_data.sent_frame_type);
	/* data for DATA[1] is read from data_prd but it is not sent */
	assert(user_data.data_source_length == DATA_PAYLOADLEN * 2);
	
	submitPing(session, null);
	user_data.block_count = 2;
	/* Sends DATA[1] + PING, PING is interleaved in DATA sequence */
	assert(0 == session.send());
	assert(FrameType.PING == user_data.sent_frame_type);
	/* data for DATA[2] is read from data_prd but it is not sent */
	assert(user_data.data_source_length == DATA_PAYLOADLEN);
	
	user_data.block_count = 2;
	/* Sends DATA[2..3] */
	assert(0 == session.send());
	
	assert(stream.shutFlags & ShutdownFlag.WR);
	
	session.free();
}

private void check_session_read_data_with_padding(Buffers bufs, size_t datalen) {
	Session session;
	MyUserData user_data = MyUserData(&session);
	Callbacks callbacks;
	ubyte[] input;
	
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.on_data_chunk_cb = &user_data.cb_handlers.onDataChunk;
	session = new Session(SERVER, *callbacks);

	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	input = bufs.remove();
	
	user_data.frame_recv_cb_called = 0;
	user_data.data_chunk_len = 0;
	
	assert(cast(size_t)input.length == session.memRecv(input));
	
	assert(1 == user_data.frame_recv_cb_called);
	assert(datalen == user_data.data_chunk_len);
	
	Mem.free(input);
	session.free();
}

void test_session_pack_data_with_padding() {
	Session session;
	MyUserData user_data = MyUserData(&session);
	Callbacks callbacks;
	DataProvider data_prd;
	Frame* frame;
	int datalen = 55;
	
	
	callbacks.write_cb = &user_data.cb_handlers.writeWouldBlock;
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.select_padding_length_cb = &user_data.cb_handlers.selectPaddingLength;
	
	data_prd = &user_data.datasrc.readFixedLength;
	
	session = new Session(CLIENT, *callbacks);
	
	user_data.padlen = 63;
	
	submitRequest(session, pri_spec_default, null, data_prd, null);
	user_data.block_count = 1;
	user_data.data_source_length = datalen;
	/* Sends HEADERS */
	assert(0 == session.send());
	assert(FrameType.HEADERS == user_data.sent_frame_type);
	
	frame = &session.aob.item.frame;
	
	assert(user_data.padlen == frame.data.padlen);
	assert(frame.hd.flags & FrameFlags.PADDED);
	
	/* Check reception of this DATA frame */
	check_session_read_data_with_padding(session.aob.framebufs, datalen);
	
	session.free();
}

void test_session_pack_headers_with_padding() {
	Session session, sv_session;
	Accumulator acc;
	MyUserData user_data = MyUserData(&session);
	Callbacks callbacks;
	
	
	callbacks.write_cb = &user_data.cb_handlers.writeToAccumulator;
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.select_padding_length_cb = &user_data.cb_handlers.selectPaddingLength;
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	
	acc.length = 0;
	user_data.acc = &acc;
	
	session = new Session(CLIENT, *callbacks);
	sv_session = new Session(SERVER, *callbacks);
	
	user_data.padlen = 163;

	assert(1 == submitRequest(session, pri_spec_default, reqhf, DataProvider.init, null));
	assert(0 == session.send());
	
	assert(acc.length < MAX_PAYLOADLEN);
	user_data.frame_recv_cb_called = 0;
	assert(cast(int)acc.length == sv_session.memRecv(acc[]), "memRecv");
	assert(1 == user_data.frame_recv_cb_called, "frame_recv_cb_called");
	assert(!sv_session.getNextOutboundItem());
	
	sv_session.free();
	session.free();
}

void test_session_pack_settings_payload() {
	Setting[2] iva;
	ubyte[64] buf;
	int len;
	Setting[] resiva;

	iva[0].id = Setting.HEADER_TABLE_SIZE;
	iva[0].value = 1023;
	iva[1].id = Setting.INITIAL_WINDOW_SIZE;
	iva[1].value = 4095;
	
	len = packSettingsPayload(buf.ptr[0 .. 64], iva);
	assert(2 * FRAME_SETTINGS_ENTRY_LENGTH == len);
	Settings.unpack(resiva, buf[0 .. len]);
	assert(2 == resiva.length);
	assert(Setting.HEADER_TABLE_SIZE == resiva[0].id);
	assert(1023 == resiva[0].value);
	assert(Setting.INITIAL_WINDOW_SIZE == resiva[1].id);
	assert(4095 == resiva[1].value);
	
	Mem.free(resiva);
	
	len = packSettingsPayload(buf[0 .. 9] /* too small */, iva);
	assert(ErrorCode.INSUFF_BUFSIZE == len);
}

void checkStreamDependencySiblings(Stream stream, Stream dep_prev, Stream dep_next, Stream sib_prev, Stream sib_next) {
	assert(dep_prev == stream.depPrev);
	assert(dep_next == stream.depNext);
	assert(sib_prev == stream.sibPrev);
	assert(sib_next == stream.sibNext);
}

/* http2_stream_dep_add() and its families functions should be
   tested in http2_stream_test.c, but it is easier to use
   http2_session_open_stream().  Therefore, we test them here. */
void test_session_stream_dep_add() {
	Session session;
	Callbacks callbacks;
	Stream a, b, c, d, e;
	
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	
	c = openStreamWithDep(session, 5, a);
	b = openStreamWithDep(session, 3, a);
	d = openStreamWithDep(session, 7, c);
	
	/* a
   * |
   * b--c
   *    |
   *    d
   */
	
	assert(4 == a.subStreams);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(DEFAULT_WEIGHT * 2 == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, c);
	checkStreamDependencySiblings(c, null, d, b, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(4 == session.roots.num_streams);
	assert(a == session.roots.head);
	assert(!a.rootNext);
	
	e = openStreamWithDepExclusive(session, 9, a);
	
	/* a
   * |
   * e
   * |
   * b--c
   *    |
   *    d
   */
	
	assert(5 == a.subStreams);
	assert(4 == e.subStreams);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(DEFAULT_WEIGHT == a.sumDepWeight);
	assert(DEFAULT_WEIGHT * 2 == e.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, e, null, null);
	checkStreamDependencySiblings(e, a, b, null, null);
	checkStreamDependencySiblings(b, e, null, null, c);
	checkStreamDependencySiblings(c, null, d, b, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(5 == session.roots.num_streams);
	assert(a == session.roots.head);
	assert(!a.rootNext);
	
	session.free();
}

void test_session_stream_dep_remove() {
	Session session;
	Callbacks callbacks;
	Stream a, b, c, d, e, f;

	/* Remove root */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
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
	
	assert(1 == a.subStreams);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(0 == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, null, null, null);
	checkStreamDependencySiblings(b, null, null, null, null);
	checkStreamDependencySiblings(c, null, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(3 == session.roots.num_streams);
	assert(b == session.roots.head);
	assert(c == b.rootNext);
	assert(!c.rootNext);
	
	session.free();
	
	/* Remove left most stream */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
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
	
	assert(3 == a.subStreams, "substreams is: " ~ a.subStreams.to!string);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(DEFAULT_WEIGHT == a.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(0 == b.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, c, null, null);
	checkStreamDependencySiblings(b, null, null, null, null);
	checkStreamDependencySiblings(c, a, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	assert(3 == session.roots.num_streams);
	assert(a == session.roots.head);
	assert(!a.rootNext);
	
	session.free();
	
	/* Remove right most stream */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
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
	
	assert(3 == a.subStreams);
	assert(1 == b.subStreams);
	assert(1 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(DEFAULT_WEIGHT * 2 == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(0 == c.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, d, null, null);
	checkStreamDependencySiblings(b, null, null, d, null);
	checkStreamDependencySiblings(c, null, null, null, null);
	checkStreamDependencySiblings(d, a, null, null, b);
	
	session.free();
	
	/* Remove middle stream */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, a);
	e = openStreamWithDep(session, 9, c);
	f = openStreamWithDep(session, 11, c);
	
	/* a
   * |
   * d--c--b
   *    |
   *    f--e
   */
	
	assert(6 == a.subStreams);
	assert(1 == b.subStreams);
	assert(3 == c.subStreams);
	assert(1 == d.subStreams);
	assert(1 == e.subStreams);
	assert(1 == f.subStreams);
	
	assert(DEFAULT_WEIGHT * 3 == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT * 2 == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(0 == e.sumDepWeight);
	assert(0 == f.sumDepWeight);
	
	c.remove();
	
	/* becomes:
   * a
   * |
   * d--f--e--b
   */
	
	assert(5 == a.subStreams);
	assert(1 == b.subStreams);
	assert(1 == c.subStreams);
	assert(1 == d.subStreams);
	assert(1 == e.subStreams);
	assert(1 == f.subStreams);
	
	/* c's weight 16 is distributed evenly to e and f.  Each weight of e
     and f becomes 8. */
	assert(DEFAULT_WEIGHT * 2 + 8 * 2 == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(0 == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(0 == e.sumDepWeight);
	assert(0 == f.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, d, null, null);
	checkStreamDependencySiblings(b, null, null, e, null);
	checkStreamDependencySiblings(c, null, null, null, null);
	checkStreamDependencySiblings(e, null, null, f, b);
	checkStreamDependencySiblings(f, null, null, d, e);
	checkStreamDependencySiblings(d, a, null, null, f);
	
	session.free();
}

void test_session_stream_dep_add_subtree() {
	Session session;
	Callbacks callbacks;
	Stream a, b, c, d, e, f;
	
	
	
	/* dep_stream has dep_next */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
	e = openStream(session, 9);
	f = openStreamWithDep(session, 11, e);
	
	/* a         e
   * |         |
   * c--b      f
   * |
   * d
   */
	
	a.addSubtree(e, session);
	
	/* becomes
   * a
   * |
   * e--c--b
   * |  |
   * f  d
   */
	
	assert(6 == a.subStreams);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	assert(2 == e.subStreams);
	assert(1 == f.subStreams);
	
	assert(DEFAULT_WEIGHT * 3 == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(DEFAULT_WEIGHT == e.sumDepWeight);
	assert(0 == f.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, e, null, null);
	checkStreamDependencySiblings(b, null, null, c, null);
	checkStreamDependencySiblings(c, null, d, e, b);
	checkStreamDependencySiblings(d, c, null, null, null);
	checkStreamDependencySiblings(e, a, f, null, c);
	checkStreamDependencySiblings(f, e, null, null, null);
	
	session.free();
	
	/* dep_stream has dep_next and now we insert subtree */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
	e = openStream(session, 9);
	f = openStreamWithDep(session, 11, e);
	
	/* a         e
   * |         |
   * c--b      f
   * |
   * d
   */
	
	a.insertSubtree(e, session);
	
	/* becomes
   * a
   * |
   * e
   * |
   * f--c--b
   *    |
   *    d
   */
	
	assert(6 == a.subStreams);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	assert(5 == e.subStreams);
	assert(1 == f.subStreams);
	
	assert(DEFAULT_WEIGHT == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(DEFAULT_WEIGHT * 3 == e.sumDepWeight);
	assert(0 == f.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, e, null, null);
	checkStreamDependencySiblings(e, a, f, null, null);
	checkStreamDependencySiblings(f, e, null, null, c);
	checkStreamDependencySiblings(b, null, null, c, null);
	checkStreamDependencySiblings(c, null, d, f, b);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	session.free();
}

void test_session_stream_dep_remove_subtree() {
	Session session;
	Callbacks callbacks;
	Stream a, b, c, d, e;

	/* Remove left most stream */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	c.removeSubtree();
	
	/* becomes
   * a  c
   * |  |
   * b  d
   */
	
	assert(2 == a.subStreams);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(DEFAULT_WEIGHT == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, null);
	checkStreamDependencySiblings(c, null, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	session.free();
	
	/* Remove right most stream */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	b.removeSubtree();
	
	/* becomes
   * a  b
   * |
   * c
   * |
   * d
   */
	
	assert(3 == a.subStreams);
	assert(1 == b.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(DEFAULT_WEIGHT == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, c, null, null);
	checkStreamDependencySiblings(c, a, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	checkStreamDependencySiblings(b, null, null, null, null);
	
	session.free();
	
	/* Remove middle stream */
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	e = openStreamWithDep(session, 9, a);
	c = openStreamWithDep(session, 5, a);
	b = openStreamWithDep(session, 3, a);
	d = openStreamWithDep(session, 7, c);
	
	/* a
   * |
   * b--c--e
   *    |
   *    d
   */
	
	c.removeSubtree();
	
	/* becomes
   * a     c
   * |     |
   * b--e  d
   */
	
	assert(3 == a.subStreams);
	assert(1 == b.subStreams);
	assert(1 == e.subStreams);
	assert(2 == c.subStreams);
	assert(1 == d.subStreams);
	
	assert(DEFAULT_WEIGHT * 2 == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(0 == e.sumDepWeight);
	
	checkStreamDependencySiblings(a, null, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, e);
	checkStreamDependencySiblings(e, null, null, b, null);
	checkStreamDependencySiblings(c, null, d, null, null);
	checkStreamDependencySiblings(d, c, null, null, null);
	
	session.free();
}

void test_session_stream_dep_make_head_root() {
	Session session;
	Callbacks callbacks;
	Stream a, b, c, d;

	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	
	c = openStream(session, 5);
	
	/* a     c
   * |
   * b
   */
	
	c.removeSubtree();
	c.makeTopmostRoot(session);
	
	/*
   * c
   * |
   * a
   * |
   * b
   */
	
	assert(3 == c.subStreams);
	assert(2 == a.subStreams);
	assert(1 == b.subStreams);
	
	assert(DEFAULT_WEIGHT == c.sumDepWeight);
	assert(DEFAULT_WEIGHT == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	
	checkStreamDependencySiblings(c, null, a, null, null);
	checkStreamDependencySiblings(a, c, b, null, null);
	checkStreamDependencySiblings(b, a, null, null, null);
	
	session.free();
	
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	
	b = openStream(session, 3);
	
	c = openStream(session, 5);
	
	/*
   * a  b   c
   */
	
	c.removeSubtree();
	c.makeTopmostRoot(session);
	
	/*
   * c
   * |
   * b--a
   */
	
	assert(3 == c.subStreams);
	assert(1 == a.subStreams);
	assert(1 == b.subStreams);
	
	assert(DEFAULT_WEIGHT * 2 == c.sumDepWeight);
	assert(0 == b.sumDepWeight);
	assert(0 == a.sumDepWeight);
	
	checkStreamDependencySiblings(c, null, b, null, null);
	checkStreamDependencySiblings(b, c, null, null, a);
	checkStreamDependencySiblings(a, null, null, b, null);
	
	session.free();
	
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	
	c = openStream(session, 5);
	d = openStreamWithDep(session, 7, c);
	
	/* a     c
   * |     |
   * b     d
   */
	
	c.removeSubtree();
	c.makeTopmostRoot(session);
	
	/*
   * c
   * |
   * a--d
   * |
   * b
   */
	
	assert(4 == c.subStreams);
	assert(1 == d.subStreams);
	assert(2 == a.subStreams);
	assert(1 == b.subStreams);
	
	assert(DEFAULT_WEIGHT * 2 == c.sumDepWeight);
	assert(0 == d.sumDepWeight);
	assert(DEFAULT_WEIGHT == a.sumDepWeight);
	assert(0 == b.sumDepWeight);
	
	checkStreamDependencySiblings(c, null, a, null, null);
	checkStreamDependencySiblings(d, null, null, a, null);
	checkStreamDependencySiblings(a, c, b, null, d);
	checkStreamDependencySiblings(b, a, null, null, null);
	
	session.free();
}

void test_session_stream_attach_item() {
	Session session;
	Callbacks callbacks;
	Stream a, b, c, d;
	OutboundItem da, db, dc, dd;
	
	
	
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
	/* a
   * |
   * c--b
   * |
   * d
   */
	
	db = createDataOutboundItem();
	
	b.attachItem(db, session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	
	assert(16 == b.effectiveWeight);
	
	assert(16 == a.sumNorestWeight);
	
	assert(1 == db.queued);
	
	dc = createDataOutboundItem();
	
	c.attachItem(dc, session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.TOP == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	
	assert(16 * 16 / 32 == b.effectiveWeight);
	assert(16 * 16 / 32 == c.effectiveWeight);
	
	assert(32 == a.sumNorestWeight);
	
	assert(1 == dc.queued);
	
	da = createDataOutboundItem();
	
	a.attachItem(da, session);
	
	assert(StreamDPRI.TOP == a.dpri);
	assert(StreamDPRI.REST == b.dpri);
	assert(StreamDPRI.REST == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	
	assert(16 == a.effectiveWeight);
	
	assert(1 == da.queued);
	
	a.detachItem(session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.TOP == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	
	assert(16 * 16 / 32 == b.effectiveWeight);
	assert(16 * 16 / 32 == c.effectiveWeight);
	
	dd = createDataOutboundItem();
	
	d.attachItem(dd, session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.TOP == c.dpri);
	assert(StreamDPRI.REST == d.dpri);
	
	assert(16 * 16 / 32 == b.effectiveWeight);
	assert(16 * 16 / 32 == c.effectiveWeight);
	
	assert(0 == dd.queued);
	
	c.detachItem(session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.REST == d.dpri);
	
	assert(16 * 16 / 16 == b.effectiveWeight);
	
	assert(0 == dd.queued);
	
	b.detachItem(session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.NO_ITEM == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.TOP == d.dpri);
	
	assert(16 * 16 / 16 == d.effectiveWeight);
	
	assert(1 == dd.queued);
	
	session.free();
}

void test_session_stream_attach_item_subtree() {
	Session session;
	Callbacks callbacks;
	Stream a, b, c, d, e, f;
	OutboundItem db, dd, de;
	
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	b = openStreamWithDep(session, 3, a);
	c = openStreamWithDep(session, 5, a);
	d = openStreamWithDep(session, 7, c);
	
	e = openStream(session, 9);
	f = openStreamWithDep(session, 11, e);
	/*
   * a        e
   * |        |
   * c--b     f
   * |
   * d
   */
	
	de = createDataOutboundItem();
	
	e.attachItem(de, session);
	
	db = createDataOutboundItem();
	
	b.attachItem(db, session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	assert(StreamDPRI.TOP == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	assert(16 == b.effectiveWeight);
	assert(16 == e.effectiveWeight);
	
	/* Insert subtree e under a */
	
	e.removeSubtree();
	a.insertSubtree(e, session);
	
	/*
   * a
   * |
   * e
   * |
   * f--c--b
   *    |
   *    d
   */
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.REST == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	assert(StreamDPRI.TOP == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	assert(16 == e.effectiveWeight);
	
	/* Remove subtree b */
	
	b.removeSubtree();
	
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
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	assert(StreamDPRI.TOP == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	assert(16 == b.effectiveWeight);
	assert(16 == e.effectiveWeight);
	
	/* Remove subtree a */
	
	a.removeSubtree();
	
	a.makeRoot(session);
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	assert(StreamDPRI.TOP == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	/* Remove subtree c */
	
	c.removeSubtree();
	
	c.makeRoot(session);
	
	/*
   * a       b     c
   * |             |
   * e             d
   * |
   * f
   */
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.NO_ITEM == d.dpri);
	assert(StreamDPRI.TOP == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	dd = createDataOutboundItem();
	
	d.attachItem(dd, session);
	
	/* Add subtree c to a */
	
	c.removeSubtree();
	a.addSubtree(c, session);
	
	/*
   * a       b
   * |
   * c--e
   * |  |
   * d  f
   */
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.REST == d.dpri);
	assert(StreamDPRI.TOP == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	assert(16 == b.effectiveWeight);
	assert(16 * 16 / 16 == e.effectiveWeight);
	
	assert(32 == a.sumNorestWeight);
	assert(16 == c.sumNorestWeight);
	
	/* Insert b under a */
	
	b.removeSubtree();
	a.insertSubtree(b, session);
	
	/*
   * a
   * |
   * b
   * |
   * e--c
   * |  |
   * f  d
   */
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.REST == d.dpri);
	assert(StreamDPRI.REST == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	assert(16 == b.effectiveWeight);
	
	assert(16 == a.sumNorestWeight);
	assert(0 == b.sumNorestWeight);
	
	/* Remove subtree b */
	
	b.removeSubtree();
	b.makeRoot(session);
	
	/*
   * b       a
   * |
   * e--c
   * |  |
   * f  d
   */
	
	assert(StreamDPRI.NO_ITEM == a.dpri);
	assert(StreamDPRI.TOP == b.dpri);
	assert(StreamDPRI.NO_ITEM == c.dpri);
	assert(StreamDPRI.REST == d.dpri);
	assert(StreamDPRI.REST == e.dpri);
	assert(StreamDPRI.NO_ITEM == f.dpri);
	
	assert(0 == a.sumNorestWeight);
	assert(0 == b.sumNorestWeight);
	
	session.free();
}

void test_session_keep_closed_stream() {
	Session session;
	Callbacks callbacks;
	const size_t max_concurrent_streams = 5;
	Setting iv = Setting(Setting.MAX_CONCURRENT_STREAMS, max_concurrent_streams);
	size_t i;
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	
	submitSettings(session, (&iv)[0 .. 1]);
	
	for (i = 0; i < max_concurrent_streams; ++i) {
		openStream(session, cast(int)i * 2 + 1);
	}
	
	assert(0 == session.num_closed_streams);
	
	session.closeStream(1, FrameError.NO_ERROR);
	
	assert(1 == session.num_closed_streams);
	assert(1 == session.closed_stream_tail.id);
	assert(session.closed_stream_tail == session.closed_stream_head);
	
	session.closeStream(5, FrameError.NO_ERROR);
	
	assert(2 == session.num_closed_streams);
	assert(5 == session.closed_stream_tail.id);
	assert(1 == session.closed_stream_head.id);
	assert(session.closed_stream_head == session.closed_stream_tail.closedPrev);
	assert(!session.closed_stream_tail.closedNext);
	assert(session.closed_stream_tail == session.closed_stream_head.closedNext);
	assert(!session.closed_stream_head.closedPrev);
	
	openStream(session, 11);
	
	assert(1 == session.num_closed_streams);
	assert(5 == session.closed_stream_tail.id);
	assert(session.closed_stream_tail == session.closed_stream_head);
	assert(!session.closed_stream_head.closedPrev);
	assert(!session.closed_stream_head.closedNext);
	
	openStream(session, 13);
	
	assert(0 == session.num_closed_streams);
	assert(!session.closed_stream_tail);
	assert(!session.closed_stream_head);
	
	session.free();
}

void test_session_keep_idle_stream() {
	Session session;
	Callbacks callbacks;
	const size_t max_concurrent_streams = 1;
	Setting iv = Setting(Setting.MAX_CONCURRENT_STREAMS, max_concurrent_streams);
	int i;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	
	submitSettings(session, (&iv)[0 .. 1]);
	
	/* We at least allow 2 idle streams even if max concurrent streams
     is very low. */
	for (i = 0; i < 2; ++i) {
		session.openStream(i * 2 + 1, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	}

	assert(2 == session.num_idle_streams);
	
	assert(1 == session.idle_stream_head.id);
	assert(3 == session.idle_stream_tail.id);
	
	session.openStream(5, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	
	assert(2 == session.num_idle_streams);
	
	assert(3 == session.idle_stream_head.id);
	assert(5 == session.idle_stream_tail.id);
	
	session.free();
}

void test_session_detach_idle_stream() {
	Session session;
	Callbacks callbacks;
	int i;
	Stream stream;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	
	for (i = 1; i <= 3; ++i) {
		session.openStream(i, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	}
	
	assert(3 == session.num_idle_streams);
	
	/* Detach middle stream */
	stream = session.getStreamRaw(2);
	
	assert(session.idle_stream_head == stream.closedPrev);
	assert(session.idle_stream_tail == stream.closedNext);
	assert(stream == session.idle_stream_head.closedNext);
	assert(stream == session.idle_stream_tail.closedPrev);
	
	session.detachIdleStream(stream);
	
	assert(2 == session.num_idle_streams);
	
	assert(!stream.closedPrev);
	assert(!stream.closedNext);
	
	assert(session.idle_stream_head == session.idle_stream_tail.closedPrev);
	assert(session.idle_stream_tail == session.idle_stream_head.closedNext);
	
	/* Detach head stream */
	stream = session.idle_stream_head;
	
	session.detachIdleStream(stream);
	
	assert(1 == session.num_idle_streams);
	
	assert(session.idle_stream_head == session.idle_stream_tail);
	assert(!session.idle_stream_head.closedPrev);
	assert(!session.idle_stream_head.closedNext);
	
	/* Detach last stream */
	
	stream = session.idle_stream_head;
	
	session.detachIdleStream(stream);
	
	assert(0 == session.num_idle_streams);
	
	assert(!session.idle_stream_head);
	assert(!session.idle_stream_tail);
	
	for (i = 4; i <= 5; ++i) {
		session.openStream(i, StreamFlags.NONE, pri_spec_default, StreamState.IDLE, null);
	}
	
	assert(2 == session.num_idle_streams);
	
	/* Detach tail stream */
	
	stream = session.idle_stream_tail;
	
	session.detachIdleStream(stream);
	
	assert(1 == session.num_idle_streams);
	
	assert(session.idle_stream_head == session.idle_stream_tail);
	assert(!session.idle_stream_head.closedPrev);
	assert(!session.idle_stream_head.closedNext);
	
	session.free();
}

void test_session_large_dep_tree() {
	Session session;
	Callbacks callbacks;
	size_t i;
	Stream dep_stream;
	Stream root_stream;
	int stream_id;
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	
	stream_id = 1;
	for (i = 0; i < MAX_DEP_TREE_LENGTH; ++i) {
		dep_stream = session.openStreamWithDep(stream_id, dep_stream);
		stream_id += 2;
	}
	
	root_stream = session.getStream(1);
	
	/* Check that last dep_stream must be part of tree */
	assert(root_stream.subtreeContains(dep_stream));
	
	dep_stream = session.openStreamWithDep(stream_id, dep_stream);
	
	/* We exceeded MAX_DEP_TREE_LENGTH limit.  dep_stream is now
     root node and has no descendants. */
	assert(!root_stream.subtreeContains(dep_stream));
	assert(dep_stream.inDepTree());
	
	session.free();
}

void test_session_graceful_shutdown() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.on_stream_exit_cb = &user_data.cb_handlers.onStreamExit;
	
	session = new Session(SERVER, *callbacks);
	
	openStream(session, 301);
	openStream(session, 302);
	openStream(session, 309);
	openStream(session, 311);
	openStream(session, 319);
	
	assert(0 == submitShutdownNotice(session));
	
	user_data.frame_send_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == user_data.frame_send_cb_called);
	assert((1u << 31) - 1 == session.local_last_stream_id);
	
	assert(0 == submitGoAway(session, 311, FrameError.NO_ERROR, null));
	
	user_data.frame_send_cb_called = 0;
	user_data.stream_close_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == user_data.frame_send_cb_called);
	assert(311 == session.local_last_stream_id);
	assert(1 == user_data.stream_close_cb_called);

	assert(0 == session.terminateSession(301, FrameError.NO_ERROR));
	
	user_data.frame_send_cb_called = 0;
	user_data.stream_close_cb_called = 0;
	
	assert(0 == session.send());
	
	assert(1 == user_data.frame_send_cb_called);
	assert(301 == session.local_last_stream_id);
	assert(2 == user_data.stream_close_cb_called);
	
	assert(session.getStream(301));
	assert(session.getStream(302));
	assert(!session.getStream(309));
	assert(!session.getStream(311));
	assert(!session.getStream(319));
	
	session.free();
}

void test_session_on_header_temporal_failure() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	Buffers bufs = framePackBuffers();
	Buffer* buf;
	Deflater deflater;
	HeaderField[] hfa = [HeaderField("alpha", "bravo"), HeaderField("charlie", "delta")];
	HeaderField[] hfa_copy;
	size_t hdpos;
	int rv;
	Frame frame;
	FrameHeader hd;
	OutboundItem item;
		
	callbacks.on_header_field_cb = &user_data.cb_handlers.onHeaderFieldRstStream;
	
	session = new Session(SERVER, *callbacks);
		
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);

	hfa_copy = reqhf.copy();
	
	frame.headers = Headers(FrameFlags.END_STREAM, 1, HeadersCategory.REQUEST, pri_spec_default, hfa_copy);
	frame.headers.pack(bufs, deflater);
	frame.headers.free();
	
	/* We are going to create CONTINUATION.  First serialize header
     block, and then frame header. */
	hdpos = bufs.length;
	
	buf = &bufs.head.buf;
	buf.last += FRAME_HDLEN;
	
	deflater.deflate(bufs, hfa[1 .. 2]);
	
	hd = FrameHeader(cast(int)(bufs.length - hdpos - FRAME_HDLEN), FrameType.CONTINUATION, FrameFlags.END_HEADERS, 1);
	
	hd.pack(buf.pos[hdpos .. buf.available]);
	
	rv = session.memRecv((*buf)[]);
	
	assert(rv == bufs.length);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	/* Make sure no header decompression error occurred */
	assert(GoAwayFlags.NONE == session.goaway_flags);
	
	bufs.free();
	
	deflater.free();
	session.free();
}

void test_session_read_client_preface() {
	Session session;
	Callbacks callbacks;
	Options options;
	int rv;
	Frame ping_frame;
	ubyte[16] buf;

	options.setRecvClientPreface(1);
	
	/* Check success case */
	session = new Session(SERVER, *callbacks, options);
	
	assert(session.opt_flags & OptionsMask.RECV_CLIENT_PREFACE);
	
	rv = session.memRecv(cast(ubyte[])CLIENT_CONNECTION_PREFACE);
	
	assert(rv == CLIENT_CONNECTION_PREFACE.length);
	assert(InboundState.READ_FIRST_SETTINGS == session.iframe.state);
	
	/* Receiving PING is error because we want SETTINGS. */
	ping_frame.ping = Ping(FrameFlags.NONE, null);
	
	ping_frame.ping.hd.pack(buf[0 .. $]);
	
	rv = session.memRecv(buf[0 .. FRAME_HDLEN]);
	assert(FRAME_HDLEN == rv);
	assert(InboundState.IGN_ALL == session.iframe.state);
	assert(0 == session.iframe.payloadleft);
	
	ping_frame.ping.free();
	
	session.free();
	
	/* Check bad case */
	session = new Session(SERVER, *callbacks, options);
	
	/* Feed preface with one byte less */
	rv = session.memRecv(cast(ubyte[])CLIENT_CONNECTION_PREFACE[0 .. $-1]);
	
	assert(rv == CLIENT_CONNECTION_PREFACE.length - 1);
	assert(InboundState.READ_CLIENT_PREFACE == session.iframe.state);
	assert(1 == session.iframe.payloadleft);
	
	rv = session.memRecv(cast(ubyte[])"\0");
	
	assert(ErrorCode.BAD_PREFACE == rv);
	
	session.free();	
}

void test_session_delete_data_item() {
	Session session;
	Callbacks callbacks;
	Stream a;
	DataProvider prd = toDelegate(&MyDataSource.readFailure);
		
	session = new Session(SERVER, *callbacks);
	
	a = openStream(session, 1);
	openStreamWithDep(session, 3, a);
	
	/* We don't care about these members, since we won't send data */
	
	/* This data item will be marked as TOP */
	assert(0 == submitData(session, FrameFlags.NONE, 1, prd));
	/* This data item will be marked as REST */
	assert(0 == submitData(session, FrameFlags.NONE, 3, prd));
	
	session.free();
}

void test_session_open_idle_stream() {
	Session session;
	Callbacks callbacks;
	Stream stream;
	Stream opened_stream;
	PrioritySpec pri_spec;
	Frame frame;
	
	session = new Session(SERVER, *callbacks);
	
	pri_spec = PrioritySpec(0, 3, 0);
	
	frame.priority = Priority(1, pri_spec);
	
	assert(0 == session.onPriority(frame));
	
	stream = session.getStreamRaw(1);
	
	assert(StreamState.IDLE == stream.state);
	assert(!stream.closedPrev);
	assert(!stream.closedNext);
	assert(1 == session.num_idle_streams);
	assert(session.idle_stream_head == stream);
	assert(session.idle_stream_tail == stream);

	opened_stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	assert(stream == opened_stream);
	assert(StreamState.OPENING == stream.state);
	assert(0 == session.num_idle_streams);
	assert(!session.idle_stream_head);
	assert(!session.idle_stream_tail);
	
	frame.priority.free();
	
	session.free();
}

void test_session_cancel_reserved_remote() {
	Session session;
	Callbacks callbacks;
	Stream stream;
	Frame frame;
	HeaderField[] hfa;
	
	Deflater deflater;

	Buffers bufs = framePackBuffers();
	int rv;	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	stream = session.openStream(2, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	session.last_recv_stream_id = 2;
	
	submitRstStream(session, 2, FrameError.CANCEL);
	
	assert(StreamState.CLOSING == stream.state);
	
	assert(0 == session.send());
	
	hfa = reshf.copy();
	
	frame.headers = Headers(FrameFlags.END_HEADERS, 2, HeadersCategory.PUSH_RESPONSE, pri_spec_default, hfa);
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf[]);

	assert(bufs.head.buf.length == rv);
	
	/* stream is not dangling, so assign null */
	stream = null;
	
	/* No RST_STREAM or GOAWAY is generated since stream should be in
     StreamState.CLOSING and push response should be ignored. */
	assert(0 == session.ob_pq.length);
	
	/* Check that we can receive push response HEADERS while RST_STREAM
     is just queued. */
	session.openStream(4, StreamFlags.NONE, pri_spec_default, StreamState.RESERVED, null);
	
	session.last_recv_stream_id = 4;
	
	submitRstStream(session, 2, FrameError.CANCEL);
	
	bufs.reset();
	
	frame.hd.stream_id = 4;
	rv = frame.headers.pack(bufs, deflater);
	
	assert(0 == rv);
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(1 == session.ob_pq.length);
	
	frame.headers.free();
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_session_reset_pending_headers() {
	Session session;
	Callbacks callbacks;
	Stream stream;
	int stream_id;
	MyUserData user_data = MyUserData(&session);
		
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_frame_sent_cb = &user_data.cb_handlers.onFrameSent;
	callbacks.on_frame_failure_cb = &user_data.cb_handlers.onFrameFailure;
	callbacks.on_stream_exit_cb = &user_data.cb_handlers.onStreamExit;
	
	session = new Session(CLIENT, *callbacks);
	
	stream_id = submitRequest(session, pri_spec_default, null, DataProvider.init, null);
	assert(stream_id >= 1);
	
	submitRstStream(session, stream_id, FrameError.CANCEL);
	
	session.remote_settings.max_concurrent_streams = 0;
	
	/* RST_STREAM cancels pending HEADERS and is not actually sent. */
	user_data.frame_send_cb_called = 0;
	assert(0 == session.send());
	
	assert(0 == user_data.frame_send_cb_called);
	
	stream = session.getStream(stream_id);
	
	assert(!stream);
	
	/* See HEADERS is not sent.  on_stream_close is called just like
     transmission failure. */
	session.remote_settings.max_concurrent_streams = 1;
	
	user_data.frame_not_send_cb_called = 0;
	user_data.stream_close_error_code = FrameError.NO_ERROR;
	assert(0 == session.send());
	
	assert(1 == user_data.frame_not_send_cb_called);
	assert(FrameType.HEADERS == user_data.not_sent_frame_type);
	assert(FrameError.CANCEL == user_data.stream_close_error_code);
	
	stream = session.getStream(stream_id);
	
	assert(!stream);
	
	session.free();
}


void test_session_send_data_callback() {
	Session session;
	Callbacks callbacks;
	Accumulator acc;
	MyUserData user_data = MyUserData(&session);
	FrameHeader hd;

	callbacks.write_cb = &user_data.cb_handlers.writeToAccumulator;
	callbacks.write_data_cb = &user_data.cb_handlers.writeData;
	DataProvider data_prd = &user_data.datasrc.readNoCopy;

	acc.length = 0;
	user_data.acc = &acc;

	user_data.data_source_length = DATA_PAYLOADLEN * 2;

	session = new Session(CLIENT, *callbacks);

	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);

	submitData(session, FrameFlags.END_STREAM, 1, data_prd);

	assert(0 == session.send());
	assert((FRAME_HDLEN + DATA_PAYLOADLEN) * 2 == acc.length, "Accumulator length was: " ~ acc.length.to!string);

	hd.unpack(acc[]);

	assert(16384 == hd.length);
	assert(FrameType.DATA == hd.type);
	assert(FrameFlags.NONE == hd.flags, "Frame flag was: " ~ hd.flags.to!string);

	hd.unpack(acc.buf[FRAME_HDLEN + hd.length .. acc.buf.length]);

	assert(16384 == hd.length);
	assert(FrameType.DATA == hd.type);
	assert(FrameFlags.END_STREAM == hd.flags);

	session.free();
}

private void check_http_recv_headers_fail(Session session, ref MyUserData user_data, ref Deflater deflater, int stream_id, int stream_state, in HeaderField[] hfa) 
{
	
	int rv;
	OutboundItem item;
	Buffers bufs = framePackBuffers();
	if (stream_state != -1) 
		session.openStream(stream_id, StreamFlags.NONE, pri_spec_default, cast(StreamState)stream_state, null);
	
	packHeaders(bufs, deflater, stream_id, FrameFlags.END_HEADERS, hfa);
	
	user_data.invalid_frame_recv_cb_called = 0;
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(1 == user_data.invalid_frame_recv_cb_called, user_data.invalid_frame_recv_cb_called.to!string);
	assert(0 == session.send());
	
	bufs.free();
}


private void check_http_recv_headers_ok(Session session, ref MyUserData user_data, ref Deflater deflater, int stream_id, int stream_state, in HeaderField[] hfa) 
{
	
	int rv;
	Buffers bufs = framePackBuffers();

	if (stream_state != -1) 
		session.openStream(stream_id, StreamFlags.NONE, pri_spec_default, cast(StreamState)stream_state, null);
	
	packHeaders(bufs, deflater, stream_id, FrameFlags.END_HEADERS, hfa);
	
	user_data.frame_recv_cb_called = 0;
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);	

	assert(!session.getNextOutboundItem());

	assert(1 == user_data.frame_recv_cb_called);
	
	bufs.free();
}

void test_http_mandatory_headers() 
{
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);
	callbacks.on_invalid_frame_cb = &user_data.cb_handlers.onInvalidFrame;
	callbacks.on_frame_cb = &user_data.cb_handlers.onFrame;
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
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
	const HeaderField[] badauthority_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":method", "POST"),
		HeaderField(":authority", "\x0d\x0alocalhost"), HeaderField(":path", "/")];
	const HeaderField[] badhdbtw_reqhf = [
		HeaderField(":scheme", "https"), 		HeaderField(":method", "GET"), 
		HeaderField("foo", "\x0d\x0a"), HeaderField(":authority", "localhost"),
		HeaderField(":path", "/")];
	const HeaderField[] asteriskget1_reqhf = [
		HeaderField(":path", "*"), HeaderField(":scheme", "https"),
		HeaderField(":authority", "localhost"), HeaderField(":method", "GET")];
	const HeaderField[] asteriskget2_reqhf = [
		HeaderField(":scheme", "https"), HeaderField(":authority", "localhost"),
		HeaderField(":method", "GET"), HeaderField(":path", "*")];
	const HeaderField[] asteriskoptions1_reqhf = [
		HeaderField(":path", "*"), HeaderField(":scheme", "https"),
		HeaderField(":authority", "localhost"), HeaderField(":method", "OPTIONS")];
	const HeaderField[] asteriskoptions2_reqhf = [
		HeaderField(":scheme", "https"), HeaderField(":authority", "localhost"),
		HeaderField(":method", "OPTIONS"), HeaderField(":path", "*")];
		
	session = new Session(CLIENT, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* response header lacks :status */
	check_http_recv_headers_fail(session, user_data, deflater, 1, StreamState.OPENING, nostatus_reshf);
	
	/* response header has 2 :status */
	check_http_recv_headers_fail(session, user_data, deflater, 3, StreamState.OPENING, dupstatus_reshf);
	
	/* response header has bad pseudo header :scheme */
	check_http_recv_headers_fail(session, user_data, deflater, 5, StreamState.OPENING, badpseudo_reshf);
	
	/* response header has :status after regular header field */
	check_http_recv_headers_fail(session, user_data, deflater, 7, StreamState.OPENING, latepseudo_reshf);
	
	/* response header has bad status code */
	check_http_recv_headers_fail(session, user_data, deflater, 9, StreamState.OPENING, badstatus_reshf);
	
	/* response header has bad content-length */
	check_http_recv_headers_fail(session, user_data, deflater, 11, StreamState.OPENING, badcl_reshf);
	
	/* response header has multiple content-length */
	check_http_recv_headers_fail(session, user_data, deflater, 13, StreamState.OPENING, dupcl_reshf);
	
	/* response header has disallowed header field */
	check_http_recv_headers_fail(session, user_data, deflater, 15, StreamState.OPENING, badhd_reshf);
	
	deflater.free();
	
	session.free();
	
	/* check server side */
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* request header has no :path */
	check_http_recv_headers_fail(session, user_data, deflater, 1, -1, nopath_reqhf);
	
	/* request header has CONNECT method, but followed by :path */
	check_http_recv_headers_fail(session, user_data, deflater, 3, -1, earlyconnect_reqhf);
	
	/* request header has CONNECT method following :path */
	check_http_recv_headers_fail(session, user_data, deflater, 5, -1, lateconnect_reqhf);
	
	/* request header has multiple :path */
	check_http_recv_headers_fail(session, user_data, deflater, 7, -1, duppath_reqhf);
	
	/* request header has bad content-length */
	check_http_recv_headers_fail(session, user_data, deflater, 9, -1, badcl_reqhf);
	
	/* request header has multiple content-length */
	check_http_recv_headers_fail(session, user_data, deflater, 11, -1, dupcl_reqhf);

	/* request header has disallowed header field */
	//check_http_recv_headers_fail(session, user_data, deflater, 13, -1, badhd_reqhf);

	/* request header has :authority header field containing illegal characters */
	check_http_recv_headers_fail(session, user_data, deflater, 15, -1, badauthority_reqhf);

	/*  request header has regular header field containing illegal 
	 * character before all mandatory header fields are seen. */
	check_http_recv_headers_fail(session, user_data, deflater, 17, -1, badhdbtw_reqhf);

	/* request header has "*" in :path header field while method is GET.
     :path is received before :method */
	check_http_recv_headers_fail(session, user_data, deflater, 19, -1, asteriskget1_reqhf);
	
	/* request header has "*" in :path header field while method is GET.
     :method is received before :path */
	check_http_recv_headers_fail(session, user_data, deflater, 21, -1, asteriskget2_reqhf);
	
	/* OPTIONS method can include "*" in :path header field.  :path is
     received before :method. */
	check_http_recv_headers_ok(session, user_data, deflater, 23, -1, asteriskoptions1_reqhf);
	
	/* OPTIONS method can include "*" in :path header field.  :method is
     received before :path. */
	check_http_recv_headers_ok(session, user_data, deflater, 25, -1, asteriskoptions2_reqhf);

	deflater.free();
	
	session.free();
}

void test_http_content_length() {
	Session session;
	Callbacks callbacks;
	Deflater deflater;

	Buffers bufs = framePackBuffers();
	int rv;
	Stream stream;
	const HeaderField[] cl_reshf = [HeaderField(":status", "200"),
		HeaderField("te", "trailers"),
		HeaderField("content-length", "9000000000")];
	const HeaderField[] cl_reqhf = [
		HeaderField(":path", "/"),        HeaderField(":method", "PUT"),
		HeaderField(":scheme", "https"),  HeaderField("te", "trailers"),
		HeaderField("host", "localhost"), HeaderField("content-length", "9000000000")];

	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packHeaders(bufs, deflater, 1, FrameFlags.END_HEADERS, cl_reshf);
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	assert(!session.getNextOutboundItem());
	assert(9000000000L == stream.contentLength);
	assert(200 == stream.statusCode);
	
	deflater.free();
	
	session.free();
	
	bufs.reset();
	
	/* check server side */
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	packHeaders(bufs, deflater, 1, FrameFlags.END_HEADERS, cl_reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	stream = session.getStream(1);
	
	assert(!session.getNextOutboundItem());
	assert(9000000000L == stream.contentLength);
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http_content_length_mismatch() {
	Session session;
	Callbacks callbacks;
	Deflater deflater;

	Buffers bufs = framePackBuffers();
	int rv;
	const HeaderField[] cl_reqhf = [
		HeaderField(":path", "/"), HeaderField(":method", "PUT"),
		HeaderField(":authority", "localhost"), HeaderField(":scheme", "https"),
		HeaderField("content-length", "20")];
	OutboundItem item;
	FrameHeader hd;
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* header says content-length: 20, but HEADERS has END_STREAM flag set */
	packHeaders(bufs, deflater, 1, cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.END_STREAM), cl_reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* header says content-length: 20, but DATA has 0 byte */
	packHeaders(bufs, deflater, 3, FrameFlags.END_HEADERS, cl_reqhf);

	hd = FrameHeader(0, FrameType.DATA, FrameFlags.END_STREAM, 3);
	hd.pack(bufs.head.buf.last[0 .. bufs.head.buf.available]);
	bufs.head.buf.last += FRAME_HDLEN;
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* header says content-length: 20, but DATA has 21 bytes */
	packHeaders(bufs, deflater, 5, FrameFlags.END_HEADERS, cl_reqhf);

	hd = FrameHeader(21, FrameType.DATA, FrameFlags.END_STREAM, 5);
	hd.pack(bufs.head.buf.last[0 .. bufs.head.buf.available]);
	bufs.head.buf.last += FRAME_HDLEN + 21;
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http_non_final_response() {
	Session session;
	Callbacks callbacks;
	Deflater deflater;

	Buffers bufs = framePackBuffers();
	int rv;
	const HeaderField[] nonfinal_reshf = [HeaderField(":status", "100")];
	OutboundItem item;
	FrameHeader hd;
	Stream stream;
		
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* non-final HEADERS with END_STREAM is illegal */
	stream = session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packHeaders(bufs, deflater, 1, cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.END_STREAM), nonfinal_reshf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* non-final HEADERS followed by non-empty DATA is illegal */
	stream = session.openStream(3, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packHeaders(bufs, deflater, 3, FrameFlags.END_HEADERS, nonfinal_reshf);

	hd = FrameHeader(10, FrameType.DATA, FrameFlags.END_STREAM, 3);
	hd.pack(bufs.head.buf.last[0 .. bufs.head.buf.available]);
	bufs.head.buf.last += FRAME_HDLEN + 10;
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* non-final HEADERS followed by empty DATA (without END_STREAM) is
     ok */
	stream = session.openStream(5, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packHeaders(bufs, deflater, 5, FrameFlags.END_HEADERS, nonfinal_reshf);

	hd = FrameHeader(0, FrameType.DATA, FrameFlags.NONE, 5);
	hd.pack(bufs.head.buf.last[0 .. bufs.head.buf.available]);
	bufs.head.buf.last += FRAME_HDLEN;
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(!session.getNextOutboundItem());
	
	bufs.reset();
	
	/* non-final HEADERS followed by empty DATA (with END_STREAM) is
     illegal */
	stream = session.openStream(7, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packHeaders(bufs, deflater, 7, FrameFlags.END_HEADERS, nonfinal_reshf);

	hd = FrameHeader(0, FrameType.DATA, FrameFlags.END_STREAM, 7);
	hd.pack(bufs.head.buf.last[0 .. bufs.head.buf.available]);
	bufs.head.buf.last += FRAME_HDLEN;
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* non-final HEADERS followed by final HEADERS is OK */
	stream = session.openStream(9, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packHeaders(bufs, deflater, 9, FrameFlags.END_HEADERS, nonfinal_reshf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	packHeaders(bufs, deflater, 9, FrameFlags.END_HEADERS, reshf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(!session.getNextOutboundItem());
	
	bufs.reset();
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http_trailer_headers() {
	Session session;
	Callbacks callbacks;
	Deflater deflater;

	Buffers bufs = framePackBuffers();
	int rv;
	const HeaderField[] trailer_reqhf = [
		HeaderField("foo", "bar"),
	];
	OutboundItem item;
		
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* good trailer header */
	packHeaders(bufs, deflater, 1, FrameFlags.END_HEADERS, reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	packHeaders(bufs, deflater, 1, cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.END_STREAM), trailer_reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(!session.getNextOutboundItem());
	
	bufs.reset();
	
	/* trailer header without END_STREAM is illegal */
	packHeaders(bufs, deflater, 3, FrameFlags.END_HEADERS, reqhf);
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	packHeaders(bufs, deflater, 3, FrameFlags.END_HEADERS, trailer_reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	/* trailer header including pseudo header field is illegal */
	packHeaders(bufs, deflater, 5, FrameFlags.END_HEADERS, reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	bufs.reset();
	
	packHeaders(bufs, deflater, 5, FrameFlags.END_HEADERS, reqhf);
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	
	assert(0 == session.send());
	
	bufs.reset();
	
	deflater.free();
	
	session.free();
	
	bufs.free();
}

void test_http_ignore_content_length() {
	Session session;
	Callbacks callbacks;
	Deflater deflater;

	Buffers bufs = framePackBuffers();
	int rv;
	const HeaderField[] cl_reshf = [HeaderField(":status", "304"), HeaderField("content-length", "20")];
	const HeaderField[] conn_reqhf = [HeaderField(":authority", "localhost"), HeaderField(":method", "CONNECT"), HeaderField("content-length", "999999")];
	Stream stream;

	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	/* If status 304, content-length must be ignored */
	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packHeaders(bufs, deflater, 1, cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.END_STREAM), cl_reshf);
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(!session.getNextOutboundItem());
	
	bufs.reset();
	
	deflater.free();
	session.free();
	
	/* If request method is CONNECT, content-length must be ignored */
	session = new Session(SERVER, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	packHeaders(bufs, deflater, 1, FrameFlags.END_HEADERS, conn_reqhf);
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(!session.getNextOutboundItem());
	
	stream = session.getStream(1);
	
	assert(-1 == stream.contentLength);
	assert((stream.httpFlags & HTTPFlags.METH_CONNECT) > 0);
	
	deflater.free();
	session.free();
	bufs.free();
}

void test_http_ignore_regular_header() {
	Session session;
	Callbacks callbacks;
	MyUserData user_data = MyUserData(&session);

	const HeaderField[] bad_reqhf = [
		HeaderField(":authority", "localhost"), HeaderField(":scheme", "https"),
		HeaderField(":path", "/"),              HeaderField(":method", "GET"),
		HeaderField("foo", "\x00"),           HeaderField("bar", "buzz")
	];
	const HeaderField[] bad_reshf = [
		HeaderField(":authority", "localhost"), HeaderField(":scheme", "https"),
		HeaderField(":path", "/"), HeaderField(":method", "GET"), HeaderField("bar", "buzz")
	];
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	callbacks.on_header_field_cb = &user_data.cb_handlers.onHeaderFieldPause;

	int rv;
	Buffers bufs = framePackBuffers();
	Deflater deflater;

	int proclen;
	size_t i;

	session = new Session(SERVER, *callbacks);

	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);

	packHeaders(bufs, deflater, 1, cast(FrameFlags)(FrameFlags.END_HEADERS | FrameFlags.END_STREAM), bad_reqhf);

	for(i = 0; i < 4; ++i) {
		rv = session.memRecv(bufs.head.buf.pos[proclen .. bufs.head.buf.length]);
		assert(rv > 0);
		proclen += rv;
		assert(bad_reshf[i] == user_data.hf);
	}

	rv = session.memRecv(bufs.head.buf.pos[proclen .. bufs.head.buf.length]);

	assert(rv > 0);
	/* header field "foo" must be ignored because it has illegal value.
	 * So we have "bar" header field for 5th header. */
	assert(bad_reshf[4] == user_data.hf);

	proclen += rv;

	assert(bufs.head.buf.length == proclen);

	deflater.free();
	session.free();
	bufs.free();
}

void test_http_record_request_method() {
	Session session;
	Callbacks callbacks;
	const HeaderField[] conn_reqhf = [HeaderField(":method", "CONNECT"), HeaderField(":authority", "localhost")];
	const HeaderField[] conn_reshf = [HeaderField(":status", "200"), HeaderField("content-length", "9999")];
	Stream stream;
	int rv;
	Buffers bufs = framePackBuffers();
	Deflater deflater;
	
	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	session = new Session(CLIENT, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	
	assert(1 == submitRequest(session, pri_spec_default, conn_reqhf, DataProvider.init, null));
	
	assert(0 == session.send());
	
	stream = session.getStream(1);
	
	assert(HTTPFlags.METH_CONNECT == stream.httpFlags);
	
	packHeaders(bufs, deflater, 1, FrameFlags.END_HEADERS, conn_reshf);
	
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert((HTTPFlags.METH_CONNECT & stream.httpFlags) > 0);
	assert(-1 == stream.contentLength);
	
	deflater.free();
	session.free();
	bufs.free();
}

void test_http_push_promise() {
	Session session;
	Callbacks callbacks;
	Deflater deflater;

	Buffers bufs = framePackBuffers();
	int rv;
	Stream stream;
	const HeaderField[] bad_reqhf = [HeaderField(":method", "GET")];
	OutboundItem item;

	
	callbacks.write_cb = toDelegate(&MyCallbacks.writeNull);
	
	/* good PUSH_PROMISE case */
	session = new Session(CLIENT, *callbacks);
	
	deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);

	session.openStream(1, StreamFlags.NONE, pri_spec_default, StreamState.OPENING, null);
	
	packPushPromise(bufs, deflater, 1, FrameFlags.END_HEADERS, 2, reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(!session.getNextOutboundItem());
	
	stream = session.getStream(2);
	assert(stream);
	
	bufs.reset();
	
	packHeaders(bufs, deflater, 2, FrameFlags.END_HEADERS, reshf);
		
	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	assert(!session.getNextOutboundItem());
	
	assert(200 == stream.statusCode);
	
	bufs.reset();
	
	/* PUSH_PROMISE lacks mandatory header */
	packPushPromise(bufs, deflater, 1, FrameFlags.END_HEADERS, 4, bad_reqhf);

	rv = session.memRecv(bufs.head.buf[]);
	
	assert(bufs.head.buf.length == rv);
	
	item = session.getNextOutboundItem();
	
	assert(FrameType.RST_STREAM == item.frame.hd.type);
	assert(4 == item.frame.hd.stream_id);
	
	bufs.reset();
	
	deflater.free();
	session.free();
	bufs.free();
}

unittest {

	import memutils.allocators;
	enum Debugger = 0x02;
	assert(0 == getAllocator!Debugger().bytesAllocated());

	test_session_read();
	test_session_read_invalid_stream_id();
	test_session_read_invalid_frame();
	test_session_read_eof();
	test_session_read_data();
	test_session_read_continuation();
	test_session_read_headers_with_priority();
	test_session_read_premature_headers();
	test_session_read_unknown_frame();
	test_session_read_unexpected_continuation();
	test_session_read_settings_header_table_size();
	test_session_read_too_large_frame_length();
	test_session_continue();
	test_session_add_frame();
	test_session_on_request_headers_received();
	test_session_on_response_headers_received();
	test_session_on_headers_received();
	test_session_on_push_response_headers_received();
	test_session_on_priority_received();
	test_session_on_rst_stream_received();
	test_session_on_settings_received();
	test_session_on_push_promise_received();
	test_session_on_ping_received();
	test_session_on_goaway_received();
	test_session_on_window_update_received();
	test_session_on_data_received();
	test_session_write_headers_start_stream();
	test_session_write_headers_reply();
	test_session_write_headers_frame_size_error();
	test_session_write_headers_push_reply();
	test_session_write_rst_stream();
	test_session_write_push_promise();
	test_session_is_my_stream_id();
	test_session_upgrade();
	test_session_reprioritize_stream();
	test_session_reprioritize_stream_with_idle_stream_dep();
	test_submit_data();
	test_submit_data_read_length_too_large();
	test_submit_data_read_length_smallest();
	test_submit_data_twice();
	test_submit_request_with_data();
	test_submit_request_without_data();
	test_submit_response_with_data();
	test_submit_response_without_data();
	test_submit_headers_start_stream();
	test_submit_headers_reply();
	test_submit_headers_push_reply();
	test_submit_headers();
	test_submit_headers_continuation();
	test_submit_priority();
	test_submit_settings();
	test_submit_settings_update_local_window_size();
	test_submit_push_promise();
	test_submit_window_update();
	test_submit_window_update_local_window_size();
	test_submit_shutdown_notice();
	test_submit_invalid_hf();
	test_session_open_stream();
	test_session_open_stream_with_idle_stream_dep();
	test_session_get_next_ob_item();
	test_session_pop_next_ob_item();
	test_session_reply_fail();
	test_session_max_concurrent_streams();
	test_session_stop_data_with_rst_stream();
	test_session_defer_data();
	test_session_flow_control();
	test_session_flow_control_data_recv();
	test_session_flow_control_data_with_padding_recv();
	test_session_data_read_temporal_failure();
	test_session_on_stream_close();
	test_session_on_ctrl_not_send();
	test_session_get_outbound_queue_size();
	test_session_get_effective_local_window_size();
	test_session_set_option();
	test_session_data_backoff_by_high_pri_frame();
	test_session_pack_data_with_padding();
	test_session_pack_headers_with_padding();
	test_session_pack_settings_payload();
	test_session_stream_dep_add();
	test_session_stream_dep_remove();
	test_session_stream_dep_add_subtree();
	test_session_stream_dep_remove_subtree();
	test_session_stream_dep_make_head_root();
	test_session_stream_attach_item();
	test_session_stream_attach_item_subtree();
	test_session_keep_closed_stream();
	test_session_keep_idle_stream();
	test_session_detach_idle_stream();
	test_session_large_dep_tree();
	test_session_graceful_shutdown();
	test_session_on_header_temporal_failure();
	test_session_read_client_preface();
	test_session_delete_data_item();
	test_session_open_idle_stream();
	test_session_cancel_reserved_remote();
	test_session_reset_pending_headers();
	test_session_send_data_callback();
	test_http_mandatory_headers();
	test_http_content_length();
	test_http_content_length_mismatch();
	test_http_non_final_response();
	test_http_trailer_headers();
	test_http_ignore_content_length();
	test_http_ignore_regular_header();
	test_http_record_request_method();
	test_http_push_promise();
	//getAllocator!Debugger().printMap();
	assert(0 == getAllocator!Debugger().bytesAllocated());
}