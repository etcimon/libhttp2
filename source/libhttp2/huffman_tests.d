/**
 * Huffman Tests
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.huffman_tests;

import libhttp2.constants;
//static if (TEST_ALL):

import libhttp2.buffers;
import libhttp2.huffman;
import libhttp2.deflater;
import libhttp2.inflater;
import libhttp2.types;
import libhttp2.frame;
import libhttp2.helpers;
import libhttp2.tests;
import std.c.string : memcmp, memset;

void test_hd_deflate() {
	Deflater deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	Inflater inflater = Inflater(true);
	HeaderField[] hfa1 = [HeaderField(":path", "/my-example/index.html"), HeaderField(":scheme", "https"), HeaderField("hello", "world")];
	HeaderField[] hfa2 = [HeaderField(":path", "/script.js"), HeaderField(":scheme", "https")];
	HeaderField[] hfa3 = [HeaderField("cookie", "k1=v1"), HeaderField("cookie", "k2=v2"), HeaderField("via", "proxy")];
	HeaderField[] hfa4 = [HeaderField(":path", "/style.css"), HeaderField("cookie", "k1=v1"), HeaderField("cookie", "k1=v1")];
	HeaderField[] hfa5 = [HeaderField(":path", "/style.css"), HeaderField("x-nghttp2", "")];
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderFields output;
	ErrorCode rv;

	rv = deflater.deflate(bufs, hfa1);
	blocklen = bufs.length;
	assert(0 == rv);
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(3 == output.length);
	assert(hfa1.equals(output[0 .. 3]));
	
	output.reset();
	bufs.reset();
	
	/* Second headers */
	rv = deflater.deflate(bufs, hfa2);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(2 == output.length);
	assert(hfa2.equals(output[0 .. 2]));
	
	output.reset();
	bufs.reset();
	
	/* Third headers, including same header field name, but value is not
     the same. */
	rv = deflater.deflate(bufs, hfa3);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(3 == output.length);
	assert(hfa3.equals(output[0 .. 3]));
	
	output.reset();
	bufs.reset();
	
	/* Fourth headers, including duplicate header fields. */
	rv = deflater.deflate(bufs, hfa4);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(3 == output.length);
	assert(hfa4.equals(output[0 .. 3]));
	
	output.reset();
	bufs.reset();
	
	/* Fifth headers includes empty value */
	rv = deflater.deflate(bufs, hfa5);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(2 == output.length);
	assert(hfa5.equals(output[0 .. 2]));
	
	output.reset();
	bufs.reset();
	
	/* Cleanup */
	bufs.free();
	inflater.free();
	deflater.free();
}

void test_hd_deflate_same_indexed_repr() {
	Deflater deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	Inflater inflater = Inflater(true);
	HeaderField[] hfa1 = [HeaderField("cookie", "alpha"), HeaderField("cookie", "alpha")];
	HeaderField[] hfa2 = [HeaderField("cookie", "alpha"), HeaderField("cookie", "alpha"), HeaderField("cookie", "alpha")];
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderFields output;
	ErrorCode rv;

	/* Encode 2 same headers.  Emit 1 literal reprs and 1 index repr. */
	rv = deflater.deflate(bufs, hfa1);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(2 == output.length);
	assert(hfa1.equals(output[]));
	
	output.reset();
	bufs.reset();
	
	/* Encode 3 same headers.  This time, emits 3 index reprs. */
	rv = deflater.deflate(bufs, hfa2);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen == 3);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(3 == output.length);
	assert(hfa2.equals(output[0 .. 3]));
	
	output.reset();
	bufs.reset();
	
	/* Cleanup */
	bufs.free();
	inflater.free();
	deflater.free();
}

void test_hd_inflate_indexed() {
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderField hf = HeaderField(":path", "/");
	HeaderFields output;

	bufs.add((1 << 7) | 4);
	
	blocklen = bufs.length;
	
	assert(1 == blocklen);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(1 == output.length);
	
	assert(hf == output.hfa_raw[0]);
	
	output.reset();
	bufs.reset();
	
	/* index = 0 is error */
	bufs.add(1 << 7);
	
	blocklen = bufs.length;
	
	assert(1 == blocklen);
	assert(ErrorCode.HEADER_COMP == output.inflate(inflater, bufs, 0));
	
	bufs.free();
	inflater.free();
}

void test_hd_inflate_indname_noinc() {
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderField[] hfa = [
		/* Huffman */
		HeaderField("user-agent", "nghttp2"),
		/* Expecting no huffman */
		HeaderField("user-agent", "x")
	];
	size_t i;
	HeaderFields output;

	foreach (ref hf; hfa) {
		assert(0 == bufs.emitIndexedNameBlock(57, hf, false));
		blocklen = bufs.length;
		
		assert(blocklen > 0);
		assert(blocklen == output.inflate(inflater, bufs, 0));
		assert(1 == output.length);
		assert(hf == output.hfa_raw[0]);
		assert(0 == inflater.ctx.hd_table.length);
		
		output.reset();
		bufs.reset();
	}
	
	bufs.free();
	inflater.free();
}

void test_hd_inflate_indname_inc() {
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderField hf = HeaderField("user-agent", "nghttp2");
	HeaderFields output;
	assert(0 == bufs.emitIndexedNameBlock(57, hf, 1));
	blocklen = bufs.length;
	
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(1 == output.length);
	assert(hf == output.hfa_raw[0]);
	assert(1 == inflater.ctx.hd_table.length);
	assert(hf == inflater.ctx.get(static_table.length + inflater.ctx.hd_table.length - 1).hf);
	
	output.reset();
	bufs.free();
	inflater.free();
}

void test_hd_inflate_indname_inc_eviction() {
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	ubyte[1024] value;
	memset(value.ptr, '0', value.length);
	HeaderFields output;
	HeaderField hf;

	hf.value = cast(string)value;
	hf.flag = HeaderFlag.NONE;

	assert(0 == bufs.emitIndexedNameBlock(14, hf, true));
	assert(0 == bufs.emitIndexedNameBlock(15, hf, true));
	assert(0 == bufs.emitIndexedNameBlock(16, hf, true));
	assert(0 == bufs.emitIndexedNameBlock(17, hf, true));
	
	blocklen = bufs.length;

	assert(blocklen > 0);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(4 == output.length);
	assert(14 == output.hfa_raw[0].name.length);
	assert("accept-charset" == output.hfa_raw[0].name);
	assert(value.length == output.hfa_raw[0].value.length);
	
	output.reset();
	bufs.reset();
	
	assert(3 == inflater.ctx.hd_table.length);
	
	bufs.free();
	inflater.free();
}

void test_hd_inflate_newname_noinc() {
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderField[] hfa = [/* Expecting huffman for both */
		HeaderField("my-long-content-length", "nghttp2"),
		/* Expecting no huffman for both */
		HeaderField("x", "y"),
		/* Huffman for key only */
		HeaderField("my-long-content-length", "y"),
		/* Huffman for value only */
		HeaderField("x", "nghttp2")];
	size_t i;
	HeaderFields output;
	
	foreach (ref hf; hfa) {
		assert(0 == bufs.emitNewNameBlock(hf, false));
		
		blocklen = bufs.length;
		
		assert(blocklen > 0);
		assert(blocklen == output.inflate(inflater, bufs, 0));
		
		assert(1 == output.length);
		assert(hf == output.hfa_raw[0]);
		assert(0 == inflater.ctx.hd_table.length);
		
		output.reset();
		bufs.reset();
	}
	
	bufs.free();
	inflater.free();
}

void test_hd_inflate_newname_inc() {
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderField hf = HeaderField("x-rel", "nghttp2");
	HeaderFields output;

	assert(0 == bufs.emitNewNameBlock(hf, true));
	
	blocklen = bufs.length;
	
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(1 == output.length);
	assert(hf == output.hfa_raw[0]);
	assert(1 == inflater.ctx.hd_table.length);
	assert(hf == inflater.ctx.get(static_table.length + inflater.ctx.hd_table.length - 1).hf);
	
	output.reset();
	bufs.free();
	inflater.free();
}

void test_hd_inflate_clearall_inc() {
	Inflater inflater = Inflater(true);
	Buffers bufs = largeBuffers(8192);
	size_t blocklen;
	HeaderField hf;
	ubyte[4060] value;
	memset(value.ptr, '0', value.length);
	HeaderFields output;

	/* Total 4097 bytes space required to hold this entry */
	hf.name = "alpha";
	hf.value = cast(string)value;
	hf.flag = HeaderFlag.NONE;
		
	assert(0 == bufs.emitNewNameBlock(hf, true));
	
	blocklen = bufs.length;
	
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(1 == output.length);
	assert(hf == output.hfa_raw[0]);
	assert(0 == inflater.ctx.hd_table.length);
	
	output.reset();
	
	/* Do it again */
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(1 == output.length);
	assert(hf == output.hfa_raw[0]);
	assert(0 == inflater.ctx.hd_table.length);
	
	output.reset();
	bufs.reset();
	
	/* This time, 4096 bytes space required, which is just fits in the header table */	
	hf.value = hf.value[0 .. 4059];
	assert(0 == bufs.emitNewNameBlock(hf, true));
	
	blocklen = bufs.length;
	
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(1 == output.length);
	assert(hf == output.hfa_raw[0]);
	assert(1 == inflater.ctx.hd_table.length);
	
	output.reset();
	bufs.reset();
	
	bufs.free();
	inflater.free();
}

void test_hd_inflate_zero_length_huffman() {
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	/* Literal header without indexing - new name */
	ubyte[] data = [0x40, 0x01, 0x78 /* 'x' */, 0x80];
	HeaderFields output;

	bufs.add(cast(string)data);
	
	/* /\* Literal header without indexing - new name *\/ */
	/* ptr[0] = 0x40; */
	/* ptr[1] = 1; */
	/* ptr[2] = 'x'; */
	/* ptr[3] = 0x80; */
	
	
	assert(4 == output.inflate(inflater, bufs, 0));
	
	assert(1 == output.length);
	assert(1 == output.hfa_raw[0].name.length);
	assert('x' == output.hfa_raw[0].name[0]);
	assert(null == output.hfa_raw[0].value);
	assert(0 == output.hfa_raw[0].value.length);
	
	output.reset();
	bufs.free();
	inflater.free();
}

void test_hd_ringbuf_reserve() {
	Deflater deflater;
	Inflater inflater = Inflater(true);
	HeaderField hf;
	Buffers bufs = framePackBuffers();
	HeaderFields output;
	int i;
	size_t rv;
	size_t blocklen;
		
	hf.flag = HeaderFlag.NONE;
	hf.name = "a";
	char[] value = Mem.alloc!(char[])(4);
	memset(value.ptr, 0, value.length);
	hf.value = cast(string) value;
	deflater = Deflater(8000);
	
	
	inflater.changeTableSize(8000);
	deflater.changeTableSize(8000);
	
	for (i = 0; i < 150; ++i) {
		memcpy(value.ptr, &i, i.sizeof);
		rv = deflater.deflate(bufs, hf);
		blocklen = bufs.length;
		
		assert(0 == rv);
		assert(blocklen > 0);
		
		assert(blocklen == output.inflate(inflater, bufs, 0));
		
		assert(1 == output.length);
		assert(hf == output.hfa_raw[0]);
		
		output.reset();
		bufs.reset();
	}
	
	bufs.free();
	inflater.free();
	deflater.free();
	
	Mem.free(hf.value);
}

void test_hd_change_table_size() {
	Deflater deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	Inflater inflater = Inflater(true);
	HeaderField[] hfa = [HeaderField("alpha", "bravo"), HeaderField("charlie", "delta")];
	HeaderField[] hfa2 = [HeaderField(":path", "/")];
	Buffers bufs = framePackBuffers();
	size_t rv;
	HeaderFields output;
	size_t blocklen;
		
	/* inflater changes notifies 8000 max header table size */
	inflater.changeTableSize(8000);
	deflater.changeTableSize(8000);
	
	assert(4096 == deflater.ctx.hd_table_bufsize_max);
	
	assert(8000 == inflater.ctx.hd_table_bufsize_max);
	assert(8000 == inflater.settings_hd_table_bufsize_max);
	
	/* This will emit encoding context update with header table size 4096 */
	rv = deflater.deflate(bufs, hfa[0 .. 2]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(2 == deflater.ctx.hd_table.length);
	assert(4096 == deflater.ctx.hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(2 == inflater.ctx.hd_table.length);
	assert(4096 == inflater.ctx.hd_table_bufsize_max);
	assert(8000 == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	bufs.reset();
	
	/* inflater changes header table size to 1024 */
	inflater.changeTableSize(1024);
	deflater.changeTableSize(1024);
	
	assert(1024 == deflater.ctx.hd_table_bufsize_max);
	
	assert(1024 == inflater.ctx.hd_table_bufsize_max);
	assert(1024 == inflater.settings_hd_table_bufsize_max);
	
	rv = deflater.deflate(bufs, hfa[0 .. 2]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(2 == deflater.ctx.hd_table.length);
	assert(1024 == deflater.ctx.hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(2 == inflater.ctx.hd_table.length);
	assert(1024 == inflater.ctx.hd_table_bufsize_max);
	assert(1024 == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	bufs.reset();
	
	/* inflater changes header table size to 0 */
	inflater.changeTableSize(0);
	deflater.changeTableSize(0);
	
	assert(0 == deflater.ctx.hd_table.length);
	assert(0 == deflater.ctx.hd_table_bufsize_max);
	
	assert(0 == inflater.ctx.hd_table.length);
	assert(0 == inflater.ctx.hd_table_bufsize_max);
	assert(0 == inflater.settings_hd_table_bufsize_max);
	
	rv = deflater.deflate(bufs, hfa[0 .. 2]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(0 == deflater.ctx.hd_table.length);
	assert(0 == deflater.ctx.hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(0 == inflater.ctx.hd_table.length);
	assert(0 == inflater.ctx.hd_table_bufsize_max);
	assert(0 == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	bufs.reset();
	
	bufs.free();
	inflater.free();
	deflater.free();
	
	/* Check table buffer is expanded */
	bufs = framePackBuffers();
	
	deflater = Deflater(8192);
	inflater = Inflater(true);
	
	/* First inflater changes header table size to 8000 */
	inflater.changeTableSize(8000);
	deflater.changeTableSize(8000);
	
	assert(8000 == deflater.ctx.hd_table_bufsize_max);
	
	assert(8000 == inflater.ctx.hd_table_bufsize_max);
	assert(8000 == inflater.settings_hd_table_bufsize_max);
	
	rv = deflater.deflate(bufs, hfa[0 .. 2]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(2 == deflater.ctx.hd_table.length);
	assert(8000 == deflater.ctx.hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(2 == inflater.ctx.hd_table.length);
	assert(8000 == inflater.ctx.hd_table_bufsize_max);
	assert(8000 == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	bufs.reset();
	
	inflater.changeTableSize(16383);
	deflater.changeTableSize(16383);
	
	assert(8192 == deflater.ctx.hd_table_bufsize_max);
	
	assert(16383 == inflater.ctx.hd_table_bufsize_max);
	assert(16383 == inflater.settings_hd_table_bufsize_max);
	
	rv = deflater.deflate(bufs, hfa[0 .. 2]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(2 == deflater.ctx.hd_table.length);
	assert(8192 == deflater.ctx.hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(2 == inflater.ctx.hd_table.length);
	assert(8192 == inflater.ctx.hd_table_bufsize_max);
	assert(16383 == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	bufs.reset();
	
	/* Lastly, check the error condition */
	
	rv = bufs.emitTableSize(25600);
	assert(rv == 0);
	assert(ErrorCode.HEADER_COMP == output.inflate(inflater, bufs, 0));
	
	output.reset();
	bufs.reset();
	
	inflater.free();
	deflater.free();
	
	/* Check that encoder can handle the case where its allowable buffer
     size is less than default size, 4096 */
	deflater = Deflater(1024);
	inflater = Inflater(true);
	
	assert(1024 == deflater.ctx.hd_table_bufsize_max);
	
	/* This emits context update with buffer size 1024 */
	rv = deflater.deflate(bufs, hfa[0 .. 2]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(2 == deflater.ctx.hd_table.length);
	assert(1024 == deflater.ctx.hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(2 == inflater.ctx.hd_table.length);
	assert(1024 == inflater.ctx.hd_table_bufsize_max);
	assert(4096 == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	bufs.reset();
	
	inflater.free();
	deflater.free();
	
	/* Check that table size uint.max can be received */
	deflater = Deflater(uint.max);
	inflater = Inflater(true);
	
	inflater.changeTableSize(uint.max);
	deflater.changeTableSize(uint.max);
	
	rv = deflater.deflate(bufs, hfa[0 .. 2]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(uint.max == deflater.ctx.hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(uint.max == inflater.ctx.hd_table_bufsize_max);
	assert(uint.max == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	bufs.reset();
	
	inflater.free();
	deflater.free();
	
	/* Check that context update emitted twice
	 */
	deflater = Deflater(4096);
	inflater = Inflater(true);
	
	inflater.changeTableSize(0);
	inflater.changeTableSize(3000);
	deflater.changeTableSize(0);
	deflater.changeTableSize(3000);
	
	assert(0 == deflater.min_hd_table_bufsize_max);
	assert(3000 == deflater.ctx.hd_table_bufsize_max);
	
	rv = deflater.deflate(bufs, hfa2[0 .. 1]);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(3 < blocklen);
	assert(3000 == deflater.ctx.hd_table_bufsize_max);
	assert(uint.max == deflater.min_hd_table_bufsize_max);
	
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(3000 == inflater.ctx.hd_table_bufsize_max);
	assert(3000 == inflater.settings_hd_table_bufsize_max);
	
	output.reset();
	
	inflater.free();
	deflater.free();
	
	bufs.free();
}

void check_deflate_inflate(ref Deflater deflater, ref Inflater inflater, HeaderField[] hfa) 
{
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderFields output;
	ErrorCode rv;

	rv = deflater.deflate(bufs, hfa);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen >= 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	assert(hfa.length == output.length);
	assert(hfa.equals(output[]));
	output.reset();
	bufs.free();
}

void test_hd_deflate_inflate() {
	Deflater deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	Inflater inflater = Inflater(true);
	HeaderField[] hfa1 = [
		HeaderField(":status", "200 OK"),
		HeaderField("access-control-allow-origin", "*"),
		HeaderField("cache-control", "private, max-age=0, must-revalidate"),
		HeaderField("content-length", "76073"),
		HeaderField("content-type", "text/html"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("expires", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("server", "Apache"),
		HeaderField("vary", "foobar"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "MISS from alphabravo"),
		HeaderField("x-cache-action", "MISS"),
		HeaderField("x-cache-age", "0"),
		HeaderField("x-cache-lookup", "MISS from alphabravo:3128"),
		HeaderField("x-lb-nocache", "true")
	];
	HeaderField[] hfa2 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=56682045"),
		HeaderField("content-type", "text/css"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("expires", "Thu, 14 May 2015 07:22:57 GMT"),
		HeaderField("last-modified", "Tue, 14 May 2013 07:22:15 GMT"),
		HeaderField("vary", "Accept-Encoding"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")];

	HeaderField[] hfa3 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=56682072"),
		HeaderField("content-type", "text/css"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("expires", "Thu, 14 May 2015 07:23:24 GMT"),
		HeaderField("last-modified", "Tue, 14 May 2013 07:22:13 GMT"),
		HeaderField("vary", "Accept-Encoding"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")
	];

	HeaderField[] hfa4 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=56682022"),
		HeaderField("content-type", "text/css"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("expires", "Thu, 14 May 2015 07:22:34 GMT"),
		HeaderField("last-modified", "Tue, 14 May 2013 07:22:14 GMT"),
		HeaderField("vary", "Accept-Encoding"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")
	];
	HeaderField[] hfa5 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=4461139"),
		HeaderField("content-type", "application/x-javascript"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("expires", "Mon, 16 Sep 2013 21:34:31 GMT"),
		HeaderField("last-modified", "Thu, 05 May 2011 09:15:59 GMT"),
		HeaderField("vary", "Accept-Encoding"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")
	];

	HeaderField[] hfa6 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=18645951"),
		HeaderField("content-type", "application/x-javascript"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("expires", "Fri, 28 Feb 2014 01:48:03 GMT"),
		HeaderField("last-modified", "Tue, 12 Jul 2011 16:02:59 GMT"),
		HeaderField("vary", "Accept-Encoding"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128"),
	];
	HeaderField[] hfa7 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=31536000"),
		HeaderField("content-type", "application/javascript"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("etag", "\"6807-4dc5b54e0dcc0\""),
		HeaderField("expires", "Wed, 21 May 2014 08:32:17 GMT"),
		HeaderField("last-modified", "Fri, 10 May 2013 11:18:51 GMT"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")
	];
	HeaderField[] hfa8 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=31536000"),
		HeaderField("content-type", "application/javascript"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("etag", "\"41c6-4de7d28585b00\""),
		HeaderField("expires", "Thu, 12 Jun 2014 10:00:58 GMT"),
		HeaderField("last-modified", "Thu, 06 Jun 2013 14:30:36 GMT"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")
	];

	HeaderField[] hfa9 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=31536000"),
		HeaderField("content-type", "application/javascript"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("etag", "\"19d6e-4dc5b35a541c0\""),
		HeaderField("expires", "Wed, 21 May 2014 08:32:18 GMT"),
		HeaderField("last-modified", "Fri, 10 May 2013 11:10:07 GMT"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")
	];
	HeaderField[] hfa10 = [
		HeaderField(":status", "304 Not Modified"),
		HeaderField("age", "0"),
		HeaderField("cache-control", "max-age=56682045"),
		HeaderField("content-type", "text/css"),
		HeaderField("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
		HeaderField("expires", "Thu, 14 May 2015 07:22:57 GMT"),
		HeaderField("last-modified", "Tue, 14 May 2013 07:21:53 GMT"),
		HeaderField("vary", "Accept-Encoding"),
		HeaderField("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
		HeaderField("x-cache", "HIT from alphabravo"),
		HeaderField("x-cache-lookup", "HIT from alphabravo:3128")
	];

	check_deflate_inflate(deflater, inflater, hfa1);
	check_deflate_inflate(deflater, inflater, hfa2);
	check_deflate_inflate(deflater, inflater, hfa3);
	check_deflate_inflate(deflater, inflater, hfa4);
	check_deflate_inflate(deflater, inflater, hfa5);
	check_deflate_inflate(deflater, inflater, hfa6);
	check_deflate_inflate(deflater, inflater, hfa7);
	check_deflate_inflate(deflater, inflater, hfa8);
	check_deflate_inflate(deflater, inflater, hfa9);
	check_deflate_inflate(deflater, inflater, hfa10);
	
	inflater.free();
	deflater.free();
}

void test_hd_no_index() {
	Deflater deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	Inflater inflater = Inflater(true);
	Buffers bufs = framePackBuffers();
	size_t blocklen;
	HeaderField[] hfa = [
		HeaderField(":method", "GET"), HeaderField(":method", "POST"),
		HeaderField(":path", "/foo"),  HeaderField("version", "HTTP/1.1"),
		HeaderField(":method", "GET")
	];
	size_t i;
	HeaderFields output;
	ErrorCode rv;
	
	/* 1st :method: GET can be indexable, last one is not */
	foreach (ref hf; hfa[1 .. $]) {
		hf.flag = HeaderFlag.NO_INDEX;
	}

	rv = deflater.deflate(bufs, hfa);
	blocklen = bufs.length;
	
	assert(0 == rv);
	assert(blocklen > 0);
	assert(blocklen == output.inflate(inflater, bufs, 0));
	
	assert(hfa.length == output.length);
	assert(hfa.equals(output[]));
	
	assert(output.hfa_raw[0].flag == HeaderFlag.NONE);

	foreach (ref hf; output[][1 .. $])
		assert(hf.flag == HeaderFlag.NO_INDEX);
	
	output.reset();
	
	bufs.free();
	inflater.free();
	deflater.free();
}

void test_hd_deflate_bound() {
	Deflater deflater = Deflater(DEFAULT_MAX_DEFLATE_BUFFER_SIZE);
	HeaderField[] hfa = [HeaderField(":method", "GET"), HeaderField("alpha", "bravo")];
	Buffers bufs = framePackBuffers();
	size_t bound, bound2;
	
	bound = deflater.upperBound(hfa);
	
	assert(12 + 6 * 2 * 2 + hfa[0].name.length + hfa[0].value.length + hfa[1].name.length + hfa[1].value.length == bound);
	
	deflater.deflate(bufs, hfa);
	
	assert(bound > cast(size_t)bufs.length);
	
	bound2 = deflater.upperBound(hfa);
	
	assert(bound == bound2);
	
	bufs.free();
	deflater.free();
}

void test_hd_public_api() {
	Deflater deflater = Deflater(4096);
	Inflater inflater = Inflater(true);
	HeaderField[] hfa = [HeaderField("alpha", "bravo"), HeaderField("charlie", "delta")];
	ubyte[4096] buf;
	size_t buflen;
	size_t blocklen;
	Buffers bufs = framePackBuffers();

	buflen = deflater.upperBound(hfa);
	
	blocklen = deflater.deflate(buf[0 .. buflen], hfa);
	
	assert(blocklen > 0);
	bufs.free();
	bufs = new Buffers(buf[0 .. blocklen]);
	bufs.head.buf.last += blocklen;
	HeaderFields dummy;
	assert(blocklen == dummy.inflate(inflater, bufs, 0));
	dummy.reset();
	bufs.free();
	
	inflater.free();
	deflater.free();

	/* See ErrorCode.INSUFF_BUFSIZE */
	deflater = Deflater(4096);

	blocklen = deflater.deflate(buf[0 .. blocklen - 1], hfa);
	
	assert(ErrorCode.INSUFF_BUFSIZE == blocklen);
	deflater.free();
}

private size_t encodeLength(ubyte *buf, ulong n, size_t prefix) {
	size_t k = (1 << prefix) - 1;
	size_t len;
	*buf &= ~(cast(ubyte)k);
	if (n >= k) {
		*buf++ |= cast(ubyte) k;
		n -= k;
		++len;
	} else {
		*buf++ |= cast(ubyte) n;
		return 1;
	}
	do {
		++len;
		if (n >= 128) {
			*buf++ = cast(ubyte)((1 << 7) | ((cast(ubyte)n) & 0x7f));
			n >>= 7;
		} else {
			*buf++ = cast(ubyte)n;
			break;
		}
	} while (n);
	return len;
}

void test_hd_decode_length() {
	uint output;
	size_t shift;
	bool is_final;
	ubyte[16] buf;
	ubyte* bufp;
	size_t len;
	size_t rv;
	size_t i;

	len = encodeLength(buf.ptr, uint.max, 7);

	rv = output.decodeLength(shift, is_final, 0, 0, buf.ptr, buf.ptr + cast(size_t)len, 7);
	
	assert(cast(int)len == rv, len.to!string ~ " != " ~ rv.to!string);
	assert(false != is_final);
	assert(uint.max == output);
	
	/* Make sure that we can decode integer if we feed 1 byte at a time */
	output = 0;
	shift = 0;
	is_final = false;
	bufp = buf.ptr;
	
	for (i = 0; i < len; ++i, ++bufp) {
		rv = output.decodeLength(shift, is_final, output, shift, bufp, bufp + 1, 7);
		assert(rv == 1);
		
		if (is_final) {
			break;
		}
	}
	
	assert(i == len - 1);
	assert(0 != is_final);
	assert(uint.max == output);
	
	/* Check overflow case */
	memset(buf.ptr, 0, buf.length);
	len = encodeLength(buf.ptr, 1L << 32, 7);
	
	rv = output.decodeLength(shift, is_final, 0, 0, buf.ptr, buf.ptr + len, 7);
	
	assert(-1 == rv);
}

void test_hd_huff_encode() {
	ErrorCode rv;
	size_t len;
	Buffers bufs, outbufs;
	Decoder ctx;
	const ubyte[] t1 = [22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0];
	
	bufs = framePackBuffers();
	outbufs = framePackBuffers();

	rv = bufs.encodeHuffman(cast(string)t1);
	
	assert(rv == 0);
		
	len = ctx.decode(outbufs, bufs.cur.buf[], true);
	
	assert(bufs.length == len);
	assert(cast(size_t)t1.length == outbufs.length);
	
	assert(t1[0 .. $] == outbufs.cur.buf.pos[0 .. t1.length]);
	
	bufs.free();
	outbufs.free();
}

unittest {
	test_hd_deflate();
	test_hd_deflate_same_indexed_repr();
	test_hd_inflate_indexed();
	test_hd_inflate_indname_noinc();
	test_hd_inflate_indname_inc();
	test_hd_inflate_indname_inc_eviction();
	test_hd_inflate_newname_noinc();
	test_hd_inflate_newname_inc();
	test_hd_inflate_clearall_inc();
	test_hd_inflate_zero_length_huffman();
	test_hd_ringbuf_reserve();
	test_hd_change_table_size();
	test_hd_deflate_inflate();
	test_hd_no_index();
	test_hd_deflate_bound();
	test_hd_public_api();
	test_hd_decode_length();
	test_hd_huff_encode();
}