/**
 * Tests
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.tests;

import core.stdc.stdlib;
import core.stdc.string;
import libhttp2.constants;
import libhttp2.types;
import libhttp2.helpers;
import libhttp2.inflater;
import libhttp2.deflater;
import libhttp2.session;
import libhttp2.stream;
import libhttp2.frame;
import libhttp2.huffman;
import libhttp2.buffers;
import std.algorithm : min;

struct HeaderFields
{
	HeaderField[] opSlice() 
	{
		return hfa_raw[0 .. length];
	}

	HeaderField[] opSlice(size_t i, size_t j) {
		assert(j <= length);
		return hfa_raw[i .. j];
	}

	size_t opDollar() const { return length; }

	void add(HeaderField hf) {
		HeaderField* hfp = hfa_raw.ptr + length;
		length++;
		if (hf.name.length > 0) 
			hfp.name = Mem.copy(hf.name);
		
		if (hf.value.length > 0)
			hfp.value = Mem.copy(hf.value);

		hfp.flag = hf.flag;
	}

	void reset() {
		size_t i;
		for (i = 0; i < length; ++i) {
			if (hfa_raw[i].name) 
				Mem.free(hfa_raw[i].name);
			if (hfa_raw[i].value) 
				Mem.free(hfa_raw[i].value);
		}
		hfa_raw.destroy();
		length = 0;
	}

	/// returns the amount of headers added to hfa
	int inflate(ref Inflater inflater, Buffers bufs, size_t offset) 
	{
		int rv;
		HeaderField hf;
		InflateFlag inflate_flag;
		Buffers.Chain ci;
		Buffer* buf;
		Buffer bp;
		bool is_final;
		int processed;
		
		for (ci = bufs.head; ci; ci = ci.next) {
			buf = &ci.buf;
			is_final = buf.length == 0 || !ci.next;
			bp = *buf;

			if (offset) {
				int n;
				
				n = min(cast(int)offset, bp.length);
				bp.pos += n;
				offset -= n;
			}

			for (;;) {
				inflate_flag = InflateFlag.NONE;
				rv = inflater.inflate(hf, inflate_flag, bp[], is_final);
				if (rv < 0)
					return rv;
				
				bp.pos += rv;
				processed += rv;
				if (inflate_flag & InflateFlag.EMIT) 
					add(hf);
				if (inflate_flag & InflateFlag.FINAL)
					break;
			}
		}
		inflater.endHeaders();
		
		return processed;
	}

	HeaderField[256] hfa_raw;
	size_t length;
}

int compareBytes(in string a, in string b) {
	int rv;
	
	if (a.length == b.length) {
		return memcmp(a.ptr, b.ptr, a.length);
	}
	
	if (a.length < b.length) {
		rv = memcmp(a.ptr, b.ptr, a.length);
		
		if (rv == 0) {
			return -1;
		}
		
		return rv;
	}
	
	rv = memcmp(a.ptr, b.ptr, b.length);
	
	if (rv == 0) {
		return 1;
	}
	
	return rv;
}

extern(C)
int compareHeaderFields(in void *lhs, in void *rhs) {
	const HeaderField a = *cast(HeaderField*)lhs;
	const HeaderField b = *cast(HeaderField*)rhs;
	int rv;
	
	rv = compareBytes(a.name, b.name);
	
	if (rv == 0) {
		return compareBytes(a.value, b.value);
	}
	
	return rv;
}

void sort(HeaderField[] hfa) {
	qsort(hfa.ptr, hfa.length, HeaderField.sizeof, &compareHeaderFields);
}

void packHeaders(Buffers bufs, ref Deflater deflater, int stream_id, FrameFlags flags, in HeaderField[] hfa)
{
	HeaderField[] hfa_copy;
	Frame frame;
	hfa_copy = hfa.copy();		
	frame.headers = Headers(flags, stream_id, HeadersCategory.HEADERS, PrioritySpec.init, hfa_copy);
	frame.headers.pack(bufs, deflater);	
	frame.headers.free();
}

void packPushPromise(Buffers bufs, ref Deflater deflater, int stream_id, FrameFlags flags, int promised_stream_id, in HeaderField[] hfa) {
	HeaderField[] hfa_copy;
	Frame frame;
	hfa_copy = hfa.copy();
	
	frame.push_promise = PushPromise(flags, stream_id, promised_stream_id, hfa_copy);
	frame.push_promise.pack(bufs, deflater);
	frame.push_promise.free();
}

Buffers framePackBuffers() 
{
	/* 1 for Pad Length */
	return new Buffers(4096, 16, FRAME_HDLEN + 1);
}

Buffers largeBuffers(size_t chunk_size) 
{
	/* 1 for Pad Length */
	return new Buffers(chunk_size, 16, FRAME_HDLEN + 1);
}

private Stream openStreamWithAll(Session session, int stream_id, int weight, bool exclusive, Stream dep_stream)
{
	PrioritySpec pri_spec;
	int dep_stream_id;
	
	if (dep_stream) {
		dep_stream_id = dep_stream.id;
	} else {
		dep_stream_id = 0;
	}
	
	pri_spec = PrioritySpec(dep_stream_id, weight, exclusive);

	return session.openStream(stream_id, StreamFlags.NONE, pri_spec, StreamState.OPENED, null);
}

Stream openStream(Session session, int stream_id) 
{
	return openStreamWithAll(session, stream_id, DEFAULT_WEIGHT, false, null);
}

Stream openStreamWithDep(Session session, int stream_id, Stream dep_stream)
{
	return openStreamWithAll(session, stream_id, DEFAULT_WEIGHT, false, dep_stream);
}

Stream openStreamWithDepWeight(Session session, int stream_id, int weight, Stream dep_stream)
{
	return openStreamWithAll(session, stream_id, weight, false, dep_stream);
}

Stream openStreamWithDepExclusive(Session session, int stream_id, Stream dep_stream) 
{
	return openStreamWithAll(session, stream_id, DEFAULT_WEIGHT, true, dep_stream);
}

OutboundItem createDataOutboundItem() {
	return Mem.alloc!OutboundItem();
}
