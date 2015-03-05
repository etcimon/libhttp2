/*
 * http2 - HTTP/2 C Library
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
module libhttp2.deflater;

import libhttp2.constants;
import libhttp2.types;
import libhttp2.buffers;
import libhttp2.huffman;

//http2_hd_deflater
struct Deflater
{
    HDTable ctx;

    /// The upper limit of the header table size the deflater accepts.
    size_t deflate_hd_table_bufsize_max;

    /// Minimum header table size notified in the next context update
    size_t min_hd_table_bufsize_max;

    /// If nonzero, send header table size using encoding context update in the next deflate process
    bool notify_table_size_change;

	/*
	 * Initializes |deflater| for deflating name/values pairs.
	 *
	 * The encoder only uses up to DEFAULT_MAX_DEFLATE_BUFFER_SIZE bytes
	 * for header table even if the larger value is specified later in changeTableSize().
	 */
	this(size_t _deflate_hd_table_bufsize_max = DEFAULT_MAX_DEFLATE_BUFFER_SIZE)
	{
		ctx = Mem.alloc!HDTable();
		
		if (deflate_hd_table_bufsize_max < HD_DEFAULT_MAX_BUFFER_SIZE) {
			notify_table_size_change = true;
			ctx.hd_table_bufsize_max = _deflate_hd_table_bufsize_max;
		} else {
			notify_table_size_change = false;
		}
		
		deflate_hd_table_bufsize_max = _deflate_hd_table_bufsize_max;
		min_hd_table_bufsize_max = uint.max;
	}

	void free()
	{
		Mem.free(ctx);
	}

	/*
	 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
	 * the |bufs|.
	 *
	 * This function expands |bufs| as necessary to store the result. If
	 * buffers is full and the process still requires more space, this
	 * funtion fails and returns ErrorCode.HEADER_COMP.
	 *
	 * After this function returns, it is safe to delete the |nva|.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 * 
	 * ErrorCode.HEADER_COMP
	 *     Deflation process has failed.
	 * ErrorCode.BUFFER_ERROR
	 *     Out of buffer space.
	 */
	ErrorCode deflate(Buffers bufs, in NVPair[] nva) {
		size_t i;
		ErrorCode rv;
		
		if (ctx.bad)
			return ErrorCode.HEADER_COMP;
		
		if (notify_table_size_change) {
			size_t _min_hd_table_bufsize_max  = min_hd_table_bufsize_max;
			
			notify_table_size_change = false;
			min_hd_table_bufsize_max = uint.max;
			
			if (ctx.hd_table_bufsize_max > _min_hd_table_bufsize_max) {
				
				rv = emitTableSize(bufs, _min_hd_table_bufsize_max);

				if (rv != 0) {
					goto fail;
				}
			}
			
			rv = emitTableSize(bufs, ctx.hd_table_bufsize_max);
			
			if (rv != 0) {
				goto fail;
			}
		}
		
		for (i = 0; i < nva.length; ++i) {
			rv = deflateNV(bufs, nva[i]);
			if (rv != 0)
				goto fail;
		}
		
		DEBUGF(fprintf(stderr, "deflatehd: all input name/value pairs were deflated\n"));
		
		return 0;
	fail:
		DEBUGF(fprintf(stderr, "deflatehd: error return %d\n", rv));
		
		ctx.bad = 1;
		return rv;
	}

	/**
	 * Deflates the |nva|, which has the |nva.length| name/value pairs, into
	 * the |buf| of length |buf.length|.
	 *
	 * If |buf| is not large enough to store the deflated header block,
	 * this function fails with $(D ErrorCode.INSUFF_BUFSIZE).  The
	 * caller should use `Deflater.upperBound()` to know the upper
	 * bound of buffer size required to deflate given header name/value
	 * pairs.
	 *
	 * Once this function fails, subsequent call of this function always
	 * returns $(D ErrorCode.HEADER_COMP).
	 *
	 * After this function returns, it is safe to delete the |nva|.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * $(D ErrorCode.HEADER_COMP)
	 *     Deflation process has failed.
	 * $(D ErrorCode.INSUFF_BUFSIZE)
	 *     The provided |buflen| size is too small to hold the output.
	 */
	ErrorCode deflate(ubyte[] buf, in NVPair[] nva)
	{
		Buffers bufs;
		ErrorCode rv;
		
		mem = ctx.mem;
		
		bufs = Buffers(buf[0 .. buflen]);
				
		rv = deflate(bufs, nva);
		
		buflen = bufs.length;
		
		bufs.free();
		
		if (rv == ErrorCode.BUFFER_ERROR) {
			return ErrorCode.INSUFF_BUFSIZE;
		}
		
		if (rv != 0) {
			return rv;
		}
		
		return cast(int)buflen;
	}

	/**
	 * Returns an upper bound on the compressed size after deflation of |nva|
	 */
	size_t upperBound(in NVPair[] nva) {
		size_t n = 0;
		size_t i;
		
		/* Possible Maximum Header Table Size Change.  Encoding (1u << 31) -
		   1 using 4 bit prefix requires 6 bytes.  We may emit this at most
		   twice. 
		*/
		n += 12;
		
		/* Use Literal Header Field without indexing - New Name, since it is
		   most space consuming format.  Also we choose the less one between
		   non-huffman and huffman, so using literal byte count is
		   sufficient for upper bound.

		   Encoding (1u << 31) - 1 using 7 bit prefix requires 6 bytes.  We
		   need 2 of this for |nvlen| header fields.
		 */
		n += 6 * 2 * nva.length;
		
		for (i = 0; i < nva.length; ++i) {
			n += nva[i].name.length + nva[i].value.length;
		}
		
		return n;
	}

	/**
	 * Changes header table size of the |Deflater| to
	 * |settings_hd_table_bufsize_max| bytes.  This may trigger eviction
	 * in the dynamic table.
	 *
	 * The |settings_hd_table_bufsize_max| should be the value received in
	 * SETTINGS_HEADER_TABLE_SIZE.
	 *
	 * The deflater never uses more memory than ``hd_table_bufsize_max`` bytes 
	 * specified in the constructor.  Therefore, if |settings_hd_table_bufsize_max| > 
	 * ``hd_table_bufsize_max``, resulting maximum table size becomes``hd_table_bufsize_max``.
	 */
	void changeTableSize(size_t settings_hd_table_bufsize_max) {
		import std.algorithm : min;

		size_t next_bufsize = min(settings_hd_table_bufsize_max, deflate_hd_table_bufsize_max);
		
		ctx.hd_table_bufsize_max = next_bufsize;
		
		min_hd_table_bufsize_max = min(min_hd_table_bufsize_max, next_bufsize);
		
		notify_table_size_change = true;
		
		ctx.shrink();

	}
	

package:
	ErrorCode deflateNV(Buffers bufs, const ref NVPair nv) {
		ErrorCode rv;
		int res;
		bool found;
		int idx;
		bool incidx;
		uint name_hash = nv.name.hash();
		uint value_hash = nv.value.hash();
		
		DEBUGF(fprintf(stderr, "deflatehd: deflating "));
		DEBUGF(fwrite(nv.name, 1, stderr));
		DEBUGF(fprintf(stderr, ": "));
		DEBUGF(fwrite(nv.value, 1, stderr));
		DEBUGF(fprintf(stderr, "\n"));		

		res = ctx.search(nv, name_hash, value_hash, found);

		idx = res;
		
		if (found) {
			
			DEBUGF(fprintf(stderr, "deflatehd: name/value match index=%zd\n", idx));
			
			rv = emitIndexedBlock(bufs, idx);

			if (rv != 0)
				return rv;
			
			return 0;
		}
		
		if (idx != -1)
			DEBUGF(fprintf(stderr, "deflatehd: name match index=%zd\n", res));

		
		if (shouldIndex(nv)) 
		{
			HDEntry new_ent;
			if (idx != -1 && idx < cast(int) static_table.length) {
				NVPair nv_indname;
				nv_indname = nv;
				nv_indname.name = ctx.get(idx).nv.name;
				new_ent = ctx.add(nv_indname, name_hash, value_hash, HDFlags.VALUE_ALLOC);
			} else 
				new_ent = ctx.add(nv, name_hash, value_hash, HDFlags.NAME_ALLOC | HDFlags.VALUE_ALLOC);

			if (!new_ent)
				return ErrorCode.HEADER_COMP;


			incidx = true;
		}

		if (idx == -1)
			rv = emitNewNameBlock(bufs, nv, incidx);
		else
			rv = emitIndexedNameBlock(bufs, idx, nv, incidx);
		
		if (rv != 0)
			return rv;

		
		return 0;
	}

	bool shouldIndex(in NVPair nv)
	{
		if ((nv.flags & NVFlags.NO_INDEX) || entryRoom(nv.name.length, nv.value.length) > ctx.hd_table_bufsize_max * 3 / 4) 
		{
			return false;
		}

		return  !name_match(nv, ":path") && 	 	!name_match(nv, "content-length") &&
				!name_match(nv, "set-cookie") && 	!name_match(nv, "etag") &&
				!name_match(nv, "if-modified-since") &&
				!name_match(nv, "if-none-match") && !name_match(nv, "location") &&
				!name_match(nv, "age");
	}

}

package:

ErrorCode emitIndexedNameBlock(Buffers bufs, size_t idx, const ref NVPair nv, bool inc_indexing) {
	ErrorCode rv;
	ubyte* bufp;
	size_t blocklen;
	ubyte[16] sb;
	size_t prefixlen;
	bool no_index;
	
	no_index = (nv.flags & NVFlags.NO_INDEX) != 0;
	
	if (inc_indexing)
		prefixlen = 6;
	else
		prefixlen = 4;
	
	DEBUGF(fprintf(stderr, "deflatehd: emit indname index=%zu, valuelen=%zu, "
			"indexing=%d, no_index=%d\n",
			idx, nv.valuelen, inc_indexing, no_index));
	
	blocklen = countEncodedLength(idx + 1, prefixlen);
	
	if (sizeof(sb) < blocklen) {
		return ErrorCode.HEADER_COMP;
	}
	
	bufp = sb.ptr;
	
	*bufp = packFirstByte(inc_indexing, no_index);
	
	encodeLength(bufp, idx + 1, prefixlen);
	
	rv = bufs.add(sb[0 .. blocklen]);
	if (rv != 0)
		return rv;
		
	rv = emitString(bufs, nv.value);
	if (rv != 0) 
		return rv;
	
	return 0;
}

ErrorCode emitNewNameBlock(Buffers bufs, in NVPair nv, bool inc_indexing) {
	int rv;
	bool no_index;
	
	no_index = (nv.flags & NVFlags.NO_INDEX) != 0;
	
	DEBUGF(fprintf(stderr, "deflatehd: emit newname namelen=%zu, valuelen=%zu, indexing=%d, no_index=%d\n",	nv.name.length, nv.value.length, inc_indexing, no_index));
	
	rv = bufs.add(packFirstByte(inc_indexing, no_index));
	if (rv != 0) {
		return rv;
	}
	
	rv = emitString(bufs, nv.name);
	if (rv != 0) {
		return rv;
	}
	
	rv = emitString(bufs, nv.value);
	if (rv != 0) {
		return rv;
	}
	
	return 0;
}

int emitIndexedBlock(Buffers bufs, size_t idx) {
	int rv;
	size_t blocklen;
	ubyte[16] sb;
	ubyte *bufp;
	
	blocklen = countEncodedLength(idx + 1, 7);
	
	DEBUGF(fprintf(stderr, "deflatehd: emit indexed index=%zu, %zu bytes\n", idx,
			blocklen));
	
	if (sizeof(sb) < blocklen) {
		return ErrorCode.HEADER_COMP;
	}
	
	bufp = sb.ptr;
	*bufp = 0x80;
	encodeLength(bufp, idx + 1, 7);
	
	rv = bufs.add(sb[0 .. blocklen]);
	if (rv != 0) {
		return rv;
	}
	
	return 0;
}

ErrorCode emitString(Buffers bufs, in ubyte[] str) {
	ErrorCode rv;
	size_t len = str.length;
	ubyte[16] sb;
	ubyte *bufp;
	size_t blocklen;
	size_t enclen;
	bool huffman;

	{ // count the required bytes for encoding str
		size_t i;
		size_t nbits = 0;
		
		for (i = 0; i < len; ++i) {
			nbits += symbol_table[str[i]].nbits;
		}
		/* pad the prefix of EOS (256) */
		enclen = (nbits + 7) / 8;
	}
	
	if (enclen < len)
		huffman = true;
	else
		enclen = len;
	
	blocklen = countEncodedLength(enclen, 7);
	
	DEBUGF(fprintf(stderr, "deflatehd: emit string str="));
	DEBUGF(fwrite(str, len, 1, stderr));
	DEBUGF(fprintf(stderr, ", length=%zu, huffman=%d, encoded_length=%zu\n", len, huffman, enclen));
	
	if (sizeof(sb) < blocklen) {
		return ErrorCode.HEADER_COMP;
	}
	
	bufp = sb.ptr;
	*bufp = huffman ? 1 << 7 : 0;
	encodeLength(bufp, enclen, 7);
	
	rv = bufs.add(sb[0 .. blocklen]);

	if (rv != 0)
		return rv;
		
	if (huffman) {
		rv = encodeHuffman(bufs, str);
	} else {
		assert(enclen == len);
		rv = bufs.add(str);
	}
	
	return rv;
}


ErrorCode emitTableSize(Buffers bufs, size_t table_size) {
	ErrorCode rv;
	ubyte *bufp;
	size_t blocklen;
	ubyte[16] sb;
	
	DEBUGF(fprintf(stderr, "deflatehd: emit table_size=%zu\n", table_size));
	
	blocklen = countEncodedLength(table_size, 5);
	
	if (sb.length < blocklen) {
		return ErrorCode.HEADER_COMP;
	}
	
	bufp = sb.ptr;
	
	*bufp = 0x20;
	
	encodeLength(bufp, table_size, 5);
	
	rv = bufs.add(sb[0 .. blocklen]);
	if (rv != 0)
		return rv;
	
	return 0;
}

ubyte packFirstByte(bool inc_indexing, bool no_index) {
	if (inc_indexing) 
		return 0x40;	
	if (no_index)
		return 0x10;	
	return 0;
}

size_t encodeLength(ubyte* buf, size_t n, size_t prefix) {
	size_t k = (1 << prefix) - 1;
	ubyte *begin = buf;
	
	*buf &= ~k;
	
	if (n < k) {
		*buf |= n;
		return 1;
	}
	
	*buf++ |= k;
	n -= k;
	
	for (; n >= 128; n >>= 7) {
		*buf++ = (1 << 7) | (n & 0x7f);
	}
	
	*buf++ = cast(ubyte)n;
	
	return cast(size_t)(buf - begin);
}


/*
 * Encodes the given data |src| with length |srclen| to the |bufs|.
 * This function expands extra buffers in |bufs| if necessary.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.BUFFER_ERROR
 *     Out of buffer space.
 */
ErrorCode encodeHuffman(Buffers bufs, in ubyte[] src) {
	ErrorCode rv;
	int rembits = 8;
	size_t i;
	size_t avail;

	avail = bufs.curAvailable;
	
	for (i = 0; i < src.length; ++i) 
	{
		const Symbol sym = symbol_table[src[i]];
		if (rembits == 8) {
			if (avail) {
				bufs.addHold(0);
			} else {
				rv = bufs.addHold(0);
				if (rv != 0) {
					return rv;
				}
				avail = bufs.curAvailable;
			}
		}
		rembits = sym.encode(bufs, avail, rembits);
		if (rembits < 0) {
			return cast(ErrorCode) rembits;
		}
	}
	/* 256 is special terminal symbol, pad with its prefix */
	if (rembits < 8) {
		/* if rembits < 8, we should have at least 1 buffer space available */
		const Symbol sym = symbol_table[256];
		assert(avail);
		/* Caution we no longer adjust avail here */
		bufs.fastOr(sym.code >> (sym.nbits - rembits));
	}
	
	return 0;
}

size_t countEncodedLength(size_t n, size_t prefix) {
    size_t k = (1 << prefix) - 1;
    size_t len = 0;
    
    if (n < k) {
        return 1;
    }
    
    n -= k;
    ++len;
    
    for (; n >= 128; n >>= 7, ++len)
        continue;
    
    return len + 1;
}
