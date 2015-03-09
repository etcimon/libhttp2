module libhttp2.inflater;

import libhttp2.types;
import libhttp2.buffers;
import libhttp2.huffman;
import std.algorithm : min;

//http2_hd_inflater
struct Inflater
{
	HDTable ctx;
	
	/// header buffer
	Buffers hfbufs;
	
	/// Stores current state of huffman decoding
	Decoder huff_decoder;
	
	/// Pointer to the entry which is used current header emission, for reference counting purposes.
	HDEntry ent_keep;
	
	/// The number of bytes to read
	size_t left;
	
	/// The index in indexed repr or indexed name
	size_t index;
	
	/// The length of new name encoded in literal.  For huffman encoded string, this is the length after it is decoded.
	size_t newnamelen;
	
	/// The maximum header table size the inflater supports. This is the same value transmitted in SETTINGS_HEADER_TABLE_SIZE
	size_t settings_hd_table_bufsize_max = HD_DEFAULT_MAX_BUFFER_SIZE;
	
	/// The number of next shift to decode integer 
	size_t shift;
	
	OpCode opcode = OpCode.NONE;
	
	InflateState state = InflateState.OPCODE;
	
	/// true if string is huffman encoded
	bool huffman_encoded;
	
	/// true if deflater requires that current entry is indexed
	bool index_required;
	
	/// true if deflater requires that current entry must not be indexed
	bool no_index;
	
	this(bool dummy = false) {
		ctx = Mem.alloc!HDTable();
		scope(failure) Mem.free(ctx);
		hfbufs = Mem.alloc!Buffers(MAX_HF_LEN / 8, 8, 1, 0);
	}

	void free() {
		Mem.free(ctx);
		hfbufs.free();
		Mem.free(hfbufs);
	}

	/**
	 * Changes header table size in the |Inflater|.  This may trigger
	 * eviction in the dynamic table.
	 *
	 * The |settings_hd_table_bufsize_max| should be the value transmitted
	 * in SETTINGS_HEADER_TABLE_SIZE.
	 */
	void changeTableSize(size_t settings_hd_table_bufsize_max) 
	{
		settings_hd_table_bufsize_max = settings_hd_table_bufsize_max;
		ctx.hd_table_bufsize_max = settings_hd_table_bufsize_max;
		shrink();
	}

	/**
	 * Inflates name/value block stored in |input| with length |input.length|. 
	 * This function performs decompression.  For each successful emission of
	 * header field, $(D InflateFlag.EMIT) is set in |inflate_flags| and a header field
	 * is assigned to |hf_out| and the function returns.  The caller must not free 
	 * the members of |hf_out|.
	 *
	 * The |hf_out| may include pointers to the memory region in the |input|.
	 * The caller must retain the |input| while the |hf_out| is used.
	 *
	 * The application should call this function repeatedly until the
	 * `(*inflate_flags) & InflateFlag.FINAL` is true and
	 * return value is non-negative. This means the all input values are
	 * processed successfully.  Then the application must call
	 * `endHeaders()` to prepare for the next header
	 * block input.
	 *
	 * The caller can feed complete compressed header block.  It also can
	 * feed it in several chunks.  The caller must set |is_final| to
	 * true if the given input is the last block of the compressed
	 * header.
	 *
	 * This function returns the number of bytes processed if it succeeds,
	 * or one of the following negative error codes:
	 *
	 * $(D ErrorCode.HEADER_COMP)
	 *     Inflation process has failed.
	 * $(D ErrorCode.BUFFER_ERROR)
	 *     The heder field name or value is too large.
	 *
	 * Example follows::
	 *
	 *     void inflateHeaderBlock(ref Inflater hd_inflater, ubyte[] input, bool final)
	 *     {
	 *         size_t rv;
	 *
	 *         for(;;) {
	 *             HeaderField nv;
	 *             InflateFlag inflate_flags;
	 *
	 *             rv = hd_inflater.inflate(hf, inflate_flags, input, final);
	 *
	 *             if(rv < 0) {
	 *                 fprintf(stderr, "inflate failed with error code %zd", rv);
	 *                 return;
	 *             }
	 *
	 *             input = input[rv .. $];
	 *
	 *             if(inflate_flags & InflateFlag.EMIT) {
	 *                 fwrite(hf.name, 1, stderr);
	 *                 fprintf(stderr, ": ");
	 *                 fwrite(hf.value, 1, stderr);
	 *                 fprintf(stderr, "\n");
	 *             }
	 * 
	 *             if(inflate_flags & InflateFlag.FINAL) {
	 *                 hd_inflater.endHeaders();
	 *                 break;
	 *             }
	 *             if((inflate_flags & InflateFlag.EMIT) == 0 && input.length == 0) {
	 *                break;
	 *             }
	 *         }
	 *     }
	 *
	 */
	ErrorCode inflate()(ref HeaderField hf_out, auto ref InflateFlag inflate_flags, ubyte[] input, bool is_final)
	{
		ErrorCode rv;
		ubyte* pos = input.ptr;
		ubyte* first = input.ptr;
		ubyte* last = input.ptr + input.length;
		bool rfin; // read finished
		
		if (ctx.bad) return ErrorCode.HEADER_COMP;
		scope(failure) ctx.bad = 1;
		
		DEBUGF(fprintf(stderr, "inflatehd: start state=%d\n", state));

		ent_keep = HDEntry.init;
		inflate_flags = InflateFlag.NONE;

		for (; pos != last;) {
			switch (state) {
				case InflateState.OPCODE:
					if ((*pos & 0xe0) == 0x20) {
						DEBUGF(fprintf(stderr, "inflatehd: header table size change\n"));
						opcode = OpCode.INDEXED;
						state = InflateState.READ_TABLE_SIZE;
					} else if (*pos & 0x80) {
						DEBUGF(fprintf(stderr, "inflatehd: indexed repr\n"));
						opcode = OpCode.INDEXED;
						state = InflateState.READ_INDEX;
					} else {
						if (*pos == 0x40 || *pos == 0 || *pos == 0x10) {
							DEBUGF(fprintf(stderr, "inflatehd: literal header repr - new name\n"));
							opcode = OpCode.NEWNAME;
							state = InflateState.NEWNAME_CHECK_NAMELEN;
						} else {
							DEBUGF(fprintf(stderr, "inflatehd: literal header repr - indexed name\n"));
							opcode = OpCode.INDNAME;
							state = InflateState.READ_INDEX;
						}
						index_required = (*pos & 0x40) != 0;
						no_index = (*pos & 0xf0) == 0x10;
						DEBUGF(fprintf(stderr, "inflatehd: indexing required=%d, no_index=%d\n", index_required, no_index));

						if (opcode == OpCode.NEWNAME)
							++pos;
					}
					left = 0;
					shift = 0;
					break;
				case InflateState.READ_TABLE_SIZE:
					rfin = false;
					rv = readLength(rfin, pos, last, 5, settings_hd_table_bufsize_max);
					if (rv < 0) 
						goto fail;

					pos += rv;

					if (!rfin)
						goto almost_ok;

					DEBUGF(fprintf(stderr, "inflatehd: table_size=%zu\n", left));
					ctx.hd_table_bufsize_max = left;
					ctx.shrink();
					state = InflateState.OPCODE;
					break;
				case InflateState.READ_INDEX: {
					size_t prefixlen;
					
					if (opcode == OpCode.INDEXED)
						prefixlen = 7;
					else if (index_required)
						prefixlen = 6;
					else 
						prefixlen = 4;

					rfin = false;
					size_t maxlen = ctx.hd_table.length + static_table.length;
					rv = readLength(rfin, pos, last, prefixlen, maxlen);

					if (rv < 0) 
						goto fail;
										
					pos += rv;
					
					if (!rfin)
						goto almost_ok;
										
					if (left == 0) {
						rv = ErrorCode.HEADER_COMP;
						goto fail;
					}
					
					DEBUGF(fprintf(stderr, "inflatehd: index=%zu\n", left));
					if (opcode == OpCode.INDEXED) {
						index = left;
						--index;
						
						hf_out = commitIndexed();

						if (hf_out == HeaderField.init)
							goto fail;

						state = InflateState.OPCODE;
						/* If rv == 1, no header was emitted */
						if (rv == 0) {
							*inflate_flags |= InflateFlag.EMIT;
							return cast(int)(pos - first);
						}
					} else {
						index = left;
						--index;
						
						state = InflateState.CHECK_VALUELEN;
					}
					break;
				}
				case InflateState.NEWNAME_CHECK_NAMELEN:
					setHuffmanEncoded(pos);
					state = InflateState.NEWNAME_READ_NAMELEN;
					left = 0;
					shift = 0;
					DEBUGF(fprintf(stderr, "inflatehd: huffman encoded=%d\n", huffman_encoded != 0));
					/* Fall through */
				case InflateState.NEWNAME_READ_NAMELEN:
					rfin = false;
					rv = readLength(rfin, pos, last, 7, MAX_HF_LEN);

					if (rv < 0)
						goto fail;

					pos += rv;
					if (!rfin) {
						DEBUGF(fprintf(stderr, "inflatehd: integer not fully decoded. current=%zu\n", left));						
						goto almost_ok;
					}
					
					if (huffman_encoded) {
						huff_decoder = Decoder.init;						
						state = InflateState.NEWNAME_READ_NAMEHUFF;
					} else
						state = InflateState.NEWNAME_READ_NAME;
					break;
				case InflateState.NEWNAME_READ_NAMEHUFF:
					rv = readHuffman(hfbufs, pos, last);

					if (rv < 0)
						goto fail;

					pos += rv;
					
					DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));
					
					if (left) {
						DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n", left));
						goto almost_ok;
					}
					
					newnamelen = hfbufs.length;
					
					state = InflateState.CHECK_VALUELEN;
					
					break;
				case InflateState.NEWNAME_READ_NAME:
					rv = read(hfbufs, pos, last);

					if (rv < 0)
						goto fail;
					
					pos += rv;
					
					DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));
					if (left) {
						DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n", left));
						
						goto almost_ok;
					}
					
					newnamelen = hfbufs.length;
					
					state = InflateState.CHECK_VALUELEN;
					
					break;
				case InflateState.CHECK_VALUELEN:
					setHuffmanEncoded(pos);
					state = InflateState.READ_VALUELEN;
					left = 0;
					shift = 0;
					DEBUGF(fprintf(stderr, "inflatehd: huffman encoded=%d\n", huffman_encoded != 0));

					/* Fall through */
				case InflateState.READ_VALUELEN:
					rfin = false;
					rv = readLength(rfin, pos, last, 7, MAX_HF_LEN);
					if (rv < 0)
						goto fail;
										
					pos += rv;
					
					if (!rfin)
						goto almost_ok;
										
					DEBUGF(fprintf(stderr, "inflatehd: valuelen=%zu\n", left));
					if (left == 0) {
						if (opcode == OpCode.NEWNAME)
							hf_out = commitNewName();
						else
							hf_out = commitIndexedName();

						if (rv != 0)
							goto fail;

						state = InflateState.OPCODE;
						inflate_flags |= InflateFlag.EMIT;
						return cast(int)(pos - first);
					}
					
					if (huffman_encoded) {
						huff_decoder = Decoder.init;
						
						state = InflateState.READ_VALUEHUFF;
					} else {
						state = InflateState.READ_VALUE;
					}
					break;
				case InflateState.READ_VALUEHUFF:
					rv = readHuffman(hfbufs, pos, last);

					if (rv < 0) 
						goto fail;
										
					pos += rv;
					
					DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));
					
					if (left) {
						DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n", left));
						
						goto almost_ok;
					}
					
					if (opcode == OpCode.NEWNAME) 
						hf_out = commitNewName();
					else
						hf_out = commitIndexedName();
															
					state = InflateState.OPCODE;
					inflate_flags |= InflateFlag.EMIT;
					
					return cast(int)(pos - first);

				case InflateState.READ_VALUE:
					rv = read(hfbufs, pos, last);

					if (rv < 0) {
						DEBUGF(fprintf(stderr, "inflatehd: value read failure %zd: %s\n", rv, toString(cast(ErrorCode)rv)));
						goto fail;
					}
					
					pos += rv;
					
					DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));
					
					if (left) {
						DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n", left));
						goto almost_ok;
					}
					
					if (opcode == OpCode.NEWNAME)
						hf_out = commitNewName();
					else
						hf_out = commitIndexedName();

					state = InflateState.OPCODE;
					inflate_flags |= InflateFlag.EMIT;
					
					return cast(int)(pos - first);
			}
		}
		
		assert(pos is last);
		
		DEBUGF(fprintf(stderr, "inflatehd: all input bytes were processed\n"));
		
		if (is_final) {
			DEBUGF(fprintf(stderr, "inflatehd: is_final set\n"));
			
			if (state != InflateState.OPCODE) {
				DEBUGF(fprintf(stderr, "inflatehd: unacceptable state=%d\n", state));
				rv = ErrorCode.HEADER_COMP;
				
				goto fail;
			}
			inflate_flags |= InflateFlag.FINAL;
		}
		return cast(int)(pos - first);
		
	almost_ok:
		if (is_final && state != InflateState.OPCODE) {
			DEBUGF(fprintf(stderr, "inflatehd: input ended prematurely\n"));			
			rv = ErrorCode.HEADER_COMP;			
			goto fail;
		}

		return cast(int)(pos - first);
		
	fail:
		DEBUGF(fprintf(stderr, "inflatehd: error return %zd\n", rv));		
		ctx.bad = 1;
		return rv;
		
	}

	/**
	 * Signals the end of decompression for one header block.
	 */
	void endHeaders() {
		ent_keep = HDEntry.init;
	}

	void setHuffmanEncoded(in ubyte* input) {
		huffman_encoded = (*input & (1 << 7)) != 0;
	}
	
	/*
	 * Decodes the integer from the range [in, last).  The result is
	 * assigned to |left|.  If the |left| is 0, then
	 * it performs variable integer decoding from scratch. Otherwise, it
	 * uses the |left| as the initial value and continues to
	 * decode assuming that [in, last) begins with intermediary sequence.
	 *
	 * This function returns the number of bytes read if it succeeds, or
	 * one of the following negative error codes:
	 *
	 * ErrorCode.HEADER_COMP
	 *   Integer decoding failed
	 */
	int readLength(ref bool is_final, ubyte* input, ubyte* last, size_t prefix, size_t maxlen) 
	{
		int rv;
		uint output;
		
		is_final = false;

		rv = decodeLength(output, shift, is_final, cast(uint)left, shift, input, last, prefix);
		
		if (rv == -1) {
			DEBUGF(fprintf(stderr, "inflatehd: integer decoding failed\n"));
			return cast(int)ErrorCode.HEADER_COMP;
		}
		
		if (output > maxlen) {
			DEBUGF(fprintf(stderr, "inflatehd: integer exceeded the maximum value %zu\n", maxlen));
			return cast(int)ErrorCode.HEADER_COMP;
		}
		
		left = output;
		
		DEBUGF(fprintf(stderr, "inflatehd: decoded integer is %u\n", output));
		
		return rv;
	}
	
	/*
	 * Reads |left| bytes from the range [in, last) and performs
	 * huffman decoding against them and pushes the result into the
	 * |buffer|.
	 *
	 * This function returns the number of bytes read if it succeeds, or
	 * one of the following negative error codes:
	 *
	 * ErrorCode.HEADER_COMP
	 *   Huffman decoding failed
	 * ErrorCode.BUFFER_ERROR
	 *     Out of buffer space.
	 */
	int readHuffman(Buffers bufs, ubyte* input, ubyte* last) {
		int readlen;
		bool rfin;

		if (cast(size_t) (last - input) >= left) {
			last = input + left;
			rfin = true;
		}

		readlen = huff_decoder.decode(bufs, input, last - input, rfin);

		if (readlen < 0) {
			DEBUGF(fprintf(stderr, "inflatehd: huffman decoding failed\n"));
			return readlen;
		}
		left -= cast(size_t)readlen;
		return readlen;
	}
	
	/*
	 * Reads |left| bytes from the range [in, last) and copies
	 * them into the |buffer|.
	 *
	 * This function returns the number of bytes read if it succeeds, or
	 * one of the following negative error codes:
	 *
	 * ErrorCode.HEADER_COMP
	 *   Header decompression failed
	 * ErrorCode.BUFFER_ERROR
	 *     Out of buffer space.
	 */
	int read(Buffers bufs, ubyte* input, ubyte* last) 
	{
		ErrorCode rv;
		size_t len = min(cast(size_t)(last - input), left);

		rv = bufs.add(input[0 .. len]);

		if (rv != 0)
			return cast(int) rv;

		left -= len;
		return cast(int) len;
	}

	HeaderField removeBufs(bool value_only) {
		HeaderField nv;
		size_t buflen;
		ubyte[] buf;
		Buffer* pbuf;
		
		if (index_required || hfbufs.head != hfbufs.cur) {			
			buf = hfbufs.remove();			
			buflen = buf.length;
			
			if (value_only)
				hf.name = null;
			else
				hf.name = buf[0 .. newnamelen];
			
			hf.value = (buf + hf.name.length)[0 .. buflen - hf.name.length];
			
			return nv;
		}
		
		// If we are not going to store header in header table and name/value are in first chunk, 
		// we just refer them from hf, instead of mallocing another memory.		
		pbuf = &hfbufs.head.buf;
		
		if (value_only)
			hf.name = null;
		else
			hf.name = pbuf.pos[0 .. newnamelen];
		
		hf.value = (pbuf.pos + hf.name.length)[0 .. pbuf.length - hf.name.length];
		
		// Resetting does not change the content of first buffer
		hfbufs.reset();
		
		return nv;
	}

package:	
	/*
	 * Finalize literal header representation - new name- reception. If
	 * header is emitted, it is returned
	 */
	HeaderField commitNewName() {
		HeaderField hf = removeBufs(false);
		HeaderField ret;
		
		if (no_index)
			hf.flag = HeaderFlag.NO_INDEX;
		else
			hf.flag = HeaderFlag.NONE;
		
		if (index_required) {
			HDEntry new_ent;
			HDFlags ent_flags;
			
			/* hf.value points to the middle of the buffer pointed by
		       hf.name.  So we just need to keep track of hf.name for memory
		       management. */
			ent_flags = HDFlags.NAME_ALLOC | HDFlags.NAME_GIFT;
			
			new_ent = ctx.add(hf, hf.name.hash(), hf.value.hash(), ent_flags);
			
			ret = emitIndexedHeader(new_ent);
			
			ent_keep = new_ent;
			
			return ret;
		}
		
		ret = emitLiteralHeader(nv);
		
		return ret;
	}
	
	/// Finalize literal header representation - indexed name reception. If header is emitted, the HeaderField is returned
	HeaderField commitIndexedName() {
		HeaderField ret;
		HDEntry ent_name;
		
		HeaderField hf = removeBufs(true /* value only */);
		
		if (no_index)
			hf.flag = HeaderFlag.NO_INDEX;
		else
			hf.flag = HeaderFlag.NONE;
		
		ent_name = ctx.get(index);		
		hf.name = ent_name.hf.name;
		
		if (index_required) {
			HDEntry new_ent;
			HDFlags ent_flags;
			bool static_name;
			
			ent_flags = HDFlags.VALUE_ALLOC | HDFlags.VALUE_GIFT;
			static_name = index < static_table.length;
			
			if (!static_name) 
				ent_flags |= HDFlags.NAME_ALLOC;
			
			new_ent = ctx.add(hf, ent_name.name_hash, hf.value.hash(), ent_flags);
			ret = emitIndexedHeader(new_ent);
			ent_keep = new_ent;
			
			return ret;
		}
		
		ret = emitLiteralHeader(nv);
		
		return 0;
	}

	/*
	 * Finalize indexed header representation reception. If header is
	 * emitted, returns it
	 */
	HeaderField commitIndexed() {
		HDEntry ent = ctx.get(index);		
		return emitIndexedHeader(ent);
	}

	// for debugging
	HeaderField emitIndexedHeader(ref HDEntry ent) {
		DEBUGF(fprintf(stderr, "inflatehd: header emission: "));
		DEBUGF(fwrite(ent.hf.name, 1, stderr));
		DEBUGF(fprintf(stderr, ": "));
		DEBUGF(fwrite(ent.hf.value, 1, stderr));
		DEBUGF(fprintf(stderr, "\n"));
		
		return ent.nv;
	}
	
	HeaderField emitLiteralHeader(ref HeaderField nv) {
		DEBUGF(fprintf(stderr, "inflatehd: header emission: "));
		DEBUGF(fwrite(hf.name, 1, stderr));
		DEBUGF(fprintf(stderr, ": "));
		DEBUGF(fwrite(hf.value, 1, stderr));
		DEBUGF(fprintf(stderr, "\n"));
		
		return nv;
	}


}


