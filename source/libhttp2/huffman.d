/**
 * Huffman
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.huffman;

import libhttp2.types;
import libhttp2.buffers;
import libhttp2.constants;
import memutils.circularbuffer;
import memutils.utils;
import core.exception;

const HD_DEFAULT_MAX_BUFFER_SIZE = DEFAULT_HEADER_TABLE_SIZE;

const ENTRY_OVERHEAD = 32;

/// The maximum length of one header field.  This is the sum of the length of name and value.  
/// This is not specified by the spec. We just chose the arbitrary size */
const MAX_HF_LEN = 65536;

/// Default size of maximum table buffer size for encoder. Even if remote decoder notifies 
/// larger buffer size for its decoding, encoder only uses the memory up to this value.
const DEFAULT_MAX_DEFLATE_BUFFER_SIZE = (1 << 12);


/// The flags for header inflation.
enum InflateFlag : ubyte
{
	/// No flag set.
	NONE = 0,
	
	/// Indicates all headers were inflated.
	FINAL = 0x01,
	
	/// Indicates a header was emitted.
	EMIT = 0x02
}

package:

enum HDFlags 
{
	NONE = 0,
	/* Indicates name was dynamically allocated and must be freed */
	NAME_ALLOC = 1,
	/* Indicates value was dynamically allocated and must be freed */
	VALUE_ALLOC = 1 << 1,
	/* Indicates that the name was gifted to the entry and no copying
     necessary. */
	NAME_GIFT = 1 << 2,
	/* Indicates that the value was gifted to the entry and no copying
     necessary. */
	VALUE_GIFT = 1 << 3
}

class HDEntry
{
	HeaderField hf;
	uint name_hash;
	uint value_hash;
	HDFlags flags;

	/*
	 * Initializes the HDEntry members. If HDFlags.NAME_ALLOC bit
	 * set in the |flags|, the content pointed by the |name| with length
	 * |name.length| is copied. Likewise, if HDFlags.VALUE_ALLOC bit
	 * set in the |flags|, the content pointed by the |value| with length
	 * |valuelen| is copied.  The |name_hash| and |value_hash| are hash
	 * value for |name| and |value| respectively.
	 */
	this(HDFlags _flags, in string name,  in string value, uint _name_hash, uint _value_hash) {
		int rv = 0;
		
		flags = _flags;
		
		/// Since HDEntry is used for indexing, ent.hf.flag always HeaderFlag.NONE
		hf.flag = HeaderFlag.NONE;
		
		if ((flags & HDFlags.NAME_ALLOC) && (flags & HDFlags.NAME_GIFT) == 0) {
			if (name.length == 0)
				/* We should not allow empty header field name */
				hf.name = null;
			else
				hf.name = cast(string)Mem.copy(name);

		} else
			hf.name = cast(string)name;
		
		scope(failure)
		if (flags & HDFlags.NAME_ALLOC) {
			Mem.free(hf.name);
		}
		
		if ((flags & HDFlags.VALUE_ALLOC) && (flags & HDFlags.VALUE_GIFT) == 0) {
			if (value.length == 0)
				hf.value = null;
			else
				hf.value = cast(string) Mem.copy(value);
		} else {
			hf.value = cast(string) value;
		}
				
		name_hash = _name_hash;
		value_hash = _value_hash;
	}
	
	~this() 
	{
		if (flags & HDFlags.NAME_ALLOC) {
			Mem.free(hf.name);
		}
		
		if (flags & HDFlags.VALUE_ALLOC) {
			Mem.free(hf.value);
		}
	}
}

struct StaticEntry {
	HDEntry ent;
	size_t index;
}

enum OpCode 
{
	NONE,
	INDEXED,
	NEWNAME,
	INDNAME
}

enum InflateState 
{
	OPCODE,
	READ_TABLE_SIZE,
	READ_INDEX,
	NEWNAME_CHECK_NAMELEN,
	NEWNAME_READ_NAMELEN,
	NEWNAME_READ_NAMEHUFF,
	NEWNAME_READ_NAME,
	CHECK_VALUELEN,
	READ_VALUELEN,
	READ_VALUEHUFF,
	READ_VALUE
}

class HDTable
{
	/// dynamic header table
	CircularBuffer!HDEntry hd_table;
	
	/// Abstract buffer size of hd_table as described in the spec. This is the sum of length of name/value in hd_table +
	/// ENTRY_OVERHEAD bytes overhead per each entry.
	size_t hd_table_bufsize;
	
	/// The effective header table size.
	size_t hd_table_bufsize_max = HD_DEFAULT_MAX_BUFFER_SIZE;
	
	/// If inflate/deflate error occurred, this value is set to 1 and further invocation of inflate/deflate will fail with ErrorCode.HEADER_COMP.
	bool bad;
	
	this() {
		hd_table = CircularBuffer!HDEntry(hd_table_bufsize_max / ENTRY_OVERHEAD);
	}
	
	void shrink(size_t room = 0) 
	{
		while (hd_table_bufsize + room > hd_table_bufsize_max && hd_table.length > 0) {
			// TODO: Debugging printf

			size_t idx = hd_table.length - 1;
			HDEntry ent = hd_table[idx];
			hd_table_bufsize -= entryRoom(ent.hf.name.length, ent.hf.value.length);
			hd_table.popBack();
		}
	}
	
	HDEntry add(const ref HeaderField hf, uint name_hash, uint value_hash, HDFlags entry_flags) {
		int rv;
		HDEntry new_ent;
		size_t room = entryRoom(hf.name.length, hf.value.length);		
		shrink(room);

		new_ent = new HDEntry(entry_flags, hf.name, hf.value, name_hash, value_hash);

		if (room <= hd_table_bufsize_max) {
			hd_table.put(new_ent);
			hd_table_bufsize += room;
		}

		return new_ent;
	}

	HDEntry get(size_t idx) {
		assert(idx < hd_table.length + static_table.length);

		if (idx >= static_table.length) 
			return hd_table[idx - static_table.length];

		return static_table[static_table_index[idx]].ent;

	}

	int search(const ref HeaderField hf, uint name_hash, uint value_hash, ref bool found) {
		int left = -1;
		int right = cast(int) static_table.length;
		size_t i;
		int res = -1;

		int use_index = (hf.flag & HeaderFlag.NO_INDEX) == 0;
		
		// Search dynamic table first, so that we can find recently used entry first
		if (use_index) {
			for (i = 0; i < hd_table.length; ++i) {
				HDEntry* ent = &hd_table[i];

				if (ent.name_hash != name_hash || ent.hf.name != hf.name)
					continue;

				if (res == -1)
					res =  cast(int) (i + static_table.length);

				if (ent.value_hash == value_hash && ent.hf.value == hf.value) {
					found = true;
					return cast(int) (i + static_table.length);
				}
			}
		}
		
		while (right - left > 1) {
			size_t mid = (left + right) / 2;
			HDEntry* ent = &static_table[mid].ent;
			if (ent.name_hash < name_hash)
				left = cast(int) mid;
			else
				right = cast(int) mid;
		}
		
		for (i = right; i < static_table.length; ++i) {
			HDEntry* ent = &static_table[i].ent;
			if (ent.name_hash != name_hash)
				break;
			
			if (ent.hf.name == hf.name)
			{
				if (res == -1)
					res =  cast(int) (i + static_table.length);

				if (use_index && ent.value_hash == value_hash && ent.hf.value == hf.value) 
				{
					found = true;
					return cast(int) (static_table[i].index);
				}
			}
		}
		
		return res;
	}
}


enum DecodeFlag : int {
	NONE = 0,
	/// FSA accepts this state as the end of huffman encoding sequence.
	ACCEPTED = 1,
	/* This state emits symbol */
	SYM = (1 << 1),
	/* If state machine reaches this state, decoding fails. */
	FAIL = (1 << 2)
}

struct Decode {
	/* huffman decoding state, which is actually the node ID of internal
     huffman tree.  We have 257 leaf nodes, but they are identical to
     root node other than emitting a symbol, so we have 256 internal
     nodes [1..255], inclusive. */
	ubyte state;
	/// bitwise OR of zero or more of the DecodeFlag
	DecodeFlag flags;
	/// symbol if DecodeFlag.SYM flag set
	ubyte sym;
} 

alias DecodeTable = Decode[16];

struct Decoder
{
	/* Current huffman decoding state. We stripped leaf nodes, so the value range is [0..255], inclusive. */
	ubyte state;

	/// true if we can say that the decoding process succeeds at this state
	bool accept = true;

	/*
	 * Decodes the given data |src|. The |ctx| must
	 * be initialized by DecodeConext.init. The result
	 * will be added to |dest|. This function may expand |dest| as
	 * needed. The caller is responsible to release the memory of |dest|
	 * by calling Buffers.free() or export its content using
	 * Buffers.remove().
	 *
	 * The caller must set the |is_final| to true if the given input is
	 * the final block.
	 *
	 * This function returns the number of read bytes from the |src|.
	 *
	 * If this function fails, it returns one of the following negative
	 * return codes:
	 *
	 * ErrorCode.NOMEM
	 *     Out of memory.
	 * ErrorCode.BUFFER_ERROR
	 *     Maximum buffer capacity size exceeded.
	 * ErrorCode.HEADER_COMP
	 *     Decoding process has failed.
	 */
	int decode(Buffers bufs, in ubyte[] src, bool is_final)
	{
		size_t i, j;
		ErrorCode rv;
		int avail = bufs.curAvailable;
		
		/* We use the decoding algorithm described in http://graphics.ics.uci.edu/pub/Prefix.pdf */
		for (i = 0; i < src.length; ++i) {
			ubyte input = src[i] >> 4;
			for (j = 0; j < 2; ++j) {
				const Decode t = decode_table[state][input];

				if (t.flags & DecodeFlag.FAIL) {
					return ErrorCode.HEADER_COMP;
				}

				if (t.flags & DecodeFlag.SYM) {
					if (avail) {
						bufs.fastAdd(t.sym);
						--avail;
					} else {
						rv = bufs.add(t.sym);
						if (rv != 0)
							return cast(int)rv;
						avail = bufs.curAvailable;
					}
				}

				state = t.state;
				accept = (t.flags & DecodeFlag.ACCEPTED) != 0;
				input = src[i] & 0xf;
			}
		}

		if (is_final && !accept)
			return cast(int) ErrorCode.HEADER_COMP;

		return cast(int)i;
	}

}


/*
 * Decodes |prefix| prefixed integer stored from |input|.  The |last|
 * represents the 1 beyond the last of the valid contiguous memory
 * region from |input|.  The decoded integer must be less than or equal
 * to uint.max.
 *
 * If the |n| is nonzero, it is used as a initial value, this
 * function assumes the |input| starts with intermediate data.
 *
 * If an entire integer is decoded successfully, the |is_final| is
 * set to true.
 *
 * This function stores the decoded integer in |res| if it succeed,
 * including partial decoding (in this case, number of shift to make
 * in the next call will be stored in |shift_ptr|) and returns number
 * of bytes processed, or returns -1, indicating decoding error.
 */
int decodeLength(ref uint res, ref size_t shift_ptr, ref bool is_final, // <-- output
				 uint n /* initial */, size_t shift, ubyte* input, ubyte* last, size_t prefix) 
{
	uint k = (1 << prefix) - 1;
	ubyte* start = input;

	shift_ptr = 0;
	is_final = false;
	
	if (n == 0) {
		if ((*input & k) != k) {
			res = (*input) & k;
			is_final = true;
			return true;
		}
		
		n = k;
		
		if (++input == last) {
			res = n;
			return cast(int)(input - start);
		}
	}
	
	for (; input != last; ++input, shift += 7) {
		uint add = *input & 0x7f;
		
		if ((uint.max >> shift) < add) {
			LOGF("inflate: integer overflow on shift\n");
			return -1;
		}
		
		add <<= shift;
		
		if (uint.max - add < n) {
			LOGF("inflate: integer overflow on addition\n");
			return -1;
		}
		
		n += add;
		
		if ((*input & (1 << 7)) == 0) 
			break;
	}
	
	shift_ptr = shift;
	
	if (input == last) {
		res = n;
		return cast(int)(input - start);
	}
	
	res = n;
	is_final = true;
	return cast(int)(input + 1 - start);
}

struct Symbol
{
	/// The number of bits in this code
	uint nbits;
	/// Huffman code aligned to LSB
	uint code;

	/*
	 * Encodes huffman code |sym| into |bufs|, whose least |rembits|
	 * bits are not filled yet.  The |rembits| must be in range [1, 8],
	 * inclusive.  At the end of the process, the |bufs| is updated
	 * and points where next output should be placed. The number of
	 * unfilled bits in the pointed location is returned.
	 */
	int encode(Buffers bufs, ref size_t avail, size_t rembits)
	{
		int rv;
		size_t _nbits = nbits;
		uint _code = code;
		
		/* We assume that nbits <= 32 */
		if (rembits > _nbits) {
			bufs.fastOrHold(cast(ubyte) (_code << (rembits - _nbits)));
			return cast(int)(rembits - _nbits);
		}
		
		if (rembits == _nbits) {
			bufs.fastOr(cast(ubyte)_code);
			--avail;
			return 8;
		}
		
		bufs.fastOr(cast(ubyte)(_code >> (_nbits - rembits)));
		--avail;
		
		_nbits -= rembits;
		if (_nbits & 0x7) {
			/* align code to MSB byte boundary */
			_code <<= 8 - (_nbits & 0x7);
		}
		
		/* we lose at most 3 bytes, but it is not critical in practice */
		if (avail < (_nbits + 7) / 8) {
			rv = bufs.advance();
			if (rv != 0) {
				return rv;
			}
			avail = bufs.curAvailable;
			/* we assume that we at least 3 buffer space available */
			assert(avail >= 3);
		}
		
		/* fast path, since most code is less than 8 */
		if (_nbits < 8) {
			bufs.fastAddHold(cast(ubyte)_code);
			avail = bufs.curAvailable;
			return cast(int)(8 - _nbits);
		}
		
		/* handle longer code path */
		if (_nbits > 24) {
			bufs.fastAdd(_code >> 24);
			_nbits -= 8;
		}
		
		if (_nbits > 16) {
			bufs.fastAdd(cast(ubyte)(_code >> 16));
			_nbits -= 8;
		}
		
		if (_nbits > 8) {
			bufs.fastAdd(cast(ubyte)(_code >> 8));
			_nbits -= 8;
		}
		
		if (_nbits == 8) {
			bufs.fastAdd(cast(ubyte)_code);
			avail = bufs.curAvailable;
			return 8;
		}
		
		bufs.fastAddHold(cast(ubyte)_code);
		avail = bufs.curAvailable;
		return cast(int)(8 - _nbits);
	}

}

size_t entryRoom(size_t namelen, size_t valuelen) {
	return ENTRY_OVERHEAD + namelen + valuelen;
}

uint hash(in string str) {
	uint h = 0;
	size_t n = str.length;
	ubyte* s = cast(ubyte*)str.ptr;
	while (n > 0) {
		h = h * 31 + *s++;
		--n;
	}
	return h;
}

/// Sorted by hash(name) and its table index
__gshared StaticEntry[] static_table;

static this() { 
	if (static_table) return;

	/* Make scalar initialization form of HeaderField */
	string MAKE_STATIC_ENT(int I, string N, string V, long NH, int VH) {
		return `StaticEntry( 
					new HDEntry(HDFlags.NONE, "` ~ N ~ `", "` ~ V ~ `", ` ~ NH.to!string ~ `, ` ~ VH.to!string ~ `), 
				` ~ I.to!string ~ 
			`)`;
	}

	mixin(`static_table = [` ~ 
		MAKE_STATIC_ENT(20, "age", "", 96511, 0) ~ `,` ~
		MAKE_STATIC_ENT(59, "via", "", 116750, 0) ~ `,` ~
		MAKE_STATIC_ENT(32, "date", "", 3076014, 0) ~ `,` ~
		MAKE_STATIC_ENT(33, "etag", "", 3123477, 0) ~ `,` ~
		MAKE_STATIC_ENT(36, "from", "", 3151786, 0) ~ `,` ~
		MAKE_STATIC_ENT(37, "host", "", 3208616, 0) ~ `,` ~
		MAKE_STATIC_ENT(44, "link", "", 3321850, 0) ~ `,` ~
		MAKE_STATIC_ENT(58, "vary", "", 3612210, 0) ~ `,` ~
		MAKE_STATIC_ENT(38, "if-match", "", 34533653, 0) ~ `,` ~
		MAKE_STATIC_ENT(41, "if-range", "", 39145613, 0) ~ `,` ~
		MAKE_STATIC_ENT(3, ":path", "/", 56997727, 47) ~ `,` ~
		MAKE_STATIC_ENT(4, ":path", "/index.html", 56997727, 2144181430) ~ `,` ~
		MAKE_STATIC_ENT(21, "allow", "", 92906313, 0) ~ `,` ~
		MAKE_STATIC_ENT(49, "range", "", 108280125, 0) ~ `,` ~
		MAKE_STATIC_ENT(14, "accept-charset", "", 124285319, 0) ~ `,` ~
		MAKE_STATIC_ENT(43, "last-modified", "", 150043680, 0) ~ `,` ~
		MAKE_STATIC_ENT(48, "proxy-authorization", "", 329532250, 0) ~ `,` ~
		MAKE_STATIC_ENT(57, "user-agent", "", 486342275, 0) ~ `,` ~
		MAKE_STATIC_ENT(40, "if-none-match", "", 646073760, 0) ~ `,` ~
		MAKE_STATIC_ENT(30, "content-type", "", 785670158, 0) ~ `,` ~
		MAKE_STATIC_ENT(16, "accept-language", "", 802785917, 0) ~ `,` ~
		MAKE_STATIC_ENT(50, "referer", "", 1085069613, 0) ~ `,` ~
		MAKE_STATIC_ENT(51, "refresh", "", 1085444827, 0) ~ `,` ~
		MAKE_STATIC_ENT(55, "strict-transport-security", "", 1153852136, 0) ~ `,` ~
		MAKE_STATIC_ENT(54, "set-cookie", "", 1237214767, 0) ~ `,` ~
		MAKE_STATIC_ENT(56, "transfer-encoding", "", 1274458357, 0) ~ `,` ~
		MAKE_STATIC_ENT(17, "accept-ranges", "", 1397189435, 0) ~ `,` ~
		MAKE_STATIC_ENT(42, "if-unmodified-since", "", 1454068927, 0) ~ `,` ~
		MAKE_STATIC_ENT(46, "max-forwards", "", 1619948695, 0) ~ `,` ~
		MAKE_STATIC_ENT(45, "location", "", 1901043637, 0) ~ `,` ~
		MAKE_STATIC_ENT(52, "retry-after", "", 1933352567, 0) ~ `,` ~
		MAKE_STATIC_ENT(25, "content-encoding", "", 2095084583, 0) ~ `,` ~
		MAKE_STATIC_ENT(28, "content-location", "", 2284906121, 0) ~ `,` ~
		MAKE_STATIC_ENT(39, "if-modified-since", "", 2302095846, 0) ~ `,` ~
		MAKE_STATIC_ENT(18, "accept", "", 2871506184, 0) ~ `,` ~
		MAKE_STATIC_ENT(29, "content-range", "", 2878374633, 0) ~ `,` ~
		MAKE_STATIC_ENT(22, "authorization", "", 2909397113, 0) ~ `,` ~
		MAKE_STATIC_ENT(31, "cookie", "", 2940209764, 0) ~ `,` ~
		MAKE_STATIC_ENT(0, ":authority", "", 2962729033, 0) ~ `,` ~
		MAKE_STATIC_ENT(35, "expires", "", 2985731892, 0) ~ `,` ~
		MAKE_STATIC_ENT(34, "expect", "", 3005803609, 0) ~ `,` ~
		MAKE_STATIC_ENT(24, "content-disposition", "", 3027699811, 0) ~ `,` ~
		MAKE_STATIC_ENT(26, "content-language", "", 3065240108, 0) ~ `,` ~
		MAKE_STATIC_ENT(1, ":method", "GET", 3153018267, 70454) ~ `,` ~
		MAKE_STATIC_ENT(2, ":method", "POST", 3153018267, 2461856) ~ `,` ~
		MAKE_STATIC_ENT(27, "content-length", "", 3162187450, 0) ~ `,` ~
		MAKE_STATIC_ENT(19, "access-control-allow-origin", "", 3297999203, 0) ~ `,` ~
		MAKE_STATIC_ENT(5, ":scheme", "http", 3322585695, 3213448) ~ `,` ~
		MAKE_STATIC_ENT(6, ":scheme", "https", 3322585695, 99617003) ~ `,` ~
		MAKE_STATIC_ENT(7, ":status", "200", 3338091692, 49586) ~ `,` ~
		MAKE_STATIC_ENT(8, ":status", "204", 3338091692, 49590) ~ `,` ~
		MAKE_STATIC_ENT(9, ":status", "206", 3338091692, 49592) ~ `,` ~
		MAKE_STATIC_ENT(10, ":status", "304", 3338091692, 50551) ~ `,` ~
		MAKE_STATIC_ENT(11, ":status", "400", 3338091692, 51508) ~ `,` ~
		MAKE_STATIC_ENT(12, ":status", "404", 3338091692, 51512) ~ `,` ~
		MAKE_STATIC_ENT(13, ":status", "500", 3338091692, 52469) ~ `,` ~
		MAKE_STATIC_ENT(53, "server", "", 3389140803, 0) ~ `,` ~
		MAKE_STATIC_ENT(47, "proxy-authenticate", "", 3993199572, 0) ~ `,` ~
		MAKE_STATIC_ENT(60, "www-authenticate", "", 4051929931, 0) ~ `,` ~
		MAKE_STATIC_ENT(23, "cache-control", "", 4086191634, 0) ~ `,` ~
		MAKE_STATIC_ENT(15, "accept-encoding", "gzip, deflate", 4127597688, 1733326877) 
		~ `];`);
	
	assert(static_table.length == 61, "Invalid static table length");
};

/* Index to the position in static_table */
__gshared immutable size_t[61] static_table_index = [38, 43, 44, 10, 11, 47, 48, 49, 50, 51, 52, 53, 54, 55, 14, 60, 20, 26, 34, 46, 0, 12, 36, 59, 41, 31, 42, 45, 32, 35, 19, 37, 2, 3, 40, 39, 4, 5, 8, 33, 18, 9, 27, 15, 6, 29, 28, 57, 16, 13, 21, 22, 30, 56, 24, 23, 25, 17, 7, 1, 58];

__gshared immutable Symbol[258] symbol_table = [
	Symbol(13, 0x1ff8), Symbol(23, 0x7fffd8), Symbol(28, 0xfffffe2), Symbol(28, 0xfffffe3), Symbol(28, 0xfffffe4), Symbol(28, 0xfffffe5), Symbol(28, 0xfffffe6), Symbol(28, 0xfffffe7), Symbol(28, 0xfffffe8), Symbol(24, 0xffffea), Symbol(30, 0x3ffffffc), Symbol(28, 0xfffffe9), Symbol(28, 0xfffffea), Symbol(30, 0x3ffffffd), Symbol(28, 0xfffffeb), Symbol(28, 0xfffffec), Symbol(28, 0xfffffed), Symbol(28, 0xfffffee), Symbol(28, 0xfffffef), Symbol(28, 0xffffff0), Symbol(28, 0xffffff1), Symbol(28, 0xffffff2), Symbol(30, 0x3ffffffe), Symbol(28, 0xffffff3), Symbol(28, 0xffffff4), Symbol(28, 0xffffff5), Symbol(28, 0xffffff6), Symbol(28, 0xffffff7), Symbol(28, 0xffffff8), Symbol(28, 0xffffff9), Symbol(28, 0xffffffa), Symbol(28, 0xffffffb), Symbol(6, 0x14), Symbol(10, 0x3f8), Symbol(10, 0x3f9), Symbol(12, 0xffa), Symbol(13, 0x1ff9), Symbol(6, 0x15), Symbol(8, 0xf8), Symbol(11, 0x7fa), Symbol(10, 0x3fa), Symbol(10, 0x3fb), Symbol(8, 0xf9), Symbol(11, 0x7fb), Symbol(8, 0xfa), Symbol(6, 0x16), Symbol(6, 0x17), Symbol(6, 0x18), Symbol(5, 0x0), Symbol(5, 0x1), Symbol(5, 0x2), Symbol(6, 0x19), Symbol(6, 0x1a), Symbol(6, 0x1b), Symbol(6, 0x1c), Symbol(6, 0x1d), Symbol(6, 0x1e), Symbol(6, 0x1f), Symbol(7, 0x5c), Symbol(8, 0xfb), Symbol(15, 0x7ffc), Symbol(6, 0x20), Symbol(12, 0xffb), Symbol(10, 0x3fc), Symbol(13, 0x1ffa), Symbol(6, 0x21), Symbol(7, 0x5d), Symbol(7, 0x5e), Symbol(7, 0x5f), Symbol(7, 0x60), Symbol(7, 0x61), Symbol(7, 0x62), Symbol(7, 0x63), Symbol(7, 0x64), Symbol(7, 0x65), Symbol(7, 0x66), Symbol(7, 0x67), Symbol(7, 0x68), Symbol(7, 0x69), Symbol(7, 0x6a), Symbol(7, 0x6b), Symbol(7, 0x6c), Symbol(7, 0x6d), Symbol(7, 0x6e), Symbol(7, 0x6f), Symbol(7, 0x70), Symbol(7, 0x71), Symbol(7, 0x72), Symbol(8, 0xfc), Symbol(7, 0x73), Symbol(8, 0xfd), Symbol(13, 0x1ffb), Symbol(19, 0x7fff0), Symbol(13, 0x1ffc), Symbol(14, 0x3ffc), Symbol(6, 0x22), Symbol(15, 0x7ffd), Symbol(5, 0x3), Symbol(6, 0x23), Symbol(5, 0x4), Symbol(6, 0x24), Symbol(5, 0x5), Symbol(6, 0x25), Symbol(6, 0x26), Symbol(6, 0x27), Symbol(5, 0x6), Symbol(7, 0x74), Symbol(7, 0x75), Symbol(6, 0x28), Symbol(6, 0x29), Symbol(6, 0x2a), Symbol(5, 0x7), Symbol(6, 0x2b), Symbol(7, 0x76), Symbol(6, 0x2c), Symbol(5, 0x8), Symbol(5, 0x9), Symbol(6, 0x2d), Symbol(7, 0x77), Symbol(7, 0x78), Symbol(7, 0x79), Symbol(7, 0x7a), Symbol(7, 0x7b), Symbol(15, 0x7ffe), Symbol(11, 0x7fc), Symbol(14, 0x3ffd), Symbol(13, 0x1ffd), Symbol(28, 0xffffffc), Symbol(20, 0xfffe6), Symbol(22, 0x3fffd2), Symbol(20, 0xfffe7), Symbol(20, 0xfffe8), Symbol(22, 0x3fffd3), Symbol(22, 0x3fffd4), Symbol(22, 0x3fffd5), Symbol(23, 0x7fffd9), Symbol(22, 0x3fffd6), Symbol(23, 0x7fffda), Symbol(23, 0x7fffdb), Symbol(23, 0x7fffdc), Symbol(23, 0x7fffdd), Symbol(23, 0x7fffde), Symbol(24, 0xffffeb), Symbol(23, 0x7fffdf), Symbol(24, 0xffffec), Symbol(24, 0xffffed), Symbol(22, 0x3fffd7), Symbol(23, 0x7fffe0), Symbol(24, 0xffffee), Symbol(23, 0x7fffe1), Symbol(23, 0x7fffe2), Symbol(23, 0x7fffe3), Symbol(23, 0x7fffe4), Symbol(21, 0x1fffdc), Symbol(22, 0x3fffd8), Symbol(23, 0x7fffe5), Symbol(22, 0x3fffd9), Symbol(23, 0x7fffe6), Symbol(23, 0x7fffe7), Symbol(24, 0xffffef), Symbol(22, 0x3fffda), Symbol(21, 0x1fffdd), Symbol(20, 0xfffe9), Symbol(22, 0x3fffdb), Symbol(22, 0x3fffdc), Symbol(23, 0x7fffe8), Symbol(23, 0x7fffe9), Symbol(21, 0x1fffde), Symbol(23, 0x7fffea), Symbol(22, 0x3fffdd), Symbol(22, 0x3fffde), Symbol(24, 0xfffff0), Symbol(21, 0x1fffdf), Symbol(22, 0x3fffdf), Symbol(23, 0x7fffeb), Symbol(23, 0x7fffec), Symbol(21, 0x1fffe0), Symbol(21, 0x1fffe1), Symbol(22, 0x3fffe0), Symbol(21, 0x1fffe2), Symbol(23, 0x7fffed), Symbol(22, 0x3fffe1), Symbol(23, 0x7fffee), Symbol(23, 0x7fffef), Symbol(20, 0xfffea), Symbol(22, 0x3fffe2), Symbol(22, 0x3fffe3), Symbol(22, 0x3fffe4), Symbol(23, 0x7ffff0), Symbol(22, 0x3fffe5), Symbol(22, 0x3fffe6), Symbol(23, 0x7ffff1), Symbol(26, 0x3ffffe0), Symbol(26, 0x3ffffe1), Symbol(20, 0xfffeb), Symbol(19, 0x7fff1), Symbol(22, 0x3fffe7), Symbol(23, 0x7ffff2), Symbol(22, 0x3fffe8), Symbol(25, 0x1ffffec), Symbol(26, 0x3ffffe2), Symbol(26, 0x3ffffe3), Symbol(26, 0x3ffffe4), Symbol(27, 0x7ffffde), Symbol(27, 0x7ffffdf), Symbol(26, 0x3ffffe5), Symbol(24, 0xfffff1), Symbol(25, 0x1ffffed), Symbol(19, 0x7fff2), Symbol(21, 0x1fffe3), Symbol(26, 0x3ffffe6), Symbol(27, 0x7ffffe0), Symbol(27, 0x7ffffe1), Symbol(26, 0x3ffffe7), Symbol(27, 0x7ffffe2), Symbol(24, 0xfffff2), Symbol(21, 0x1fffe4), Symbol(21, 0x1fffe5), Symbol(26, 0x3ffffe8), Symbol(26, 0x3ffffe9), Symbol(28, 0xffffffd), Symbol(27, 0x7ffffe3), Symbol(27, 0x7ffffe4), Symbol(27, 0x7ffffe5), Symbol(20, 0xfffec), Symbol(24, 0xfffff3), Symbol(20, 0xfffed), Symbol(21, 0x1fffe6), Symbol(22, 0x3fffe9), Symbol(21, 0x1fffe7), Symbol(21, 0x1fffe8), Symbol(23, 0x7ffff3), Symbol(22, 0x3fffea), Symbol(22, 0x3fffeb), Symbol(25, 0x1ffffee), Symbol(25, 0x1ffffef), Symbol(24, 0xfffff4), Symbol(24, 0xfffff5), Symbol(26, 0x3ffffea), Symbol(23, 0x7ffff4), Symbol(26, 0x3ffffeb), Symbol(27, 0x7ffffe6), Symbol(26, 0x3ffffec), Symbol(26, 0x3ffffed), Symbol(27, 0x7ffffe7), Symbol(27, 0x7ffffe8), Symbol(27, 0x7ffffe9), Symbol(27, 0x7ffffea), Symbol(27, 0x7ffffeb), Symbol(28, 0xffffffe), Symbol(27, 0x7ffffec), Symbol(27, 0x7ffffed), Symbol(27, 0x7ffffee), Symbol(27, 0x7ffffef), Symbol(27, 0x7fffff0), Symbol(26, 0x3ffffee), Symbol(30, 0x3fffffff)
];


__gshared immutable DecodeTable[256] decode_table = [
	/* 0 */
	[Decode(4, DecodeFlag.NONE, 0), Decode(5, DecodeFlag.NONE, 0), Decode(7, DecodeFlag.NONE, 0), Decode(8, DecodeFlag.NONE, 0), Decode(11, DecodeFlag.NONE, 0), Decode(12, DecodeFlag.NONE, 0), Decode(16, DecodeFlag.NONE, 0), Decode(19, DecodeFlag.NONE, 0), Decode(25, DecodeFlag.NONE, 0), Decode(28, DecodeFlag.NONE, 0), Decode(32, DecodeFlag.NONE, 0), Decode(35, DecodeFlag.NONE, 0), Decode(42, DecodeFlag.NONE, 0), Decode(49, DecodeFlag.NONE, 0), Decode(57, DecodeFlag.NONE, 0), Decode(64, DecodeFlag.ACCEPTED, 0)],
	/* 1 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 48), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 49), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 50), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 97), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 99), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 101), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 105), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 111), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 115), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 116), Decode(13, DecodeFlag.NONE, 0), Decode(14, DecodeFlag.NONE, 0), Decode(17, DecodeFlag.NONE, 0), Decode(18, DecodeFlag.NONE, 0), Decode(20, DecodeFlag.NONE, 0), Decode(21, DecodeFlag.NONE, 0)],
	/* 2 */
	[Decode(1, DecodeFlag.SYM, 48), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 48), Decode(1, DecodeFlag.SYM, 49), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 49), Decode(1, DecodeFlag.SYM, 50), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 50), Decode(1, DecodeFlag.SYM, 97), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 97), Decode(1, DecodeFlag.SYM, 99), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 99), Decode(1, DecodeFlag.SYM, 101), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 101), Decode(1, DecodeFlag.SYM, 105), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 105), Decode(1, DecodeFlag.SYM, 111), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 111)],
	/* 3 */
	[Decode(2, DecodeFlag.SYM, 48), Decode(9, DecodeFlag.SYM, 48), Decode(23, DecodeFlag.SYM, 48), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 48), Decode(2, DecodeFlag.SYM, 49), Decode(9, DecodeFlag.SYM, 49), Decode(23, DecodeFlag.SYM, 49), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 49), Decode(2, DecodeFlag.SYM, 50), Decode(9, DecodeFlag.SYM, 50), Decode(23, DecodeFlag.SYM, 50), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 50), Decode(2, DecodeFlag.SYM, 97), Decode(9, DecodeFlag.SYM, 97), Decode(23, DecodeFlag.SYM, 97), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 97)],
	/* 4 */
	[Decode(3, DecodeFlag.SYM, 48), Decode(6, DecodeFlag.SYM, 48), Decode(10, DecodeFlag.SYM, 48), Decode(15, DecodeFlag.SYM, 48), Decode(24, DecodeFlag.SYM, 48), Decode(31, DecodeFlag.SYM, 48), Decode(41, DecodeFlag.SYM, 48), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 48), Decode(3, DecodeFlag.SYM, 49), Decode(6, DecodeFlag.SYM, 49), Decode(10, DecodeFlag.SYM, 49), Decode(15, DecodeFlag.SYM, 49), Decode(24, DecodeFlag.SYM, 49), Decode(31, DecodeFlag.SYM, 49), Decode(41, DecodeFlag.SYM, 49), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 49)],
	/* 5 */
	[Decode(3, DecodeFlag.SYM, 50), Decode(6, DecodeFlag.SYM, 50), Decode(10, DecodeFlag.SYM, 50), Decode(15, DecodeFlag.SYM, 50), Decode(24, DecodeFlag.SYM, 50), Decode(31, DecodeFlag.SYM, 50), Decode(41, DecodeFlag.SYM, 50), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 50), Decode(3, DecodeFlag.SYM, 97), Decode(6, DecodeFlag.SYM, 97), Decode(10, DecodeFlag.SYM, 97), Decode(15, DecodeFlag.SYM, 97), Decode(24, DecodeFlag.SYM, 97), Decode(31, DecodeFlag.SYM, 97), Decode(41, DecodeFlag.SYM, 97), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 97)],
	/* 6 */
	[Decode(2, DecodeFlag.SYM, 99), Decode(9, DecodeFlag.SYM, 99), Decode(23, DecodeFlag.SYM, 99), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 99), Decode(2, DecodeFlag.SYM, 101), Decode(9, DecodeFlag.SYM, 101), Decode(23, DecodeFlag.SYM, 101), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 101), Decode(2, DecodeFlag.SYM, 105), Decode(9, DecodeFlag.SYM, 105), Decode(23, DecodeFlag.SYM, 105), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 105), Decode(2, DecodeFlag.SYM, 111), Decode(9, DecodeFlag.SYM, 111), Decode(23, DecodeFlag.SYM, 111), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 111)],
	/* 7 */
	[Decode(3, DecodeFlag.SYM, 99), Decode(6, DecodeFlag.SYM, 99), Decode(10, DecodeFlag.SYM, 99), Decode(15, DecodeFlag.SYM, 99), Decode(24, DecodeFlag.SYM, 99), Decode(31, DecodeFlag.SYM, 99), Decode(41, DecodeFlag.SYM, 99), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 99), Decode(3, DecodeFlag.SYM, 101), Decode(6, DecodeFlag.SYM, 101), Decode(10, DecodeFlag.SYM, 101), Decode(15, DecodeFlag.SYM, 101), Decode(24, DecodeFlag.SYM, 101), Decode(31, DecodeFlag.SYM, 101), Decode(41, DecodeFlag.SYM, 101), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 101)],
	/* 8 */
	[Decode(3, DecodeFlag.SYM, 105), Decode(6, DecodeFlag.SYM, 105), Decode(10, DecodeFlag.SYM, 105), Decode(15, DecodeFlag.SYM, 105), Decode(24, DecodeFlag.SYM, 105), Decode(31, DecodeFlag.SYM, 105), Decode(41, DecodeFlag.SYM, 105), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 105), Decode(3, DecodeFlag.SYM, 111), Decode(6, DecodeFlag.SYM, 111), Decode(10, DecodeFlag.SYM, 111), Decode(15, DecodeFlag.SYM, 111), Decode(24, DecodeFlag.SYM, 111), Decode(31, DecodeFlag.SYM, 111), Decode(41, DecodeFlag.SYM, 111), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 111)],
	/* 9 */
	[Decode(1, DecodeFlag.SYM, 115), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 115), Decode(1, DecodeFlag.SYM, 116), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 116), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 32), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 37), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 45), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 46), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 47), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 51), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 52), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 53), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 54), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 55), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 56), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 57)],
	/* 10 */
	[Decode(2, DecodeFlag.SYM, 115), Decode(9, DecodeFlag.SYM, 115), Decode(23, DecodeFlag.SYM, 115), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 115), Decode(2, DecodeFlag.SYM, 116), Decode(9, DecodeFlag.SYM, 116), Decode(23, DecodeFlag.SYM, 116), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 116), Decode(1, DecodeFlag.SYM, 32), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 32), Decode(1, DecodeFlag.SYM, 37), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 37), Decode(1, DecodeFlag.SYM, 45), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 45), Decode(1, DecodeFlag.SYM, 46), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 46)],
	/* 11 */
	[Decode(3, DecodeFlag.SYM, 115), Decode(6, DecodeFlag.SYM, 115), Decode(10, DecodeFlag.SYM, 115), Decode(15, DecodeFlag.SYM, 115), Decode(24, DecodeFlag.SYM, 115), Decode(31, DecodeFlag.SYM, 115), Decode(41, DecodeFlag.SYM, 115), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 115), Decode(3, DecodeFlag.SYM, 116), Decode(6, DecodeFlag.SYM, 116), Decode(10, DecodeFlag.SYM, 116), Decode(15, DecodeFlag.SYM, 116), Decode(24, DecodeFlag.SYM, 116), Decode(31, DecodeFlag.SYM, 116), Decode(41, DecodeFlag.SYM, 116), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 116)],
	/* 12 */
	[Decode(2, DecodeFlag.SYM, 32), Decode(9, DecodeFlag.SYM, 32), Decode(23, DecodeFlag.SYM, 32), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 32), Decode(2, DecodeFlag.SYM, 37), Decode(9, DecodeFlag.SYM, 37), Decode(23, DecodeFlag.SYM, 37), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 37), Decode(2, DecodeFlag.SYM, 45), Decode(9, DecodeFlag.SYM, 45), Decode(23, DecodeFlag.SYM, 45), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 45), Decode(2, DecodeFlag.SYM, 46), Decode(9, DecodeFlag.SYM, 46), Decode(23, DecodeFlag.SYM, 46), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 46)],
	/* 13 */
	[Decode(3, DecodeFlag.SYM, 32), Decode(6, DecodeFlag.SYM, 32), Decode(10, DecodeFlag.SYM, 32), Decode(15, DecodeFlag.SYM, 32), Decode(24, DecodeFlag.SYM, 32), Decode(31, DecodeFlag.SYM, 32), Decode(41, DecodeFlag.SYM, 32), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 32), Decode(3, DecodeFlag.SYM, 37), Decode(6, DecodeFlag.SYM, 37), Decode(10, DecodeFlag.SYM, 37), Decode(15, DecodeFlag.SYM, 37), Decode(24, DecodeFlag.SYM, 37), Decode(31, DecodeFlag.SYM, 37), Decode(41, DecodeFlag.SYM, 37), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 37)],
	/* 14 */
	[Decode(3, DecodeFlag.SYM, 45), Decode(6, DecodeFlag.SYM, 45), Decode(10, DecodeFlag.SYM, 45), Decode(15, DecodeFlag.SYM, 45), Decode(24, DecodeFlag.SYM, 45), Decode(31, DecodeFlag.SYM, 45), Decode(41, DecodeFlag.SYM, 45), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 45), Decode(3, DecodeFlag.SYM, 46), Decode(6, DecodeFlag.SYM, 46), Decode(10, DecodeFlag.SYM, 46), Decode(15, DecodeFlag.SYM, 46), Decode(24, DecodeFlag.SYM, 46), Decode(31, DecodeFlag.SYM, 46), Decode(41, DecodeFlag.SYM, 46), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 46)],
	/* 15 */
	[Decode(1, DecodeFlag.SYM, 47), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 47), Decode(1, DecodeFlag.SYM, 51), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 51), Decode(1, DecodeFlag.SYM, 52), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 52), Decode(1, DecodeFlag.SYM, 53), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 53), Decode(1, DecodeFlag.SYM, 54), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 54), Decode(1, DecodeFlag.SYM, 55), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 55), Decode(1, DecodeFlag.SYM, 56), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 56), Decode(1, DecodeFlag.SYM, 57), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 57)],
	/* 16 */
	[Decode(2, DecodeFlag.SYM, 47), Decode(9, DecodeFlag.SYM, 47), Decode(23, DecodeFlag.SYM, 47), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 47), Decode(2, DecodeFlag.SYM, 51), Decode(9, DecodeFlag.SYM, 51), Decode(23, DecodeFlag.SYM, 51), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 51), Decode(2, DecodeFlag.SYM, 52), Decode(9, DecodeFlag.SYM, 52), Decode(23, DecodeFlag.SYM, 52), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 52), Decode(2, DecodeFlag.SYM, 53), Decode(9, DecodeFlag.SYM, 53), Decode(23, DecodeFlag.SYM, 53), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 53)],
	/* 17 */
	[Decode(3, DecodeFlag.SYM, 47), Decode(6, DecodeFlag.SYM, 47), Decode(10, DecodeFlag.SYM, 47), Decode(15, DecodeFlag.SYM, 47), Decode(24, DecodeFlag.SYM, 47), Decode(31, DecodeFlag.SYM, 47), Decode(41, DecodeFlag.SYM, 47), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 47), Decode(3, DecodeFlag.SYM, 51), Decode(6, DecodeFlag.SYM, 51), Decode(10, DecodeFlag.SYM, 51), Decode(15, DecodeFlag.SYM, 51), Decode(24, DecodeFlag.SYM, 51), Decode(31, DecodeFlag.SYM, 51), Decode(41, DecodeFlag.SYM, 51), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 51)],
	/* 18 */
	[Decode(3, DecodeFlag.SYM, 52), Decode(6, DecodeFlag.SYM, 52), Decode(10, DecodeFlag.SYM, 52), Decode(15, DecodeFlag.SYM, 52), Decode(24, DecodeFlag.SYM, 52), Decode(31, DecodeFlag.SYM, 52), Decode(41, DecodeFlag.SYM, 52), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 52), Decode(3, DecodeFlag.SYM, 53), Decode(6, DecodeFlag.SYM, 53), Decode(10, DecodeFlag.SYM, 53), Decode(15, DecodeFlag.SYM, 53), Decode(24, DecodeFlag.SYM, 53), Decode(31, DecodeFlag.SYM, 53), Decode(41, DecodeFlag.SYM, 53), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 53)],
	/* 19 */
	[Decode(2, DecodeFlag.SYM, 54), Decode(9, DecodeFlag.SYM, 54), Decode(23, DecodeFlag.SYM, 54), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 54), Decode(2, DecodeFlag.SYM, 55), Decode(9, DecodeFlag.SYM, 55), Decode(23, DecodeFlag.SYM, 55), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 55), Decode(2, DecodeFlag.SYM, 56), Decode(9, DecodeFlag.SYM, 56), Decode(23, DecodeFlag.SYM, 56), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 56), Decode(2, DecodeFlag.SYM, 57), Decode(9, DecodeFlag.SYM, 57), Decode(23, DecodeFlag.SYM, 57), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 57)],
	/* 20 */
	[Decode(3, DecodeFlag.SYM, 54), Decode(6, DecodeFlag.SYM, 54), Decode(10, DecodeFlag.SYM, 54), Decode(15, DecodeFlag.SYM, 54), Decode(24, DecodeFlag.SYM, 54), Decode(31, DecodeFlag.SYM, 54), Decode(41, DecodeFlag.SYM, 54), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 54), Decode(3, DecodeFlag.SYM, 55), Decode(6, DecodeFlag.SYM, 55), Decode(10, DecodeFlag.SYM, 55), Decode(15, DecodeFlag.SYM, 55), Decode(24, DecodeFlag.SYM, 55), Decode(31, DecodeFlag.SYM, 55), Decode(41, DecodeFlag.SYM, 55), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 55)],
	/* 21 */
	[Decode(3, DecodeFlag.SYM, 56), Decode(6, DecodeFlag.SYM, 56), Decode(10, DecodeFlag.SYM, 56), Decode(15, DecodeFlag.SYM, 56), Decode(24, DecodeFlag.SYM, 56), Decode(31, DecodeFlag.SYM, 56), Decode(41, DecodeFlag.SYM, 56), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 56), Decode(3, DecodeFlag.SYM, 57), Decode(6, DecodeFlag.SYM, 57), Decode(10, DecodeFlag.SYM, 57), Decode(15, DecodeFlag.SYM, 57), Decode(24, DecodeFlag.SYM, 57), Decode(31, DecodeFlag.SYM, 57), Decode(41, DecodeFlag.SYM, 57), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 57)],
	/* 22 */
	[Decode(26, DecodeFlag.NONE, 0), Decode(27, DecodeFlag.NONE, 0), Decode(29, DecodeFlag.NONE, 0), Decode(30, DecodeFlag.NONE, 0), Decode(33, DecodeFlag.NONE, 0), Decode(34, DecodeFlag.NONE, 0), Decode(36, DecodeFlag.NONE, 0), Decode(37, DecodeFlag.NONE, 0), Decode(43, DecodeFlag.NONE, 0), Decode(46, DecodeFlag.NONE, 0), Decode(50, DecodeFlag.NONE, 0), Decode(53, DecodeFlag.NONE, 0), Decode(58, DecodeFlag.NONE, 0), Decode(61, DecodeFlag.NONE, 0), Decode(65, DecodeFlag.NONE, 0), Decode(68, DecodeFlag.ACCEPTED, 0)],
	/* 23 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 61), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 65), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 95), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 98), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 100), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 102), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 103), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 104), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 108), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 109), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 110), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 112), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 114), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 117), Decode(38, DecodeFlag.NONE, 0), Decode(39, DecodeFlag.NONE, 0)],
	/* 24 */
	[Decode(1, DecodeFlag.SYM, 61), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 61), Decode(1, DecodeFlag.SYM, 65), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 65), Decode(1, DecodeFlag.SYM, 95), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 95), Decode(1, DecodeFlag.SYM, 98), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 98), Decode(1, DecodeFlag.SYM, 100), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 100), Decode(1, DecodeFlag.SYM, 102), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 102), Decode(1, DecodeFlag.SYM, 103), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 103), Decode(1, DecodeFlag.SYM, 104), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 104)],
	/* 25 */
	[Decode(2, DecodeFlag.SYM, 61), Decode(9, DecodeFlag.SYM, 61), Decode(23, DecodeFlag.SYM, 61), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 61), Decode(2, DecodeFlag.SYM, 65), Decode(9, DecodeFlag.SYM, 65), Decode(23, DecodeFlag.SYM, 65), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 65), Decode(2, DecodeFlag.SYM, 95), Decode(9, DecodeFlag.SYM, 95), Decode(23, DecodeFlag.SYM, 95), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 95), Decode(2, DecodeFlag.SYM, 98), Decode(9, DecodeFlag.SYM, 98), Decode(23, DecodeFlag.SYM, 98), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 98)],
	/* 26 */
	[Decode(3, DecodeFlag.SYM, 61), Decode(6, DecodeFlag.SYM, 61), Decode(10, DecodeFlag.SYM, 61), Decode(15, DecodeFlag.SYM, 61), Decode(24, DecodeFlag.SYM, 61), Decode(31, DecodeFlag.SYM, 61), Decode(41, DecodeFlag.SYM, 61), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 61), Decode(3, DecodeFlag.SYM, 65), Decode(6, DecodeFlag.SYM, 65), Decode(10, DecodeFlag.SYM, 65), Decode(15, DecodeFlag.SYM, 65), Decode(24, DecodeFlag.SYM, 65), Decode(31, DecodeFlag.SYM, 65), Decode(41, DecodeFlag.SYM, 65), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 65)],
	/* 27 */
	[Decode(3, DecodeFlag.SYM, 95), Decode(6, DecodeFlag.SYM, 95), Decode(10, DecodeFlag.SYM, 95), Decode(15, DecodeFlag.SYM, 95), Decode(24, DecodeFlag.SYM, 95), Decode(31, DecodeFlag.SYM, 95), Decode(41, DecodeFlag.SYM, 95), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 95), Decode(3, DecodeFlag.SYM, 98), Decode(6, DecodeFlag.SYM, 98), Decode(10, DecodeFlag.SYM, 98), Decode(15, DecodeFlag.SYM, 98), Decode(24, DecodeFlag.SYM, 98), Decode(31, DecodeFlag.SYM, 98), Decode(41, DecodeFlag.SYM, 98), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 98)],
	/* 28 */
	[Decode(2, DecodeFlag.SYM, 100), Decode(9, DecodeFlag.SYM, 100), Decode(23, DecodeFlag.SYM, 100), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 100), Decode(2, DecodeFlag.SYM, 102), Decode(9, DecodeFlag.SYM, 102), Decode(23, DecodeFlag.SYM, 102), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 102), Decode(2, DecodeFlag.SYM, 103), Decode(9, DecodeFlag.SYM, 103), Decode(23, DecodeFlag.SYM, 103), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 103), Decode(2, DecodeFlag.SYM, 104), Decode(9, DecodeFlag.SYM, 104), Decode(23, DecodeFlag.SYM, 104), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 104)],
	/* 29 */
	[Decode(3, DecodeFlag.SYM, 100), Decode(6, DecodeFlag.SYM, 100), Decode(10, DecodeFlag.SYM, 100), Decode(15, DecodeFlag.SYM, 100), Decode(24, DecodeFlag.SYM, 100), Decode(31, DecodeFlag.SYM, 100), Decode(41, DecodeFlag.SYM, 100), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 100), Decode(3, DecodeFlag.SYM, 102), Decode(6, DecodeFlag.SYM, 102), Decode(10, DecodeFlag.SYM, 102), Decode(15, DecodeFlag.SYM, 102), Decode(24, DecodeFlag.SYM, 102), Decode(31, DecodeFlag.SYM, 102), Decode(41, DecodeFlag.SYM, 102), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 102)],
	/* 30 */
	[Decode(3, DecodeFlag.SYM, 103), Decode(6, DecodeFlag.SYM, 103), Decode(10, DecodeFlag.SYM, 103), Decode(15, DecodeFlag.SYM, 103), Decode(24, DecodeFlag.SYM, 103), Decode(31, DecodeFlag.SYM, 103), Decode(41, DecodeFlag.SYM, 103), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 103), Decode(3, DecodeFlag.SYM, 104), Decode(6, DecodeFlag.SYM, 104), Decode(10, DecodeFlag.SYM, 104), Decode(15, DecodeFlag.SYM, 104), Decode(24, DecodeFlag.SYM, 104), Decode(31, DecodeFlag.SYM, 104), Decode(41, DecodeFlag.SYM, 104), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 104)],
	/* 31 */
	[Decode(1, DecodeFlag.SYM, 108), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 108), Decode(1, DecodeFlag.SYM, 109), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 109), Decode(1, DecodeFlag.SYM, 110), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 110), Decode(1, DecodeFlag.SYM, 112), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 112), Decode(1, DecodeFlag.SYM, 114), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 114), Decode(1, DecodeFlag.SYM, 117), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 117), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 58), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 66), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 67), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 68)],
	/* 32 */
	[Decode(2, DecodeFlag.SYM, 108), Decode(9, DecodeFlag.SYM, 108), Decode(23, DecodeFlag.SYM, 108), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 108), Decode(2, DecodeFlag.SYM, 109), Decode(9, DecodeFlag.SYM, 109), Decode(23, DecodeFlag.SYM, 109), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 109), Decode(2, DecodeFlag.SYM, 110), Decode(9, DecodeFlag.SYM, 110), Decode(23, DecodeFlag.SYM, 110), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 110), Decode(2, DecodeFlag.SYM, 112), Decode(9, DecodeFlag.SYM, 112), Decode(23, DecodeFlag.SYM, 112), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 112)],
	/* 33 */
	[Decode(3, DecodeFlag.SYM, 108), Decode(6, DecodeFlag.SYM, 108), Decode(10, DecodeFlag.SYM, 108), Decode(15, DecodeFlag.SYM, 108), Decode(24, DecodeFlag.SYM, 108), Decode(31, DecodeFlag.SYM, 108), Decode(41, DecodeFlag.SYM, 108), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 108), Decode(3, DecodeFlag.SYM, 109), Decode(6, DecodeFlag.SYM, 109), Decode(10, DecodeFlag.SYM, 109), Decode(15, DecodeFlag.SYM, 109), Decode(24, DecodeFlag.SYM, 109), Decode(31, DecodeFlag.SYM, 109), Decode(41, DecodeFlag.SYM, 109), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 109)],
	/* 34 */
	[Decode(3, DecodeFlag.SYM, 110), Decode(6, DecodeFlag.SYM, 110), Decode(10, DecodeFlag.SYM, 110), Decode(15, DecodeFlag.SYM, 110), Decode(24, DecodeFlag.SYM, 110), Decode(31, DecodeFlag.SYM, 110), Decode(41, DecodeFlag.SYM, 110), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 110), Decode(3, DecodeFlag.SYM, 112), Decode(6, DecodeFlag.SYM, 112), Decode(10, DecodeFlag.SYM, 112), Decode(15, DecodeFlag.SYM, 112), Decode(24, DecodeFlag.SYM, 112), Decode(31, DecodeFlag.SYM, 112), Decode(41, DecodeFlag.SYM, 112), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 112)],
	/* 35 */
	[Decode(2, DecodeFlag.SYM, 114), Decode(9, DecodeFlag.SYM, 114), Decode(23, DecodeFlag.SYM, 114), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 114), Decode(2, DecodeFlag.SYM, 117), Decode(9, DecodeFlag.SYM, 117), Decode(23, DecodeFlag.SYM, 117), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 117), Decode(1, DecodeFlag.SYM, 58), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 58), Decode(1, DecodeFlag.SYM, 66), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 66), Decode(1, DecodeFlag.SYM, 67), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 67), Decode(1, DecodeFlag.SYM, 68), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 68)],
	/* 36 */
	[Decode(3, DecodeFlag.SYM, 114), Decode(6, DecodeFlag.SYM, 114), Decode(10, DecodeFlag.SYM, 114), Decode(15, DecodeFlag.SYM, 114), Decode(24, DecodeFlag.SYM, 114), Decode(31, DecodeFlag.SYM, 114), Decode(41, DecodeFlag.SYM, 114), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 114), Decode(3, DecodeFlag.SYM, 117), Decode(6, DecodeFlag.SYM, 117), Decode(10, DecodeFlag.SYM, 117), Decode(15, DecodeFlag.SYM, 117), Decode(24, DecodeFlag.SYM, 117), Decode(31, DecodeFlag.SYM, 117), Decode(41, DecodeFlag.SYM, 117), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 117)],
	/* 37 */
	[Decode(2, DecodeFlag.SYM, 58), Decode(9, DecodeFlag.SYM, 58), Decode(23, DecodeFlag.SYM, 58), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 58), Decode(2, DecodeFlag.SYM, 66), Decode(9, DecodeFlag.SYM, 66), Decode(23, DecodeFlag.SYM, 66), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 66), Decode(2, DecodeFlag.SYM, 67), Decode(9, DecodeFlag.SYM, 67), Decode(23, DecodeFlag.SYM, 67), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 67), Decode(2, DecodeFlag.SYM, 68), Decode(9, DecodeFlag.SYM, 68), Decode(23, DecodeFlag.SYM, 68), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 68)],
	/* 38 */
	[Decode(3, DecodeFlag.SYM, 58), Decode(6, DecodeFlag.SYM, 58), Decode(10, DecodeFlag.SYM, 58), Decode(15, DecodeFlag.SYM, 58), Decode(24, DecodeFlag.SYM, 58), Decode(31, DecodeFlag.SYM, 58), Decode(41, DecodeFlag.SYM, 58), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 58), Decode(3, DecodeFlag.SYM, 66), Decode(6, DecodeFlag.SYM, 66), Decode(10, DecodeFlag.SYM, 66), Decode(15, DecodeFlag.SYM, 66), Decode(24, DecodeFlag.SYM, 66), Decode(31, DecodeFlag.SYM, 66), Decode(41, DecodeFlag.SYM, 66), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 66)],
	/* 39 */
	[Decode(3, DecodeFlag.SYM, 67), Decode(6, DecodeFlag.SYM, 67), Decode(10, DecodeFlag.SYM, 67), Decode(15, DecodeFlag.SYM, 67), Decode(24, DecodeFlag.SYM, 67), Decode(31, DecodeFlag.SYM, 67), Decode(41, DecodeFlag.SYM, 67), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 67), Decode(3, DecodeFlag.SYM, 68), Decode(6, DecodeFlag.SYM, 68), Decode(10, DecodeFlag.SYM, 68), Decode(15, DecodeFlag.SYM, 68), Decode(24, DecodeFlag.SYM, 68), Decode(31, DecodeFlag.SYM, 68), Decode(41, DecodeFlag.SYM, 68), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 68)],
	/* 40 */
	[Decode(44, DecodeFlag.NONE, 0), Decode(45, DecodeFlag.NONE, 0), Decode(47, DecodeFlag.NONE, 0), Decode(48, DecodeFlag.NONE, 0), Decode(51, DecodeFlag.NONE, 0), Decode(52, DecodeFlag.NONE, 0), Decode(54, DecodeFlag.NONE, 0), Decode(55, DecodeFlag.NONE, 0), Decode(59, DecodeFlag.NONE, 0), Decode(60, DecodeFlag.NONE, 0), Decode(62, DecodeFlag.NONE, 0), Decode(63, DecodeFlag.NONE, 0), Decode(66, DecodeFlag.NONE, 0), Decode(67, DecodeFlag.NONE, 0), Decode(69, DecodeFlag.NONE, 0), Decode(72, DecodeFlag.ACCEPTED, 0)],
	/* 41 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 69), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 70), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 71), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 72), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 73), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 74), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 75), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 76), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 77), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 78), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 79), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 80), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 81), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 82), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 83), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 84)],
	/* 42 */
	[Decode(1, DecodeFlag.SYM, 69), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 69), Decode(1, DecodeFlag.SYM, 70), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 70), Decode(1, DecodeFlag.SYM, 71), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 71), Decode(1, DecodeFlag.SYM, 72), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 72), Decode(1, DecodeFlag.SYM, 73), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 73), Decode(1, DecodeFlag.SYM, 74), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 74), Decode(1, DecodeFlag.SYM, 75), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 75), Decode(1, DecodeFlag.SYM, 76), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 76)],
	/* 43 */
	[Decode(2, DecodeFlag.SYM, 69), Decode(9, DecodeFlag.SYM, 69), Decode(23, DecodeFlag.SYM, 69), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 69), Decode(2, DecodeFlag.SYM, 70), Decode(9, DecodeFlag.SYM, 70), Decode(23, DecodeFlag.SYM, 70), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 70), Decode(2, DecodeFlag.SYM, 71), Decode(9, DecodeFlag.SYM, 71), Decode(23, DecodeFlag.SYM, 71), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 71), Decode(2, DecodeFlag.SYM, 72), Decode(9, DecodeFlag.SYM, 72), Decode(23, DecodeFlag.SYM, 72), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 72)],
	/* 44 */
	[Decode(3, DecodeFlag.SYM, 69), Decode(6, DecodeFlag.SYM, 69), Decode(10, DecodeFlag.SYM, 69), Decode(15, DecodeFlag.SYM, 69), Decode(24, DecodeFlag.SYM, 69), Decode(31, DecodeFlag.SYM, 69), Decode(41, DecodeFlag.SYM, 69), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 69), Decode(3, DecodeFlag.SYM, 70), Decode(6, DecodeFlag.SYM, 70), Decode(10, DecodeFlag.SYM, 70), Decode(15, DecodeFlag.SYM, 70), Decode(24, DecodeFlag.SYM, 70), Decode(31, DecodeFlag.SYM, 70), Decode(41, DecodeFlag.SYM, 70), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 70)],
	/* 45 */
	[Decode(3, DecodeFlag.SYM, 71), Decode(6, DecodeFlag.SYM, 71), Decode(10, DecodeFlag.SYM, 71), Decode(15, DecodeFlag.SYM, 71), Decode(24, DecodeFlag.SYM, 71), Decode(31, DecodeFlag.SYM, 71), Decode(41, DecodeFlag.SYM, 71), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 71), Decode(3, DecodeFlag.SYM, 72), Decode(6, DecodeFlag.SYM, 72), Decode(10, DecodeFlag.SYM, 72), Decode(15, DecodeFlag.SYM, 72), Decode(24, DecodeFlag.SYM, 72), Decode(31, DecodeFlag.SYM, 72), Decode(41, DecodeFlag.SYM, 72), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 72)],
	/* 46 */
	[Decode(2, DecodeFlag.SYM, 73), Decode(9, DecodeFlag.SYM, 73), Decode(23, DecodeFlag.SYM, 73), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 73), Decode(2, DecodeFlag.SYM, 74), Decode(9, DecodeFlag.SYM, 74), Decode(23, DecodeFlag.SYM, 74), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 74), Decode(2, DecodeFlag.SYM, 75), Decode(9, DecodeFlag.SYM, 75), Decode(23, DecodeFlag.SYM, 75), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 75), Decode(2, DecodeFlag.SYM, 76), Decode(9, DecodeFlag.SYM, 76), Decode(23, DecodeFlag.SYM, 76), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 76)],
	/* 47 */
	[Decode(3, DecodeFlag.SYM, 73), Decode(6, DecodeFlag.SYM, 73), Decode(10, DecodeFlag.SYM, 73), Decode(15, DecodeFlag.SYM, 73), Decode(24, DecodeFlag.SYM, 73), Decode(31, DecodeFlag.SYM, 73), Decode(41, DecodeFlag.SYM, 73), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 73), Decode(3, DecodeFlag.SYM, 74), Decode(6, DecodeFlag.SYM, 74), Decode(10, DecodeFlag.SYM, 74), Decode(15, DecodeFlag.SYM, 74), Decode(24, DecodeFlag.SYM, 74), Decode(31, DecodeFlag.SYM, 74), Decode(41, DecodeFlag.SYM, 74), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 74)],
	/* 48 */
	[Decode(3, DecodeFlag.SYM, 75), Decode(6, DecodeFlag.SYM, 75), Decode(10, DecodeFlag.SYM, 75), Decode(15, DecodeFlag.SYM, 75), Decode(24, DecodeFlag.SYM, 75), Decode(31, DecodeFlag.SYM, 75), Decode(41, DecodeFlag.SYM, 75), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 75), Decode(3, DecodeFlag.SYM, 76), Decode(6, DecodeFlag.SYM, 76), Decode(10, DecodeFlag.SYM, 76), Decode(15, DecodeFlag.SYM, 76), Decode(24, DecodeFlag.SYM, 76), Decode(31, DecodeFlag.SYM, 76), Decode(41, DecodeFlag.SYM, 76), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 76)],
	/* 49 */
	[Decode(1, DecodeFlag.SYM, 77), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 77), Decode(1, DecodeFlag.SYM, 78), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 78), Decode(1, DecodeFlag.SYM, 79), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 79), Decode(1, DecodeFlag.SYM, 80), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 80), Decode(1, DecodeFlag.SYM, 81), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 81), Decode(1, DecodeFlag.SYM, 82), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 82), Decode(1, DecodeFlag.SYM, 83), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 83), Decode(1, DecodeFlag.SYM, 84), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 84)],
	/* 50 */
	[Decode(2, DecodeFlag.SYM, 77), Decode(9, DecodeFlag.SYM, 77), Decode(23, DecodeFlag.SYM, 77), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 77), Decode(2, DecodeFlag.SYM, 78), Decode(9, DecodeFlag.SYM, 78), Decode(23, DecodeFlag.SYM, 78), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 78), Decode(2, DecodeFlag.SYM, 79), Decode(9, DecodeFlag.SYM, 79), Decode(23, DecodeFlag.SYM, 79), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 79), Decode(2, DecodeFlag.SYM, 80), Decode(9, DecodeFlag.SYM, 80), Decode(23, DecodeFlag.SYM, 80), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 80)],
	/* 51 */
	[Decode(3, DecodeFlag.SYM, 77), Decode(6, DecodeFlag.SYM, 77), Decode(10, DecodeFlag.SYM, 77), Decode(15, DecodeFlag.SYM, 77), Decode(24, DecodeFlag.SYM, 77), Decode(31, DecodeFlag.SYM, 77), Decode(41, DecodeFlag.SYM, 77), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 77), Decode(3, DecodeFlag.SYM, 78), Decode(6, DecodeFlag.SYM, 78), Decode(10, DecodeFlag.SYM, 78), Decode(15, DecodeFlag.SYM, 78), Decode(24, DecodeFlag.SYM, 78), Decode(31, DecodeFlag.SYM, 78), Decode(41, DecodeFlag.SYM, 78), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 78)],
	/* 52 */
	[Decode(3, DecodeFlag.SYM, 79), Decode(6, DecodeFlag.SYM, 79), Decode(10, DecodeFlag.SYM, 79), Decode(15, DecodeFlag.SYM, 79), Decode(24, DecodeFlag.SYM, 79), Decode(31, DecodeFlag.SYM, 79), Decode(41, DecodeFlag.SYM, 79), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 79), Decode(3, DecodeFlag.SYM, 80), Decode(6, DecodeFlag.SYM, 80), Decode(10, DecodeFlag.SYM, 80), Decode(15, DecodeFlag.SYM, 80), Decode(24, DecodeFlag.SYM, 80), Decode(31, DecodeFlag.SYM, 80), Decode(41, DecodeFlag.SYM, 80), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 80)],
	/* 53 */
	[Decode(2, DecodeFlag.SYM, 81), Decode(9, DecodeFlag.SYM, 81), Decode(23, DecodeFlag.SYM, 81), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 81), Decode(2, DecodeFlag.SYM, 82), Decode(9, DecodeFlag.SYM, 82), Decode(23, DecodeFlag.SYM, 82), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 82), Decode(2, DecodeFlag.SYM, 83), Decode(9, DecodeFlag.SYM, 83), Decode(23, DecodeFlag.SYM, 83), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 83), Decode(2, DecodeFlag.SYM, 84), Decode(9, DecodeFlag.SYM, 84), Decode(23, DecodeFlag.SYM, 84), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 84)],
	/* 54 */
	[Decode(3, DecodeFlag.SYM, 81), Decode(6, DecodeFlag.SYM, 81), Decode(10, DecodeFlag.SYM, 81), Decode(15, DecodeFlag.SYM, 81), Decode(24, DecodeFlag.SYM, 81), Decode(31, DecodeFlag.SYM, 81), Decode(41, DecodeFlag.SYM, 81), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 81), Decode(3, DecodeFlag.SYM, 82), Decode(6, DecodeFlag.SYM, 82), Decode(10, DecodeFlag.SYM, 82), Decode(15, DecodeFlag.SYM, 82), Decode(24, DecodeFlag.SYM, 82), Decode(31, DecodeFlag.SYM, 82), Decode(41, DecodeFlag.SYM, 82), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 82)],
	/* 55 */
	[Decode(3, DecodeFlag.SYM, 83), Decode(6, DecodeFlag.SYM, 83), Decode(10, DecodeFlag.SYM, 83), Decode(15, DecodeFlag.SYM, 83), Decode(24, DecodeFlag.SYM, 83), Decode(31, DecodeFlag.SYM, 83), Decode(41, DecodeFlag.SYM, 83), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 83), Decode(3, DecodeFlag.SYM, 84), Decode(6, DecodeFlag.SYM, 84), Decode(10, DecodeFlag.SYM, 84), Decode(15, DecodeFlag.SYM, 84), Decode(24, DecodeFlag.SYM, 84), Decode(31, DecodeFlag.SYM, 84), Decode(41, DecodeFlag.SYM, 84), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 84)],
	/* 56 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 85), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 86), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 87), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 89), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 106), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 107), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 113), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 118), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 119), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 120), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 121), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 122), Decode(70, DecodeFlag.NONE, 0), Decode(71, DecodeFlag.NONE, 0), Decode(73, DecodeFlag.NONE, 0), Decode(74, DecodeFlag.ACCEPTED, 0)],
	/* 57 */
	[Decode(1, DecodeFlag.SYM, 85), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 85), Decode(1, DecodeFlag.SYM, 86), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 86), Decode(1, DecodeFlag.SYM, 87), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 87), Decode(1, DecodeFlag.SYM, 89), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 89), Decode(1, DecodeFlag.SYM, 106), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 106), Decode(1, DecodeFlag.SYM, 107), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 107), Decode(1, DecodeFlag.SYM, 113), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 113), Decode(1, DecodeFlag.SYM, 118), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 118)],
	/* 58 */
	[Decode(2, DecodeFlag.SYM, 85), Decode(9, DecodeFlag.SYM, 85), Decode(23, DecodeFlag.SYM, 85), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 85), Decode(2, DecodeFlag.SYM, 86), Decode(9, DecodeFlag.SYM, 86), Decode(23, DecodeFlag.SYM, 86), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 86), Decode(2, DecodeFlag.SYM, 87), Decode(9, DecodeFlag.SYM, 87), Decode(23, DecodeFlag.SYM, 87), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 87), Decode(2, DecodeFlag.SYM, 89), Decode(9, DecodeFlag.SYM, 89), Decode(23, DecodeFlag.SYM, 89), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 89)],
	/* 59 */
	[Decode(3, DecodeFlag.SYM, 85), Decode(6, DecodeFlag.SYM, 85), Decode(10, DecodeFlag.SYM, 85), Decode(15, DecodeFlag.SYM, 85), Decode(24, DecodeFlag.SYM, 85), Decode(31, DecodeFlag.SYM, 85), Decode(41, DecodeFlag.SYM, 85), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 85), Decode(3, DecodeFlag.SYM, 86), Decode(6, DecodeFlag.SYM, 86), Decode(10, DecodeFlag.SYM, 86), Decode(15, DecodeFlag.SYM, 86), Decode(24, DecodeFlag.SYM, 86), Decode(31, DecodeFlag.SYM, 86), Decode(41, DecodeFlag.SYM, 86), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 86)],
	/* 60 */
	[Decode(3, DecodeFlag.SYM, 87), Decode(6, DecodeFlag.SYM, 87), Decode(10, DecodeFlag.SYM, 87), Decode(15, DecodeFlag.SYM, 87), Decode(24, DecodeFlag.SYM, 87), Decode(31, DecodeFlag.SYM, 87), Decode(41, DecodeFlag.SYM, 87), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 87), Decode(3, DecodeFlag.SYM, 89), Decode(6, DecodeFlag.SYM, 89), Decode(10, DecodeFlag.SYM, 89), Decode(15, DecodeFlag.SYM, 89), Decode(24, DecodeFlag.SYM, 89), Decode(31, DecodeFlag.SYM, 89), Decode(41, DecodeFlag.SYM, 89), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 89)],
	/* 61 */
	[Decode(2, DecodeFlag.SYM, 106), Decode(9, DecodeFlag.SYM, 106), Decode(23, DecodeFlag.SYM, 106), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 106), Decode(2, DecodeFlag.SYM, 107), Decode(9, DecodeFlag.SYM, 107), Decode(23, DecodeFlag.SYM, 107), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 107), Decode(2, DecodeFlag.SYM, 113), Decode(9, DecodeFlag.SYM, 113), Decode(23, DecodeFlag.SYM, 113), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 113), Decode(2, DecodeFlag.SYM, 118), Decode(9, DecodeFlag.SYM, 118), Decode(23, DecodeFlag.SYM, 118), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 118)],
	/* 62 */
	[Decode(3, DecodeFlag.SYM, 106), Decode(6, DecodeFlag.SYM, 106), Decode(10, DecodeFlag.SYM, 106), Decode(15, DecodeFlag.SYM, 106), Decode(24, DecodeFlag.SYM, 106), Decode(31, DecodeFlag.SYM, 106), Decode(41, DecodeFlag.SYM, 106), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 106), Decode(3, DecodeFlag.SYM, 107), Decode(6, DecodeFlag.SYM, 107), Decode(10, DecodeFlag.SYM, 107), Decode(15, DecodeFlag.SYM, 107), Decode(24, DecodeFlag.SYM, 107), Decode(31, DecodeFlag.SYM, 107), Decode(41, DecodeFlag.SYM, 107), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 107)],
	/* 63 */
	[Decode(3, DecodeFlag.SYM, 113), Decode(6, DecodeFlag.SYM, 113), Decode(10, DecodeFlag.SYM, 113), Decode(15, DecodeFlag.SYM, 113), Decode(24, DecodeFlag.SYM, 113), Decode(31, DecodeFlag.SYM, 113), Decode(41, DecodeFlag.SYM, 113), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 113), Decode(3, DecodeFlag.SYM, 118), Decode(6, DecodeFlag.SYM, 118), Decode(10, DecodeFlag.SYM, 118), Decode(15, DecodeFlag.SYM, 118), Decode(24, DecodeFlag.SYM, 118), Decode(31, DecodeFlag.SYM, 118), Decode(41, DecodeFlag.SYM, 118), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 118)],
	/* 64 */
	[Decode(1, DecodeFlag.SYM, 119), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 119), Decode(1, DecodeFlag.SYM, 120), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 120), Decode(1, DecodeFlag.SYM, 121), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 121), Decode(1, DecodeFlag.SYM, 122), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 122), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 38), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 42), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 44), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 59), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 88), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 90), Decode(75, DecodeFlag.NONE, 0), Decode(78, DecodeFlag.NONE, 0)],
	/* 65 */
	[Decode(2, DecodeFlag.SYM, 119), Decode(9, DecodeFlag.SYM, 119), Decode(23, DecodeFlag.SYM, 119), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 119), Decode(2, DecodeFlag.SYM, 120), Decode(9, DecodeFlag.SYM, 120), Decode(23, DecodeFlag.SYM, 120), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 120), Decode(2, DecodeFlag.SYM, 121), Decode(9, DecodeFlag.SYM, 121), Decode(23, DecodeFlag.SYM, 121), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 121), Decode(2, DecodeFlag.SYM, 122), Decode(9, DecodeFlag.SYM, 122), Decode(23, DecodeFlag.SYM, 122), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 122)],
	/* 66 */
	[Decode(3, DecodeFlag.SYM, 119), Decode(6, DecodeFlag.SYM, 119), Decode(10, DecodeFlag.SYM, 119), Decode(15, DecodeFlag.SYM, 119), Decode(24, DecodeFlag.SYM, 119), Decode(31, DecodeFlag.SYM, 119), Decode(41, DecodeFlag.SYM, 119), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 119), Decode(3, DecodeFlag.SYM, 120), Decode(6, DecodeFlag.SYM, 120), Decode(10, DecodeFlag.SYM, 120), Decode(15, DecodeFlag.SYM, 120), Decode(24, DecodeFlag.SYM, 120), Decode(31, DecodeFlag.SYM, 120), Decode(41, DecodeFlag.SYM, 120), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 120)],
	/* 67 */
	[Decode(3, DecodeFlag.SYM, 121), Decode(6, DecodeFlag.SYM, 121), Decode(10, DecodeFlag.SYM, 121), Decode(15, DecodeFlag.SYM, 121), Decode(24, DecodeFlag.SYM, 121), Decode(31, DecodeFlag.SYM, 121), Decode(41, DecodeFlag.SYM, 121), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 121), Decode(3, DecodeFlag.SYM, 122), Decode(6, DecodeFlag.SYM, 122), Decode(10, DecodeFlag.SYM, 122), Decode(15, DecodeFlag.SYM, 122), Decode(24, DecodeFlag.SYM, 122), Decode(31, DecodeFlag.SYM, 122), Decode(41, DecodeFlag.SYM, 122), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 122)],
	/* 68 */
	[Decode(1, DecodeFlag.SYM, 38), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 38), Decode(1, DecodeFlag.SYM, 42), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 42), Decode(1, DecodeFlag.SYM, 44), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 44), Decode(1, DecodeFlag.SYM, 59), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 59), Decode(1, DecodeFlag.SYM, 88), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 88), Decode(1, DecodeFlag.SYM, 90), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 90), Decode(76, DecodeFlag.NONE, 0), Decode(77, DecodeFlag.NONE, 0), Decode(79, DecodeFlag.NONE, 0), Decode(81, DecodeFlag.NONE, 0)],
	/* 69 */
	[Decode(2, DecodeFlag.SYM, 38), Decode(9, DecodeFlag.SYM, 38), Decode(23, DecodeFlag.SYM, 38), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 38), Decode(2, DecodeFlag.SYM, 42), Decode(9, DecodeFlag.SYM, 42), Decode(23, DecodeFlag.SYM, 42), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 42), Decode(2, DecodeFlag.SYM, 44), Decode(9, DecodeFlag.SYM, 44), Decode(23, DecodeFlag.SYM, 44), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 44), Decode(2, DecodeFlag.SYM, 59), Decode(9, DecodeFlag.SYM, 59), Decode(23, DecodeFlag.SYM, 59), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 59)],
	/* 70 */
	[Decode(3, DecodeFlag.SYM, 38), Decode(6, DecodeFlag.SYM, 38), Decode(10, DecodeFlag.SYM, 38), Decode(15, DecodeFlag.SYM, 38), Decode(24, DecodeFlag.SYM, 38), Decode(31, DecodeFlag.SYM, 38), Decode(41, DecodeFlag.SYM, 38), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 38), Decode(3, DecodeFlag.SYM, 42), Decode(6, DecodeFlag.SYM, 42), Decode(10, DecodeFlag.SYM, 42), Decode(15, DecodeFlag.SYM, 42), Decode(24, DecodeFlag.SYM, 42), Decode(31, DecodeFlag.SYM, 42), Decode(41, DecodeFlag.SYM, 42), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 42)],
	/* 71 */
	[Decode(3, DecodeFlag.SYM, 44), Decode(6, DecodeFlag.SYM, 44), Decode(10, DecodeFlag.SYM, 44), Decode(15, DecodeFlag.SYM, 44), Decode(24, DecodeFlag.SYM, 44), Decode(31, DecodeFlag.SYM, 44), Decode(41, DecodeFlag.SYM, 44), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 44), Decode(3, DecodeFlag.SYM, 59), Decode(6, DecodeFlag.SYM, 59), Decode(10, DecodeFlag.SYM, 59), Decode(15, DecodeFlag.SYM, 59), Decode(24, DecodeFlag.SYM, 59), Decode(31, DecodeFlag.SYM, 59), Decode(41, DecodeFlag.SYM, 59), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 59)],
	/* 72 */
	[Decode(2, DecodeFlag.SYM, 88), Decode(9, DecodeFlag.SYM, 88), Decode(23, DecodeFlag.SYM, 88), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 88), Decode(2, DecodeFlag.SYM, 90), Decode(9, DecodeFlag.SYM, 90), Decode(23, DecodeFlag.SYM, 90), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 90), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 33), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 34), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 40), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 41), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 63), Decode(80, DecodeFlag.NONE, 0), Decode(82, DecodeFlag.NONE, 0), Decode(84, DecodeFlag.NONE, 0)],
	/* 73 */
	[Decode(3, DecodeFlag.SYM, 88), Decode(6, DecodeFlag.SYM, 88), Decode(10, DecodeFlag.SYM, 88), Decode(15, DecodeFlag.SYM, 88), Decode(24, DecodeFlag.SYM, 88), Decode(31, DecodeFlag.SYM, 88), Decode(41, DecodeFlag.SYM, 88), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 88), Decode(3, DecodeFlag.SYM, 90), Decode(6, DecodeFlag.SYM, 90), Decode(10, DecodeFlag.SYM, 90), Decode(15, DecodeFlag.SYM, 90), Decode(24, DecodeFlag.SYM, 90), Decode(31, DecodeFlag.SYM, 90), Decode(41, DecodeFlag.SYM, 90), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 90)],
	/* 74 */
	[Decode(1, DecodeFlag.SYM, 33), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 33), Decode(1, DecodeFlag.SYM, 34), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 34), Decode(1, DecodeFlag.SYM, 40), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 40), Decode(1, DecodeFlag.SYM, 41), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 41), Decode(1, DecodeFlag.SYM, 63), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 63), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 39), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 43), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 124), Decode(83, DecodeFlag.NONE, 0), Decode(85, DecodeFlag.NONE, 0), Decode(88, DecodeFlag.NONE, 0)],
	/* 75 */
	[Decode(2, DecodeFlag.SYM, 33), Decode(9, DecodeFlag.SYM, 33), Decode(23, DecodeFlag.SYM, 33), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 33), Decode(2, DecodeFlag.SYM, 34), Decode(9, DecodeFlag.SYM, 34), Decode(23, DecodeFlag.SYM, 34), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 34), Decode(2, DecodeFlag.SYM, 40), Decode(9, DecodeFlag.SYM, 40), Decode(23, DecodeFlag.SYM, 40), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 40), Decode(2, DecodeFlag.SYM, 41), Decode(9, DecodeFlag.SYM, 41), Decode(23, DecodeFlag.SYM, 41), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 41)],
	/* 76 */
	[Decode(3, DecodeFlag.SYM, 33), Decode(6, DecodeFlag.SYM, 33), Decode(10, DecodeFlag.SYM, 33), Decode(15, DecodeFlag.SYM, 33), Decode(24, DecodeFlag.SYM, 33), Decode(31, DecodeFlag.SYM, 33), Decode(41, DecodeFlag.SYM, 33), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 33), Decode(3, DecodeFlag.SYM, 34), Decode(6, DecodeFlag.SYM, 34), Decode(10, DecodeFlag.SYM, 34), Decode(15, DecodeFlag.SYM, 34), Decode(24, DecodeFlag.SYM, 34), Decode(31, DecodeFlag.SYM, 34), Decode(41, DecodeFlag.SYM, 34), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 34)],
	/* 77 */
	[Decode(3, DecodeFlag.SYM, 40), Decode(6, DecodeFlag.SYM, 40), Decode(10, DecodeFlag.SYM, 40), Decode(15, DecodeFlag.SYM, 40), Decode(24, DecodeFlag.SYM, 40), Decode(31, DecodeFlag.SYM, 40), Decode(41, DecodeFlag.SYM, 40), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 40), Decode(3, DecodeFlag.SYM, 41), Decode(6, DecodeFlag.SYM, 41), Decode(10, DecodeFlag.SYM, 41), Decode(15, DecodeFlag.SYM, 41), Decode(24, DecodeFlag.SYM, 41), Decode(31, DecodeFlag.SYM, 41), Decode(41, DecodeFlag.SYM, 41), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 41)],
	/* 78 */
	[Decode(2, DecodeFlag.SYM, 63), Decode(9, DecodeFlag.SYM, 63), Decode(23, DecodeFlag.SYM, 63), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 63), Decode(1, DecodeFlag.SYM, 39), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 39), Decode(1, DecodeFlag.SYM, 43), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 43), Decode(1, DecodeFlag.SYM, 124), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 124), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 35), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 62), Decode(86, DecodeFlag.NONE, 0), Decode(87, DecodeFlag.NONE, 0), Decode(89, DecodeFlag.NONE, 0), Decode(90, DecodeFlag.NONE, 0)],
	/* 79 */
	[Decode(3, DecodeFlag.SYM, 63), Decode(6, DecodeFlag.SYM, 63), Decode(10, DecodeFlag.SYM, 63), Decode(15, DecodeFlag.SYM, 63), Decode(24, DecodeFlag.SYM, 63), Decode(31, DecodeFlag.SYM, 63), Decode(41, DecodeFlag.SYM, 63), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 63), Decode(2, DecodeFlag.SYM, 39), Decode(9, DecodeFlag.SYM, 39), Decode(23, DecodeFlag.SYM, 39), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 39), Decode(2, DecodeFlag.SYM, 43), Decode(9, DecodeFlag.SYM, 43), Decode(23, DecodeFlag.SYM, 43), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 43)],
	/* 80 */
	[Decode(3, DecodeFlag.SYM, 39), Decode(6, DecodeFlag.SYM, 39), Decode(10, DecodeFlag.SYM, 39), Decode(15, DecodeFlag.SYM, 39), Decode(24, DecodeFlag.SYM, 39), Decode(31, DecodeFlag.SYM, 39), Decode(41, DecodeFlag.SYM, 39), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 39), Decode(3, DecodeFlag.SYM, 43), Decode(6, DecodeFlag.SYM, 43), Decode(10, DecodeFlag.SYM, 43), Decode(15, DecodeFlag.SYM, 43), Decode(24, DecodeFlag.SYM, 43), Decode(31, DecodeFlag.SYM, 43), Decode(41, DecodeFlag.SYM, 43), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 43)],
	/* 81 */
	[Decode(2, DecodeFlag.SYM, 124), Decode(9, DecodeFlag.SYM, 124), Decode(23, DecodeFlag.SYM, 124), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 124), Decode(1, DecodeFlag.SYM, 35), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 35), Decode(1, DecodeFlag.SYM, 62), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 62), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 0), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 36), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 64), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 91), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 93), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 126), Decode(91, DecodeFlag.NONE, 0), Decode(92, DecodeFlag.NONE, 0)],
	/* 82 */
	[Decode(3, DecodeFlag.SYM, 124), Decode(6, DecodeFlag.SYM, 124), Decode(10, DecodeFlag.SYM, 124), Decode(15, DecodeFlag.SYM, 124), Decode(24, DecodeFlag.SYM, 124), Decode(31, DecodeFlag.SYM, 124), Decode(41, DecodeFlag.SYM, 124), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 124), Decode(2, DecodeFlag.SYM, 35), Decode(9, DecodeFlag.SYM, 35), Decode(23, DecodeFlag.SYM, 35), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 35), Decode(2, DecodeFlag.SYM, 62), Decode(9, DecodeFlag.SYM, 62), Decode(23, DecodeFlag.SYM, 62), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 62)],
	/* 83 */
	[Decode(3, DecodeFlag.SYM, 35), Decode(6, DecodeFlag.SYM, 35), Decode(10, DecodeFlag.SYM, 35), Decode(15, DecodeFlag.SYM, 35), Decode(24, DecodeFlag.SYM, 35), Decode(31, DecodeFlag.SYM, 35), Decode(41, DecodeFlag.SYM, 35), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 35), Decode(3, DecodeFlag.SYM, 62), Decode(6, DecodeFlag.SYM, 62), Decode(10, DecodeFlag.SYM, 62), Decode(15, DecodeFlag.SYM, 62), Decode(24, DecodeFlag.SYM, 62), Decode(31, DecodeFlag.SYM, 62), Decode(41, DecodeFlag.SYM, 62), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 62)],
	/* 84 */
	[Decode(1, DecodeFlag.SYM, 0), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 0), Decode(1, DecodeFlag.SYM, 36), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 36), Decode(1, DecodeFlag.SYM, 64), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 64), Decode(1, DecodeFlag.SYM, 91), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 91), Decode(1, DecodeFlag.SYM, 93), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 93), Decode(1, DecodeFlag.SYM, 126), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 126), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 94), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 125), Decode(93, DecodeFlag.NONE, 0), Decode(94, DecodeFlag.NONE, 0)],
	/* 85 */
	[Decode(2, DecodeFlag.SYM, 0), Decode(9, DecodeFlag.SYM, 0), Decode(23, DecodeFlag.SYM, 0), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 0), Decode(2, DecodeFlag.SYM, 36), Decode(9, DecodeFlag.SYM, 36), Decode(23, DecodeFlag.SYM, 36), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 36), Decode(2, DecodeFlag.SYM, 64), Decode(9, DecodeFlag.SYM, 64), Decode(23, DecodeFlag.SYM, 64), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 64), Decode(2, DecodeFlag.SYM, 91), Decode(9, DecodeFlag.SYM, 91), Decode(23, DecodeFlag.SYM, 91), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 91)],
	/* 86 */
	[Decode(3, DecodeFlag.SYM, 0), Decode(6, DecodeFlag.SYM, 0), Decode(10, DecodeFlag.SYM, 0), Decode(15, DecodeFlag.SYM, 0), Decode(24, DecodeFlag.SYM, 0), Decode(31, DecodeFlag.SYM, 0), Decode(41, DecodeFlag.SYM, 0), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 0), Decode(3, DecodeFlag.SYM, 36), Decode(6, DecodeFlag.SYM, 36), Decode(10, DecodeFlag.SYM, 36), Decode(15, DecodeFlag.SYM, 36), Decode(24, DecodeFlag.SYM, 36), Decode(31, DecodeFlag.SYM, 36), Decode(41, DecodeFlag.SYM, 36), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 36)],
	/* 87 */
	[Decode(3, DecodeFlag.SYM, 64), Decode(6, DecodeFlag.SYM, 64), Decode(10, DecodeFlag.SYM, 64), Decode(15, DecodeFlag.SYM, 64), Decode(24, DecodeFlag.SYM, 64), Decode(31, DecodeFlag.SYM, 64), Decode(41, DecodeFlag.SYM, 64), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 64), Decode(3, DecodeFlag.SYM, 91), Decode(6, DecodeFlag.SYM, 91), Decode(10, DecodeFlag.SYM, 91), Decode(15, DecodeFlag.SYM, 91), Decode(24, DecodeFlag.SYM, 91), Decode(31, DecodeFlag.SYM, 91), Decode(41, DecodeFlag.SYM, 91), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 91)],
	/* 88 */
	[Decode(2, DecodeFlag.SYM, 93), Decode(9, DecodeFlag.SYM, 93), Decode(23, DecodeFlag.SYM, 93), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 93), Decode(2, DecodeFlag.SYM, 126), Decode(9, DecodeFlag.SYM, 126), Decode(23, DecodeFlag.SYM, 126), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 126), Decode(1, DecodeFlag.SYM, 94), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 94), Decode(1, DecodeFlag.SYM, 125), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 125), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 60), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 96), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 123), Decode(95, DecodeFlag.NONE, 0)],
	/* 89 */
	[Decode(3, DecodeFlag.SYM, 93), Decode(6, DecodeFlag.SYM, 93), Decode(10, DecodeFlag.SYM, 93), Decode(15, DecodeFlag.SYM, 93), Decode(24, DecodeFlag.SYM, 93), Decode(31, DecodeFlag.SYM, 93), Decode(41, DecodeFlag.SYM, 93), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 93), Decode(3, DecodeFlag.SYM, 126), Decode(6, DecodeFlag.SYM, 126), Decode(10, DecodeFlag.SYM, 126), Decode(15, DecodeFlag.SYM, 126), Decode(24, DecodeFlag.SYM, 126), Decode(31, DecodeFlag.SYM, 126), Decode(41, DecodeFlag.SYM, 126), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 126)],
	/* 90 */
	[Decode(2, DecodeFlag.SYM, 94), Decode(9, DecodeFlag.SYM, 94), Decode(23, DecodeFlag.SYM, 94), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 94), Decode(2, DecodeFlag.SYM, 125), Decode(9, DecodeFlag.SYM, 125), Decode(23, DecodeFlag.SYM, 125), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 125), Decode(1, DecodeFlag.SYM, 60), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 60), Decode(1, DecodeFlag.SYM, 96), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 96), Decode(1, DecodeFlag.SYM, 123), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 123), Decode(96, DecodeFlag.NONE, 0), Decode(110, DecodeFlag.NONE, 0)],
	/* 91 */
	[Decode(3, DecodeFlag.SYM, 94), Decode(6, DecodeFlag.SYM, 94), Decode(10, DecodeFlag.SYM, 94), Decode(15, DecodeFlag.SYM, 94), Decode(24, DecodeFlag.SYM, 94), Decode(31, DecodeFlag.SYM, 94), Decode(41, DecodeFlag.SYM, 94), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 94), Decode(3, DecodeFlag.SYM, 125), Decode(6, DecodeFlag.SYM, 125), Decode(10, DecodeFlag.SYM, 125), Decode(15, DecodeFlag.SYM, 125), Decode(24, DecodeFlag.SYM, 125), Decode(31, DecodeFlag.SYM, 125), Decode(41, DecodeFlag.SYM, 125), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 125)],
	/* 92 */
	[Decode(2, DecodeFlag.SYM, 60), Decode(9, DecodeFlag.SYM, 60), Decode(23, DecodeFlag.SYM, 60), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 60), Decode(2, DecodeFlag.SYM, 96), Decode(9, DecodeFlag.SYM, 96), Decode(23, DecodeFlag.SYM, 96), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 96), Decode(2, DecodeFlag.SYM, 123), Decode(9, DecodeFlag.SYM, 123), Decode(23, DecodeFlag.SYM, 123), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 123), Decode(97, DecodeFlag.NONE, 0), Decode(101, DecodeFlag.NONE, 0), Decode(111, DecodeFlag.NONE, 0), Decode(133, DecodeFlag.NONE, 0)],
	/* 93 */
	[Decode(3, DecodeFlag.SYM, 60), Decode(6, DecodeFlag.SYM, 60), Decode(10, DecodeFlag.SYM, 60), Decode(15, DecodeFlag.SYM, 60), Decode(24, DecodeFlag.SYM, 60), Decode(31, DecodeFlag.SYM, 60), Decode(41, DecodeFlag.SYM, 60), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 60), Decode(3, DecodeFlag.SYM, 96), Decode(6, DecodeFlag.SYM, 96), Decode(10, DecodeFlag.SYM, 96), Decode(15, DecodeFlag.SYM, 96), Decode(24, DecodeFlag.SYM, 96), Decode(31, DecodeFlag.SYM, 96), Decode(41, DecodeFlag.SYM, 96), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 96)],
	/* 94 */
	[Decode(3, DecodeFlag.SYM, 123), Decode(6, DecodeFlag.SYM, 123), Decode(10, DecodeFlag.SYM, 123), Decode(15, DecodeFlag.SYM, 123), Decode(24, DecodeFlag.SYM, 123), Decode(31, DecodeFlag.SYM, 123), Decode(41, DecodeFlag.SYM, 123), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 123), Decode(98, DecodeFlag.NONE, 0), Decode(99, DecodeFlag.NONE, 0), Decode(102, DecodeFlag.NONE, 0), Decode(105, DecodeFlag.NONE, 0), Decode(112, DecodeFlag.NONE, 0), Decode(119, DecodeFlag.NONE, 0), Decode(134, DecodeFlag.NONE, 0), Decode(153, DecodeFlag.NONE, 0)],
	/* 95 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 92), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 195), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 208), Decode(100, DecodeFlag.NONE, 0), Decode(103, DecodeFlag.NONE, 0), Decode(104, DecodeFlag.NONE, 0), Decode(106, DecodeFlag.NONE, 0), Decode(107, DecodeFlag.NONE, 0), Decode(113, DecodeFlag.NONE, 0), Decode(116, DecodeFlag.NONE, 0), Decode(120, DecodeFlag.NONE, 0), Decode(126, DecodeFlag.NONE, 0), Decode(135, DecodeFlag.NONE, 0), Decode(142, DecodeFlag.NONE, 0), Decode(154, DecodeFlag.NONE, 0), Decode(169, DecodeFlag.NONE, 0)],
	/* 96 */
	[Decode(1, DecodeFlag.SYM, 92), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 92), Decode(1, DecodeFlag.SYM, 195), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 195), Decode(1, DecodeFlag.SYM, 208), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 208), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 128), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 130), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 131), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 162), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 184), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 194), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 224), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 226), Decode(108, DecodeFlag.NONE, 0), Decode(109, DecodeFlag.NONE, 0)],
	/* 97 */
	[Decode(2, DecodeFlag.SYM, 92), Decode(9, DecodeFlag.SYM, 92), Decode(23, DecodeFlag.SYM, 92), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 92), Decode(2, DecodeFlag.SYM, 195), Decode(9, DecodeFlag.SYM, 195), Decode(23, DecodeFlag.SYM, 195), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 195), Decode(2, DecodeFlag.SYM, 208), Decode(9, DecodeFlag.SYM, 208), Decode(23, DecodeFlag.SYM, 208), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 208), Decode(1, DecodeFlag.SYM, 128), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 128), Decode(1, DecodeFlag.SYM, 130), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 130)],
	/* 98 */
	[Decode(3, DecodeFlag.SYM, 92), Decode(6, DecodeFlag.SYM, 92), Decode(10, DecodeFlag.SYM, 92), Decode(15, DecodeFlag.SYM, 92), Decode(24, DecodeFlag.SYM, 92), Decode(31, DecodeFlag.SYM, 92), Decode(41, DecodeFlag.SYM, 92), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 92), Decode(3, DecodeFlag.SYM, 195), Decode(6, DecodeFlag.SYM, 195), Decode(10, DecodeFlag.SYM, 195), Decode(15, DecodeFlag.SYM, 195), Decode(24, DecodeFlag.SYM, 195), Decode(31, DecodeFlag.SYM, 195), Decode(41, DecodeFlag.SYM, 195), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 195)],
	/* 99 */
	[Decode(3, DecodeFlag.SYM, 208), Decode(6, DecodeFlag.SYM, 208), Decode(10, DecodeFlag.SYM, 208), Decode(15, DecodeFlag.SYM, 208), Decode(24, DecodeFlag.SYM, 208), Decode(31, DecodeFlag.SYM, 208), Decode(41, DecodeFlag.SYM, 208), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 208), Decode(2, DecodeFlag.SYM, 128), Decode(9, DecodeFlag.SYM, 128), Decode(23, DecodeFlag.SYM, 128), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 128), Decode(2, DecodeFlag.SYM, 130), Decode(9, DecodeFlag.SYM, 130), Decode(23, DecodeFlag.SYM, 130), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 130)],
	/* 100 */
	[Decode(3, DecodeFlag.SYM, 128), Decode(6, DecodeFlag.SYM, 128), Decode(10, DecodeFlag.SYM, 128), Decode(15, DecodeFlag.SYM, 128), Decode(24, DecodeFlag.SYM, 128), Decode(31, DecodeFlag.SYM, 128), Decode(41, DecodeFlag.SYM, 128), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 128), Decode(3, DecodeFlag.SYM, 130), Decode(6, DecodeFlag.SYM, 130), Decode(10, DecodeFlag.SYM, 130), Decode(15, DecodeFlag.SYM, 130), Decode(24, DecodeFlag.SYM, 130), Decode(31, DecodeFlag.SYM, 130), Decode(41, DecodeFlag.SYM, 130), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 130)],
	/* 101 */
	[Decode(1, DecodeFlag.SYM, 131), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 131), Decode(1, DecodeFlag.SYM, 162), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 162), Decode(1, DecodeFlag.SYM, 184), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 184), Decode(1, DecodeFlag.SYM, 194), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 194), Decode(1, DecodeFlag.SYM, 224), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 224), Decode(1, DecodeFlag.SYM, 226), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 226), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 153), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 161), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 167), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 172)],
	/* 102 */
	[Decode(2, DecodeFlag.SYM, 131), Decode(9, DecodeFlag.SYM, 131), Decode(23, DecodeFlag.SYM, 131), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 131), Decode(2, DecodeFlag.SYM, 162), Decode(9, DecodeFlag.SYM, 162), Decode(23, DecodeFlag.SYM, 162), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 162), Decode(2, DecodeFlag.SYM, 184), Decode(9, DecodeFlag.SYM, 184), Decode(23, DecodeFlag.SYM, 184), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 184), Decode(2, DecodeFlag.SYM, 194), Decode(9, DecodeFlag.SYM, 194), Decode(23, DecodeFlag.SYM, 194), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 194)],
	/* 103 */
	[Decode(3, DecodeFlag.SYM, 131), Decode(6, DecodeFlag.SYM, 131), Decode(10, DecodeFlag.SYM, 131), Decode(15, DecodeFlag.SYM, 131), Decode(24, DecodeFlag.SYM, 131), Decode(31, DecodeFlag.SYM, 131), Decode(41, DecodeFlag.SYM, 131), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 131), Decode(3, DecodeFlag.SYM, 162), Decode(6, DecodeFlag.SYM, 162), Decode(10, DecodeFlag.SYM, 162), Decode(15, DecodeFlag.SYM, 162), Decode(24, DecodeFlag.SYM, 162), Decode(31, DecodeFlag.SYM, 162), Decode(41, DecodeFlag.SYM, 162), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 162)],
	/* 104 */
	[Decode(3, DecodeFlag.SYM, 184), Decode(6, DecodeFlag.SYM, 184), Decode(10, DecodeFlag.SYM, 184), Decode(15, DecodeFlag.SYM, 184), Decode(24, DecodeFlag.SYM, 184), Decode(31, DecodeFlag.SYM, 184), Decode(41, DecodeFlag.SYM, 184), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 184), Decode(3, DecodeFlag.SYM, 194), Decode(6, DecodeFlag.SYM, 194), Decode(10, DecodeFlag.SYM, 194), Decode(15, DecodeFlag.SYM, 194), Decode(24, DecodeFlag.SYM, 194), Decode(31, DecodeFlag.SYM, 194), Decode(41, DecodeFlag.SYM, 194), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 194)],
	/* 105 */
	[Decode(2, DecodeFlag.SYM, 224), Decode(9, DecodeFlag.SYM, 224), Decode(23, DecodeFlag.SYM, 224), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 224), Decode(2, DecodeFlag.SYM, 226), Decode(9, DecodeFlag.SYM, 226), Decode(23, DecodeFlag.SYM, 226), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 226), Decode(1, DecodeFlag.SYM, 153), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 153), Decode(1, DecodeFlag.SYM, 161), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 161), Decode(1, DecodeFlag.SYM, 167), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 167), Decode(1, DecodeFlag.SYM, 172), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 172)],
	/* 106 */
	[Decode(3, DecodeFlag.SYM, 224), Decode(6, DecodeFlag.SYM, 224), Decode(10, DecodeFlag.SYM, 224), Decode(15, DecodeFlag.SYM, 224), Decode(24, DecodeFlag.SYM, 224), Decode(31, DecodeFlag.SYM, 224), Decode(41, DecodeFlag.SYM, 224), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 224), Decode(3, DecodeFlag.SYM, 226), Decode(6, DecodeFlag.SYM, 226), Decode(10, DecodeFlag.SYM, 226), Decode(15, DecodeFlag.SYM, 226), Decode(24, DecodeFlag.SYM, 226), Decode(31, DecodeFlag.SYM, 226), Decode(41, DecodeFlag.SYM, 226), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 226)],
	/* 107 */
	[Decode(2, DecodeFlag.SYM, 153), Decode(9, DecodeFlag.SYM, 153), Decode(23, DecodeFlag.SYM, 153), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 153), Decode(2, DecodeFlag.SYM, 161), Decode(9, DecodeFlag.SYM, 161), Decode(23, DecodeFlag.SYM, 161), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 161), Decode(2, DecodeFlag.SYM, 167), Decode(9, DecodeFlag.SYM, 167), Decode(23, DecodeFlag.SYM, 167), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 167), Decode(2, DecodeFlag.SYM, 172), Decode(9, DecodeFlag.SYM, 172), Decode(23, DecodeFlag.SYM, 172), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 172)],
	/* 108 */
	[Decode(3, DecodeFlag.SYM, 153), Decode(6, DecodeFlag.SYM, 153), Decode(10, DecodeFlag.SYM, 153), Decode(15, DecodeFlag.SYM, 153), Decode(24, DecodeFlag.SYM, 153), Decode(31, DecodeFlag.SYM, 153), Decode(41, DecodeFlag.SYM, 153), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 153), Decode(3, DecodeFlag.SYM, 161), Decode(6, DecodeFlag.SYM, 161), Decode(10, DecodeFlag.SYM, 161), Decode(15, DecodeFlag.SYM, 161), Decode(24, DecodeFlag.SYM, 161), Decode(31, DecodeFlag.SYM, 161), Decode(41, DecodeFlag.SYM, 161), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 161)],
	/* 109 */
	[Decode(3, DecodeFlag.SYM, 167), Decode(6, DecodeFlag.SYM, 167), Decode(10, DecodeFlag.SYM, 167), Decode(15, DecodeFlag.SYM, 167), Decode(24, DecodeFlag.SYM, 167), Decode(31, DecodeFlag.SYM, 167), Decode(41, DecodeFlag.SYM, 167), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 167), Decode(3, DecodeFlag.SYM, 172), Decode(6, DecodeFlag.SYM, 172), Decode(10, DecodeFlag.SYM, 172), Decode(15, DecodeFlag.SYM, 172), Decode(24, DecodeFlag.SYM, 172), Decode(31, DecodeFlag.SYM, 172), Decode(41, DecodeFlag.SYM, 172), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 172)],
	/* 110 */
	[Decode(114, DecodeFlag.NONE, 0), Decode(115, DecodeFlag.NONE, 0), Decode(117, DecodeFlag.NONE, 0), Decode(118, DecodeFlag.NONE, 0), Decode(121, DecodeFlag.NONE, 0), Decode(123, DecodeFlag.NONE, 0), Decode(127, DecodeFlag.NONE, 0), Decode(130, DecodeFlag.NONE, 0), Decode(136, DecodeFlag.NONE, 0), Decode(139, DecodeFlag.NONE, 0), Decode(143, DecodeFlag.NONE, 0), Decode(146, DecodeFlag.NONE, 0), Decode(155, DecodeFlag.NONE, 0), Decode(162, DecodeFlag.NONE, 0), Decode(170, DecodeFlag.NONE, 0), Decode(180, DecodeFlag.NONE, 0)],
	/* 111 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 176), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 177), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 179), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 209), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 216), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 217), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 227), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 229), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 230), Decode(122, DecodeFlag.NONE, 0), Decode(124, DecodeFlag.NONE, 0), Decode(125, DecodeFlag.NONE, 0), Decode(128, DecodeFlag.NONE, 0), Decode(129, DecodeFlag.NONE, 0), Decode(131, DecodeFlag.NONE, 0), Decode(132, DecodeFlag.NONE, 0)],
	/* 112 */
	[Decode(1, DecodeFlag.SYM, 176), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 176), Decode(1, DecodeFlag.SYM, 177), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 177), Decode(1, DecodeFlag.SYM, 179), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 179), Decode(1, DecodeFlag.SYM, 209), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 209), Decode(1, DecodeFlag.SYM, 216), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 216), Decode(1, DecodeFlag.SYM, 217), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 217), Decode(1, DecodeFlag.SYM, 227), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 227), Decode(1, DecodeFlag.SYM, 229), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 229)],
	/* 113 */
	[Decode(2, DecodeFlag.SYM, 176), Decode(9, DecodeFlag.SYM, 176), Decode(23, DecodeFlag.SYM, 176), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 176), Decode(2, DecodeFlag.SYM, 177), Decode(9, DecodeFlag.SYM, 177), Decode(23, DecodeFlag.SYM, 177), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 177), Decode(2, DecodeFlag.SYM, 179), Decode(9, DecodeFlag.SYM, 179), Decode(23, DecodeFlag.SYM, 179), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 179), Decode(2, DecodeFlag.SYM, 209), Decode(9, DecodeFlag.SYM, 209), Decode(23, DecodeFlag.SYM, 209), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 209)],
	/* 114 */
	[Decode(3, DecodeFlag.SYM, 176), Decode(6, DecodeFlag.SYM, 176), Decode(10, DecodeFlag.SYM, 176), Decode(15, DecodeFlag.SYM, 176), Decode(24, DecodeFlag.SYM, 176), Decode(31, DecodeFlag.SYM, 176), Decode(41, DecodeFlag.SYM, 176), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 176), Decode(3, DecodeFlag.SYM, 177), Decode(6, DecodeFlag.SYM, 177), Decode(10, DecodeFlag.SYM, 177), Decode(15, DecodeFlag.SYM, 177), Decode(24, DecodeFlag.SYM, 177), Decode(31, DecodeFlag.SYM, 177), Decode(41, DecodeFlag.SYM, 177), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 177)],
	/* 115 */
	[Decode(3, DecodeFlag.SYM, 179), Decode(6, DecodeFlag.SYM, 179), Decode(10, DecodeFlag.SYM, 179), Decode(15, DecodeFlag.SYM, 179), Decode(24, DecodeFlag.SYM, 179), Decode(31, DecodeFlag.SYM, 179), Decode(41, DecodeFlag.SYM, 179), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 179), Decode(3, DecodeFlag.SYM, 209), Decode(6, DecodeFlag.SYM, 209), Decode(10, DecodeFlag.SYM, 209), Decode(15, DecodeFlag.SYM, 209), Decode(24, DecodeFlag.SYM, 209), Decode(31, DecodeFlag.SYM, 209), Decode(41, DecodeFlag.SYM, 209), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 209)],
	/* 116 */
	[Decode(2, DecodeFlag.SYM, 216), Decode(9, DecodeFlag.SYM, 216), Decode(23, DecodeFlag.SYM, 216), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 216), Decode(2, DecodeFlag.SYM, 217), Decode(9, DecodeFlag.SYM, 217), Decode(23, DecodeFlag.SYM, 217), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 217), Decode(2, DecodeFlag.SYM, 227), Decode(9, DecodeFlag.SYM, 227), Decode(23, DecodeFlag.SYM, 227), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 227), Decode(2, DecodeFlag.SYM, 229), Decode(9, DecodeFlag.SYM, 229), Decode(23, DecodeFlag.SYM, 229), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 229)],
	/* 117 */
	[Decode(3, DecodeFlag.SYM, 216), Decode(6, DecodeFlag.SYM, 216), Decode(10, DecodeFlag.SYM, 216), Decode(15, DecodeFlag.SYM, 216), Decode(24, DecodeFlag.SYM, 216), Decode(31, DecodeFlag.SYM, 216), Decode(41, DecodeFlag.SYM, 216), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 216), Decode(3, DecodeFlag.SYM, 217), Decode(6, DecodeFlag.SYM, 217), Decode(10, DecodeFlag.SYM, 217), Decode(15, DecodeFlag.SYM, 217), Decode(24, DecodeFlag.SYM, 217), Decode(31, DecodeFlag.SYM, 217), Decode(41, DecodeFlag.SYM, 217), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 217)],
	/* 118 */
	[Decode(3, DecodeFlag.SYM, 227), Decode(6, DecodeFlag.SYM, 227), Decode(10, DecodeFlag.SYM, 227), Decode(15, DecodeFlag.SYM, 227), Decode(24, DecodeFlag.SYM, 227), Decode(31, DecodeFlag.SYM, 227), Decode(41, DecodeFlag.SYM, 227), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 227), Decode(3, DecodeFlag.SYM, 229), Decode(6, DecodeFlag.SYM, 229), Decode(10, DecodeFlag.SYM, 229), Decode(15, DecodeFlag.SYM, 229), Decode(24, DecodeFlag.SYM, 229), Decode(31, DecodeFlag.SYM, 229), Decode(41, DecodeFlag.SYM, 229), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 229)],
	/* 119 */
	[Decode(1, DecodeFlag.SYM, 230), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 230), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 129), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 132), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 133), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 134), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 136), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 146), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 154), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 156), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 160), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 163), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 164), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 169), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 170), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 173)],
	/* 120 */
	[Decode(2, DecodeFlag.SYM, 230), Decode(9, DecodeFlag.SYM, 230), Decode(23, DecodeFlag.SYM, 230), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 230), Decode(1, DecodeFlag.SYM, 129), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 129), Decode(1, DecodeFlag.SYM, 132), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 132), Decode(1, DecodeFlag.SYM, 133), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 133), Decode(1, DecodeFlag.SYM, 134), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 134), Decode(1, DecodeFlag.SYM, 136), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 136), Decode(1, DecodeFlag.SYM, 146), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 146)],
	/* 121 */
	[Decode(3, DecodeFlag.SYM, 230), Decode(6, DecodeFlag.SYM, 230), Decode(10, DecodeFlag.SYM, 230), Decode(15, DecodeFlag.SYM, 230), Decode(24, DecodeFlag.SYM, 230), Decode(31, DecodeFlag.SYM, 230), Decode(41, DecodeFlag.SYM, 230), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 230), Decode(2, DecodeFlag.SYM, 129), Decode(9, DecodeFlag.SYM, 129), Decode(23, DecodeFlag.SYM, 129), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 129), Decode(2, DecodeFlag.SYM, 132), Decode(9, DecodeFlag.SYM, 132), Decode(23, DecodeFlag.SYM, 132), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 132)],
	/* 122 */
	[Decode(3, DecodeFlag.SYM, 129), Decode(6, DecodeFlag.SYM, 129), Decode(10, DecodeFlag.SYM, 129), Decode(15, DecodeFlag.SYM, 129), Decode(24, DecodeFlag.SYM, 129), Decode(31, DecodeFlag.SYM, 129), Decode(41, DecodeFlag.SYM, 129), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 129), Decode(3, DecodeFlag.SYM, 132), Decode(6, DecodeFlag.SYM, 132), Decode(10, DecodeFlag.SYM, 132), Decode(15, DecodeFlag.SYM, 132), Decode(24, DecodeFlag.SYM, 132), Decode(31, DecodeFlag.SYM, 132), Decode(41, DecodeFlag.SYM, 132), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 132)],
	/* 123 */
	[Decode(2, DecodeFlag.SYM, 133), Decode(9, DecodeFlag.SYM, 133), Decode(23, DecodeFlag.SYM, 133), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 133), Decode(2, DecodeFlag.SYM, 134), Decode(9, DecodeFlag.SYM, 134), Decode(23, DecodeFlag.SYM, 134), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 134), Decode(2, DecodeFlag.SYM, 136), Decode(9, DecodeFlag.SYM, 136), Decode(23, DecodeFlag.SYM, 136), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 136), Decode(2, DecodeFlag.SYM, 146), Decode(9, DecodeFlag.SYM, 146), Decode(23, DecodeFlag.SYM, 146), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 146)],
	/* 124 */
	[Decode(3, DecodeFlag.SYM, 133), Decode(6, DecodeFlag.SYM, 133), Decode(10, DecodeFlag.SYM, 133), Decode(15, DecodeFlag.SYM, 133), Decode(24, DecodeFlag.SYM, 133), Decode(31, DecodeFlag.SYM, 133), Decode(41, DecodeFlag.SYM, 133), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 133), Decode(3, DecodeFlag.SYM, 134), Decode(6, DecodeFlag.SYM, 134), Decode(10, DecodeFlag.SYM, 134), Decode(15, DecodeFlag.SYM, 134), Decode(24, DecodeFlag.SYM, 134), Decode(31, DecodeFlag.SYM, 134), Decode(41, DecodeFlag.SYM, 134), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 134)],
	/* 125 */
	[Decode(3, DecodeFlag.SYM, 136), Decode(6, DecodeFlag.SYM, 136), Decode(10, DecodeFlag.SYM, 136), Decode(15, DecodeFlag.SYM, 136), Decode(24, DecodeFlag.SYM, 136), Decode(31, DecodeFlag.SYM, 136), Decode(41, DecodeFlag.SYM, 136), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 136), Decode(3, DecodeFlag.SYM, 146), Decode(6, DecodeFlag.SYM, 146), Decode(10, DecodeFlag.SYM, 146), Decode(15, DecodeFlag.SYM, 146), Decode(24, DecodeFlag.SYM, 146), Decode(31, DecodeFlag.SYM, 146), Decode(41, DecodeFlag.SYM, 146), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 146)],
	/* 126 */
	[Decode(1, DecodeFlag.SYM, 154), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 154), Decode(1, DecodeFlag.SYM, 156), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 156), Decode(1, DecodeFlag.SYM, 160), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 160), Decode(1, DecodeFlag.SYM, 163), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 163), Decode(1, DecodeFlag.SYM, 164), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 164), Decode(1, DecodeFlag.SYM, 169), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 169), Decode(1, DecodeFlag.SYM, 170), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 170), Decode(1, DecodeFlag.SYM, 173), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 173)],
	/* 127 */
	[Decode(2, DecodeFlag.SYM, 154), Decode(9, DecodeFlag.SYM, 154), Decode(23, DecodeFlag.SYM, 154), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 154), Decode(2, DecodeFlag.SYM, 156), Decode(9, DecodeFlag.SYM, 156), Decode(23, DecodeFlag.SYM, 156), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 156), Decode(2, DecodeFlag.SYM, 160), Decode(9, DecodeFlag.SYM, 160), Decode(23, DecodeFlag.SYM, 160), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 160), Decode(2, DecodeFlag.SYM, 163), Decode(9, DecodeFlag.SYM, 163), Decode(23, DecodeFlag.SYM, 163), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 163)],
	/* 128 */
	[Decode(3, DecodeFlag.SYM, 154), Decode(6, DecodeFlag.SYM, 154), Decode(10, DecodeFlag.SYM, 154), Decode(15, DecodeFlag.SYM, 154), Decode(24, DecodeFlag.SYM, 154), Decode(31, DecodeFlag.SYM, 154), Decode(41, DecodeFlag.SYM, 154), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 154), Decode(3, DecodeFlag.SYM, 156), Decode(6, DecodeFlag.SYM, 156), Decode(10, DecodeFlag.SYM, 156), Decode(15, DecodeFlag.SYM, 156), Decode(24, DecodeFlag.SYM, 156), Decode(31, DecodeFlag.SYM, 156), Decode(41, DecodeFlag.SYM, 156), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 156)],
	/* 129 */
	[Decode(3, DecodeFlag.SYM, 160), Decode(6, DecodeFlag.SYM, 160), Decode(10, DecodeFlag.SYM, 160), Decode(15, DecodeFlag.SYM, 160), Decode(24, DecodeFlag.SYM, 160), Decode(31, DecodeFlag.SYM, 160), Decode(41, DecodeFlag.SYM, 160), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 160), Decode(3, DecodeFlag.SYM, 163), Decode(6, DecodeFlag.SYM, 163), Decode(10, DecodeFlag.SYM, 163), Decode(15, DecodeFlag.SYM, 163), Decode(24, DecodeFlag.SYM, 163), Decode(31, DecodeFlag.SYM, 163), Decode(41, DecodeFlag.SYM, 163), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 163)],
	/* 130 */
	[Decode(2, DecodeFlag.SYM, 164), Decode(9, DecodeFlag.SYM, 164), Decode(23, DecodeFlag.SYM, 164), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 164), Decode(2, DecodeFlag.SYM, 169), Decode(9, DecodeFlag.SYM, 169), Decode(23, DecodeFlag.SYM, 169), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 169), Decode(2, DecodeFlag.SYM, 170), Decode(9, DecodeFlag.SYM, 170), Decode(23, DecodeFlag.SYM, 170), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 170), Decode(2, DecodeFlag.SYM, 173), Decode(9, DecodeFlag.SYM, 173), Decode(23, DecodeFlag.SYM, 173), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 173)],
	/* 131 */
	[Decode(3, DecodeFlag.SYM, 164), Decode(6, DecodeFlag.SYM, 164), Decode(10, DecodeFlag.SYM, 164), Decode(15, DecodeFlag.SYM, 164), Decode(24, DecodeFlag.SYM, 164), Decode(31, DecodeFlag.SYM, 164), Decode(41, DecodeFlag.SYM, 164), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 164), Decode(3, DecodeFlag.SYM, 169), Decode(6, DecodeFlag.SYM, 169), Decode(10, DecodeFlag.SYM, 169), Decode(15, DecodeFlag.SYM, 169), Decode(24, DecodeFlag.SYM, 169), Decode(31, DecodeFlag.SYM, 169), Decode(41, DecodeFlag.SYM, 169), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 169)],
	/* 132 */
	[Decode(3, DecodeFlag.SYM, 170), Decode(6, DecodeFlag.SYM, 170), Decode(10, DecodeFlag.SYM, 170), Decode(15, DecodeFlag.SYM, 170), Decode(24, DecodeFlag.SYM, 170), Decode(31, DecodeFlag.SYM, 170), Decode(41, DecodeFlag.SYM, 170), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 170), Decode(3, DecodeFlag.SYM, 173), Decode(6, DecodeFlag.SYM, 173), Decode(10, DecodeFlag.SYM, 173), Decode(15, DecodeFlag.SYM, 173), Decode(24, DecodeFlag.SYM, 173), Decode(31, DecodeFlag.SYM, 173), Decode(41, DecodeFlag.SYM, 173), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 173)],
	/* 133 */
	[Decode(137, DecodeFlag.NONE, 0), Decode(138, DecodeFlag.NONE, 0), Decode(140, DecodeFlag.NONE, 0), Decode(141, DecodeFlag.NONE, 0), Decode(144, DecodeFlag.NONE, 0), Decode(145, DecodeFlag.NONE, 0), Decode(147, DecodeFlag.NONE, 0), Decode(150, DecodeFlag.NONE, 0), Decode(156, DecodeFlag.NONE, 0), Decode(159, DecodeFlag.NONE, 0), Decode(163, DecodeFlag.NONE, 0), Decode(166, DecodeFlag.NONE, 0), Decode(171, DecodeFlag.NONE, 0), Decode(174, DecodeFlag.NONE, 0), Decode(181, DecodeFlag.NONE, 0), Decode(190, DecodeFlag.NONE, 0)],
	/* 134 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 178), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 181), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 185), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 186), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 187), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 189), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 190), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 196), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 198), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 228), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 232), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 233), Decode(148, DecodeFlag.NONE, 0), Decode(149, DecodeFlag.NONE, 0), Decode(151, DecodeFlag.NONE, 0), Decode(152, DecodeFlag.NONE, 0)],
	/* 135 */
	[Decode(1, DecodeFlag.SYM, 178), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 178), Decode(1, DecodeFlag.SYM, 181), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 181), Decode(1, DecodeFlag.SYM, 185), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 185), Decode(1, DecodeFlag.SYM, 186), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 186), Decode(1, DecodeFlag.SYM, 187), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 187), Decode(1, DecodeFlag.SYM, 189), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 189), Decode(1, DecodeFlag.SYM, 190), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 190), Decode(1, DecodeFlag.SYM, 196), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 196)],
	/* 136 */
	[Decode(2, DecodeFlag.SYM, 178), Decode(9, DecodeFlag.SYM, 178), Decode(23, DecodeFlag.SYM, 178), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 178), Decode(2, DecodeFlag.SYM, 181), Decode(9, DecodeFlag.SYM, 181), Decode(23, DecodeFlag.SYM, 181), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 181), Decode(2, DecodeFlag.SYM, 185), Decode(9, DecodeFlag.SYM, 185), Decode(23, DecodeFlag.SYM, 185), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 185), Decode(2, DecodeFlag.SYM, 186), Decode(9, DecodeFlag.SYM, 186), Decode(23, DecodeFlag.SYM, 186), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 186)],
	/* 137 */
	[Decode(3, DecodeFlag.SYM, 178), Decode(6, DecodeFlag.SYM, 178), Decode(10, DecodeFlag.SYM, 178), Decode(15, DecodeFlag.SYM, 178), Decode(24, DecodeFlag.SYM, 178), Decode(31, DecodeFlag.SYM, 178), Decode(41, DecodeFlag.SYM, 178), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 178), Decode(3, DecodeFlag.SYM, 181), Decode(6, DecodeFlag.SYM, 181), Decode(10, DecodeFlag.SYM, 181), Decode(15, DecodeFlag.SYM, 181), Decode(24, DecodeFlag.SYM, 181), Decode(31, DecodeFlag.SYM, 181), Decode(41, DecodeFlag.SYM, 181), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 181)],
	/* 138 */
	[Decode(3, DecodeFlag.SYM, 185), Decode(6, DecodeFlag.SYM, 185), Decode(10, DecodeFlag.SYM, 185), Decode(15, DecodeFlag.SYM, 185), Decode(24, DecodeFlag.SYM, 185), Decode(31, DecodeFlag.SYM, 185), Decode(41, DecodeFlag.SYM, 185), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 185), Decode(3, DecodeFlag.SYM, 186), Decode(6, DecodeFlag.SYM, 186), Decode(10, DecodeFlag.SYM, 186), Decode(15, DecodeFlag.SYM, 186), Decode(24, DecodeFlag.SYM, 186), Decode(31, DecodeFlag.SYM, 186), Decode(41, DecodeFlag.SYM, 186), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 186)],
	/* 139 */
	[Decode(2, DecodeFlag.SYM, 187), Decode(9, DecodeFlag.SYM, 187), Decode(23, DecodeFlag.SYM, 187), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 187), Decode(2, DecodeFlag.SYM, 189), Decode(9, DecodeFlag.SYM, 189), Decode(23, DecodeFlag.SYM, 189), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 189), Decode(2, DecodeFlag.SYM, 190), Decode(9, DecodeFlag.SYM, 190), Decode(23, DecodeFlag.SYM, 190), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 190), Decode(2, DecodeFlag.SYM, 196), Decode(9, DecodeFlag.SYM, 196), Decode(23, DecodeFlag.SYM, 196), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 196)],
	/* 140 */
	[Decode(3, DecodeFlag.SYM, 187), Decode(6, DecodeFlag.SYM, 187), Decode(10, DecodeFlag.SYM, 187), Decode(15, DecodeFlag.SYM, 187), Decode(24, DecodeFlag.SYM, 187), Decode(31, DecodeFlag.SYM, 187), Decode(41, DecodeFlag.SYM, 187), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 187), Decode(3, DecodeFlag.SYM, 189), Decode(6, DecodeFlag.SYM, 189), Decode(10, DecodeFlag.SYM, 189), Decode(15, DecodeFlag.SYM, 189), Decode(24, DecodeFlag.SYM, 189), Decode(31, DecodeFlag.SYM, 189), Decode(41, DecodeFlag.SYM, 189), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 189)],
	/* 141 */
	[Decode(3, DecodeFlag.SYM, 190), Decode(6, DecodeFlag.SYM, 190), Decode(10, DecodeFlag.SYM, 190), Decode(15, DecodeFlag.SYM, 190), Decode(24, DecodeFlag.SYM, 190), Decode(31, DecodeFlag.SYM, 190), Decode(41, DecodeFlag.SYM, 190), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 190), Decode(3, DecodeFlag.SYM, 196), Decode(6, DecodeFlag.SYM, 196), Decode(10, DecodeFlag.SYM, 196), Decode(15, DecodeFlag.SYM, 196), Decode(24, DecodeFlag.SYM, 196), Decode(31, DecodeFlag.SYM, 196), Decode(41, DecodeFlag.SYM, 196), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 196)],
	/* 142 */
	[Decode(1, DecodeFlag.SYM, 198), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 198), Decode(1, DecodeFlag.SYM, 228), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 228), Decode(1, DecodeFlag.SYM, 232), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 232), Decode(1, DecodeFlag.SYM, 233), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 233), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 1), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 135), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 137), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 138), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 139), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 140), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 141), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 143)],
	/* 143 */
	[Decode(2, DecodeFlag.SYM, 198), Decode(9, DecodeFlag.SYM, 198), Decode(23, DecodeFlag.SYM, 198), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 198), Decode(2, DecodeFlag.SYM, 228), Decode(9, DecodeFlag.SYM, 228), Decode(23, DecodeFlag.SYM, 228), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 228), Decode(2, DecodeFlag.SYM, 232), Decode(9, DecodeFlag.SYM, 232), Decode(23, DecodeFlag.SYM, 232), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 232), Decode(2, DecodeFlag.SYM, 233), Decode(9, DecodeFlag.SYM, 233), Decode(23, DecodeFlag.SYM, 233), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 233)],
	/* 144 */
	[Decode(3, DecodeFlag.SYM, 198), Decode(6, DecodeFlag.SYM, 198), Decode(10, DecodeFlag.SYM, 198), Decode(15, DecodeFlag.SYM, 198), Decode(24, DecodeFlag.SYM, 198), Decode(31, DecodeFlag.SYM, 198), Decode(41, DecodeFlag.SYM, 198), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 198), Decode(3, DecodeFlag.SYM, 228), Decode(6, DecodeFlag.SYM, 228), Decode(10, DecodeFlag.SYM, 228), Decode(15, DecodeFlag.SYM, 228), Decode(24, DecodeFlag.SYM, 228), Decode(31, DecodeFlag.SYM, 228), Decode(41, DecodeFlag.SYM, 228), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 228)],
	/* 145 */
	[Decode(3, DecodeFlag.SYM, 232), Decode(6, DecodeFlag.SYM, 232), Decode(10, DecodeFlag.SYM, 232), Decode(15, DecodeFlag.SYM, 232), Decode(24, DecodeFlag.SYM, 232), Decode(31, DecodeFlag.SYM, 232), Decode(41, DecodeFlag.SYM, 232), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 232), Decode(3, DecodeFlag.SYM, 233), Decode(6, DecodeFlag.SYM, 233), Decode(10, DecodeFlag.SYM, 233), Decode(15, DecodeFlag.SYM, 233), Decode(24, DecodeFlag.SYM, 233), Decode(31, DecodeFlag.SYM, 233), Decode(41, DecodeFlag.SYM, 233), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 233)],
	/* 146 */
	[Decode(1, DecodeFlag.SYM, 1), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 1), Decode(1, DecodeFlag.SYM, 135), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 135), Decode(1, DecodeFlag.SYM, 137), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 137), Decode(1, DecodeFlag.SYM, 138), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 138), Decode(1, DecodeFlag.SYM, 139), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 139), Decode(1, DecodeFlag.SYM, 140), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 140), Decode(1, DecodeFlag.SYM, 141), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 141), Decode(1, DecodeFlag.SYM, 143), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 143)],
	/* 147 */
	[Decode(2, DecodeFlag.SYM, 1), Decode(9, DecodeFlag.SYM, 1), Decode(23, DecodeFlag.SYM, 1), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 1), Decode(2, DecodeFlag.SYM, 135), Decode(9, DecodeFlag.SYM, 135), Decode(23, DecodeFlag.SYM, 135), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 135), Decode(2, DecodeFlag.SYM, 137), Decode(9, DecodeFlag.SYM, 137), Decode(23, DecodeFlag.SYM, 137), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 137), Decode(2, DecodeFlag.SYM, 138), Decode(9, DecodeFlag.SYM, 138), Decode(23, DecodeFlag.SYM, 138), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 138)],
	/* 148 */
	[Decode(3, DecodeFlag.SYM, 1), Decode(6, DecodeFlag.SYM, 1), Decode(10, DecodeFlag.SYM, 1), Decode(15, DecodeFlag.SYM, 1), Decode(24, DecodeFlag.SYM, 1), Decode(31, DecodeFlag.SYM, 1), Decode(41, DecodeFlag.SYM, 1), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 1), Decode(3, DecodeFlag.SYM, 135), Decode(6, DecodeFlag.SYM, 135), Decode(10, DecodeFlag.SYM, 135), Decode(15, DecodeFlag.SYM, 135), Decode(24, DecodeFlag.SYM, 135), Decode(31, DecodeFlag.SYM, 135), Decode(41, DecodeFlag.SYM, 135), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 135)],
	/* 149 */
	[Decode(3, DecodeFlag.SYM, 137), Decode(6, DecodeFlag.SYM, 137), Decode(10, DecodeFlag.SYM, 137), Decode(15, DecodeFlag.SYM, 137), Decode(24, DecodeFlag.SYM, 137), Decode(31, DecodeFlag.SYM, 137), Decode(41, DecodeFlag.SYM, 137), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 137), Decode(3, DecodeFlag.SYM, 138), Decode(6, DecodeFlag.SYM, 138), Decode(10, DecodeFlag.SYM, 138), Decode(15, DecodeFlag.SYM, 138), Decode(24, DecodeFlag.SYM, 138), Decode(31, DecodeFlag.SYM, 138), Decode(41, DecodeFlag.SYM, 138), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 138)],
	/* 150 */
	[Decode(2, DecodeFlag.SYM, 139), Decode(9, DecodeFlag.SYM, 139), Decode(23, DecodeFlag.SYM, 139), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 139), Decode(2, DecodeFlag.SYM, 140), Decode(9, DecodeFlag.SYM, 140), Decode(23, DecodeFlag.SYM, 140), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 140), Decode(2, DecodeFlag.SYM, 141), Decode(9, DecodeFlag.SYM, 141), Decode(23, DecodeFlag.SYM, 141), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 141), Decode(2, DecodeFlag.SYM, 143), Decode(9, DecodeFlag.SYM, 143), Decode(23, DecodeFlag.SYM, 143), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 143)],
	/* 151 */
	[Decode(3, DecodeFlag.SYM, 139), Decode(6, DecodeFlag.SYM, 139), Decode(10, DecodeFlag.SYM, 139), Decode(15, DecodeFlag.SYM, 139), Decode(24, DecodeFlag.SYM, 139), Decode(31, DecodeFlag.SYM, 139), Decode(41, DecodeFlag.SYM, 139), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 139), Decode(3, DecodeFlag.SYM, 140), Decode(6, DecodeFlag.SYM, 140), Decode(10, DecodeFlag.SYM, 140), Decode(15, DecodeFlag.SYM, 140), Decode(24, DecodeFlag.SYM, 140), Decode(31, DecodeFlag.SYM, 140), Decode(41, DecodeFlag.SYM, 140), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 140)],
	/* 152 */
	[Decode(3, DecodeFlag.SYM, 141), Decode(6, DecodeFlag.SYM, 141), Decode(10, DecodeFlag.SYM, 141), Decode(15, DecodeFlag.SYM, 141), Decode(24, DecodeFlag.SYM, 141), Decode(31, DecodeFlag.SYM, 141), Decode(41, DecodeFlag.SYM, 141), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 141), Decode(3, DecodeFlag.SYM, 143), Decode(6, DecodeFlag.SYM, 143), Decode(10, DecodeFlag.SYM, 143), Decode(15, DecodeFlag.SYM, 143), Decode(24, DecodeFlag.SYM, 143), Decode(31, DecodeFlag.SYM, 143), Decode(41, DecodeFlag.SYM, 143), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 143)],
	/* 153 */
	[Decode(157, DecodeFlag.NONE, 0), Decode(158, DecodeFlag.NONE, 0), Decode(160, DecodeFlag.NONE, 0), Decode(161, DecodeFlag.NONE, 0), Decode(164, DecodeFlag.NONE, 0), Decode(165, DecodeFlag.NONE, 0), Decode(167, DecodeFlag.NONE, 0), Decode(168, DecodeFlag.NONE, 0), Decode(172, DecodeFlag.NONE, 0), Decode(173, DecodeFlag.NONE, 0), Decode(175, DecodeFlag.NONE, 0), Decode(177, DecodeFlag.NONE, 0), Decode(182, DecodeFlag.NONE, 0), Decode(185, DecodeFlag.NONE, 0), Decode(191, DecodeFlag.NONE, 0), Decode(207, DecodeFlag.NONE, 0)],
	/* 154 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 147), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 149), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 150), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 151), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 152), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 155), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 157), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 158), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 165), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 166), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 168), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 174), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 175), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 180), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 182), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 183)],
	/* 155 */
	[Decode(1, DecodeFlag.SYM, 147), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 147), Decode(1, DecodeFlag.SYM, 149), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 149), Decode(1, DecodeFlag.SYM, 150), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 150), Decode(1, DecodeFlag.SYM, 151), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 151), Decode(1, DecodeFlag.SYM, 152), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 152), Decode(1, DecodeFlag.SYM, 155), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 155), Decode(1, DecodeFlag.SYM, 157), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 157), Decode(1, DecodeFlag.SYM, 158), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 158)],
	/* 156 */
	[Decode(2, DecodeFlag.SYM, 147), Decode(9, DecodeFlag.SYM, 147), Decode(23, DecodeFlag.SYM, 147), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 147), Decode(2, DecodeFlag.SYM, 149), Decode(9, DecodeFlag.SYM, 149), Decode(23, DecodeFlag.SYM, 149), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 149), Decode(2, DecodeFlag.SYM, 150), Decode(9, DecodeFlag.SYM, 150), Decode(23, DecodeFlag.SYM, 150), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 150), Decode(2, DecodeFlag.SYM, 151), Decode(9, DecodeFlag.SYM, 151), Decode(23, DecodeFlag.SYM, 151), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 151)],
	/* 157 */
	[Decode(3, DecodeFlag.SYM, 147), Decode(6, DecodeFlag.SYM, 147), Decode(10, DecodeFlag.SYM, 147), Decode(15, DecodeFlag.SYM, 147), Decode(24, DecodeFlag.SYM, 147), Decode(31, DecodeFlag.SYM, 147), Decode(41, DecodeFlag.SYM, 147), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 147), Decode(3, DecodeFlag.SYM, 149), Decode(6, DecodeFlag.SYM, 149), Decode(10, DecodeFlag.SYM, 149), Decode(15, DecodeFlag.SYM, 149), Decode(24, DecodeFlag.SYM, 149), Decode(31, DecodeFlag.SYM, 149), Decode(41, DecodeFlag.SYM, 149), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 149)],
	/* 158 */
	[Decode(3, DecodeFlag.SYM, 150), Decode(6, DecodeFlag.SYM, 150), Decode(10, DecodeFlag.SYM, 150), Decode(15, DecodeFlag.SYM, 150), Decode(24, DecodeFlag.SYM, 150), Decode(31, DecodeFlag.SYM, 150), Decode(41, DecodeFlag.SYM, 150), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 150), Decode(3, DecodeFlag.SYM, 151), Decode(6, DecodeFlag.SYM, 151), Decode(10, DecodeFlag.SYM, 151), Decode(15, DecodeFlag.SYM, 151), Decode(24, DecodeFlag.SYM, 151), Decode(31, DecodeFlag.SYM, 151), Decode(41, DecodeFlag.SYM, 151), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 151)],
	/* 159 */
	[Decode(2, DecodeFlag.SYM, 152), Decode(9, DecodeFlag.SYM, 152), Decode(23, DecodeFlag.SYM, 152), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 152), Decode(2, DecodeFlag.SYM, 155), Decode(9, DecodeFlag.SYM, 155), Decode(23, DecodeFlag.SYM, 155), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 155), Decode(2, DecodeFlag.SYM, 157), Decode(9, DecodeFlag.SYM, 157), Decode(23, DecodeFlag.SYM, 157), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 157), Decode(2, DecodeFlag.SYM, 158), Decode(9, DecodeFlag.SYM, 158), Decode(23, DecodeFlag.SYM, 158), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 158)],
	/* 160 */
	[Decode(3, DecodeFlag.SYM, 152), Decode(6, DecodeFlag.SYM, 152), Decode(10, DecodeFlag.SYM, 152), Decode(15, DecodeFlag.SYM, 152), Decode(24, DecodeFlag.SYM, 152), Decode(31, DecodeFlag.SYM, 152), Decode(41, DecodeFlag.SYM, 152), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 152), Decode(3, DecodeFlag.SYM, 155), Decode(6, DecodeFlag.SYM, 155), Decode(10, DecodeFlag.SYM, 155), Decode(15, DecodeFlag.SYM, 155), Decode(24, DecodeFlag.SYM, 155), Decode(31, DecodeFlag.SYM, 155), Decode(41, DecodeFlag.SYM, 155), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 155)],
	/* 161 */
	[Decode(3, DecodeFlag.SYM, 157), Decode(6, DecodeFlag.SYM, 157), Decode(10, DecodeFlag.SYM, 157), Decode(15, DecodeFlag.SYM, 157), Decode(24, DecodeFlag.SYM, 157), Decode(31, DecodeFlag.SYM, 157), Decode(41, DecodeFlag.SYM, 157), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 157), Decode(3, DecodeFlag.SYM, 158), Decode(6, DecodeFlag.SYM, 158), Decode(10, DecodeFlag.SYM, 158), Decode(15, DecodeFlag.SYM, 158), Decode(24, DecodeFlag.SYM, 158), Decode(31, DecodeFlag.SYM, 158), Decode(41, DecodeFlag.SYM, 158), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 158)],
	/* 162 */
	[Decode(1, DecodeFlag.SYM, 165), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 165), Decode(1, DecodeFlag.SYM, 166), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 166), Decode(1, DecodeFlag.SYM, 168), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 168), Decode(1, DecodeFlag.SYM, 174), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 174), Decode(1, DecodeFlag.SYM, 175), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 175), Decode(1, DecodeFlag.SYM, 180), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 180), Decode(1, DecodeFlag.SYM, 182), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 182), Decode(1, DecodeFlag.SYM, 183), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 183)],
	/* 163 */
	[Decode(2, DecodeFlag.SYM, 165), Decode(9, DecodeFlag.SYM, 165), Decode(23, DecodeFlag.SYM, 165), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 165), Decode(2, DecodeFlag.SYM, 166), Decode(9, DecodeFlag.SYM, 166), Decode(23, DecodeFlag.SYM, 166), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 166), Decode(2, DecodeFlag.SYM, 168), Decode(9, DecodeFlag.SYM, 168), Decode(23, DecodeFlag.SYM, 168), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 168), Decode(2, DecodeFlag.SYM, 174), Decode(9, DecodeFlag.SYM, 174), Decode(23, DecodeFlag.SYM, 174), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 174)],
	/* 164 */
	[Decode(3, DecodeFlag.SYM, 165), Decode(6, DecodeFlag.SYM, 165), Decode(10, DecodeFlag.SYM, 165), Decode(15, DecodeFlag.SYM, 165), Decode(24, DecodeFlag.SYM, 165), Decode(31, DecodeFlag.SYM, 165), Decode(41, DecodeFlag.SYM, 165), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 165), Decode(3, DecodeFlag.SYM, 166), Decode(6, DecodeFlag.SYM, 166), Decode(10, DecodeFlag.SYM, 166), Decode(15, DecodeFlag.SYM, 166), Decode(24, DecodeFlag.SYM, 166), Decode(31, DecodeFlag.SYM, 166), Decode(41, DecodeFlag.SYM, 166), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 166)],
	/* 165 */
	[Decode(3, DecodeFlag.SYM, 168), Decode(6, DecodeFlag.SYM, 168), Decode(10, DecodeFlag.SYM, 168), Decode(15, DecodeFlag.SYM, 168), Decode(24, DecodeFlag.SYM, 168), Decode(31, DecodeFlag.SYM, 168), Decode(41, DecodeFlag.SYM, 168), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 168), Decode(3, DecodeFlag.SYM, 174), Decode(6, DecodeFlag.SYM, 174), Decode(10, DecodeFlag.SYM, 174), Decode(15, DecodeFlag.SYM, 174), Decode(24, DecodeFlag.SYM, 174), Decode(31, DecodeFlag.SYM, 174), Decode(41, DecodeFlag.SYM, 174), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 174)],
	/* 166 */
	[Decode(2, DecodeFlag.SYM, 175), Decode(9, DecodeFlag.SYM, 175), Decode(23, DecodeFlag.SYM, 175), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 175), Decode(2, DecodeFlag.SYM, 180), Decode(9, DecodeFlag.SYM, 180), Decode(23, DecodeFlag.SYM, 180), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 180), Decode(2, DecodeFlag.SYM, 182), Decode(9, DecodeFlag.SYM, 182), Decode(23, DecodeFlag.SYM, 182), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 182), Decode(2, DecodeFlag.SYM, 183), Decode(9, DecodeFlag.SYM, 183), Decode(23, DecodeFlag.SYM, 183), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 183)],
	/* 167 */
	[Decode(3, DecodeFlag.SYM, 175), Decode(6, DecodeFlag.SYM, 175), Decode(10, DecodeFlag.SYM, 175), Decode(15, DecodeFlag.SYM, 175), Decode(24, DecodeFlag.SYM, 175), Decode(31, DecodeFlag.SYM, 175), Decode(41, DecodeFlag.SYM, 175), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 175), Decode(3, DecodeFlag.SYM, 180), Decode(6, DecodeFlag.SYM, 180), Decode(10, DecodeFlag.SYM, 180), Decode(15, DecodeFlag.SYM, 180), Decode(24, DecodeFlag.SYM, 180), Decode(31, DecodeFlag.SYM, 180), Decode(41, DecodeFlag.SYM, 180), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 180)],
	/* 168 */
	[Decode(3, DecodeFlag.SYM, 182), Decode(6, DecodeFlag.SYM, 182), Decode(10, DecodeFlag.SYM, 182), Decode(15, DecodeFlag.SYM, 182), Decode(24, DecodeFlag.SYM, 182), Decode(31, DecodeFlag.SYM, 182), Decode(41, DecodeFlag.SYM, 182), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 182), Decode(3, DecodeFlag.SYM, 183), Decode(6, DecodeFlag.SYM, 183), Decode(10, DecodeFlag.SYM, 183), Decode(15, DecodeFlag.SYM, 183), Decode(24, DecodeFlag.SYM, 183), Decode(31, DecodeFlag.SYM, 183), Decode(41, DecodeFlag.SYM, 183), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 183)],
	/* 169 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 188), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 191), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 197), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 231), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 239), Decode(176, DecodeFlag.NONE, 0), Decode(178, DecodeFlag.NONE, 0), Decode(179, DecodeFlag.NONE, 0), Decode(183, DecodeFlag.NONE, 0), Decode(184, DecodeFlag.NONE, 0), Decode(186, DecodeFlag.NONE, 0), Decode(187, DecodeFlag.NONE, 0), Decode(192, DecodeFlag.NONE, 0), Decode(199, DecodeFlag.NONE, 0), Decode(208, DecodeFlag.NONE, 0), Decode(223, DecodeFlag.NONE, 0)],
	/* 170 */
	[Decode(1, DecodeFlag.SYM, 188), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 188), Decode(1, DecodeFlag.SYM, 191), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 191), Decode(1, DecodeFlag.SYM, 197), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 197), Decode(1, DecodeFlag.SYM, 231), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 231), Decode(1, DecodeFlag.SYM, 239), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 239), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 9), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 142), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 144), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 145), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 148), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 159)],
	/* 171 */
	[Decode(2, DecodeFlag.SYM, 188), Decode(9, DecodeFlag.SYM, 188), Decode(23, DecodeFlag.SYM, 188), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 188), Decode(2, DecodeFlag.SYM, 191), Decode(9, DecodeFlag.SYM, 191), Decode(23, DecodeFlag.SYM, 191), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 191), Decode(2, DecodeFlag.SYM, 197), Decode(9, DecodeFlag.SYM, 197), Decode(23, DecodeFlag.SYM, 197), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 197), Decode(2, DecodeFlag.SYM, 231), Decode(9, DecodeFlag.SYM, 231), Decode(23, DecodeFlag.SYM, 231), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 231)],
	/* 172 */
	[Decode(3, DecodeFlag.SYM, 188), Decode(6, DecodeFlag.SYM, 188), Decode(10, DecodeFlag.SYM, 188), Decode(15, DecodeFlag.SYM, 188), Decode(24, DecodeFlag.SYM, 188), Decode(31, DecodeFlag.SYM, 188), Decode(41, DecodeFlag.SYM, 188), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 188), Decode(3, DecodeFlag.SYM, 191), Decode(6, DecodeFlag.SYM, 191), Decode(10, DecodeFlag.SYM, 191), Decode(15, DecodeFlag.SYM, 191), Decode(24, DecodeFlag.SYM, 191), Decode(31, DecodeFlag.SYM, 191), Decode(41, DecodeFlag.SYM, 191), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 191)],
	/* 173 */
	[Decode(3, DecodeFlag.SYM, 197), Decode(6, DecodeFlag.SYM, 197), Decode(10, DecodeFlag.SYM, 197), Decode(15, DecodeFlag.SYM, 197), Decode(24, DecodeFlag.SYM, 197), Decode(31, DecodeFlag.SYM, 197), Decode(41, DecodeFlag.SYM, 197), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 197), Decode(3, DecodeFlag.SYM, 231), Decode(6, DecodeFlag.SYM, 231), Decode(10, DecodeFlag.SYM, 231), Decode(15, DecodeFlag.SYM, 231), Decode(24, DecodeFlag.SYM, 231), Decode(31, DecodeFlag.SYM, 231), Decode(41, DecodeFlag.SYM, 231), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 231)],
	/* 174 */
	[Decode(2, DecodeFlag.SYM, 239), Decode(9, DecodeFlag.SYM, 239), Decode(23, DecodeFlag.SYM, 239), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 239), Decode(1, DecodeFlag.SYM, 9), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 9), Decode(1, DecodeFlag.SYM, 142), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 142), Decode(1, DecodeFlag.SYM, 144), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 144), Decode(1, DecodeFlag.SYM, 145), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 145), Decode(1, DecodeFlag.SYM, 148), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 148), Decode(1, DecodeFlag.SYM, 159), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 159)],
	/* 175 */
	[Decode(3, DecodeFlag.SYM, 239), Decode(6, DecodeFlag.SYM, 239), Decode(10, DecodeFlag.SYM, 239), Decode(15, DecodeFlag.SYM, 239), Decode(24, DecodeFlag.SYM, 239), Decode(31, DecodeFlag.SYM, 239), Decode(41, DecodeFlag.SYM, 239), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 239), Decode(2, DecodeFlag.SYM, 9), Decode(9, DecodeFlag.SYM, 9), Decode(23, DecodeFlag.SYM, 9), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 9), Decode(2, DecodeFlag.SYM, 142), Decode(9, DecodeFlag.SYM, 142), Decode(23, DecodeFlag.SYM, 142), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 142)],
	/* 176 */
	[Decode(3, DecodeFlag.SYM, 9), Decode(6, DecodeFlag.SYM, 9), Decode(10, DecodeFlag.SYM, 9), Decode(15, DecodeFlag.SYM, 9), Decode(24, DecodeFlag.SYM, 9), Decode(31, DecodeFlag.SYM, 9), Decode(41, DecodeFlag.SYM, 9), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 9), Decode(3, DecodeFlag.SYM, 142), Decode(6, DecodeFlag.SYM, 142), Decode(10, DecodeFlag.SYM, 142), Decode(15, DecodeFlag.SYM, 142), Decode(24, DecodeFlag.SYM, 142), Decode(31, DecodeFlag.SYM, 142), Decode(41, DecodeFlag.SYM, 142), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 142)],
	/* 177 */
	[Decode(2, DecodeFlag.SYM, 144), Decode(9, DecodeFlag.SYM, 144), Decode(23, DecodeFlag.SYM, 144), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 144), Decode(2, DecodeFlag.SYM, 145), Decode(9, DecodeFlag.SYM, 145), Decode(23, DecodeFlag.SYM, 145), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 145), Decode(2, DecodeFlag.SYM, 148), Decode(9, DecodeFlag.SYM, 148), Decode(23, DecodeFlag.SYM, 148), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 148), Decode(2, DecodeFlag.SYM, 159), Decode(9, DecodeFlag.SYM, 159), Decode(23, DecodeFlag.SYM, 159), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 159)],
	/* 178 */
	[Decode(3, DecodeFlag.SYM, 144), Decode(6, DecodeFlag.SYM, 144), Decode(10, DecodeFlag.SYM, 144), Decode(15, DecodeFlag.SYM, 144), Decode(24, DecodeFlag.SYM, 144), Decode(31, DecodeFlag.SYM, 144), Decode(41, DecodeFlag.SYM, 144), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 144), Decode(3, DecodeFlag.SYM, 145), Decode(6, DecodeFlag.SYM, 145), Decode(10, DecodeFlag.SYM, 145), Decode(15, DecodeFlag.SYM, 145), Decode(24, DecodeFlag.SYM, 145), Decode(31, DecodeFlag.SYM, 145), Decode(41, DecodeFlag.SYM, 145), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 145)],
	/* 179 */
	[Decode(3, DecodeFlag.SYM, 148), Decode(6, DecodeFlag.SYM, 148), Decode(10, DecodeFlag.SYM, 148), Decode(15, DecodeFlag.SYM, 148), Decode(24, DecodeFlag.SYM, 148), Decode(31, DecodeFlag.SYM, 148), Decode(41, DecodeFlag.SYM, 148), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 148), Decode(3, DecodeFlag.SYM, 159), Decode(6, DecodeFlag.SYM, 159), Decode(10, DecodeFlag.SYM, 159), Decode(15, DecodeFlag.SYM, 159), Decode(24, DecodeFlag.SYM, 159), Decode(31, DecodeFlag.SYM, 159), Decode(41, DecodeFlag.SYM, 159), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 159)],
	/* 180 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 171), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 206), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 215), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 225), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 236), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 237), Decode(188, DecodeFlag.NONE, 0), Decode(189, DecodeFlag.NONE, 0), Decode(193, DecodeFlag.NONE, 0), Decode(196, DecodeFlag.NONE, 0), Decode(200, DecodeFlag.NONE, 0), Decode(203, DecodeFlag.NONE, 0), Decode(209, DecodeFlag.NONE, 0), Decode(216, DecodeFlag.NONE, 0), Decode(224, DecodeFlag.NONE, 0), Decode(238, DecodeFlag.NONE, 0)],
	/* 181 */
	[Decode(1, DecodeFlag.SYM, 171), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 171), Decode(1, DecodeFlag.SYM, 206), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 206), Decode(1, DecodeFlag.SYM, 215), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 215), Decode(1, DecodeFlag.SYM, 225), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 225), Decode(1, DecodeFlag.SYM, 236), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 236), Decode(1, DecodeFlag.SYM, 237), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 237), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 199), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 207), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 234), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 235)],
	/* 182 */
	[Decode(2, DecodeFlag.SYM, 171), Decode(9, DecodeFlag.SYM, 171), Decode(23, DecodeFlag.SYM, 171), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 171), Decode(2, DecodeFlag.SYM, 206), Decode(9, DecodeFlag.SYM, 206), Decode(23, DecodeFlag.SYM, 206), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 206), Decode(2, DecodeFlag.SYM, 215), Decode(9, DecodeFlag.SYM, 215), Decode(23, DecodeFlag.SYM, 215), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 215), Decode(2, DecodeFlag.SYM, 225), Decode(9, DecodeFlag.SYM, 225), Decode(23, DecodeFlag.SYM, 225), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 225)],
	/* 183 */
	[Decode(3, DecodeFlag.SYM, 171), Decode(6, DecodeFlag.SYM, 171), Decode(10, DecodeFlag.SYM, 171), Decode(15, DecodeFlag.SYM, 171), Decode(24, DecodeFlag.SYM, 171), Decode(31, DecodeFlag.SYM, 171), Decode(41, DecodeFlag.SYM, 171), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 171), Decode(3, DecodeFlag.SYM, 206), Decode(6, DecodeFlag.SYM, 206), Decode(10, DecodeFlag.SYM, 206), Decode(15, DecodeFlag.SYM, 206), Decode(24, DecodeFlag.SYM, 206), Decode(31, DecodeFlag.SYM, 206), Decode(41, DecodeFlag.SYM, 206), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 206)],
	/* 184 */
	[Decode(3, DecodeFlag.SYM, 215), Decode(6, DecodeFlag.SYM, 215), Decode(10, DecodeFlag.SYM, 215), Decode(15, DecodeFlag.SYM, 215), Decode(24, DecodeFlag.SYM, 215), Decode(31, DecodeFlag.SYM, 215), Decode(41, DecodeFlag.SYM, 215), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 215), Decode(3, DecodeFlag.SYM, 225), Decode(6, DecodeFlag.SYM, 225), Decode(10, DecodeFlag.SYM, 225), Decode(15, DecodeFlag.SYM, 225), Decode(24, DecodeFlag.SYM, 225), Decode(31, DecodeFlag.SYM, 225), Decode(41, DecodeFlag.SYM, 225), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 225)],
	/* 185 */
	[Decode(2, DecodeFlag.SYM, 236), Decode(9, DecodeFlag.SYM, 236), Decode(23, DecodeFlag.SYM, 236), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 236), Decode(2, DecodeFlag.SYM, 237), Decode(9, DecodeFlag.SYM, 237), Decode(23, DecodeFlag.SYM, 237), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 237), Decode(1, DecodeFlag.SYM, 199), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 199), Decode(1, DecodeFlag.SYM, 207), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 207), Decode(1, DecodeFlag.SYM, 234), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 234), Decode(1, DecodeFlag.SYM, 235), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 235)],
	/* 186 */
	[Decode(3, DecodeFlag.SYM, 236), Decode(6, DecodeFlag.SYM, 236), Decode(10, DecodeFlag.SYM, 236), Decode(15, DecodeFlag.SYM, 236), Decode(24, DecodeFlag.SYM, 236), Decode(31, DecodeFlag.SYM, 236), Decode(41, DecodeFlag.SYM, 236), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 236), Decode(3, DecodeFlag.SYM, 237), Decode(6, DecodeFlag.SYM, 237), Decode(10, DecodeFlag.SYM, 237), Decode(15, DecodeFlag.SYM, 237), Decode(24, DecodeFlag.SYM, 237), Decode(31, DecodeFlag.SYM, 237), Decode(41, DecodeFlag.SYM, 237), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 237)],
	/* 187 */
	[Decode(2, DecodeFlag.SYM, 199), Decode(9, DecodeFlag.SYM, 199), Decode(23, DecodeFlag.SYM, 199), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 199), Decode(2, DecodeFlag.SYM, 207), Decode(9, DecodeFlag.SYM, 207), Decode(23, DecodeFlag.SYM, 207), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 207), Decode(2, DecodeFlag.SYM, 234), Decode(9, DecodeFlag.SYM, 234), Decode(23, DecodeFlag.SYM, 234), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 234), Decode(2, DecodeFlag.SYM, 235), Decode(9, DecodeFlag.SYM, 235), Decode(23, DecodeFlag.SYM, 235), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 235)],
	/* 188 */
	[Decode(3, DecodeFlag.SYM, 199), Decode(6, DecodeFlag.SYM, 199), Decode(10, DecodeFlag.SYM, 199), Decode(15, DecodeFlag.SYM, 199), Decode(24, DecodeFlag.SYM, 199), Decode(31, DecodeFlag.SYM, 199), Decode(41, DecodeFlag.SYM, 199), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 199), Decode(3, DecodeFlag.SYM, 207), Decode(6, DecodeFlag.SYM, 207), Decode(10, DecodeFlag.SYM, 207), Decode(15, DecodeFlag.SYM, 207), Decode(24, DecodeFlag.SYM, 207), Decode(31, DecodeFlag.SYM, 207), Decode(41, DecodeFlag.SYM, 207), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 207)],
	/* 189 */
	[Decode(3, DecodeFlag.SYM, 234), Decode(6, DecodeFlag.SYM, 234), Decode(10, DecodeFlag.SYM, 234), Decode(15, DecodeFlag.SYM, 234), Decode(24, DecodeFlag.SYM, 234), Decode(31, DecodeFlag.SYM, 234), Decode(41, DecodeFlag.SYM, 234), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 234), Decode(3, DecodeFlag.SYM, 235), Decode(6, DecodeFlag.SYM, 235), Decode(10, DecodeFlag.SYM, 235), Decode(15, DecodeFlag.SYM, 235), Decode(24, DecodeFlag.SYM, 235), Decode(31, DecodeFlag.SYM, 235), Decode(41, DecodeFlag.SYM, 235), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 235)],
	/* 190 */
	[Decode(194, DecodeFlag.NONE, 0), Decode(195, DecodeFlag.NONE, 0), Decode(197, DecodeFlag.NONE, 0), Decode(198, DecodeFlag.NONE, 0), Decode(201, DecodeFlag.NONE, 0), Decode(202, DecodeFlag.NONE, 0), Decode(204, DecodeFlag.NONE, 0), Decode(205, DecodeFlag.NONE, 0), Decode(210, DecodeFlag.NONE, 0), Decode(213, DecodeFlag.NONE, 0), Decode(217, DecodeFlag.NONE, 0), Decode(220, DecodeFlag.NONE, 0), Decode(225, DecodeFlag.NONE, 0), Decode(231, DecodeFlag.NONE, 0), Decode(239, DecodeFlag.NONE, 0), Decode(246, DecodeFlag.NONE, 0)],
	/* 191 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 192), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 193), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 200), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 201), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 202), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 205), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 210), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 213), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 218), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 219), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 238), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 240), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 242), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 243), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 255), Decode(206, DecodeFlag.NONE, 0)],
	/* 192 */
	[Decode(1, DecodeFlag.SYM, 192), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 192), Decode(1, DecodeFlag.SYM, 193), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 193), Decode(1, DecodeFlag.SYM, 200), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 200), Decode(1, DecodeFlag.SYM, 201), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 201), Decode(1, DecodeFlag.SYM, 202), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 202), Decode(1, DecodeFlag.SYM, 205), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 205), Decode(1, DecodeFlag.SYM, 210), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 210), Decode(1, DecodeFlag.SYM, 213), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 213)],
	/* 193 */
	[Decode(2, DecodeFlag.SYM, 192), Decode(9, DecodeFlag.SYM, 192), Decode(23, DecodeFlag.SYM, 192), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 192), Decode(2, DecodeFlag.SYM, 193), Decode(9, DecodeFlag.SYM, 193), Decode(23, DecodeFlag.SYM, 193), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 193), Decode(2, DecodeFlag.SYM, 200), Decode(9, DecodeFlag.SYM, 200), Decode(23, DecodeFlag.SYM, 200), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 200), Decode(2, DecodeFlag.SYM, 201), Decode(9, DecodeFlag.SYM, 201), Decode(23, DecodeFlag.SYM, 201), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 201)],
	/* 194 */
	[Decode(3, DecodeFlag.SYM, 192), Decode(6, DecodeFlag.SYM, 192), Decode(10, DecodeFlag.SYM, 192), Decode(15, DecodeFlag.SYM, 192), Decode(24, DecodeFlag.SYM, 192), Decode(31, DecodeFlag.SYM, 192), Decode(41, DecodeFlag.SYM, 192), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 192), Decode(3, DecodeFlag.SYM, 193), Decode(6, DecodeFlag.SYM, 193), Decode(10, DecodeFlag.SYM, 193), Decode(15, DecodeFlag.SYM, 193), Decode(24, DecodeFlag.SYM, 193), Decode(31, DecodeFlag.SYM, 193), Decode(41, DecodeFlag.SYM, 193), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 193)],
	/* 195 */
	[Decode(3, DecodeFlag.SYM, 200), Decode(6, DecodeFlag.SYM, 200), Decode(10, DecodeFlag.SYM, 200), Decode(15, DecodeFlag.SYM, 200), Decode(24, DecodeFlag.SYM, 200), Decode(31, DecodeFlag.SYM, 200), Decode(41, DecodeFlag.SYM, 200), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 200), Decode(3, DecodeFlag.SYM, 201), Decode(6, DecodeFlag.SYM, 201), Decode(10, DecodeFlag.SYM, 201), Decode(15, DecodeFlag.SYM, 201), Decode(24, DecodeFlag.SYM, 201), Decode(31, DecodeFlag.SYM, 201), Decode(41, DecodeFlag.SYM, 201), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 201)],
	/* 196 */
	[Decode(2, DecodeFlag.SYM, 202), Decode(9, DecodeFlag.SYM, 202), Decode(23, DecodeFlag.SYM, 202), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 202), Decode(2, DecodeFlag.SYM, 205), Decode(9, DecodeFlag.SYM, 205), Decode(23, DecodeFlag.SYM, 205), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 205), Decode(2, DecodeFlag.SYM, 210), Decode(9, DecodeFlag.SYM, 210), Decode(23, DecodeFlag.SYM, 210), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 210), Decode(2, DecodeFlag.SYM, 213), Decode(9, DecodeFlag.SYM, 213), Decode(23, DecodeFlag.SYM, 213), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 213)],
	/* 197 */
	[Decode(3, DecodeFlag.SYM, 202), Decode(6, DecodeFlag.SYM, 202), Decode(10, DecodeFlag.SYM, 202), Decode(15, DecodeFlag.SYM, 202), Decode(24, DecodeFlag.SYM, 202), Decode(31, DecodeFlag.SYM, 202), Decode(41, DecodeFlag.SYM, 202), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 202), Decode(3, DecodeFlag.SYM, 205), Decode(6, DecodeFlag.SYM, 205), Decode(10, DecodeFlag.SYM, 205), Decode(15, DecodeFlag.SYM, 205), Decode(24, DecodeFlag.SYM, 205), Decode(31, DecodeFlag.SYM, 205), Decode(41, DecodeFlag.SYM, 205), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 205)],
	/* 198 */
	[Decode(3, DecodeFlag.SYM, 210), Decode(6, DecodeFlag.SYM, 210), Decode(10, DecodeFlag.SYM, 210), Decode(15, DecodeFlag.SYM, 210), Decode(24, DecodeFlag.SYM, 210), Decode(31, DecodeFlag.SYM, 210), Decode(41, DecodeFlag.SYM, 210), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 210), Decode(3, DecodeFlag.SYM, 213), Decode(6, DecodeFlag.SYM, 213), Decode(10, DecodeFlag.SYM, 213), Decode(15, DecodeFlag.SYM, 213), Decode(24, DecodeFlag.SYM, 213), Decode(31, DecodeFlag.SYM, 213), Decode(41, DecodeFlag.SYM, 213), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 213)],
	/* 199 */
	[Decode(1, DecodeFlag.SYM, 218), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 218), Decode(1, DecodeFlag.SYM, 219), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 219), Decode(1, DecodeFlag.SYM, 238), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 238), Decode(1, DecodeFlag.SYM, 240), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 240), Decode(1, DecodeFlag.SYM, 242), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 242), Decode(1, DecodeFlag.SYM, 243), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 243), Decode(1, DecodeFlag.SYM, 255), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 255), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 203), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 204)],
	/* 200 */
	[Decode(2, DecodeFlag.SYM, 218), Decode(9, DecodeFlag.SYM, 218), Decode(23, DecodeFlag.SYM, 218), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 218), Decode(2, DecodeFlag.SYM, 219), Decode(9, DecodeFlag.SYM, 219), Decode(23, DecodeFlag.SYM, 219), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 219), Decode(2, DecodeFlag.SYM, 238), Decode(9, DecodeFlag.SYM, 238), Decode(23, DecodeFlag.SYM, 238), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 238), Decode(2, DecodeFlag.SYM, 240), Decode(9, DecodeFlag.SYM, 240), Decode(23, DecodeFlag.SYM, 240), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 240)],
	/* 201 */
	[Decode(3, DecodeFlag.SYM, 218), Decode(6, DecodeFlag.SYM, 218), Decode(10, DecodeFlag.SYM, 218), Decode(15, DecodeFlag.SYM, 218), Decode(24, DecodeFlag.SYM, 218), Decode(31, DecodeFlag.SYM, 218), Decode(41, DecodeFlag.SYM, 218), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 218), Decode(3, DecodeFlag.SYM, 219), Decode(6, DecodeFlag.SYM, 219), Decode(10, DecodeFlag.SYM, 219), Decode(15, DecodeFlag.SYM, 219), Decode(24, DecodeFlag.SYM, 219), Decode(31, DecodeFlag.SYM, 219), Decode(41, DecodeFlag.SYM, 219), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 219)],
	/* 202 */
	[Decode(3, DecodeFlag.SYM, 238), Decode(6, DecodeFlag.SYM, 238), Decode(10, DecodeFlag.SYM, 238), Decode(15, DecodeFlag.SYM, 238), Decode(24, DecodeFlag.SYM, 238), Decode(31, DecodeFlag.SYM, 238), Decode(41, DecodeFlag.SYM, 238), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 238), Decode(3, DecodeFlag.SYM, 240), Decode(6, DecodeFlag.SYM, 240), Decode(10, DecodeFlag.SYM, 240), Decode(15, DecodeFlag.SYM, 240), Decode(24, DecodeFlag.SYM, 240), Decode(31, DecodeFlag.SYM, 240), Decode(41, DecodeFlag.SYM, 240), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 240)],
	/* 203 */
	[Decode(2, DecodeFlag.SYM, 242), Decode(9, DecodeFlag.SYM, 242), Decode(23, DecodeFlag.SYM, 242), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 242), Decode(2, DecodeFlag.SYM, 243), Decode(9, DecodeFlag.SYM, 243), Decode(23, DecodeFlag.SYM, 243), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 243), Decode(2, DecodeFlag.SYM, 255), Decode(9, DecodeFlag.SYM, 255), Decode(23, DecodeFlag.SYM, 255), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 255), Decode(1, DecodeFlag.SYM, 203), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 203), Decode(1, DecodeFlag.SYM, 204), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 204)],
	/* 204 */
	[Decode(3, DecodeFlag.SYM, 242), Decode(6, DecodeFlag.SYM, 242), Decode(10, DecodeFlag.SYM, 242), Decode(15, DecodeFlag.SYM, 242), Decode(24, DecodeFlag.SYM, 242), Decode(31, DecodeFlag.SYM, 242), Decode(41, DecodeFlag.SYM, 242), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 242), Decode(3, DecodeFlag.SYM, 243), Decode(6, DecodeFlag.SYM, 243), Decode(10, DecodeFlag.SYM, 243), Decode(15, DecodeFlag.SYM, 243), Decode(24, DecodeFlag.SYM, 243), Decode(31, DecodeFlag.SYM, 243), Decode(41, DecodeFlag.SYM, 243), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 243)],
	/* 205 */
	[Decode(3, DecodeFlag.SYM, 255), Decode(6, DecodeFlag.SYM, 255), Decode(10, DecodeFlag.SYM, 255), Decode(15, DecodeFlag.SYM, 255), Decode(24, DecodeFlag.SYM, 255), Decode(31, DecodeFlag.SYM, 255), Decode(41, DecodeFlag.SYM, 255), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 255), Decode(2, DecodeFlag.SYM, 203), Decode(9, DecodeFlag.SYM, 203), Decode(23, DecodeFlag.SYM, 203), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 203), Decode(2, DecodeFlag.SYM, 204), Decode(9, DecodeFlag.SYM, 204), Decode(23, DecodeFlag.SYM, 204), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 204)],
	/* 206 */
	[Decode(3, DecodeFlag.SYM, 203), Decode(6, DecodeFlag.SYM, 203), Decode(10, DecodeFlag.SYM, 203), Decode(15, DecodeFlag.SYM, 203), Decode(24, DecodeFlag.SYM, 203), Decode(31, DecodeFlag.SYM, 203), Decode(41, DecodeFlag.SYM, 203), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 203), Decode(3, DecodeFlag.SYM, 204), Decode(6, DecodeFlag.SYM, 204), Decode(10, DecodeFlag.SYM, 204), Decode(15, DecodeFlag.SYM, 204), Decode(24, DecodeFlag.SYM, 204), Decode(31, DecodeFlag.SYM, 204), Decode(41, DecodeFlag.SYM, 204), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 204)],
	/* 207 */
	[Decode(211, DecodeFlag.NONE, 0), Decode(212, DecodeFlag.NONE, 0), Decode(214, DecodeFlag.NONE, 0), Decode(215, DecodeFlag.NONE, 0), Decode(218, DecodeFlag.NONE, 0), Decode(219, DecodeFlag.NONE, 0), Decode(221, DecodeFlag.NONE, 0), Decode(222, DecodeFlag.NONE, 0), Decode(226, DecodeFlag.NONE, 0), Decode(228, DecodeFlag.NONE, 0), Decode(232, DecodeFlag.NONE, 0), Decode(235, DecodeFlag.NONE, 0), Decode(240, DecodeFlag.NONE, 0), Decode(243, DecodeFlag.NONE, 0), Decode(247, DecodeFlag.NONE, 0), Decode(250, DecodeFlag.NONE, 0)],
	/* 208 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 211), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 212), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 214), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 221), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 222), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 223), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 241), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 244), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 245), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 246), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 247), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 248), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 250), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 251), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 252), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 253)],
	/* 209 */
	[Decode(1, DecodeFlag.SYM, 211), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 211), Decode(1, DecodeFlag.SYM, 212), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 212), Decode(1, DecodeFlag.SYM, 214), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 214), Decode(1, DecodeFlag.SYM, 221), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 221), Decode(1, DecodeFlag.SYM, 222), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 222), Decode(1, DecodeFlag.SYM, 223), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 223), Decode(1, DecodeFlag.SYM, 241), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 241), Decode(1, DecodeFlag.SYM, 244), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 244)],
	/* 210 */
	[Decode(2, DecodeFlag.SYM, 211), Decode(9, DecodeFlag.SYM, 211), Decode(23, DecodeFlag.SYM, 211), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 211), Decode(2, DecodeFlag.SYM, 212), Decode(9, DecodeFlag.SYM, 212), Decode(23, DecodeFlag.SYM, 212), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 212), Decode(2, DecodeFlag.SYM, 214), Decode(9, DecodeFlag.SYM, 214), Decode(23, DecodeFlag.SYM, 214), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 214), Decode(2, DecodeFlag.SYM, 221), Decode(9, DecodeFlag.SYM, 221), Decode(23, DecodeFlag.SYM, 221), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 221)],
	/* 211 */
	[Decode(3, DecodeFlag.SYM, 211), Decode(6, DecodeFlag.SYM, 211), Decode(10, DecodeFlag.SYM, 211), Decode(15, DecodeFlag.SYM, 211), Decode(24, DecodeFlag.SYM, 211), Decode(31, DecodeFlag.SYM, 211), Decode(41, DecodeFlag.SYM, 211), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 211), Decode(3, DecodeFlag.SYM, 212), Decode(6, DecodeFlag.SYM, 212), Decode(10, DecodeFlag.SYM, 212), Decode(15, DecodeFlag.SYM, 212), Decode(24, DecodeFlag.SYM, 212), Decode(31, DecodeFlag.SYM, 212), Decode(41, DecodeFlag.SYM, 212), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 212)],
	/* 212 */
	[Decode(3, DecodeFlag.SYM, 214), Decode(6, DecodeFlag.SYM, 214), Decode(10, DecodeFlag.SYM, 214), Decode(15, DecodeFlag.SYM, 214), Decode(24, DecodeFlag.SYM, 214), Decode(31, DecodeFlag.SYM, 214), Decode(41, DecodeFlag.SYM, 214), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 214), Decode(3, DecodeFlag.SYM, 221), Decode(6, DecodeFlag.SYM, 221), Decode(10, DecodeFlag.SYM, 221), Decode(15, DecodeFlag.SYM, 221), Decode(24, DecodeFlag.SYM, 221), Decode(31, DecodeFlag.SYM, 221), Decode(41, DecodeFlag.SYM, 221), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 221)],
	/* 213 */
	[Decode(2, DecodeFlag.SYM, 222), Decode(9, DecodeFlag.SYM, 222), Decode(23, DecodeFlag.SYM, 222), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 222), Decode(2, DecodeFlag.SYM, 223), Decode(9, DecodeFlag.SYM, 223), Decode(23, DecodeFlag.SYM, 223), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 223), Decode(2, DecodeFlag.SYM, 241), Decode(9, DecodeFlag.SYM, 241), Decode(23, DecodeFlag.SYM, 241), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 241), Decode(2, DecodeFlag.SYM, 244), Decode(9, DecodeFlag.SYM, 244), Decode(23, DecodeFlag.SYM, 244), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 244)],
	/* 214 */
	[Decode(3, DecodeFlag.SYM, 222), Decode(6, DecodeFlag.SYM, 222), Decode(10, DecodeFlag.SYM, 222), Decode(15, DecodeFlag.SYM, 222), Decode(24, DecodeFlag.SYM, 222), Decode(31, DecodeFlag.SYM, 222), Decode(41, DecodeFlag.SYM, 222), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 222), Decode(3, DecodeFlag.SYM, 223), Decode(6, DecodeFlag.SYM, 223), Decode(10, DecodeFlag.SYM, 223), Decode(15, DecodeFlag.SYM, 223), Decode(24, DecodeFlag.SYM, 223), Decode(31, DecodeFlag.SYM, 223), Decode(41, DecodeFlag.SYM, 223), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 223)],
	/* 215 */
	[Decode(3, DecodeFlag.SYM, 241), Decode(6, DecodeFlag.SYM, 241), Decode(10, DecodeFlag.SYM, 241), Decode(15, DecodeFlag.SYM, 241), Decode(24, DecodeFlag.SYM, 241), Decode(31, DecodeFlag.SYM, 241), Decode(41, DecodeFlag.SYM, 241), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 241), Decode(3, DecodeFlag.SYM, 244), Decode(6, DecodeFlag.SYM, 244), Decode(10, DecodeFlag.SYM, 244), Decode(15, DecodeFlag.SYM, 244), Decode(24, DecodeFlag.SYM, 244), Decode(31, DecodeFlag.SYM, 244), Decode(41, DecodeFlag.SYM, 244), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 244)],
	/* 216 */
	[Decode(1, DecodeFlag.SYM, 245), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 245), Decode(1, DecodeFlag.SYM, 246), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 246), Decode(1, DecodeFlag.SYM, 247), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 247), Decode(1, DecodeFlag.SYM, 248), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 248), Decode(1, DecodeFlag.SYM, 250), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 250), Decode(1, DecodeFlag.SYM, 251), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 251), Decode(1, DecodeFlag.SYM, 252), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 252), Decode(1, DecodeFlag.SYM, 253), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 253)],
	/* 217 */
	[Decode(2, DecodeFlag.SYM, 245), Decode(9, DecodeFlag.SYM, 245), Decode(23, DecodeFlag.SYM, 245), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 245), Decode(2, DecodeFlag.SYM, 246), Decode(9, DecodeFlag.SYM, 246), Decode(23, DecodeFlag.SYM, 246), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 246), Decode(2, DecodeFlag.SYM, 247), Decode(9, DecodeFlag.SYM, 247), Decode(23, DecodeFlag.SYM, 247), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 247), Decode(2, DecodeFlag.SYM, 248), Decode(9, DecodeFlag.SYM, 248), Decode(23, DecodeFlag.SYM, 248), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 248)],
	/* 218 */
	[Decode(3, DecodeFlag.SYM, 245), Decode(6, DecodeFlag.SYM, 245), Decode(10, DecodeFlag.SYM, 245), Decode(15, DecodeFlag.SYM, 245), Decode(24, DecodeFlag.SYM, 245), Decode(31, DecodeFlag.SYM, 245), Decode(41, DecodeFlag.SYM, 245), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 245), Decode(3, DecodeFlag.SYM, 246), Decode(6, DecodeFlag.SYM, 246), Decode(10, DecodeFlag.SYM, 246), Decode(15, DecodeFlag.SYM, 246), Decode(24, DecodeFlag.SYM, 246), Decode(31, DecodeFlag.SYM, 246), Decode(41, DecodeFlag.SYM, 246), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 246)],
	/* 219 */
	[Decode(3, DecodeFlag.SYM, 247), Decode(6, DecodeFlag.SYM, 247), Decode(10, DecodeFlag.SYM, 247), Decode(15, DecodeFlag.SYM, 247), Decode(24, DecodeFlag.SYM, 247), Decode(31, DecodeFlag.SYM, 247), Decode(41, DecodeFlag.SYM, 247), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 247), Decode(3, DecodeFlag.SYM, 248), Decode(6, DecodeFlag.SYM, 248), Decode(10, DecodeFlag.SYM, 248), Decode(15, DecodeFlag.SYM, 248), Decode(24, DecodeFlag.SYM, 248), Decode(31, DecodeFlag.SYM, 248), Decode(41, DecodeFlag.SYM, 248), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 248)],
	/* 220 */
	[Decode(2, DecodeFlag.SYM, 250), Decode(9, DecodeFlag.SYM, 250), Decode(23, DecodeFlag.SYM, 250), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 250), Decode(2, DecodeFlag.SYM, 251), Decode(9, DecodeFlag.SYM, 251), Decode(23, DecodeFlag.SYM, 251), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 251), Decode(2, DecodeFlag.SYM, 252), Decode(9, DecodeFlag.SYM, 252), Decode(23, DecodeFlag.SYM, 252), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 252), Decode(2, DecodeFlag.SYM, 253), Decode(9, DecodeFlag.SYM, 253), Decode(23, DecodeFlag.SYM, 253), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 253)],
	/* 221 */
	[Decode(3, DecodeFlag.SYM, 250), Decode(6, DecodeFlag.SYM, 250), Decode(10, DecodeFlag.SYM, 250), Decode(15, DecodeFlag.SYM, 250), Decode(24, DecodeFlag.SYM, 250), Decode(31, DecodeFlag.SYM, 250), Decode(41, DecodeFlag.SYM, 250), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 250), Decode(3, DecodeFlag.SYM, 251), Decode(6, DecodeFlag.SYM, 251), Decode(10, DecodeFlag.SYM, 251), Decode(15, DecodeFlag.SYM, 251), Decode(24, DecodeFlag.SYM, 251), Decode(31, DecodeFlag.SYM, 251), Decode(41, DecodeFlag.SYM, 251), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 251)],
	/* 222 */
	[Decode(3, DecodeFlag.SYM, 252), Decode(6, DecodeFlag.SYM, 252), Decode(10, DecodeFlag.SYM, 252), Decode(15, DecodeFlag.SYM, 252), Decode(24, DecodeFlag.SYM, 252), Decode(31, DecodeFlag.SYM, 252), Decode(41, DecodeFlag.SYM, 252), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 252), Decode(3, DecodeFlag.SYM, 253), Decode(6, DecodeFlag.SYM, 253), Decode(10, DecodeFlag.SYM, 253), Decode(15, DecodeFlag.SYM, 253), Decode(24, DecodeFlag.SYM, 253), Decode(31, DecodeFlag.SYM, 253), Decode(41, DecodeFlag.SYM, 253), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 253)],
	/* 223 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 254), Decode(227, DecodeFlag.NONE, 0), Decode(229, DecodeFlag.NONE, 0), Decode(230, DecodeFlag.NONE, 0), Decode(233, DecodeFlag.NONE, 0), Decode(234, DecodeFlag.NONE, 0), Decode(236, DecodeFlag.NONE, 0), Decode(237, DecodeFlag.NONE, 0), Decode(241, DecodeFlag.NONE, 0), Decode(242, DecodeFlag.NONE, 0), Decode(244, DecodeFlag.NONE, 0), Decode(245, DecodeFlag.NONE, 0), Decode(248, DecodeFlag.NONE, 0), Decode(249, DecodeFlag.NONE, 0), Decode(251, DecodeFlag.NONE, 0), Decode(252, DecodeFlag.NONE, 0)],
	/* 224 */
	[Decode(1, DecodeFlag.SYM, 254), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 254), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 2), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 3), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 4), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 5), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 6), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 7), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 8), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 11), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 12), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 14), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 15), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 16), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 17), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 18)],
	/* 225 */
	[Decode(2, DecodeFlag.SYM, 254), Decode(9, DecodeFlag.SYM, 254), Decode(23, DecodeFlag.SYM, 254), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 254), Decode(1, DecodeFlag.SYM, 2), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 2), Decode(1, DecodeFlag.SYM, 3), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 3), Decode(1, DecodeFlag.SYM, 4), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 4), Decode(1, DecodeFlag.SYM, 5), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 5), Decode(1, DecodeFlag.SYM, 6), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 6), Decode(1, DecodeFlag.SYM, 7), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 7)],
	/* 226 */
	[Decode(3, DecodeFlag.SYM, 254), Decode(6, DecodeFlag.SYM, 254), Decode(10, DecodeFlag.SYM, 254), Decode(15, DecodeFlag.SYM, 254), Decode(24, DecodeFlag.SYM, 254), Decode(31, DecodeFlag.SYM, 254), Decode(41, DecodeFlag.SYM, 254), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 254), Decode(2, DecodeFlag.SYM, 2), Decode(9, DecodeFlag.SYM, 2), Decode(23, DecodeFlag.SYM, 2), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 2), Decode(2, DecodeFlag.SYM, 3), Decode(9, DecodeFlag.SYM, 3), Decode(23, DecodeFlag.SYM, 3), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 3)],
	/* 227 */
	[Decode(3, DecodeFlag.SYM, 2), Decode(6, DecodeFlag.SYM, 2), Decode(10, DecodeFlag.SYM, 2), Decode(15, DecodeFlag.SYM, 2), Decode(24, DecodeFlag.SYM, 2), Decode(31, DecodeFlag.SYM, 2), Decode(41, DecodeFlag.SYM, 2), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 2), Decode(3, DecodeFlag.SYM, 3), Decode(6, DecodeFlag.SYM, 3), Decode(10, DecodeFlag.SYM, 3), Decode(15, DecodeFlag.SYM, 3), Decode(24, DecodeFlag.SYM, 3), Decode(31, DecodeFlag.SYM, 3), Decode(41, DecodeFlag.SYM, 3), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 3)],
	/* 228 */
	[Decode(2, DecodeFlag.SYM, 4), Decode(9, DecodeFlag.SYM, 4), Decode(23, DecodeFlag.SYM, 4), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 4), Decode(2, DecodeFlag.SYM, 5), Decode(9, DecodeFlag.SYM, 5), Decode(23, DecodeFlag.SYM, 5), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 5), Decode(2, DecodeFlag.SYM, 6), Decode(9, DecodeFlag.SYM, 6), Decode(23, DecodeFlag.SYM, 6), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 6), Decode(2, DecodeFlag.SYM, 7), Decode(9, DecodeFlag.SYM, 7), Decode(23, DecodeFlag.SYM, 7), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 7)],
	/* 229 */
	[Decode(3, DecodeFlag.SYM, 4), Decode(6, DecodeFlag.SYM, 4), Decode(10, DecodeFlag.SYM, 4), Decode(15, DecodeFlag.SYM, 4), Decode(24, DecodeFlag.SYM, 4), Decode(31, DecodeFlag.SYM, 4), Decode(41, DecodeFlag.SYM, 4), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 4), Decode(3, DecodeFlag.SYM, 5), Decode(6, DecodeFlag.SYM, 5), Decode(10, DecodeFlag.SYM, 5), Decode(15, DecodeFlag.SYM, 5), Decode(24, DecodeFlag.SYM, 5), Decode(31, DecodeFlag.SYM, 5), Decode(41, DecodeFlag.SYM, 5), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 5)],
	/* 230 */
	[Decode(3, DecodeFlag.SYM, 6), Decode(6, DecodeFlag.SYM, 6), Decode(10, DecodeFlag.SYM, 6), Decode(15, DecodeFlag.SYM, 6), Decode(24, DecodeFlag.SYM, 6), Decode(31, DecodeFlag.SYM, 6), Decode(41, DecodeFlag.SYM, 6), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 6), Decode(3, DecodeFlag.SYM, 7), Decode(6, DecodeFlag.SYM, 7), Decode(10, DecodeFlag.SYM, 7), Decode(15, DecodeFlag.SYM, 7), Decode(24, DecodeFlag.SYM, 7), Decode(31, DecodeFlag.SYM, 7), Decode(41, DecodeFlag.SYM, 7), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 7)],
	/* 231 */
	[Decode(1, DecodeFlag.SYM, 8), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 8), Decode(1, DecodeFlag.SYM, 11), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 11), Decode(1, DecodeFlag.SYM, 12), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 12), Decode(1, DecodeFlag.SYM, 14), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 14), Decode(1, DecodeFlag.SYM, 15), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 15), Decode(1, DecodeFlag.SYM, 16), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 16), Decode(1, DecodeFlag.SYM, 17), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 17), Decode(1, DecodeFlag.SYM, 18), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 18)],
	/* 232 */
	[Decode(2, DecodeFlag.SYM, 8), Decode(9, DecodeFlag.SYM, 8), Decode(23, DecodeFlag.SYM, 8), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 8), Decode(2, DecodeFlag.SYM, 11), Decode(9, DecodeFlag.SYM, 11), Decode(23, DecodeFlag.SYM, 11), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 11), Decode(2, DecodeFlag.SYM, 12), Decode(9, DecodeFlag.SYM, 12), Decode(23, DecodeFlag.SYM, 12), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 12), Decode(2, DecodeFlag.SYM, 14), Decode(9, DecodeFlag.SYM, 14), Decode(23, DecodeFlag.SYM, 14), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 14)],
	/* 233 */
	[Decode(3, DecodeFlag.SYM, 8), Decode(6, DecodeFlag.SYM, 8), Decode(10, DecodeFlag.SYM, 8), Decode(15, DecodeFlag.SYM, 8), Decode(24, DecodeFlag.SYM, 8), Decode(31, DecodeFlag.SYM, 8), Decode(41, DecodeFlag.SYM, 8), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 8), Decode(3, DecodeFlag.SYM, 11), Decode(6, DecodeFlag.SYM, 11), Decode(10, DecodeFlag.SYM, 11), Decode(15, DecodeFlag.SYM, 11), Decode(24, DecodeFlag.SYM, 11), Decode(31, DecodeFlag.SYM, 11), Decode(41, DecodeFlag.SYM, 11), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 11)],
	/* 234 */
	[Decode(3, DecodeFlag.SYM, 12), Decode(6, DecodeFlag.SYM, 12), Decode(10, DecodeFlag.SYM, 12), Decode(15, DecodeFlag.SYM, 12), Decode(24, DecodeFlag.SYM, 12), Decode(31, DecodeFlag.SYM, 12), Decode(41, DecodeFlag.SYM, 12), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 12), Decode(3, DecodeFlag.SYM, 14), Decode(6, DecodeFlag.SYM, 14), Decode(10, DecodeFlag.SYM, 14), Decode(15, DecodeFlag.SYM, 14), Decode(24, DecodeFlag.SYM, 14), Decode(31, DecodeFlag.SYM, 14), Decode(41, DecodeFlag.SYM, 14), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 14)],
	/* 235 */
	[Decode(2, DecodeFlag.SYM, 15), Decode(9, DecodeFlag.SYM, 15), Decode(23, DecodeFlag.SYM, 15), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 15), Decode(2, DecodeFlag.SYM, 16), Decode(9, DecodeFlag.SYM, 16), Decode(23, DecodeFlag.SYM, 16), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 16), Decode(2, DecodeFlag.SYM, 17), Decode(9, DecodeFlag.SYM, 17), Decode(23, DecodeFlag.SYM, 17), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 17), Decode(2, DecodeFlag.SYM, 18), Decode(9, DecodeFlag.SYM, 18), Decode(23, DecodeFlag.SYM, 18), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 18)],
	/* 236 */
	[Decode(3, DecodeFlag.SYM, 15), Decode(6, DecodeFlag.SYM, 15), Decode(10, DecodeFlag.SYM, 15), Decode(15, DecodeFlag.SYM, 15), Decode(24, DecodeFlag.SYM, 15), Decode(31, DecodeFlag.SYM, 15), Decode(41, DecodeFlag.SYM, 15), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 15), Decode(3, DecodeFlag.SYM, 16), Decode(6, DecodeFlag.SYM, 16), Decode(10, DecodeFlag.SYM, 16), Decode(15, DecodeFlag.SYM, 16), Decode(24, DecodeFlag.SYM, 16), Decode(31, DecodeFlag.SYM, 16), Decode(41, DecodeFlag.SYM, 16), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 16)],
	/* 237 */
	[Decode(3, DecodeFlag.SYM, 17), Decode(6, DecodeFlag.SYM, 17), Decode(10, DecodeFlag.SYM, 17), Decode(15, DecodeFlag.SYM, 17), Decode(24, DecodeFlag.SYM, 17), Decode(31, DecodeFlag.SYM, 17), Decode(41, DecodeFlag.SYM, 17), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 17), Decode(3, DecodeFlag.SYM, 18), Decode(6, DecodeFlag.SYM, 18), Decode(10, DecodeFlag.SYM, 18), Decode(15, DecodeFlag.SYM, 18), Decode(24, DecodeFlag.SYM, 18), Decode(31, DecodeFlag.SYM, 18), Decode(41, DecodeFlag.SYM, 18), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 18)],
	/* 238 */
	[Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 19), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 20), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 21), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 23), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 24), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 25), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 26), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 27), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 28), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 29), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 30), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 31), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 127), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 220), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 249), Decode(253, DecodeFlag.NONE, 0)],
	/* 239 */
	[Decode(1, DecodeFlag.SYM, 19), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 19), Decode(1, DecodeFlag.SYM, 20), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 20), Decode(1, DecodeFlag.SYM, 21), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 21), Decode(1, DecodeFlag.SYM, 23), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 23), Decode(1, DecodeFlag.SYM, 24), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 24), Decode(1, DecodeFlag.SYM, 25), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 25), Decode(1, DecodeFlag.SYM, 26), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 26), Decode(1, DecodeFlag.SYM, 27), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 27)],
	/* 240 */
	[Decode(2, DecodeFlag.SYM, 19), Decode(9, DecodeFlag.SYM, 19), Decode(23, DecodeFlag.SYM, 19), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 19), Decode(2, DecodeFlag.SYM, 20), Decode(9, DecodeFlag.SYM, 20), Decode(23, DecodeFlag.SYM, 20), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 20), Decode(2, DecodeFlag.SYM, 21), Decode(9, DecodeFlag.SYM, 21), Decode(23, DecodeFlag.SYM, 21), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 21), Decode(2, DecodeFlag.SYM, 23), Decode(9, DecodeFlag.SYM, 23), Decode(23, DecodeFlag.SYM, 23), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 23)],
	/* 241 */
	[Decode(3, DecodeFlag.SYM, 19), Decode(6, DecodeFlag.SYM, 19), Decode(10, DecodeFlag.SYM, 19), Decode(15, DecodeFlag.SYM, 19), Decode(24, DecodeFlag.SYM, 19), Decode(31, DecodeFlag.SYM, 19), Decode(41, DecodeFlag.SYM, 19), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 19), Decode(3, DecodeFlag.SYM, 20), Decode(6, DecodeFlag.SYM, 20), Decode(10, DecodeFlag.SYM, 20), Decode(15, DecodeFlag.SYM, 20), Decode(24, DecodeFlag.SYM, 20), Decode(31, DecodeFlag.SYM, 20), Decode(41, DecodeFlag.SYM, 20), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 20)],
	/* 242 */
	[Decode(3, DecodeFlag.SYM, 21), Decode(6, DecodeFlag.SYM, 21), Decode(10, DecodeFlag.SYM, 21), Decode(15, DecodeFlag.SYM, 21), Decode(24, DecodeFlag.SYM, 21), Decode(31, DecodeFlag.SYM, 21), Decode(41, DecodeFlag.SYM, 21), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 21), Decode(3, DecodeFlag.SYM, 23), Decode(6, DecodeFlag.SYM, 23), Decode(10, DecodeFlag.SYM, 23), Decode(15, DecodeFlag.SYM, 23), Decode(24, DecodeFlag.SYM, 23), Decode(31, DecodeFlag.SYM, 23), Decode(41, DecodeFlag.SYM, 23), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 23)],
	/* 243 */
	[Decode(2, DecodeFlag.SYM, 24), Decode(9, DecodeFlag.SYM, 24), Decode(23, DecodeFlag.SYM, 24), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 24), Decode(2, DecodeFlag.SYM, 25), Decode(9, DecodeFlag.SYM, 25), Decode(23, DecodeFlag.SYM, 25), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 25), Decode(2, DecodeFlag.SYM, 26), Decode(9, DecodeFlag.SYM, 26), Decode(23, DecodeFlag.SYM, 26), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 26), Decode(2, DecodeFlag.SYM, 27), Decode(9, DecodeFlag.SYM, 27), Decode(23, DecodeFlag.SYM, 27), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 27)],
	/* 244 */
	[Decode(3, DecodeFlag.SYM, 24), Decode(6, DecodeFlag.SYM, 24), Decode(10, DecodeFlag.SYM, 24), Decode(15, DecodeFlag.SYM, 24), Decode(24, DecodeFlag.SYM, 24), Decode(31, DecodeFlag.SYM, 24), Decode(41, DecodeFlag.SYM, 24), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 24), Decode(3, DecodeFlag.SYM, 25), Decode(6, DecodeFlag.SYM, 25), Decode(10, DecodeFlag.SYM, 25), Decode(15, DecodeFlag.SYM, 25), Decode(24, DecodeFlag.SYM, 25), Decode(31, DecodeFlag.SYM, 25), Decode(41, DecodeFlag.SYM, 25), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 25)],
	/* 245 */
	[Decode(3, DecodeFlag.SYM, 26), Decode(6, DecodeFlag.SYM, 26), Decode(10, DecodeFlag.SYM, 26), Decode(15, DecodeFlag.SYM, 26), Decode(24, DecodeFlag.SYM, 26), Decode(31, DecodeFlag.SYM, 26), Decode(41, DecodeFlag.SYM, 26), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 26), Decode(3, DecodeFlag.SYM, 27), Decode(6, DecodeFlag.SYM, 27), Decode(10, DecodeFlag.SYM, 27), Decode(15, DecodeFlag.SYM, 27), Decode(24, DecodeFlag.SYM, 27), Decode(31, DecodeFlag.SYM, 27), Decode(41, DecodeFlag.SYM, 27), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 27)],
	/* 246 */
	[Decode(1, DecodeFlag.SYM, 28), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 28), Decode(1, DecodeFlag.SYM, 29), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 29), Decode(1, DecodeFlag.SYM, 30), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 30), Decode(1, DecodeFlag.SYM, 31), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 31), Decode(1, DecodeFlag.SYM, 127), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 127), Decode(1, DecodeFlag.SYM, 220), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 220), Decode(1, DecodeFlag.SYM, 249), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 249), Decode(254, DecodeFlag.NONE, 0), Decode(255, DecodeFlag.NONE, 0)],
	/* 247 */
	[Decode(2, DecodeFlag.SYM, 28), Decode(9, DecodeFlag.SYM, 28), Decode(23, DecodeFlag.SYM, 28), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 28), Decode(2, DecodeFlag.SYM, 29), Decode(9, DecodeFlag.SYM, 29), Decode(23, DecodeFlag.SYM, 29), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 29), Decode(2, DecodeFlag.SYM, 30), Decode(9, DecodeFlag.SYM, 30), Decode(23, DecodeFlag.SYM, 30), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 30), Decode(2, DecodeFlag.SYM, 31), Decode(9, DecodeFlag.SYM, 31), Decode(23, DecodeFlag.SYM, 31), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 31)],
	/* 248 */
	[Decode(3, DecodeFlag.SYM, 28), Decode(6, DecodeFlag.SYM, 28), Decode(10, DecodeFlag.SYM, 28), Decode(15, DecodeFlag.SYM, 28), Decode(24, DecodeFlag.SYM, 28), Decode(31, DecodeFlag.SYM, 28), Decode(41, DecodeFlag.SYM, 28), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 28), Decode(3, DecodeFlag.SYM, 29), Decode(6, DecodeFlag.SYM, 29), Decode(10, DecodeFlag.SYM, 29), Decode(15, DecodeFlag.SYM, 29), Decode(24, DecodeFlag.SYM, 29), Decode(31, DecodeFlag.SYM, 29), Decode(41, DecodeFlag.SYM, 29), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 29)],
	/* 249 */
	[Decode(3, DecodeFlag.SYM, 30), Decode(6, DecodeFlag.SYM, 30), Decode(10, DecodeFlag.SYM, 30), Decode(15, DecodeFlag.SYM, 30), Decode(24, DecodeFlag.SYM, 30), Decode(31, DecodeFlag.SYM, 30), Decode(41, DecodeFlag.SYM, 30), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 30), Decode(3, DecodeFlag.SYM, 31), Decode(6, DecodeFlag.SYM, 31), Decode(10, DecodeFlag.SYM, 31), Decode(15, DecodeFlag.SYM, 31), Decode(24, DecodeFlag.SYM, 31), Decode(31, DecodeFlag.SYM, 31), Decode(41, DecodeFlag.SYM, 31), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 31)],
	/* 250 */
	[Decode(2, DecodeFlag.SYM, 127), Decode(9, DecodeFlag.SYM, 127), Decode(23, DecodeFlag.SYM, 127), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 127), Decode(2, DecodeFlag.SYM, 220), Decode(9, DecodeFlag.SYM, 220), Decode(23, DecodeFlag.SYM, 220), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 220), Decode(2, DecodeFlag.SYM, 249), Decode(9, DecodeFlag.SYM, 249), Decode(23, DecodeFlag.SYM, 249), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 249), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 10), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 13), Decode(0, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 22), Decode(0, DecodeFlag.FAIL, 0)],
	/* 251 */
	[Decode(3, DecodeFlag.SYM, 127), Decode(6, DecodeFlag.SYM, 127), Decode(10, DecodeFlag.SYM, 127), Decode(15, DecodeFlag.SYM, 127), Decode(24, DecodeFlag.SYM, 127), Decode(31, DecodeFlag.SYM, 127), Decode(41, DecodeFlag.SYM, 127), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 127), Decode(3, DecodeFlag.SYM, 220), Decode(6, DecodeFlag.SYM, 220), Decode(10, DecodeFlag.SYM, 220), Decode(15, DecodeFlag.SYM, 220), Decode(24, DecodeFlag.SYM, 220), Decode(31, DecodeFlag.SYM, 220), Decode(41, DecodeFlag.SYM, 220), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 220)],
	/* 252 */
	[Decode(3, DecodeFlag.SYM, 249), Decode(6, DecodeFlag.SYM, 249), Decode(10, DecodeFlag.SYM, 249), Decode(15, DecodeFlag.SYM, 249), Decode(24, DecodeFlag.SYM, 249), Decode(31, DecodeFlag.SYM, 249), Decode(41, DecodeFlag.SYM, 249), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 249), Decode(1, DecodeFlag.SYM, 10), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 10), Decode(1, DecodeFlag.SYM, 13), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 13), Decode(1, DecodeFlag.SYM, 22), Decode(22, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 22), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0)],
	/* 253 */
	[Decode(2, DecodeFlag.SYM, 10), Decode(9, DecodeFlag.SYM, 10), Decode(23, DecodeFlag.SYM, 10), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 10), Decode(2, DecodeFlag.SYM, 13), Decode(9, DecodeFlag.SYM, 13), Decode(23, DecodeFlag.SYM, 13), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 13), Decode(2, DecodeFlag.SYM, 22), Decode(9, DecodeFlag.SYM, 22), Decode(23, DecodeFlag.SYM, 22), Decode(40, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 22), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0)],
	/* 254 */
	[Decode(3, DecodeFlag.SYM, 10), Decode(6, DecodeFlag.SYM, 10), Decode(10, DecodeFlag.SYM, 10), Decode(15, DecodeFlag.SYM, 10), Decode(24, DecodeFlag.SYM, 10), Decode(31, DecodeFlag.SYM, 10), Decode(41, DecodeFlag.SYM, 10), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 10), Decode(3, DecodeFlag.SYM, 13), Decode(6, DecodeFlag.SYM, 13), Decode(10, DecodeFlag.SYM, 13), Decode(15, DecodeFlag.SYM, 13), Decode(24, DecodeFlag.SYM, 13), Decode(31, DecodeFlag.SYM, 13), Decode(41, DecodeFlag.SYM, 13), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 13)],
	/* 255 */
	[Decode(3, DecodeFlag.SYM, 22), Decode(6, DecodeFlag.SYM, 22), Decode(10, DecodeFlag.SYM, 22), Decode(15, DecodeFlag.SYM, 22), Decode(24, DecodeFlag.SYM, 22), Decode(31, DecodeFlag.SYM, 22), Decode(41, DecodeFlag.SYM, 22), Decode(56, DecodeFlag.ACCEPTED | DecodeFlag.SYM, 22), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0), Decode(0, DecodeFlag.FAIL, 0)]
];