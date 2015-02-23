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
module libhttp2.huffman_decoder;

import libhttp2.constants;
import libhttp2.types;
import memutils.circularbuffer;

const HD_DEFAULT_MAX_BUFFER_SIZE = DEFAULT_HEADER_TABLE_SIZE;

const ENTRY_OVERHEAD = 32;

/// The maximum length of one name/value pair.  This is the sum of the length of name and value.  
/// This is not specified by the spec. We just chose the arbitrary size */
const MAX_NV = 65536;

/// Default size of maximum table buffer size for encoder. Even if remote decoder notifies 
/// larger buffer size for its decoding, encoder only uses the memory up to this value.
const DEFAULT_MAX_DEFLATE_BUFFER_SIZE = (1 << 12);

/// Exported for unit test
extern const size_t STATIC_TABLE_LENGTH;

//http2_hd_flags
enum HDFlags {
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

//http2_hd_entry
class HDEntry {
	NVPair nv;
	uint name_hash;
	uint value_hash;
	/* Reference count */
	ubyte ref_cnt;
	ubyte flags;
}

//nghttp2_hd_static_entry
struct StaticEntry {
	HDEntry ent;
	size_t index;
}

//http2_hd_opcode
enum OpCode {
	NONE,
	INDEXED,
	NEWNAME,
	INDNAME
}

//http2_hd_inflate_state
enum InflateState {
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

//nghttp2_hd_context
struct HDContext {
	/// dynamic header table
	CircularBuffer!HDEntry hd_table;

	/// Abstract buffer size of hd_table as described in the spec. This is the sum of length of name/value in hd_table +
    /// NGHTTP2_HD_ENTRY_OVERHEAD bytes overhead per each entry.
	size_t hd_table_bufsize;
	/// The effective header table size.
	size_t hd_table_bufsize_max;
	/// If inflate/deflate error occurred, this value is set to 1 and further invocation of inflate/deflate will fail with NGHTTP2_ERR_HEADER_COMP.
	ubyte bad;
}

//http2_huff_decode_flag
enum DecodeFlag {
	/// FSA accepts this state as the end of huffman encoding sequence.
	NGHTTP2_HUFF_ACCEPTED = 1,
	/* This state emits symbol */
	NGHTTP2_HUFF_SYM = (1 << 1),
	/* If state machine reaches this state, decoding fails. */
	NGHTTP2_HUFF_FAIL = (1 << 2)
}

//http2_huff_decode
struct Decode {
	/* huffman decoding state, which is actually the node ID of internal
     huffman tree.  We have 257 leaf nodes, but they are identical to
     root node other than emitting a symbol, so we have 256 internal
     nodes [1..255], inclusive. */
	ubyte state;
	/// bitwise OR of zero or more of the nghttp2_huff_decode_flag
	DecodeFlag flags;
	/// symbol if NGHTTP2_HUFF_SYM flag set
	ubyte sym;
} 

alias DecodeTable = Decode[16];

//http2_hd_huff_decode_context
struct DecodeContext {
	/* Current huffman decoding state. We stripped leaf nodes, so the
     value range is [0..255], inclusive. */
	ubyte state;
	/// nonzero if we can say that the decoding process succeeds at this state
	bool accept;
}

//http2_huff_sym
struct Symbol {
	/// The number of bits in this code
	uint nbits;
	/// Huffman code aligned to LSB
	uint code;
}

//http2_hd_deflater
class HuffmanDeflater {
	HDContext ctx;
	/// The upper limit of the header table size the deflater accepts.
	size_t deflate_hd_table_bufsize_max;
	/// Minimum header table size notified in the next context update
	size_t min_hd_table_bufsize_max;
	/// If nonzero, send header table size using encoding context update in the next deflate process
	ubyte notify_table_size_change;
}

//http2_hd_inflater
class HuffmanInflater {
	HDContext ctx;

	/// header buffer
	Vector!(CircularBuffer!(NVPair)) nvbufs;

	/// Stores current state of huffman decoding
	DecodeContext huff_decode_ctx;

	/// Pointer to the nghttp2_hd_entry which is used current header emission.
	/// This is required because in some cases the ent_keep->ref_cnt == 0 and we have to keep track of it.
	HDEntry ent_keep;

	/// Pointer to the name/value pair buffer which is used in the current header emission.
	ubyte *nv_keep;

	/// The number of bytes to read
	size_t left;

	/// The index in indexed repr or indexed name
	size_t index;

	/// The length of new name encoded in literal.  For huffman encoded string, this is the length after it is decoded.
	size_t newnamelen;

	/// The maximum header table size the inflater supports. This is the same value transmitted in SETTINGS_HEADER_TABLE_SIZE
	size_t settings_hd_table_bufsize_max;

	/// The number of next shift to decode integer 
	size_t shift;

	OpCode opcode;

	InflateState state;

	/// true if string is huffman encoded
	bool huffman_encoded;

	/// true if deflater requires that current entry is indexed
	bool index_required;

	/// true if deflater requires that current entry must not be indexed
	bool no_index;
}

/*
 * Initializes the |ent| members. If HDFlags.NAME_ALLOC bit
 * set in the |flags|, the content pointed by the |name| with length
 * |namelen| is copied. Likewise, if HDFlags.VALUE_ALLOC bit
 * set in the |flags|, the content pointed by the |value| with length
 * |valuelen| is copied.  The |name_hash| and |value_hash| are hash
 * value for |name| and |value| respectively.  The hash function is
 * defined in nghttp2_hd.c.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_entry_init(nghttp2_hd_entry *ent, ubyte flags, ubyte *name,
	size_t namelen, ubyte *value, size_t valuelen,
	uint name_hash, uint value_hash,
	nghttp2_mem *mem);

void nghttp2_hd_entry_free(nghttp2_hd_entry *ent, nghttp2_mem *mem);

/*
 * Initializes |deflater| for deflating name/values pairs.
 *
 * The encoder only uses up to
 * NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE bytes for header table
 * even if the larger value is specified later in
 * nghttp2_hd_change_table_size().
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_deflate_init(nghttp2_hd_deflater *deflater, nghttp2_mem *mem);

/*
 * Initializes |deflater| for deflating name/values pairs.
 *
 * The encoder only uses up to |deflate_hd_table_bufsize_max| bytes
 * for header table even if the larger value is specified later in
 * nghttp2_hd_change_table_size().
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_hd_deflate_init2(nghttp2_hd_deflater *deflater,
	size_t deflate_hd_table_bufsize_max,
	nghttp2_mem *mem);

/*
 * Deallocates any resources allocated for |deflater|.
 */
void nghttp2_hd_deflate_free(nghttp2_hd_deflater *deflater);

/*
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the |bufs|.
 *
 * This function expands |bufs| as necessary to store the result. If
 * buffers is full and the process still requires more space, this
 * funtion fails and returns NGHTTP2_ERR_HEADER_COMP.
 *
 * After this function returns, it is safe to delete the |nva|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_HEADER_COMP
 *     Deflation process has failed.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_hd_deflate_hd_bufs(nghttp2_hd_deflater *deflater,
	nghttp2_bufs *bufs, const nghttp2_nv *nva,
	size_t nvlen);

/*
 * Initializes |inflater| for inflating name/values pairs.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
int nghttp2_hd_inflate_init(HuffmanInflater inflater, nghttp2_mem *mem);

/*
 * Deallocates any resources allocated for |inflater|.
 */
void nghttp2_hd_inflate_free(HuffmanInflater inflater);

/* For unittesting purpose */
int nghttp2_hd_emit_indname_block(nghttp2_bufs *bufs, size_t index,
	nghttp2_nv *nv, int inc_indexing);

/* For unittesting purpose */
int nghttp2_hd_emit_newname_block(nghttp2_bufs *bufs, nghttp2_nv *nv,
	int inc_indexing);

/* For unittesting purpose */
int nghttp2_hd_emit_table_size(nghttp2_bufs *bufs, size_t table_size);

/* For unittesting purpose */
HDEntry nghttp2_hd_table_get(HDContext context, size_t index);

/* For unittesting purpose */
size_t nghttp2_hd_decode_length(uint *res, size_t *shift_ptr, int *final_, uint initial, size_t shift, ubyte *input, ubyte *last, size_t prefix);

/* Huffman encoding/decoding functions */

/*
 * Counts the required bytes to encode |src| with length |len|.
 *
 * This function returns the number of required bytes to encode given
 * data, including padding of prefix of terminal symbol code. This
 * function always succeeds.
 */
size_t nghttp2_hd_huff_encode_count(const ubyte *src, size_t len);

/*
 * Encodes the given data |src| with length |srclen| to the |bufs|.
 * This function expands extra buffers in |bufs| if necessary.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_hd_huff_encode(nghttp2_bufs *bufs, const ubyte *src,
	size_t srclen);

void nghttp2_hd_huff_decode_context_init(nghttp2_hd_huff_decode_context *ctx);

/*
 * Decodes the given data |src| with length |srclen|. The |ctx| must
 * be initialized by nghttp2_hd_huff_decode_context_init(). The result
 * will be added to |dest|. This function may expand |dest| as
 * needed. The caller is responsible to release the memory of |dest|
 * by calling nghttp2_bufs_free() or export its content using
 * nghttp2_bufs_remove().
 *
 * The caller must set the |final| to nonzero if the given input is
 * the final block.
 *
 * This function returns the number of read bytes from the |in|.
 *
 * If this function fails, it returns one of the following negative
 * return codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Maximum buffer capacity size exceeded.
 * NGHTTP2_ERR_HEADER_COMP
 *     Decoding process has failed.
 */
ssize_t nghttp2_hd_huff_decode(nghttp2_hd_huff_decode_context *ctx,
	nghttp2_bufs *bufs, const ubyte *src,
	size_t srclen, int final_);

#define STATIC_TABLE_LENGTH 61

/* Make scalar initialization form of http2_nv */
#define MAKE_STATIC_ENT(I, N, V, NH, VH)                                       \
  {                                                                            \
    {                                                                          \
      { (ubyte *) N, (ubyte *)V, sizeof(N) - 1, sizeof(V) - 1, 0 }         \
      , NH, VH, 1, HTTP2_HD_FLAG_NONE                                        \
    }                                                                          \
    , I                                                                        \
  }

/* Generated by mkstatictbl.py */
/* Sorted by hash(name) and its table index */
static http2_hd_static_entry static_table[] = {
    MAKE_STATIC_ENT(20, "age", "", 96511u, 0u),
    MAKE_STATIC_ENT(59, "via", "", 116750u, 0u),
    MAKE_STATIC_ENT(32, "date", "", 3076014u, 0u),
    MAKE_STATIC_ENT(33, "etag", "", 3123477u, 0u),
    MAKE_STATIC_ENT(36, "from", "", 3151786u, 0u),
    MAKE_STATIC_ENT(37, "host", "", 3208616u, 0u),
    MAKE_STATIC_ENT(44, "link", "", 3321850u, 0u),
    MAKE_STATIC_ENT(58, "vary", "", 3612210u, 0u),
    MAKE_STATIC_ENT(38, "if-match", "", 34533653u, 0u),
    MAKE_STATIC_ENT(41, "if-range", "", 39145613u, 0u),
    MAKE_STATIC_ENT(3, ":path", "/", 56997727u, 47u),
    MAKE_STATIC_ENT(4, ":path", "/index.html", 56997727u, 2144181430u),
    MAKE_STATIC_ENT(21, "allow", "", 92906313u, 0u),
    MAKE_STATIC_ENT(49, "range", "", 108280125u, 0u),
    MAKE_STATIC_ENT(14, "accept-charset", "", 124285319u, 0u),
    MAKE_STATIC_ENT(43, "last-modified", "", 150043680u, 0u),
    MAKE_STATIC_ENT(48, "proxy-authorization", "", 329532250u, 0u),
    MAKE_STATIC_ENT(57, "user-agent", "", 486342275u, 0u),
    MAKE_STATIC_ENT(40, "if-none-match", "", 646073760u, 0u),
    MAKE_STATIC_ENT(30, "content-type", "", 785670158u, 0u),
    MAKE_STATIC_ENT(16, "accept-language", "", 802785917u, 0u),
    MAKE_STATIC_ENT(50, "referer", "", 1085069613u, 0u),
    MAKE_STATIC_ENT(51, "refresh", "", 1085444827u, 0u),
    MAKE_STATIC_ENT(55, "strict-transport-security", "", 1153852136u, 0u),
    MAKE_STATIC_ENT(54, "set-cookie", "", 1237214767u, 0u),
    MAKE_STATIC_ENT(56, "transfer-encoding", "", 1274458357u, 0u),
    MAKE_STATIC_ENT(17, "accept-ranges", "", 1397189435u, 0u),
    MAKE_STATIC_ENT(42, "if-unmodified-since", "", 1454068927u, 0u),
    MAKE_STATIC_ENT(46, "max-forwards", "", 1619948695u, 0u),
    MAKE_STATIC_ENT(45, "location", "", 1901043637u, 0u),
    MAKE_STATIC_ENT(52, "retry-after", "", 1933352567u, 0u),
    MAKE_STATIC_ENT(25, "content-encoding", "", 2095084583u, 0u),
    MAKE_STATIC_ENT(28, "content-location", "", 2284906121u, 0u),
    MAKE_STATIC_ENT(39, "if-modified-since", "", 2302095846u, 0u),
    MAKE_STATIC_ENT(18, "accept", "", 2871506184u, 0u),
    MAKE_STATIC_ENT(29, "content-range", "", 2878374633u, 0u),
    MAKE_STATIC_ENT(22, "authorization", "", 2909397113u, 0u),
    MAKE_STATIC_ENT(31, "cookie", "", 2940209764u, 0u),
    MAKE_STATIC_ENT(0, ":authority", "", 2962729033u, 0u),
    MAKE_STATIC_ENT(35, "expires", "", 2985731892u, 0u),
    MAKE_STATIC_ENT(34, "expect", "", 3005803609u, 0u),
    MAKE_STATIC_ENT(24, "content-disposition", "", 3027699811u, 0u),
    MAKE_STATIC_ENT(26, "content-language", "", 3065240108u, 0u),
    MAKE_STATIC_ENT(1, ":method", "GET", 3153018267u, 70454u),
    MAKE_STATIC_ENT(2, ":method", "POST", 3153018267u, 2461856u),
    MAKE_STATIC_ENT(27, "content-length", "", 3162187450u, 0u),
    MAKE_STATIC_ENT(19, "access-control-allow-origin", "", 3297999203u, 0u),
    MAKE_STATIC_ENT(5, ":scheme", "http", 3322585695u, 3213448u),
    MAKE_STATIC_ENT(6, ":scheme", "https", 3322585695u, 99617003u),
    MAKE_STATIC_ENT(7, ":status", "200", 3338091692u, 49586u),
    MAKE_STATIC_ENT(8, ":status", "204", 3338091692u, 49590u),
    MAKE_STATIC_ENT(9, ":status", "206", 3338091692u, 49592u),
    MAKE_STATIC_ENT(10, ":status", "304", 3338091692u, 50551u),
    MAKE_STATIC_ENT(11, ":status", "400", 3338091692u, 51508u),
    MAKE_STATIC_ENT(12, ":status", "404", 3338091692u, 51512u),
    MAKE_STATIC_ENT(13, ":status", "500", 3338091692u, 52469u),
    MAKE_STATIC_ENT(53, "server", "", 3389140803u, 0u),
    MAKE_STATIC_ENT(47, "proxy-authenticate", "", 3993199572u, 0u),
    MAKE_STATIC_ENT(60, "www-authenticate", "", 4051929931u, 0u),
    MAKE_STATIC_ENT(23, "cache-control", "", 4086191634u, 0u),
    MAKE_STATIC_ENT(15, "accept-encoding", "gzip, deflate", 4127597688u,
                    1733326877u),
};

/* Index to the position in static_table */
const size_t static_table_index[] = [
    38, 43, 44, 10, 11, 47, 48, 49, 50, 51, 52, 53, 54, 55, 14, 60,
    20, 26, 34, 46, 0,  12, 36, 59, 41, 31, 42, 45, 32, 35, 19, 37,
    2,  3,  40, 39, 4,  5,  8,  33, 18, 9,  27, 15, 6,  29, 28, 57,
    16, 13, 21, 22, 30, 56, 24, 23, 25, 17, 7,  1,  58];

const size_t HTTP2_STATIC_TABLE_LENGTH =
    sizeof(static_table) / sizeof(static_table[0]);

static int memeq(const void *s1, const void *s2, size_t n) {
  const ubyte *a = (const ubyte *)s1, *b = (const ubyte *)s2;
  ubyte c = 0;
  while (n > 0) {
    c |= (*a++) ^ (*b++);
    --n;
  }
  return c == 0;
}

static uint hash(const ubyte *s, size_t n) {
  uint h = 0;
  while (n > 0) {
    h = h * 31 + *s++;
    --n;
  }
  return h;
}

int http2_hd_entry_init(http2_hd_entry *ent, ubyte flags, ubyte *name,
                          size_t namelen, ubyte *value, size_t valuelen,
                          uint name_hash, uint value_hash,
                          http2_mem *mem) {
  int rv = 0;

  /* Since http2_hd_entry is used for indexing, ent->nv.flags always
     HTTP2_NV_FLAG_NONE */
  ent->nv.flags = HTTP2_NV_FLAG_NONE;

  if ((flags & HTTP2_HD_FLAG_NAME_ALLOC) &&
      (flags & HTTP2_HD_FLAG_NAME_GIFT) == 0) {
    if (namelen == 0) {
      /* We should not allow empty header field name */
      ent->nv.name = NULL;
    } else {
      ent->nv.name = http2_memdup(name, namelen, mem);
      if (ent->nv.name == NULL) {
        rv = HTTP2_ERR_NOMEM;
        goto fail;
      }
    }
  } else {
    ent->nv.name = name;
  }
  if ((flags & HTTP2_HD_FLAG_VALUE_ALLOC) &&
      (flags & HTTP2_HD_FLAG_VALUE_GIFT) == 0) {
    if (valuelen == 0) {
      ent->nv.value = NULL;
    } else {
      ent->nv.value = http2_memdup(value, valuelen, mem);
      if (ent->nv.value == NULL) {
        rv = HTTP2_ERR_NOMEM;
        goto fail2;
      }
    }
  } else {
    ent->nv.value = value;
  }
  ent->nv.namelen = namelen;
  ent->nv.valuelen = valuelen;
  ent->ref_cnt = 1;
  ent->flags = flags;

  ent->name_hash = name_hash;
  ent->value_hash = value_hash;

  return 0;

fail2:
  if (flags & HTTP2_HD_FLAG_NAME_ALLOC) {
    http2_mem_free(mem, ent->nv.name);
  }
fail:
  return rv;
}

void http2_hd_entry_free(http2_hd_entry *ent) {
  assert(ent->ref_cnt == 0);
  if (ent->flags & HTTP2_HD_FLAG_NAME_ALLOC) {
    http2_mem_free(mem, ent->nv.name);
  }
  if (ent->flags & HTTP2_HD_FLAG_VALUE_ALLOC) {
    http2_mem_free(mem, ent->nv.value);
  }
}

static int hd_context_init(http2_hd_context *context) {
  int rv;
  context->mem = mem;
  context->bad = 0;
  context->hd_table_bufsize_max = HD_DEFAULT_MAX_BUFFER_SIZE;
  rv = hd_ringbuf_init(&context->hd_table, context->hd_table_bufsize_max /
                                               HTTP2_HD_ENTRY_OVERHEAD,
                       mem);
  if (rv != 0) {
    return rv;
  }

  context->hd_table_bufsize = 0;
  return 0;
}

static void hd_context_free(http2_hd_context *context) {
  hd_ringbuf_free(&context->hd_table, context->mem);
}

int http2_hd_deflate_init(http2_hd_deflater *deflater) {
  return http2_hd_deflate_init2(
      deflater, HTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE, mem);
}

int http2_hd_deflate_init2(http2_hd_deflater *deflater,
                             size_t deflate_hd_table_bufsize_max,
                             http2_mem *mem) {
  int rv;
  rv = hd_context_init(&deflater->ctx, mem);
  if (rv != 0) {
    return rv;
  }

  if (deflate_hd_table_bufsize_max < HD_DEFAULT_MAX_BUFFER_SIZE) {
    deflater->notify_table_size_change = 1;
    deflater->ctx.hd_table_bufsize_max = deflate_hd_table_bufsize_max;
  } else {
    deflater->notify_table_size_change = 0;
  }

  deflater->deflate_hd_table_bufsize_max = deflate_hd_table_bufsize_max;
  deflater->min_hd_table_bufsize_max = UINT32_MAX;

  return 0;
}

int http2_hd_inflate_init(HuffmanInflater inflater) {
  int rv;

  rv = hd_context_init(&inflater->ctx, mem);
  if (rv != 0) {
    goto fail;
  }

  inflater->settings_hd_table_bufsize_max = HD_DEFAULT_MAX_BUFFER_SIZE;

  inflater->ent_keep = NULL;
  inflater->nv_keep = NULL;

  inflater->opcode = HTTP2_HD_OPCODE_NONE;
  inflater->state = HTTP2_HD_STATE_OPCODE;

  rv = http2_bufs_init3(&inflater->nvbufs, HTTP2_HD_MAX_NV / 8, 8, 1, 0,
                          mem);

  if (rv != 0) {
    goto nvbufs_fail;
  }

  inflater->huffman_encoded = 0;
  inflater->index = 0;
  inflater->left = 0;
  inflater->shift = 0;
  inflater->newnamelen = 0;
  inflater->index_required = 0;
  inflater->no_index = 0;

  return 0;

nvbufs_fail:
  hd_context_free(&inflater->ctx);
fail:
  return rv;
}

static void hd_inflate_keep_free(http2_hd_inflater *inflater) {
  http2_mem *mem;

  mem = inflater->ctx.mem;
  if (inflater->ent_keep) {
    if (inflater->ent_keep->ref_cnt == 0) {
      http2_hd_entry_free(inflater->ent_keep, mem);
      http2_mem_free(mem, inflater->ent_keep);
    }
    inflater->ent_keep = NULL;
  }

  http2_mem_free(mem, inflater->nv_keep);
  inflater->nv_keep = NULL;
}

void http2_hd_deflate_free(http2_hd_deflater *deflater) {
  hd_context_free(&deflater->ctx);
}

void http2_hd_inflate_free(http2_hd_inflater *inflater) {
  hd_inflate_keep_free(inflater);
  http2_bufs_free(&inflater->nvbufs);
  hd_context_free(&inflater->ctx);
}

static size_t entry_room(size_t namelen, size_t valuelen) {
  return HTTP2_HD_ENTRY_OVERHEAD + namelen + valuelen;
}

static int emit_indexed_header(http2_nv *nv_out, http2_hd_entry *ent) {
  DEBUGF(fprintf(stderr, "inflatehd: header emission: "));
  DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  /* ent->ref_cnt may be 0. This happens if the encoder emits literal
     block larger than header table capacity with indexing. */
  *nv_out = ent->nv;
  return 0;
}

static int emit_literal_header(http2_nv *nv_out, http2_nv *nv) {
  DEBUGF(fprintf(stderr, "inflatehd: header emission: "));
  DEBUGF(fwrite(nv->name, nv->namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(nv->value, nv->valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));
  *nv_out = *nv;
  return 0;
}

static size_t count_encoded_length(size_t n, size_t prefix) {
  size_t k = (1 << prefix) - 1;
  size_t len = 0;

  if (n < k) {
    return 1;
  }

  n -= k;
  ++len;

  for (; n >= 128; n >>= 7, ++len)
    ;

  return len + 1;
}

static size_t encode_length(ubyte *buf, size_t n, size_t prefix) {
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

  *buf++ = (ubyte)n;

  return (size_t)(buf - begin);
}

/*
 * Decodes |prefix| prefixed integer stored from |in|.  The |last|
 * represents the 1 beyond the last of the valid contiguous memory
 * region from |in|.  The decoded integer must be less than or equal
 * to UINT32_MAX.
 *
 * If the |initial| is nonzero, it is used as a initial value, this
 * function assumes the |in| starts with intermediate data.
 *
 * An entire integer is decoded successfully, decoded, the |*final| is
 * set to nonzero.
 *
 * This function stores the decoded integer in |*res| if it succeed,
 * including partial decoding (in this case, number of shift to make
 * in the next call will be stored in |*shift_ptr|) and returns number
 * of bytes processed, or returns -1, indicating decoding error.
 */
static size_t decode_length(uint *res, size_t *shift_ptr, int *final_,
                             uint initial, size_t shift, ubyte *input,
                             ubyte *last, size_t prefix) {
  uint k = (1 << prefix) - 1;
  uint n = initial;
  ubyte *start = input;

  *shift_ptr = 0;
  *final_ = 0;

  if (n == 0) {
        if ((*input & k) != k) {
            *res = (*input) & k;
            *final_ = 1;
            return 1;
        }

        n = k;

        if (++input == last) {
            *res = n;
            return (size_t)(input - start);
        }
    }

    for (; input != last; ++input, shift += 7) {
        uint add = *input & 0x7f;

        if ((UINT32_MAX >> shift) < add) {
            DEBUGF(fprintf(stderr, "inflate: integer overflow on shift\n"));
            return -1;
        }

        add <<= shift;

        if (UINT32_MAX - add < n) {
            DEBUGF(fprintf(stderr, "inflate: integer overflow on addition\n"));
            return -1;
        }

        n += add;

        if ((*input & (1 << 7)) == 0) {
            break;
        }
    }

    *shift_ptr = shift;

    if (input == last) {
        *res = n;
        return (size_t)(input - start);
    }

    *res = n;
    *final_ = 1;
    return (size_t)(input + 1 - start);
}

static int emit_table_size(http2_bufs *bufs, size_t table_size) {
  int rv;
  ubyte *bufp;
  size_t blocklen;
  ubyte sb[16];

  DEBUGF(fprintf(stderr, "deflatehd: emit table_size=%zu\n", table_size));

  blocklen = count_encoded_length(table_size, 5);

  if (sizeof(sb) < blocklen) {
    return HTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;

  *bufp = 0x20u;

  encode_length(bufp, table_size, 5);

  rv = http2_bufs_add(bufs, sb, blocklen);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_indexed_block(http2_bufs *bufs, size_t idx) {
  int rv;
  size_t blocklen;
  ubyte sb[16];
  ubyte *bufp;

  blocklen = count_encoded_length(idx + 1, 7);

  DEBUGF(fprintf(stderr, "deflatehd: emit indexed index=%zu, %zu bytes\n", idx,
                 blocklen));

  if (sizeof(sb) < blocklen) {
    return HTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;
  *bufp = 0x80u;
  encode_length(bufp, idx + 1, 7);

  rv = http2_bufs_add(bufs, sb, blocklen);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_string(http2_bufs *bufs, const ubyte *str, size_t len) {
  int rv;
  ubyte sb[16];
  ubyte *bufp;
  size_t blocklen;
  size_t enclen;
  int huffman = 0;

  enclen = http2_hd_huff_encode_count(str, len);

  if (enclen < len) {
    huffman = 1;
  } else {
    enclen = len;
  }

  blocklen = count_encoded_length(enclen, 7);

  DEBUGF(fprintf(stderr, "deflatehd: emit string str="));
  DEBUGF(fwrite(str, len, 1, stderr));
  DEBUGF(fprintf(stderr, ", length=%zu, huffman=%d, encoded_length=%zu\n", len,
                 huffman, enclen));

  if (sizeof(sb) < blocklen) {
    return HTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;
  *bufp = huffman ? 1 << 7 : 0;
  encode_length(bufp, enclen, 7);

  rv = http2_bufs_add(bufs, sb, blocklen);
  if (rv != 0) {
    return rv;
  }

  if (huffman) {
    rv = http2_hd_huff_encode(bufs, str, len);
  } else {
    assert(enclen == len);
    rv = http2_bufs_add(bufs, str, len);
  }

  return rv;
}

static ubyte pack_first_byte(int inc_indexing, int no_index) {
  if (inc_indexing) {
    return 0x40u;
  }

  if (no_index) {
    return 0x10u;
  }

  return 0;
}

static int emit_indname_block(http2_bufs *bufs, size_t idx,
                              const http2_nv *nv, int inc_indexing) {
  int rv;
  ubyte *bufp;
  size_t blocklen;
  ubyte sb[16];
  size_t prefixlen;
  int no_index;

  no_index = (nv->flags & HTTP2_NV_FLAG_NO_INDEX) != 0;

  if (inc_indexing) {
    prefixlen = 6;
  } else {
    prefixlen = 4;
  }

  DEBUGF(fprintf(stderr, "deflatehd: emit indname index=%zu, valuelen=%zu, "
                         "indexing=%d, no_index=%d\n",
                 idx, nv->valuelen, inc_indexing, no_index));

  blocklen = count_encoded_length(idx + 1, prefixlen);

  if (sizeof(sb) < blocklen) {
    return HTTP2_ERR_HEADER_COMP;
  }

  bufp = sb;

  *bufp = pack_first_byte(inc_indexing, no_index);

  encode_length(bufp, idx + 1, prefixlen);

  rv = http2_bufs_add(bufs, sb, blocklen);
  if (rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, nv->value, nv->valuelen);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

static int emit_newname_block(http2_bufs *bufs, const http2_nv *nv,
                              int inc_indexing) {
  int rv;
  int no_index;

  no_index = (nv->flags & HTTP2_NV_FLAG_NO_INDEX) != 0;

  DEBUGF(fprintf(stderr, "deflatehd: emit newname namelen=%zu, valuelen=%zu, "
                         "indexing=%d, no_index=%d\n",
                 nv->namelen, nv->valuelen, inc_indexing, no_index));

  rv = http2_bufs_addb(bufs, pack_first_byte(inc_indexing, no_index));
  if (rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, nv->name, nv->namelen);
  if (rv != 0) {
    return rv;
  }

  rv = emit_string(bufs, nv->value, nv->valuelen);
  if (rv != 0) {
    return rv;
  }

  return 0;
}

static http2_hd_entry *add_hd_table_incremental(http2_hd_context *context,
                                                  const http2_nv *nv,
                                                  uint name_hash,
                                                  uint value_hash,
                                                  ubyte entry_flags) {
  int rv;
  http2_hd_entry *new_ent;
  size_t room;
  http2_mem *mem;

  mem = context->mem;
  room = entry_room(nv->namelen, nv->valuelen);

  while (context->hd_table_bufsize + room > context->hd_table_bufsize_max &&
         context->hd_table.len > 0) {

    size_t idx = context->hd_table.len - 1;
    http2_hd_entry *ent = hd_ringbuf_get(&context->hd_table, idx);

    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);

    DEBUGF(fprintf(stderr, "hpack: remove item from header table: "));
    DEBUGF(fwrite(ent->nv.name, ent->nv.namelen, 1, stderr));
    DEBUGF(fprintf(stderr, ": "));
    DEBUGF(fwrite(ent->nv.value, ent->nv.valuelen, 1, stderr));
    DEBUGF(fprintf(stderr, "\n"));
    hd_ringbuf_pop_back(&context->hd_table);
    if (--ent->ref_cnt == 0) {
      http2_hd_entry_free(ent, mem);
      http2_mem_free(mem, ent);
    }
  }

  new_ent = http2_mem_malloc(mem, sizeof(http2_hd_entry));
  if (new_ent == NULL) {
    return NULL;
  }

  rv = http2_hd_entry_init(new_ent, entry_flags, nv->name, nv->namelen,
                             nv->value, nv->valuelen, name_hash, value_hash,
                             mem);
  if (rv != 0) {
    http2_mem_free(mem, new_ent);
    return NULL;
  }

  if (room > context->hd_table_bufsize_max) {
    /* The entry taking more than HTTP2_HD_MAX_BUFFER_SIZE is
       immediately evicted. */
    --new_ent->ref_cnt;
  } else {
    rv = hd_ringbuf_push_front(&context->hd_table, new_ent, mem);

    if (rv != 0) {
      --new_ent->ref_cnt;

      if ((entry_flags & HTTP2_HD_FLAG_NAME_ALLOC) &&
          (entry_flags & HTTP2_HD_FLAG_NAME_GIFT)) {
        /* nv->name are managed by caller. */
        new_ent->nv.name = NULL;
        new_ent->nv.namelen = 0;
      }
      if ((entry_flags & HTTP2_HD_FLAG_VALUE_ALLOC) &&
          (entry_flags & HTTP2_HD_FLAG_VALUE_GIFT)) {
        /* nv->value are managed by caller. */
        new_ent->nv.value = NULL;
        new_ent->nv.valuelen = 0;
      }

      http2_hd_entry_free(new_ent, mem);
      http2_mem_free(mem, new_ent);

      return NULL;
    }

    context->hd_table_bufsize += room;
  }
  return new_ent;
}

static int name_eq(const http2_nv *a, const http2_nv *b) {
  return a->namelen == b->namelen && memeq(a->name, b->name, a->namelen);
}

static int value_eq(const http2_nv *a, const http2_nv *b) {
  return a->valuelen == b->valuelen && memeq(a->value, b->value, a->valuelen);
}

struct {
  size_t index;
  /* Nonzero if both name and value are matched. */
  ubyte name_value_match;
} search_result;

static search_result search_hd_table(http2_hd_context *context,
                                     const http2_nv *nv, uint name_hash,
                                     uint value_hash) {
  size_t left = -1, right = (size_t)STATIC_TABLE_LENGTH;
  search_result res = {-1, 0};
  size_t i;
  int use_index = (nv->flags & HTTP2_NV_FLAG_NO_INDEX) == 0;

  /* Search dynamic table first, so that we can find recently used
     entry first */
  if (use_index) {
    for (i = 0; i < context->hd_table.len; ++i) {
      http2_hd_entry *ent = hd_ringbuf_get(&context->hd_table, i);
      if (ent->name_hash != name_hash || !name_eq(&ent->nv, nv)) {
        continue;
      }

      if (res.index == -1) {
        res.index = (size_t)(i + HTTP2_STATIC_TABLE_LENGTH);
      }

      if (ent->value_hash == value_hash && value_eq(&ent->nv, nv)) {
        res.index = (size_t)(i + HTTP2_STATIC_TABLE_LENGTH);
        res.name_value_match = 1;
        return res;
      }
    }
  }

  while (right - left > 1) {
    size_t mid = (left + right) / 2;
    http2_hd_entry *ent = &static_table[mid].ent;
    if (ent->name_hash < name_hash) {
      left = mid;
    } else {
      right = mid;
    }
  }

  for (i = right; i < STATIC_TABLE_LENGTH; ++i) {
    http2_hd_entry *ent = &static_table[i].ent;
    if (ent->name_hash != name_hash) {
      break;
    }

    if (name_eq(&ent->nv, nv)) {
      if (res.index == -1) {
        res.index = (size_t)(static_table[i].index);
      }
      if (use_index && ent->value_hash == value_hash &&
          value_eq(&ent->nv, nv)) {
        res.index = (size_t)(static_table[i].index);
        res.name_value_match = 1;
        return res;
      }
    }
  }

  return res;
}

static void hd_context_shrink_table_size(http2_hd_context *context) {
  http2_mem *mem;

  mem = context->mem;

  while (context->hd_table_bufsize > context->hd_table_bufsize_max &&
         context->hd_table.len > 0) {
    size_t idx = context->hd_table.len - 1;
    http2_hd_entry *ent = hd_ringbuf_get(&context->hd_table, idx);
    context->hd_table_bufsize -= entry_room(ent->nv.namelen, ent->nv.valuelen);
    hd_ringbuf_pop_back(&context->hd_table);
    if (--ent->ref_cnt == 0) {
      http2_hd_entry_free(ent, mem);
      http2_mem_free(mem, ent);
    }
  }
}

int http2_hd_deflate_change_table_size(http2_hd_deflater *deflater,
                                         size_t settings_hd_table_bufsize_max) {
  size_t next_bufsize = http2_min(settings_hd_table_bufsize_max,
                                    deflater->deflate_hd_table_bufsize_max);

  deflater->ctx.hd_table_bufsize_max = next_bufsize;

  deflater->min_hd_table_bufsize_max =
      http2_min(deflater->min_hd_table_bufsize_max, next_bufsize);

  deflater->notify_table_size_change = 1;

  hd_context_shrink_table_size(&deflater->ctx);
  return 0;
}

int http2_hd_inflate_change_table_size(http2_hd_inflater *inflater,
                                         size_t settings_hd_table_bufsize_max) {
  inflater->settings_hd_table_bufsize_max = settings_hd_table_bufsize_max;
  inflater->ctx.hd_table_bufsize_max = settings_hd_table_bufsize_max;
  hd_context_shrink_table_size(&inflater->ctx);
  return 0;
}

#define INDEX_RANGE_VALID(context, idx)                                        \
  ((idx) < (context)->hd_table.len + HTTP2_STATIC_TABLE_LENGTH)

static size_t get_max_index(http2_hd_context *context) {
  return context->hd_table.len + HTTP2_STATIC_TABLE_LENGTH - 1;
}

http2_hd_entry *http2_hd_table_get(http2_hd_context *context,
                                       size_t idx) {
  assert(INDEX_RANGE_VALID(context, idx));
  if (idx >= HTTP2_STATIC_TABLE_LENGTH) {
    return hd_ringbuf_get(&context->hd_table,
                          idx - HTTP2_STATIC_TABLE_LENGTH);
  } else {
    return &static_table[static_table_index[idx]].ent;
  }
}

#define name_match(NV, NAME)                                                   \
  (nv->namelen == sizeof(NAME) - 1 && memeq(nv->name, NAME, sizeof(NAME) - 1))

static int hd_deflate_should_indexing(http2_hd_deflater *deflater,
                                      const http2_nv *nv) {
  if ((nv->flags & HTTP2_NV_FLAG_NO_INDEX) ||
      entry_room(nv->namelen, nv->valuelen) >
          deflater->ctx.hd_table_bufsize_max * 3 / 4) {
    return 0;
  }
#ifdef HTTP2_XHD
  return !name_match(nv, HTTP2_XHD);
#else  /* !HTTP2_XHD */
  return !name_match(nv, ":path") && !name_match(nv, "content-length") &&
         !name_match(nv, "set-cookie") && !name_match(nv, "etag") &&
         !name_match(nv, "if-modified-since") &&
         !name_match(nv, "if-none-match") && !name_match(nv, "location") &&
         !name_match(nv, "age");
#endif /* !HTTP2_XHD */
}

static int deflate_nv(http2_hd_deflater *deflater, http2_bufs *bufs,
                      const http2_nv *nv) {
  int rv;
  search_result res;
  size_t idx;
  int incidx = 0;
  uint name_hash = hash(nv->name, nv->namelen);
  uint value_hash = hash(nv->value, nv->valuelen);
  http2_mem *mem;

  DEBUGF(fprintf(stderr, "deflatehd: deflating "));
  DEBUGF(fwrite(nv->name, nv->namelen, 1, stderr));
  DEBUGF(fprintf(stderr, ": "));
  DEBUGF(fwrite(nv->value, nv->valuelen, 1, stderr));
  DEBUGF(fprintf(stderr, "\n"));

  mem = deflater->ctx.mem;

  res = search_hd_table(&deflater->ctx, nv, name_hash, value_hash);

  idx = res.index;

  if (res.name_value_match) {

    DEBUGF(fprintf(stderr, "deflatehd: name/value match index=%zd\n", idx));

    rv = emit_indexed_block(bufs, idx);
    if (rv != 0) {
      return rv;
    }

    return 0;
  }

  if (res.index != -1) {
    DEBUGF(fprintf(stderr, "deflatehd: name match index=%zd\n", res.index));
  }

  if (hd_deflate_should_indexing(deflater, nv)) {
    http2_hd_entry *new_ent;
    if (idx != -1 && idx < (size_t)HTTP2_STATIC_TABLE_LENGTH) {
      http2_nv nv_indname;
      nv_indname = *nv;
      nv_indname.name = http2_hd_table_get(&deflater->ctx, idx)->nv.name;
      new_ent =
          add_hd_table_incremental(&deflater->ctx, &nv_indname, name_hash,
                                   value_hash, HTTP2_HD_FLAG_VALUE_ALLOC);
    } else {
      new_ent = add_hd_table_incremental(
          &deflater->ctx, nv, name_hash, value_hash,
          HTTP2_HD_FLAG_NAME_ALLOC | HTTP2_HD_FLAG_VALUE_ALLOC);
    }
    if (!new_ent) {
      return HTTP2_ERR_HEADER_COMP;
    }
    if (new_ent->ref_cnt == 0) {
      http2_hd_entry_free(new_ent, mem);
      http2_mem_free(mem, new_ent);
    }
    incidx = 1;
  }
  if (idx == -1) {
    rv = emit_newname_block(bufs, nv, incidx);
  } else {
    rv = emit_indname_block(bufs, idx, nv, incidx);
  }
  if (rv != 0) {
    return rv;
  }

  return 0;
}

int http2_hd_deflate_hd_bufs(http2_hd_deflater *deflater,
                               http2_bufs *bufs, const http2_nv *nv,
                               size_t nvlen) {
  size_t i;
  int rv = 0;

  if (deflater->ctx.bad) {
    return HTTP2_ERR_HEADER_COMP;
  }

  if (deflater->notify_table_size_change) {
    size_t min_hd_table_bufsize_max;

    min_hd_table_bufsize_max = deflater->min_hd_table_bufsize_max;

    deflater->notify_table_size_change = 0;
    deflater->min_hd_table_bufsize_max = UINT32_MAX;

    if (deflater->ctx.hd_table_bufsize_max > min_hd_table_bufsize_max) {

      rv = emit_table_size(bufs, min_hd_table_bufsize_max);

      if (rv != 0) {
        goto fail;
      }
    }

    rv = emit_table_size(bufs, deflater->ctx.hd_table_bufsize_max);

    if (rv != 0) {
      goto fail;
    }
  }

  for (i = 0; i < nvlen; ++i) {
    rv = deflate_nv(deflater, bufs, &nv[i]);
    if (rv != 0) {
      goto fail;
    }
  }

  DEBUGF(
      fprintf(stderr, "deflatehd: all input name/value pairs were deflated\n"));

  return 0;
fail:
  DEBUGF(fprintf(stderr, "deflatehd: error return %d\n", rv));

  deflater->ctx.bad = 1;
  return rv;
}

size_t http2_hd_deflate_hd(http2_hd_deflater *deflater, ubyte *buf,
                              size_t buflen, const http2_nv *nv,
                              size_t nvlen) {
  http2_bufs bufs;
  int rv;
  http2_mem *mem;

  mem = deflater->ctx.mem;

  rv = http2_bufs_wrap_init(&bufs, buf, buflen, mem);

  if (rv != 0) {
    return rv;
  }

  rv = http2_hd_deflate_hd_bufs(deflater, &bufs, nv, nvlen);

  buflen = http2_bufs_len(&bufs);

  http2_bufs_wrap_free(&bufs);

  if (rv == HTTP2_ERR_BUFFER_ERROR) {
    return HTTP2_ERR_INSUFF_BUFSIZE;
  }

  if (rv != 0) {
    return rv;
  }

  return (size_t)buflen;
}

size_t http2_hd_deflate_bound(http2_hd_deflater *deflater _U_,
                                const http2_nv *nva, size_t nvlen) {
  size_t n = 0;
  size_t i;

  /* Possible Maximum Header Table Size Change.  Encoding (1u << 31) -
     1 using 4 bit prefix requires 6 bytes.  We may emit this at most
     twice. */
  n += 12;

  /* Use Literal Header Field without indexing - New Name, since it is
     most space consuming format.  Also we choose the less one between
     non-huffman and huffman, so using literal byte count is
     sufficient for upper bound.

     Encoding (1u << 31) - 1 using 7 bit prefix requires 6 bytes.  We
     need 2 of this for |nvlen| header fields. */
  n += 6 * 2 * nvlen;

  for (i = 0; i < nvlen; ++i) {
    n += nva[i].namelen + nva[i].valuelen;
  }

  return n;
}

int http2_hd_deflate_new(http2_hd_deflater **deflater_ptr,
                           size_t deflate_hd_table_bufsize_max) {
  return http2_hd_deflate_new2(deflater_ptr, deflate_hd_table_bufsize_max,
                                 NULL);
}

int http2_hd_deflate_new2(http2_hd_deflater **deflater_ptr,
                            size_t deflate_hd_table_bufsize_max,
                            http2_mem *mem) {
  int rv;
  http2_hd_deflater *deflater;

  if (mem == NULL) {
    mem = http2_mem_default();
  }

  deflater = http2_mem_malloc(mem, sizeof(http2_hd_deflater));

  if (deflater == NULL) {
    return HTTP2_ERR_NOMEM;
  }

  rv = http2_hd_deflate_init2(deflater, deflate_hd_table_bufsize_max, mem);

  if (rv != 0) {
    http2_mem_free(mem, deflater);

    return rv;
  }

  *deflater_ptr = deflater;

  return 0;
}

void http2_hd_deflate_del(http2_hd_deflater *deflater) {
  http2_mem *mem;

  mem = deflater->ctx.mem;

  http2_hd_deflate_free(deflater);

  http2_mem_free(mem, deflater);
}

static void hd_inflate_set_huffman_encoded(http2_hd_inflater *inflater,
                                           const ubyte *in) {
  inflater->huffman_encoded = (*in & (1 << 7)) != 0;
}

/*
 * Decodes the integer from the range [in, last).  The result is
 * assigned to |inflater->left|.  If the |inflater->left| is 0, then
 * it performs variable integer decoding from scratch. Otherwise, it
 * uses the |inflater->left| as the initial value and continues to
 * decode assuming that [in, last) begins with intermediary sequence.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * HTTP2_ERR_HEADER_COMP
 *   Integer decoding failed
 */
static size_t hd_inflate_read_len(http2_hd_inflater *inflater, int *rfin,
                                   ubyte *in, ubyte *last, size_t prefix,
                                   size_t maxlen) {
  size_t rv;
  uint out;

  *rfin = 0;

  rv = decode_length(&out, &inflater->shift, rfin, (uint)inflater->left,
                     inflater->shift, in, last, prefix);

  if (rv == -1) {
    DEBUGF(fprintf(stderr, "inflatehd: integer decoding failed\n"));
    return HTTP2_ERR_HEADER_COMP;
  }

  if (out > maxlen) {
    DEBUGF(fprintf(
        stderr, "inflatehd: integer exceeded the maximum value %zu\n", maxlen));
    return HTTP2_ERR_HEADER_COMP;
  }

  inflater->left = out;

  DEBUGF(fprintf(stderr, "inflatehd: decoded integer is %u\n", out));

  return rv;
}

/*
 * Reads |inflater->left| bytes from the range [in, last) and performs
 * huffman decoding against them and pushes the result into the
 * |buffer|.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *   Out of memory
 * HTTP2_ERR_HEADER_COMP
 *   Huffman decoding failed
 * HTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
static size_t hd_inflate_read_huff(http2_hd_inflater *inflater,
                                    http2_bufs *bufs, ubyte *in,
                                    ubyte *last) {
  size_t readlen;
  int final = 0;
  if ((size_t)(last - in) >= inflater->left) {
    last = in + inflater->left;
    final = 1;
  }
  readlen = http2_hd_huff_decode(&inflater->huff_decode_ctx, bufs, in,
                                   last - in, final);

  if (readlen < 0) {
    DEBUGF(fprintf(stderr, "inflatehd: huffman decoding failed\n"));
    return readlen;
  }
  inflater->left -= (size_t)readlen;
  return readlen;
}

/*
 * Reads |inflater->left| bytes from the range [in, last) and copies
 * them into the |buffer|.
 *
 * This function returns the number of bytes read if it succeeds, or
 * one of the following negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *   Out of memory
 * HTTP2_ERR_HEADER_COMP
 *   Header decompression failed
 * HTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
static size_t hd_inflate_read(http2_hd_inflater *inflater,
                               http2_bufs *bufs, ubyte *in, ubyte *last) {
  int rv;
  size_t len = http2_min((size_t)(last - in), inflater->left);
  rv = http2_bufs_add(bufs, in, len);
  if (rv != 0) {
    return rv;
  }
  inflater->left -= len;
  return (size_t)len;
}

/*
 * Finalize indexed header representation reception. If header is
 * emitted, |*nv_out| is filled with that value and 0 is returned. If
 * no header is emitted, 1 is returned.
 *
 * This function returns either 0 or 1 if it succeeds, or one of the
 * following negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_indexed(http2_hd_inflater *inflater,
                                     http2_nv *nv_out) {
  http2_hd_entry *ent = http2_hd_table_get(&inflater->ctx, inflater->index);

  emit_indexed_header(nv_out, ent);

  return 0;
}

static int hd_inflate_remove_bufs(http2_hd_inflater *inflater, http2_nv *nv,
                                  int value_only) {
  size_t rv;
  size_t buflen;
  ubyte *buf;
  http2_buf *pbuf;

  if (inflater->index_required ||
      inflater->nvbufs.head != inflater->nvbufs.cur) {

    rv = http2_bufs_remove(&inflater->nvbufs, &buf);

    if (rv < 0) {
      return HTTP2_ERR_NOMEM;
    }

    buflen = rv;

    if (value_only) {
      nv->name = NULL;
      nv->namelen = 0;
    } else {
      nv->name = buf;
      nv->namelen = inflater->newnamelen;
    }

    nv->value = buf + nv->namelen;
    nv->valuelen = buflen - nv->namelen;

    return 0;
  }

  /* If we are not going to store header in header table and
     name/value are in first chunk, we just refer them from nv,
     instead of mallocing another memory. */

  pbuf = &inflater->nvbufs.head->buf;

  if (value_only) {
    nv->name = NULL;
    nv->namelen = 0;
  } else {
    nv->name = pbuf->pos;
    nv->namelen = inflater->newnamelen;
  }

  nv->value = pbuf->pos + nv->namelen;
  nv->valuelen = http2_buf_len(pbuf) - nv->namelen;

  /* Resetting does not change the content of first buffer */
  http2_bufs_reset(&inflater->nvbufs);

  return 0;
}

/*
 * Finalize literal header representation - new name- reception. If
 * header is emitted, |*nv_out| is filled with that value and 0 is
 * returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_newname(http2_hd_inflater *inflater,
                                     http2_nv *nv_out) {
  int rv;
  http2_nv nv;
  http2_mem *mem;

  mem = inflater->ctx.mem;

  rv = hd_inflate_remove_bufs(inflater, &nv, 0 /* name and value */);
  if (rv != 0) {
    return HTTP2_ERR_NOMEM;
  }

  if (inflater->no_index) {
    nv.flags = HTTP2_NV_FLAG_NO_INDEX;
  } else {
    nv.flags = HTTP2_NV_FLAG_NONE;
  }

  if (inflater->index_required) {
    http2_hd_entry *new_ent;
    ubyte ent_flags;

    /* nv->value points to the middle of the buffer pointed by
       nv->name.  So we just need to keep track of nv->name for memory
       management. */
    ent_flags = HTTP2_HD_FLAG_NAME_ALLOC | HTTP2_HD_FLAG_NAME_GIFT;

    new_ent =
        add_hd_table_incremental(&inflater->ctx, &nv, hash(nv.name, nv.namelen),
                                 hash(nv.value, nv.valuelen), ent_flags);

    if (new_ent) {
      emit_indexed_header(nv_out, new_ent);
      inflater->ent_keep = new_ent;

      return 0;
    }

    http2_mem_free(mem, nv.name);

    return HTTP2_ERR_NOMEM;
  }

  emit_literal_header(nv_out, &nv);

  if (nv.name != inflater->nvbufs.head->buf.pos) {
    inflater->nv_keep = nv.name;
  }

  return 0;
}

/*
 * Finalize literal header representation - indexed name-
 * reception. If header is emitted, |*nv_out| is filled with that
 * value and 0 is returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *   Out of memory
 */
static int hd_inflate_commit_indname(http2_hd_inflater *inflater,
                                     http2_nv *nv_out) {
  int rv;
  http2_nv nv;
  http2_hd_entry *ent_name;
  http2_mem *mem;

  mem = inflater->ctx.mem;

  rv = hd_inflate_remove_bufs(inflater, &nv, 1 /* value only */);
  if (rv != 0) {
    return HTTP2_ERR_NOMEM;
  }

  if (inflater->no_index) {
    nv.flags = HTTP2_NV_FLAG_NO_INDEX;
  } else {
    nv.flags = HTTP2_NV_FLAG_NONE;
  }

  ent_name = http2_hd_table_get(&inflater->ctx, inflater->index);

  nv.name = ent_name->nv.name;
  nv.namelen = ent_name->nv.namelen;

  if (inflater->index_required) {
    http2_hd_entry *new_ent;
    ubyte ent_flags;
    int static_name;

    ent_flags = HTTP2_HD_FLAG_VALUE_ALLOC | HTTP2_HD_FLAG_VALUE_GIFT;
    static_name = inflater->index < HTTP2_STATIC_TABLE_LENGTH;

    if (!static_name) {
      ent_flags |= HTTP2_HD_FLAG_NAME_ALLOC;
      /* For entry in static table, we must not touch ref_cnt, because it
         is shared by threads */
      ++ent_name->ref_cnt;
    }

    new_ent = add_hd_table_incremental(&inflater->ctx, &nv, ent_name->name_hash,
                                       hash(nv.value, nv.valuelen), ent_flags);

    if (!static_name && --ent_name->ref_cnt == 0) {
      http2_hd_entry_free(ent_name, mem);
      http2_mem_free(mem, ent_name);
    }

    if (new_ent) {
      emit_indexed_header(nv_out, new_ent);

      inflater->ent_keep = new_ent;

      return 0;
    }

    http2_mem_free(mem, nv.value);

    return HTTP2_ERR_NOMEM;
  }

  emit_literal_header(nv_out, &nv);

  if (nv.value != inflater->nvbufs.head->buf.pos) {
    inflater->nv_keep = nv.value;
  }

  return 0;
}

size_t http2_hd_inflate_hd(http2_hd_inflater *inflater, http2_nv *nv_out,
                              int *inflate_flags, ubyte *in, size_t inlen,
                              int in_final) {
  size_t rv = 0;
  ubyte *first = in;
  ubyte *last = in + inlen;
  int rfin = 0;

  if (inflater->ctx.bad) {
    return HTTP2_ERR_HEADER_COMP;
  }

  DEBUGF(fprintf(stderr, "inflatehd: start state=%d\n", inflater->state));
  hd_inflate_keep_free(inflater);
  *inflate_flags = HTTP2_HD_INFLATE_NONE;
  for (; in != last;) {
    switch (inflater->state) {
    case HTTP2_HD_STATE_OPCODE:
      if ((*in & 0xe0u) == 0x20u) {
        DEBUGF(fprintf(stderr, "inflatehd: header table size change\n"));
        inflater->opcode = HTTP2_HD_OPCODE_INDEXED;
        inflater->state = HTTP2_HD_STATE_READ_TABLE_SIZE;
      } else if (*in & 0x80u) {
        DEBUGF(fprintf(stderr, "inflatehd: indexed repr\n"));
        inflater->opcode = HTTP2_HD_OPCODE_INDEXED;
        inflater->state = HTTP2_HD_STATE_READ_INDEX;
      } else {
        if (*in == 0x40u || *in == 0 || *in == 0x10u) {
          DEBUGF(
              fprintf(stderr, "inflatehd: literal header repr - new name\n"));
          inflater->opcode = HTTP2_HD_OPCODE_NEWNAME;
          inflater->state = HTTP2_HD_STATE_NEWNAME_CHECK_NAMELEN;
        } else {
          DEBUGF(fprintf(stderr,
                         "inflatehd: literal header repr - indexed name\n"));
          inflater->opcode = HTTP2_HD_OPCODE_INDNAME;
          inflater->state = HTTP2_HD_STATE_READ_INDEX;
        }
        inflater->index_required = (*in & 0x40) != 0;
        inflater->no_index = (*in & 0xf0u) == 0x10u;
        DEBUGF(fprintf(stderr, "inflatehd: indexing required=%d, no_index=%d\n",
                       inflater->index_required, inflater->no_index));
        if (inflater->opcode == HTTP2_HD_OPCODE_NEWNAME) {
          ++in;
        }
      }
      inflater->left = 0;
      inflater->shift = 0;
      break;
    case HTTP2_HD_STATE_READ_TABLE_SIZE:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 5,
                               inflater->settings_hd_table_bufsize_max);
      if (rv < 0) {
        goto fail;
      }
      in += rv;
      if (!rfin) {
        goto almost_ok;
      }
      DEBUGF(fprintf(stderr, "inflatehd: table_size=%zu\n", inflater->left));
      inflater->ctx.hd_table_bufsize_max = inflater->left;
      hd_context_shrink_table_size(&inflater->ctx);
      inflater->state = HTTP2_HD_STATE_OPCODE;
      break;
    case HTTP2_HD_STATE_READ_INDEX: {
      size_t prefixlen;

      if (inflater->opcode == HTTP2_HD_OPCODE_INDEXED) {
        prefixlen = 7;
      } else if (inflater->index_required) {
        prefixlen = 6;
      } else {
        prefixlen = 4;
      }

      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, prefixlen,
                               get_max_index(&inflater->ctx) + 1);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      if (!rfin) {
        goto almost_ok;
      }

      if (inflater->left == 0) {
        rv = HTTP2_ERR_HEADER_COMP;
        goto fail;
      }

      DEBUGF(fprintf(stderr, "inflatehd: index=%zu\n", inflater->left));
      if (inflater->opcode == HTTP2_HD_OPCODE_INDEXED) {
        inflater->index = inflater->left;
        --inflater->index;

        rv = hd_inflate_commit_indexed(inflater, nv_out);
        if (rv < 0) {
          goto fail;
        }
        inflater->state = HTTP2_HD_STATE_OPCODE;
        /* If rv == 1, no header was emitted */
        if (rv == 0) {
          *inflate_flags |= HTTP2_HD_INFLATE_EMIT;
          return (size_t)(in - first);
        }
      } else {
        inflater->index = inflater->left;
        --inflater->index;

        inflater->state = HTTP2_HD_STATE_CHECK_VALUELEN;
      }
      break;
    }
    case HTTP2_HD_STATE_NEWNAME_CHECK_NAMELEN:
      hd_inflate_set_huffman_encoded(inflater, in);
      inflater->state = HTTP2_HD_STATE_NEWNAME_READ_NAMELEN;
      inflater->left = 0;
      inflater->shift = 0;
      DEBUGF(fprintf(stderr, "inflatehd: huffman encoded=%d\n",
                     inflater->huffman_encoded != 0));
    /* Fall through */
    case HTTP2_HD_STATE_NEWNAME_READ_NAMELEN:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 7, HTTP2_HD_MAX_NV);
      if (rv < 0) {
        goto fail;
      }
      in += rv;
      if (!rfin) {
        DEBUGF(fprintf(stderr,
                       "inflatehd: integer not fully decoded. current=%zu\n",
                       inflater->left));

        goto almost_ok;
      }

      if (inflater->huffman_encoded) {
        http2_hd_huff_decode_context_init(&inflater->huff_decode_ctx);

        inflater->state = HTTP2_HD_STATE_NEWNAME_READ_NAMEHUFF;
      } else {
        inflater->state = HTTP2_HD_STATE_NEWNAME_READ_NAME;
      }
      break;
    case HTTP2_HD_STATE_NEWNAME_READ_NAMEHUFF:
      rv = hd_inflate_read_huff(inflater, &inflater->nvbufs, in, last);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));

      if (inflater->left) {
        DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n",
                       inflater->left));

        goto almost_ok;
      }

      inflater->newnamelen = http2_bufs_len(&inflater->nvbufs);

      inflater->state = HTTP2_HD_STATE_CHECK_VALUELEN;

      break;
    case HTTP2_HD_STATE_NEWNAME_READ_NAME:
      rv = hd_inflate_read(inflater, &inflater->nvbufs, in, last);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));
      if (inflater->left) {
        DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n",
                       inflater->left));

        goto almost_ok;
      }

      inflater->newnamelen = http2_bufs_len(&inflater->nvbufs);

      inflater->state = HTTP2_HD_STATE_CHECK_VALUELEN;

      break;
    case HTTP2_HD_STATE_CHECK_VALUELEN:
      hd_inflate_set_huffman_encoded(inflater, in);
      inflater->state = HTTP2_HD_STATE_READ_VALUELEN;
      inflater->left = 0;
      inflater->shift = 0;
      DEBUGF(fprintf(stderr, "inflatehd: huffman encoded=%d\n",
                     inflater->huffman_encoded != 0));
    /* Fall through */
    case HTTP2_HD_STATE_READ_VALUELEN:
      rfin = 0;
      rv = hd_inflate_read_len(inflater, &rfin, in, last, 7, HTTP2_HD_MAX_NV);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      if (!rfin) {
        goto almost_ok;
      }

      DEBUGF(fprintf(stderr, "inflatehd: valuelen=%zu\n", inflater->left));
      if (inflater->left == 0) {
        if (inflater->opcode == HTTP2_HD_OPCODE_NEWNAME) {
          rv = hd_inflate_commit_newname(inflater, nv_out);
        } else {
          rv = hd_inflate_commit_indname(inflater, nv_out);
        }
        if (rv != 0) {
          goto fail;
        }
        inflater->state = HTTP2_HD_STATE_OPCODE;
        *inflate_flags |= HTTP2_HD_INFLATE_EMIT;
        return (size_t)(in - first);
      }

      if (inflater->huffman_encoded) {
        http2_hd_huff_decode_context_init(&inflater->huff_decode_ctx);

        inflater->state = HTTP2_HD_STATE_READ_VALUEHUFF;
      } else {
        inflater->state = HTTP2_HD_STATE_READ_VALUE;
      }
      break;
    case HTTP2_HD_STATE_READ_VALUEHUFF:
      rv = hd_inflate_read_huff(inflater, &inflater->nvbufs, in, last);
      if (rv < 0) {
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));

      if (inflater->left) {
        DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n",
                       inflater->left));

        goto almost_ok;
      }

      if (inflater->opcode == HTTP2_HD_OPCODE_NEWNAME) {
        rv = hd_inflate_commit_newname(inflater, nv_out);
      } else {
        rv = hd_inflate_commit_indname(inflater, nv_out);
      }

      if (rv != 0) {
        goto fail;
      }

      inflater->state = HTTP2_HD_STATE_OPCODE;
      *inflate_flags |= HTTP2_HD_INFLATE_EMIT;

      return (size_t)(in - first);
    case HTTP2_HD_STATE_READ_VALUE:
      rv = hd_inflate_read(inflater, &inflater->nvbufs, in, last);
      if (rv < 0) {
        DEBUGF(fprintf(stderr, "inflatehd: value read failure %zd: %s\n", rv,
                       http2_strerror((int)rv)));
        goto fail;
      }

      in += rv;

      DEBUGF(fprintf(stderr, "inflatehd: %zd bytes read\n", rv));

      if (inflater->left) {
        DEBUGF(fprintf(stderr, "inflatehd: still %zu bytes to go\n",
                       inflater->left));
        goto almost_ok;
      }

      if (inflater->opcode == HTTP2_HD_OPCODE_NEWNAME) {
        rv = hd_inflate_commit_newname(inflater, nv_out);
      } else {
        rv = hd_inflate_commit_indname(inflater, nv_out);
      }

      if (rv != 0) {
        goto fail;
      }

      inflater->state = HTTP2_HD_STATE_OPCODE;
      *inflate_flags |= HTTP2_HD_INFLATE_EMIT;

      return (size_t)(in - first);
    }
  }

  assert(in == last);

  DEBUGF(fprintf(stderr, "inflatehd: all input bytes were processed\n"));

  if (in_final) {
    DEBUGF(fprintf(stderr, "inflatehd: in_final set\n"));

    if (inflater->state != HTTP2_HD_STATE_OPCODE) {
      DEBUGF(fprintf(stderr, "inflatehd: unacceptable state=%d\n",
                     inflater->state));
      rv = HTTP2_ERR_HEADER_COMP;

      goto fail;
    }
    *inflate_flags |= HTTP2_HD_INFLATE_FINAL;
  }
  return (size_t)(in - first);

almost_ok:
  if (in_final && inflater->state != HTTP2_HD_STATE_OPCODE) {
    DEBUGF(fprintf(stderr, "inflatehd: input ended prematurely\n"));

    rv = HTTP2_ERR_HEADER_COMP;

    goto fail;
  }
  return (size_t)(in - first);

fail:
  DEBUGF(fprintf(stderr, "inflatehd: error return %zd\n", rv));

  inflater->ctx.bad = 1;
  return rv;
}

int http2_hd_inflate_end_headers(http2_hd_inflater *inflater) {
  hd_inflate_keep_free(inflater);
  return 0;
}

int http2_hd_inflate_new(http2_hd_inflater **inflater_ptr) {
  return http2_hd_inflate_new2(inflater_ptr, NULL);
}

int http2_hd_inflate_new2(http2_hd_inflater **inflater_ptr,
                            http2_mem *mem) {
  int rv;
  http2_hd_inflater *inflater;

  if (mem == NULL) {
    mem = http2_mem_default();
  }

  inflater = http2_mem_malloc(mem, sizeof(http2_hd_inflater));

  if (inflater == NULL) {
    return HTTP2_ERR_NOMEM;
  }

  rv = http2_hd_inflate_init(inflater, mem);

  if (rv != 0) {
    http2_mem_free(mem, inflater);

    return rv;
  }

  *inflater_ptr = inflater;

  return 0;
}

void http2_hd_inflate_del(http2_hd_inflater *inflater) {
  http2_mem *mem;

  mem = inflater->ctx.mem;
  http2_hd_inflate_free(inflater);

  http2_mem_free(mem, inflater);
}

int http2_hd_emit_indname_block(http2_bufs *bufs, size_t idx,
                                  http2_nv *nv, int inc_indexing) {

  return emit_indname_block(bufs, idx, nv, inc_indexing);
}

int http2_hd_emit_newname_block(http2_bufs *bufs, http2_nv *nv,
                                  int inc_indexing) {
  return emit_newname_block(bufs, nv, inc_indexing);
}

int http2_hd_emit_table_size(http2_bufs *bufs, size_t table_size) {
  return emit_table_size(bufs, table_size);
}

size_t http2_hd_decode_length(uint *res, size_t *shift_ptr, int *final,
                                 uint initial, size_t shift, ubyte *in,
                                 ubyte *last, size_t prefix) {
  return decode_length(res, shift_ptr, final, initial, shift, in, last, prefix);
}
