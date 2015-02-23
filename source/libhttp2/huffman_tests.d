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

#define GET_TABLE_ENT(context, index) http2_hd_table_get(context, index)

void test_http2_hd_deflate(void) {
  http2_hd_deflater deflater;
  http2_hd_inflater inflater;
  http2_nv nva1[] = {MAKE_NV(":path", "/my-example/index.html"),
                       MAKE_NV(":scheme", "https"), MAKE_NV("hello", "world")};
  http2_nv nva2[] = {MAKE_NV(":path", "/script.js"),
                       MAKE_NV(":scheme", "https")};
  http2_nv nva3[] = {MAKE_NV("cookie", "k1=v1"), MAKE_NV("cookie", "k2=v2"),
                       MAKE_NV("via", "proxy")};
  http2_nv nva4[] = {MAKE_NV(":path", "/style.css"),
                       MAKE_NV("cookie", "k1=v1"), MAKE_NV("cookie", "k1=v1")};
  http2_nv nva5[] = {MAKE_NV(":path", "/style.css"),
                       MAKE_NV("x-nghttp2", "")};
  http2_bufs bufs;
  size_t blocklen;
  nva_out out;
  int rv;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  assert(0 == http2_hd_deflate_init(&deflater, mem));
  assert(0 == http2_hd_inflate_init(&inflater, mem));

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva1, ARRLEN(nva1));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(3 == out.nvlen);
  assert_nv_equal(nva1, out.nva, 3);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Second headers */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva2, ARRLEN(nva2));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(2 == out.nvlen);
  assert_nv_equal(nva2, out.nva, 2);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Third headers, including same header field name, but value is not
     the same. */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva3, ARRLEN(nva3));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(3 == out.nvlen);
  assert_nv_equal(nva3, out.nva, 3);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Fourth headers, including duplicate header fields. */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva4, ARRLEN(nva4));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(3 == out.nvlen);
  assert_nv_equal(nva4, out.nva, 3);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Fifth headers includes empty value */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva5, ARRLEN(nva5));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(2 == out.nvlen);
  assert_nv_equal(nva5, out.nva, 2);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Cleanup */
  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);
}

void test_http2_hd_deflate_same_indexed_repr(void) {
  http2_hd_deflater deflater;
  http2_hd_inflater inflater;
  http2_nv nva1[] = {MAKE_NV("cookie", "alpha"), MAKE_NV("cookie", "alpha")};
  http2_nv nva2[] = {MAKE_NV("cookie", "alpha"), MAKE_NV("cookie", "alpha"),
                       MAKE_NV("cookie", "alpha")};
  http2_bufs bufs;
  size_t blocklen;
  nva_out out;
  int rv;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  assert(0 == http2_hd_deflate_init(&deflater, mem));
  assert(0 == http2_hd_inflate_init(&inflater, mem));

  /* Encode 2 same headers.  Emit 1 literal reprs and 1 index repr. */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva1, ARRLEN(nva1));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(2 == out.nvlen);
  assert_nv_equal(nva1, out.nva, 2);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Encode 3 same headers.  This time, emits 3 index reprs. */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva2, ARRLEN(nva2));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen == 3);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(3 == out.nvlen);
  assert_nv_equal(nva2, out.nva, 3);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Cleanup */
  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);
}

void test_http2_hd_inflate_indexed(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  http2_nv nv = MAKE_NV(":path", "/");
  nva_out out;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  http2_hd_inflate_init(&inflater, mem);

  http2_bufs_addb(&bufs, (1 << 7) | 4);

  blocklen = http2_bufs_len(&bufs);

  assert(1 == blocklen);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(1 == out.nvlen);

  assert_nv_equal(&nv, out.nva, 1);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* index = 0 is error */
  http2_bufs_addb(&bufs, 1 << 7);

  blocklen = http2_bufs_len(&bufs);

  assert(1 == blocklen);
  assert(HTTP2_ERR_HEADER_COMP == inflate_hd(&inflater, &out, &bufs, 0));

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_inflate_indname_noinc(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  http2_nv nv[] = {/* Huffman */
                     MAKE_NV("user-agent", "nghttp2"),
                     /* Expecting no huffman */
                     MAKE_NV("user-agent", "x")};
  size_t i;
  nva_out out;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  http2_hd_inflate_init(&inflater, mem);

  for (i = 0; i < ARRLEN(nv); ++i) {
    assert(0 == http2_hd_emit_indname_block(&bufs, 57, &nv[i], 0));

    blocklen = http2_bufs_len(&bufs);

    assert(blocklen > 0);
    assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

    assert(1 == out.nvlen);
    assert_nv_equal(&nv[i], out.nva, 1);
    assert(0 == inflater.ctx.hd_table.len);

    nva_out_reset(&out);
    http2_bufs_reset(&bufs);
  }

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_inflate_indname_inc(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  http2_nv nv = MAKE_NV("user-agent", "nghttp2");
  nva_out out;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  http2_hd_inflate_init(&inflater, mem);

  assert(0 == http2_hd_emit_indname_block(&bufs, 57, &nv, 1));

  blocklen = http2_bufs_len(&bufs);

  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  assert(1 == inflater.ctx.hd_table.len);
  assert_nv_equal(
      &nv, &GET_TABLE_ENT(&inflater.ctx, HTTP2_STATIC_TABLE_LENGTH +
                                             inflater.ctx.hd_table.len - 1)->nv,
      1);

  nva_out_reset(&out);
  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_inflate_indname_inc_eviction(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  ubyte value[1024];
  nva_out out;
  http2_nv nv;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  http2_hd_inflate_init(&inflater, mem);

  memset(value, '0', sizeof(value));
  nv.value = value;
  nv.valuelen = sizeof(value);

  nv.flags = HTTP2_NV_FLAG_NONE;

  assert(0 == http2_hd_emit_indname_block(&bufs, 14, &nv, 1));
  assert(0 == http2_hd_emit_indname_block(&bufs, 15, &nv, 1));
  assert(0 == http2_hd_emit_indname_block(&bufs, 16, &nv, 1));
  assert(0 == http2_hd_emit_indname_block(&bufs, 17, &nv, 1));

  blocklen = http2_bufs_len(&bufs);

  assert(blocklen > 0);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(4 == out.nvlen);
  assert(14 == out.nva[0].namelen);
  assert(0 == memcmp("accept-charset", out.nva[0].name, out.nva[0].namelen));
  assert(sizeof(value) == out.nva[0].valuelen);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  assert(3 == inflater.ctx.hd_table.len);

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_inflate_newname_noinc(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  http2_nv nv[] = {/* Expecting huffman for both */
                     MAKE_NV("my-long-content-length", "nghttp2"),
                     /* Expecting no huffman for both */
                     MAKE_NV("x", "y"),
                     /* Huffman for key only */
                     MAKE_NV("my-long-content-length", "y"),
                     /* Huffman for value only */
                     MAKE_NV("x", "nghttp2")};
  size_t i;
  nva_out out;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  http2_hd_inflate_init(&inflater, mem);
  for (i = 0; i < ARRLEN(nv); ++i) {
    assert(0 == http2_hd_emit_newname_block(&bufs, &nv[i], 0));

    blocklen = http2_bufs_len(&bufs);

    assert(blocklen > 0);
    assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

    assert(1 == out.nvlen);
    assert_nv_equal(&nv[i], out.nva, 1);
    assert(0 == inflater.ctx.hd_table.len);

    nva_out_reset(&out);
    http2_bufs_reset(&bufs);
  }

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_inflate_newname_inc(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  http2_nv nv = MAKE_NV("x-rel", "nghttp2");
  nva_out out;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  http2_hd_inflate_init(&inflater, mem);

  assert(0 == http2_hd_emit_newname_block(&bufs, &nv, 1));

  blocklen = http2_bufs_len(&bufs);

  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  assert(1 == inflater.ctx.hd_table.len);
  assert_nv_equal(
      &nv, &GET_TABLE_ENT(&inflater.ctx, HTTP2_STATIC_TABLE_LENGTH +
                                             inflater.ctx.hd_table.len - 1)->nv,
      1);

  nva_out_reset(&out);
  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_inflate_clearall_inc(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  http2_nv nv;
  ubyte value[4060];
  nva_out out;
  http2_mem *mem;

  mem = http2_mem_default();
  bufs_large_init(&bufs, 8192);

  nva_out_init(&out);
  /* Total 4097 bytes space required to hold this entry */
  nv.name = (ubyte *)"alpha";
  nv.namelen = strlen((char *)nv.name);
  memset(value, '0', sizeof(value));
  nv.value = value;
  nv.valuelen = sizeof(value);

  nv.flags = HTTP2_NV_FLAG_NONE;

  http2_hd_inflate_init(&inflater, mem);

  assert(0 == http2_hd_emit_newname_block(&bufs, &nv, 1));

  blocklen = http2_bufs_len(&bufs);

  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  assert(0 == inflater.ctx.hd_table.len);

  nva_out_reset(&out);

  /* Do it again */
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  assert(0 == inflater.ctx.hd_table.len);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* This time, 4096 bytes space required, which is just fits in the
     header table */
  nv.valuelen = sizeof(value) - 1;

  assert(0 == http2_hd_emit_newname_block(&bufs, &nv, 1));

  blocklen = http2_bufs_len(&bufs);

  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(1 == out.nvlen);
  assert_nv_equal(&nv, out.nva, 1);
  assert(1 == inflater.ctx.hd_table.len);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_inflate_zero_length_huffman(void) {
  http2_hd_inflater inflater;
  http2_bufs bufs;
  /* Literal header without indexing - new name */
  ubyte data[] = {0x40, 0x01, 0x78 /* 'x' */, 0x80};
  nva_out out;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  http2_bufs_add(&bufs, data, sizeof(data));

  /* /\* Literal header without indexing - new name *\/ */
  /* ptr[0] = 0x40; */
  /* ptr[1] = 1; */
  /* ptr[2] = 'x'; */
  /* ptr[3] = 0x80; */

  http2_hd_inflate_init(&inflater, mem);
  assert(4 == inflate_hd(&inflater, &out, &bufs, 0));

  assert(1 == out.nvlen);
  assert(1 == out.nva[0].namelen);
  assert('x' == out.nva[0].name[0]);
  assert(NULL == out.nva[0].value);
  assert(0 == out.nva[0].valuelen);

  nva_out_reset(&out);
  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
}

void test_http2_hd_ringbuf_reserve(void) {
  http2_hd_deflater deflater;
  http2_hd_inflater inflater;
  http2_nv nv;
  http2_bufs bufs;
  nva_out out;
  int i;
  size_t rv;
  size_t blocklen;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);
  nva_out_init(&out);

  nv.flags = HTTP2_NV_FLAG_NONE;
  nv.name = (ubyte *)"a";
  nv.namelen = strlen((const char *)nv.name);
  nv.valuelen = 4;
  nv.value = malloc(nv.valuelen);
  memset(nv.value, 0, nv.valuelen);

  http2_hd_deflate_init2(&deflater, 8000, mem);
  http2_hd_inflate_init(&inflater, mem);

  http2_hd_inflate_change_table_size(&inflater, 8000);
  http2_hd_deflate_change_table_size(&deflater, 8000);

  for (i = 0; i < 150; ++i) {
    memcpy(nv.value, &i, sizeof(i));
    rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, &nv, 1);
    blocklen = http2_bufs_len(&bufs);

    assert(0 == rv);
    assert(blocklen > 0);

    assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

    assert(1 == out.nvlen);
    assert_nv_equal(&nv, out.nva, 1);

    nva_out_reset(&out);
    http2_bufs_reset(&bufs);
  }

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);

  free(nv.value);
}

void test_http2_hd_change_table_size(void) {
  http2_hd_deflater deflater;
  http2_hd_inflater inflater;
  http2_nv nva[] = {MAKE_NV("alpha", "bravo"), MAKE_NV("charlie", "delta")};
  http2_nv nva2[] = {MAKE_NV(":path", "/")};
  http2_bufs bufs;
  size_t rv;
  nva_out out;
  size_t blocklen;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  http2_hd_deflate_init(&deflater, mem);
  http2_hd_inflate_init(&inflater, mem);

  /* inflater changes notifies 8000 max header table size */
  assert(0 == http2_hd_inflate_change_table_size(&inflater, 8000));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, 8000));

  assert(4096 == deflater.ctx.hd_table_bufsize_max);

  assert(8000 == inflater.ctx.hd_table_bufsize_max);
  assert(8000 == inflater.settings_hd_table_bufsize_max);

  /* This will emit encoding context update with header table size 4096 */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(2 == deflater.ctx.hd_table.len);
  assert(4096 == deflater.ctx.hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(2 == inflater.ctx.hd_table.len);
  assert(4096 == inflater.ctx.hd_table_bufsize_max);
  assert(8000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* inflater changes header table size to 1024 */
  assert(0 == http2_hd_inflate_change_table_size(&inflater, 1024));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, 1024));

  assert(1024 == deflater.ctx.hd_table_bufsize_max);

  assert(1024 == inflater.ctx.hd_table_bufsize_max);
  assert(1024 == inflater.settings_hd_table_bufsize_max);

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(2 == deflater.ctx.hd_table.len);
  assert(1024 == deflater.ctx.hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(2 == inflater.ctx.hd_table.len);
  assert(1024 == inflater.ctx.hd_table_bufsize_max);
  assert(1024 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* inflater changes header table size to 0 */
  assert(0 == http2_hd_inflate_change_table_size(&inflater, 0));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, 0));

  assert(0 == deflater.ctx.hd_table.len);
  assert(0 == deflater.ctx.hd_table_bufsize_max);

  assert(0 == inflater.ctx.hd_table.len);
  assert(0 == inflater.ctx.hd_table_bufsize_max);
  assert(0 == inflater.settings_hd_table_bufsize_max);

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(0 == deflater.ctx.hd_table.len);
  assert(0 == deflater.ctx.hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(0 == inflater.ctx.hd_table.len);
  assert(0 == inflater.ctx.hd_table_bufsize_max);
  assert(0 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);

  /* Check table buffer is expanded */
  frame_pack_bufs_init(&bufs);

  http2_hd_deflate_init2(&deflater, 8192, mem);
  http2_hd_inflate_init(&inflater, mem);

  /* First inflater changes header table size to 8000 */
  assert(0 == http2_hd_inflate_change_table_size(&inflater, 8000));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, 8000));

  assert(8000 == deflater.ctx.hd_table_bufsize_max);

  assert(8000 == inflater.ctx.hd_table_bufsize_max);
  assert(8000 == inflater.settings_hd_table_bufsize_max);

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(2 == deflater.ctx.hd_table.len);
  assert(8000 == deflater.ctx.hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(2 == inflater.ctx.hd_table.len);
  assert(8000 == inflater.ctx.hd_table_bufsize_max);
  assert(8000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  assert(0 == http2_hd_inflate_change_table_size(&inflater, 16383));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, 16383));

  assert(8192 == deflater.ctx.hd_table_bufsize_max);

  assert(16383 == inflater.ctx.hd_table_bufsize_max);
  assert(16383 == inflater.settings_hd_table_bufsize_max);

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(2 == deflater.ctx.hd_table.len);
  assert(8192 == deflater.ctx.hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(2 == inflater.ctx.hd_table.len);
  assert(8192 == inflater.ctx.hd_table_bufsize_max);
  assert(16383 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  /* Lastly, check the error condition */

  rv = http2_hd_emit_table_size(&bufs, 25600);
  assert(rv == 0);
  assert(HTTP2_ERR_HEADER_COMP == inflate_hd(&inflater, &out, &bufs, 0));

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);

  /* Check that encoder can handle the case where its allowable buffer
     size is less than default size, 4096 */
  http2_hd_deflate_init2(&deflater, 1024, mem);
  http2_hd_inflate_init(&inflater, mem);

  assert(1024 == deflater.ctx.hd_table_bufsize_max);

  /* This emits context update with buffer size 1024 */
  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(2 == deflater.ctx.hd_table.len);
  assert(1024 == deflater.ctx.hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(2 == inflater.ctx.hd_table.len);
  assert(1024 == inflater.ctx.hd_table_bufsize_max);
  assert(4096 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);

  /* Check that table size UINT32_MAX can be received */
  http2_hd_deflate_init2(&deflater, UINT32_MAX, mem);
  http2_hd_inflate_init(&inflater, mem);

  assert(0 == http2_hd_inflate_change_table_size(&inflater, UINT32_MAX));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, UINT32_MAX));

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, 2);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(UINT32_MAX == deflater.ctx.hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(UINT32_MAX == inflater.ctx.hd_table_bufsize_max);
  assert(UINT32_MAX == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);

  /* Check that context update emitted twice */
  http2_hd_deflate_init2(&deflater, 4096, mem);
  http2_hd_inflate_init(&inflater, mem);

  assert(0 == http2_hd_inflate_change_table_size(&inflater, 0));
  assert(0 == http2_hd_inflate_change_table_size(&inflater, 3000));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, 0));
  assert(0 == http2_hd_deflate_change_table_size(&deflater, 3000));

  assert(0 == deflater.min_hd_table_bufsize_max);
  assert(3000 == deflater.ctx.hd_table_bufsize_max);

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva2, 1);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(3 < blocklen);
  assert(3000 == deflater.ctx.hd_table_bufsize_max);
  assert(UINT32_MAX == deflater.min_hd_table_bufsize_max);

  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));
  assert(3000 == inflater.ctx.hd_table_bufsize_max);
  assert(3000 == inflater.settings_hd_table_bufsize_max);

  nva_out_reset(&out);
  http2_bufs_reset(&bufs);

  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);

  http2_bufs_free(&bufs);
}

static void check_deflate_inflate(http2_hd_deflater *deflater,
                                  http2_hd_inflater *inflater,
                                  http2_nv *nva, size_t nvlen) {
  http2_bufs bufs;
  size_t blocklen;
  nva_out out;
  int rv;

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);
  rv = http2_hd_deflate_hd_bufs(deflater, &bufs, nva, nvlen);
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen >= 0);

  assert(blocklen == inflate_hd(inflater, &out, &bufs, 0));

  assert(nvlen == out.nvlen);
  assert_nv_equal(nva, out.nva, nvlen);

  nva_out_reset(&out);
  http2_bufs_free(&bufs);
}

void test_http2_hd_deflate_inflate(void) {
  http2_hd_deflater deflater;
  http2_hd_inflater inflater;
  http2_nv nv1[] = {
      MAKE_NV(":status", "200 OK"),
      MAKE_NV("access-control-allow-origin", "*"),
      MAKE_NV("cache-control", "private, max-age=0, must-revalidate"),
      MAKE_NV("content-length", "76073"),
      MAKE_NV("content-type", "text/html"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("server", "Apache"),
      MAKE_NV("vary", "foobar"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "MISS from alphabravo"),
      MAKE_NV("x-cache-action", "MISS"),
      MAKE_NV("x-cache-age", "0"),
      MAKE_NV("x-cache-lookup", "MISS from alphabravo:3128"),
      MAKE_NV("x-lb-nocache", "true"),
  };
  http2_nv nv2[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682045"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:15 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128")};
  http2_nv nv3[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682072"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:23:24 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:13 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_nv nv4[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682022"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:22:34 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:14 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_nv nv5[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=4461139"),
      MAKE_NV("content-type", "application/x-javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Mon, 16 Sep 2013 21:34:31 GMT"),
      MAKE_NV("last-modified", "Thu, 05 May 2011 09:15:59 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_nv nv6[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=18645951"),
      MAKE_NV("content-type", "application/x-javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Fri, 28 Feb 2014 01:48:03 GMT"),
      MAKE_NV("last-modified", "Tue, 12 Jul 2011 16:02:59 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_nv nv7[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=31536000"),
      MAKE_NV("content-type", "application/javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("etag", "\"6807-4dc5b54e0dcc0\""),
      MAKE_NV("expires", "Wed, 21 May 2014 08:32:17 GMT"),
      MAKE_NV("last-modified", "Fri, 10 May 2013 11:18:51 GMT"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_nv nv8[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=31536000"),
      MAKE_NV("content-type", "application/javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("etag", "\"41c6-4de7d28585b00\""),
      MAKE_NV("expires", "Thu, 12 Jun 2014 10:00:58 GMT"),
      MAKE_NV("last-modified", "Thu, 06 Jun 2013 14:30:36 GMT"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_nv nv9[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=31536000"),
      MAKE_NV("content-type", "application/javascript"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("etag", "\"19d6e-4dc5b35a541c0\""),
      MAKE_NV("expires", "Wed, 21 May 2014 08:32:18 GMT"),
      MAKE_NV("last-modified", "Fri, 10 May 2013 11:10:07 GMT"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_nv nv10[] = {
      MAKE_NV(":status", "304 Not Modified"),
      MAKE_NV("age", "0"),
      MAKE_NV("cache-control", "max-age=56682045"),
      MAKE_NV("content-type", "text/css"),
      MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
      MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
      MAKE_NV("last-modified", "Tue, 14 May 2013 07:21:53 GMT"),
      MAKE_NV("vary", "Accept-Encoding"),
      MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
      MAKE_NV("x-cache", "HIT from alphabravo"),
      MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  http2_mem *mem;

  mem = http2_mem_default();

  http2_hd_deflate_init(&deflater, mem);
  http2_hd_inflate_init(&inflater, mem);

  check_deflate_inflate(&deflater, &inflater, nv1, ARRLEN(nv1));
  check_deflate_inflate(&deflater, &inflater, nv2, ARRLEN(nv2));
  check_deflate_inflate(&deflater, &inflater, nv3, ARRLEN(nv3));
  check_deflate_inflate(&deflater, &inflater, nv4, ARRLEN(nv4));
  check_deflate_inflate(&deflater, &inflater, nv5, ARRLEN(nv5));
  check_deflate_inflate(&deflater, &inflater, nv6, ARRLEN(nv6));
  check_deflate_inflate(&deflater, &inflater, nv7, ARRLEN(nv7));
  check_deflate_inflate(&deflater, &inflater, nv8, ARRLEN(nv8));
  check_deflate_inflate(&deflater, &inflater, nv9, ARRLEN(nv9));
  check_deflate_inflate(&deflater, &inflater, nv10, ARRLEN(nv10));

  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);
}

void test_http2_hd_no_index(void) {
  http2_hd_deflater deflater;
  http2_hd_inflater inflater;
  http2_bufs bufs;
  size_t blocklen;
  http2_nv nva[] = {
      MAKE_NV(":method", "GET"), MAKE_NV(":method", "POST"),
      MAKE_NV(":path", "/foo"),  MAKE_NV("version", "HTTP/1.1"),
      MAKE_NV(":method", "GET"),
  };
  size_t i;
  nva_out out;
  int rv;
  http2_mem *mem;

  mem = http2_mem_default();

  /* 1st :method: GET can be indexable, last one is not */
  for (i = 1; i < ARRLEN(nva); ++i) {
    nva[i].flags = HTTP2_NV_FLAG_NO_INDEX;
  }

  frame_pack_bufs_init(&bufs);

  nva_out_init(&out);

  http2_hd_deflate_init(&deflater, mem);
  http2_hd_inflate_init(&inflater, mem);

  rv = http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, ARRLEN(nva));
  blocklen = http2_bufs_len(&bufs);

  assert(0 == rv);
  assert(blocklen > 0);
  assert(blocklen == inflate_hd(&inflater, &out, &bufs, 0));

  assert(ARRLEN(nva) == out.nvlen);
  assert_nv_equal(nva, out.nva, ARRLEN(nva));

  assert(out.nva[0].flags == HTTP2_NV_FLAG_NONE);
  for (i = 1; i < ARRLEN(nva); ++i) {
    assert(out.nva[i].flags == HTTP2_NV_FLAG_NO_INDEX);
  }

  nva_out_reset(&out);

  http2_bufs_free(&bufs);
  http2_hd_inflate_free(&inflater);
  http2_hd_deflate_free(&deflater);
}

void test_http2_hd_deflate_bound(void) {
  http2_hd_deflater deflater;
  http2_nv nva[] = {MAKE_NV(":method", "GET"), MAKE_NV("alpha", "bravo")};
  http2_bufs bufs;
  size_t bound, bound2;
  http2_mem *mem;

  mem = http2_mem_default();
  frame_pack_bufs_init(&bufs);

  http2_hd_deflate_init(&deflater, mem);

  bound = http2_hd_deflate_bound(&deflater, nva, ARRLEN(nva));

  assert(12 + 6 * 2 * 2 + nva[0].namelen + nva[0].valuelen + nva[1].namelen +
                nva[1].valuelen ==
            bound);

  http2_hd_deflate_hd_bufs(&deflater, &bufs, nva, ARRLEN(nva));

  assert(bound > (size_t)http2_bufs_len(&bufs));

  bound2 = http2_hd_deflate_bound(&deflater, nva, ARRLEN(nva));

  assert(bound == bound2);

  http2_bufs_free(&bufs);
  http2_hd_deflate_free(&deflater);
}

void test_http2_hd_public_api(void) {
  http2_hd_deflater *deflater;
  http2_hd_inflater *inflater;
  http2_nv nva[] = {MAKE_NV("alpha", "bravo"), MAKE_NV("charlie", "delta")};
  ubyte buf[4096];
  size_t buflen;
  size_t blocklen;
  http2_bufs bufs;
  http2_mem *mem;

  mem = http2_mem_default();

  assert(0 == http2_hd_deflate_new(&deflater, 4096));
  assert(0 == http2_hd_inflate_new(&inflater));

  buflen = http2_hd_deflate_bound(deflater, nva, ARRLEN(nva));

  blocklen = http2_hd_deflate_hd(deflater, buf, buflen, nva, ARRLEN(nva));

  assert(blocklen > 0);

  http2_bufs_wrap_init(&bufs, buf, blocklen, mem);
  bufs.head->buf.last += blocklen;

  assert(blocklen == inflate_hd(inflater, NULL, &bufs, 0));

  http2_bufs_wrap_free(&bufs);

  http2_hd_inflate_del(inflater);
  http2_hd_deflate_del(deflater);

  /* See HTTP2_ERR_INSUFF_BUFSIZE */
  assert(0 == http2_hd_deflate_new(&deflater, 4096));

  blocklen =
      http2_hd_deflate_hd(deflater, buf, blocklen - 1, nva, ARRLEN(nva));

  assert(HTTP2_ERR_INSUFF_BUFSIZE == blocklen);

  http2_hd_deflate_del(deflater);
}

static size_t encode_length(ubyte *buf, ulong n, size_t prefix) {
  size_t k = (1 << prefix) - 1;
  size_t len = 0;
  *buf &= ~k;
  if (n >= k) {
    *buf++ |= k;
    n -= k;
    ++len;
  } else {
    *buf++ |= n;
    return 1;
  }
  do {
    ++len;
    if (n >= 128) {
      *buf++ = (1 << 7) | (n & 0x7f);
      n >>= 7;
    } else {
      *buf++ = (ubyte)n;
      break;
    }
  } while (n);
  return len;
}

void test_http2_hd_decode_length(void) {
  uint out;
  size_t shift;
  int final;
  ubyte buf[16];
  ubyte *bufp;
  size_t len;
  size_t rv;
  size_t i;

  memset(buf, 0, sizeof(buf));
  len = encode_length(buf, UINT32_MAX, 7);

  rv = http2_hd_decode_length(&out, &shift, &final, 0, 0, buf, buf + len, 7);

  assert((size_t)len == rv);
  assert(0 != final);
  assert(UINT32_MAX == out);

  /* Make sure that we can decode integer if we feed 1 byte at a
     time */
  out = 0;
  shift = 0;
  final = 0;
  bufp = buf;

  for (i = 0; i < len; ++i, ++bufp) {
    rv = http2_hd_decode_length(&out, &shift, &final, out, shift, bufp,
                                  bufp + 1, 7);

    assert(rv == 1);

    if (final) {
      break;
    }
  }

  assert(i == len - 1);
  assert(0 != final);
  assert(UINT32_MAX == out);

  /* Check overflow case */
  memset(buf, 0, sizeof(buf));
  len = encode_length(buf, 1ll << 32, 7);

  rv = http2_hd_decode_length(&out, &shift, &final, 0, 0, buf, buf + len, 7);

  assert(-1 == rv);
}

void test_http2_hd_huff_encode(void) {
  int rv;
  size_t len;
  http2_bufs bufs, outbufs;
  http2_hd_huff_decode_context ctx;
  const ubyte t1[] = {22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                        10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0};

  frame_pack_bufs_init(&bufs);
  frame_pack_bufs_init(&outbufs);

  rv = http2_hd_huff_encode(&bufs, t1, sizeof(t1));

  assert(rv == 0);

  http2_hd_huff_decode_context_init(&ctx);

  len = http2_hd_huff_decode(&ctx, &outbufs, bufs.cur->buf.pos,
                               http2_bufs_len(&bufs), 1);

  assert(http2_bufs_len(&bufs) == len);
  assert((size_t)sizeof(t1) == http2_bufs_len(&outbufs));

  assert(0 == memcmp(t1, outbufs.cur->buf.pos, sizeof(t1)));

  http2_bufs_free(&bufs);
  http2_bufs_free(&outbufs);
}
