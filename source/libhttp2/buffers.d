module libhttp2.buffers;
import memutils.circularbuffer;


alias Buffer = CircularBuffer;

struct Buffers {
	/* Points to the first buffer */
	Chain head;
	/* Buffer pointer where write occurs. */
	Chain cur;
	/* The buffer capacity of each Buffer */
	size_t chunk_length;
	/* The maximum number of `Chain`s */
	size_t max_chunk;
	/* The number of `Chain`s allocated */
	size_t chunk_used;
	/* The number of `Chain`s to keep on reset */
	size_t chunk_keep;
	/* pos offset from begin in each buffers. On initialization and
     reset, buf.pos and buf.last are positioned at buf.begin +
     offset. */
	size_t offset;
	
	class Chain {
		CircularBuffer buf;
		Chain next;
	}
}


/*
 * This is the same as calling nghttp2_bufs_init2 with the given
 * arguments and offset = 0.
 */
int nghttp2_bufs_init(nghttp2_bufs *bufs, size_t chunk_length, size_t max_chunk,
	nghttp2_mem *mem);

/*
 * This is the same as calling nghttp2_bufs_init3 with the given
 * arguments and chunk_keep = max_chunk.
 */
int nghttp2_bufs_init2(nghttp2_bufs *bufs, size_t chunk_length,
	size_t max_chunk, size_t offset, nghttp2_mem *mem);

/*
 * Initializes |bufs|. Each buffer size is given in the
 * |chunk_length|.  The maximum number of buffers is given in the
 * |max_chunk|.  On reset, first |chunk_keep| buffers are kept and
 * remaining buffers are deleted.  Each buffer will have bufs->pos and
 * bufs->last shifted to left by |offset| bytes on creation and reset.
 *
 * This function allocates first buffer.  bufs->head and bufs->cur
 * will point to the first buffer after this call.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     chunk_keep is 0; or max_chunk < chunk_keep; or offset is too
 *     long.
 */
int nghttp2_bufs_init3(nghttp2_bufs *bufs, size_t chunk_length,
	size_t max_chunk, size_t chunk_keep, size_t offset,
	nghttp2_mem *mem);

/*
 * Frees any related resources to the |bufs|.
 */
void nghttp2_bufs_free(nghttp2_bufs *bufs);

/*
 * Initializes |bufs| using supplied buffer |begin| of length |len|.
 * The first buffer bufs->head uses buffer |begin|.  The buffer size
 * is fixed and no allocate extra chunk buffer is allocated.  In other
 * words, max_chunk = chunk_keep = 1.  To free the resource allocated
 * for |bufs|, use nghttp2_bufs_wrap_free().
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 */
int nghttp2_bufs_wrap_init(nghttp2_bufs *bufs, uint8_t *begin, size_t len,
	nghttp2_mem *mem);

/*
 * Frees any related resource to the |bufs|.  This function does not
 * free supplied buffer provided in nghttp2_bufs_wrap_init().
 */
void nghttp2_bufs_wrap_free(nghttp2_bufs *bufs);

/*
 * Reallocates internal buffer using |chunk_length|.  The max_chunk,
 * chunk_keep and offset do not change.  After successful allocation
 * of new buffer, previous buffers are deallocated without copying
 * anything into new buffers.  chunk_used is reset to 1.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_INVALID_ARGUMENT
 *     chunk_length < offset
 */
int nghttp2_bufs_realloc(nghttp2_bufs *bufs, size_t chunk_length);

/*
 * Appends the |data| of length |len| to the |bufs|. The write starts
 * at bufs->cur->buf.last. A new buffers will be allocated to store
 * all data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_bufs_add(nghttp2_bufs *bufs, const void *data, size_t len);

/*
 * Appends a single byte |b| to the |bufs|. The write starts at
 * bufs->cur->buf.last. A new buffers will be allocated to store all
 * data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_bufs_addb(nghttp2_bufs *bufs, uint8_t b);

/*
 * Behaves like nghttp2_bufs_addb(), but this does not update
 * buf->last pointer.
 */
int nghttp2_bufs_addb_hold(nghttp2_bufs *bufs, uint8_t b);

#define nghttp2_bufs_fast_addb(BUFS, B)                                        \
do {                                                                         \
*(BUFS)->cur->buf.last++ = B;                                              \
} while (0)

#define nghttp2_bufs_fast_addb_hold(BUFS, B)                                   \
do {                                                                         \
*(BUFS)->cur->buf.last = B;                                                \
} while (0)

/*
 * Performs bitwise-OR of |b| at bufs->cur->buf.last. A new buffers
 * will be allocated if necessary.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_bufs_orb(nghttp2_bufs *bufs, uint8_t b);

/*
 * Behaves like nghttp2_bufs_orb(), but does not update buf->last
 * pointer.
 */
int nghttp2_bufs_orb_hold(nghttp2_bufs *bufs, uint8_t b);

#define nghttp2_bufs_fast_orb(BUFS, B)                                         \
do {                                                                         \
*(BUFS)->cur->buf.last++ |= B;                                             \
} while (0)

#define nghttp2_bufs_fast_orb_hold(BUFS, B)                                    \
do {                                                                         \
*(BUFS)->cur->buf.last |= B;                                               \
} while (0)

/*
 * Copies all data stored in |bufs| to the contagious buffer.  This
 * function allocates the contagious memory to store all data in
 * |bufs| and assigns it to |*out|.
 *
 * On successful return, nghttp2_bufs_len(bufs) returns 0, just like
 * after calling nghttp2_bufs_reset().

 * This function returns the length of copied data and assigns the
 * pointer to copied data to |*out| if it succeeds, or one of the
 * following negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 */
ssize_t nghttp2_bufs_remove(nghttp2_bufs *bufs, uint8_t **out);

/*
 * Resets |bufs| and makes the buffers empty.
 */
void nghttp2_bufs_reset(nghttp2_bufs *bufs);

/*
 * Moves bufs->cur to bufs->cur->next.  If resulting bufs->cur is
 * NULL, this function allocates new buffers and bufs->cur points to
 * it.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory
 * NGHTTP2_ERR_BUFFER_ERROR
 *     Out of buffer space.
 */
int nghttp2_bufs_advance(nghttp2_bufs *bufs);

/* Sets bufs->cur to bufs->head */
#define nghttp2_bufs_rewind(BUFS)                                              \
do {                                                                         \
(BUFS)->cur = (BUFS)->head;                                                \
} while (0)

/*
 * Move bufs->cur, from the current position, using next member, to
 * the last buf which has nghttp2_buf_len(buf) > 0 without seeing buf
 * which satisfies nghttp2_buf_len(buf) == 0.  If
 * nghttp2_buf_len(&bufs->cur->buf) == 0 or bufs->cur->next is NULL,
 * bufs->cur is unchanged.
 */
void nghttp2_bufs_seek_last_present(nghttp2_bufs *bufs);

/*
 * Returns nonzero if bufs->cur->next is not emtpy.
 */
int nghttp2_bufs_next_present(nghttp2_bufs *bufs);

#define nghttp2_bufs_cur_avail(BUFS) nghttp2_buf_avail(&(BUFS)->cur->buf)

/*
 * Returns the buffer length of |bufs|.
 */
ssize_t nghttp2_bufs_len(nghttp2_bufs *bufs);
