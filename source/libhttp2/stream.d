/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
module libhttp2.stream;

import libhttp2.constants;
import libhttp2.types;
import libhttp2.frame;
import std.algorithm : max;

const MAX_DEP_TREE_LENGTH = 100;

struct StreamRoots {

    void add(Stream stream) {
        if (head) {
            stream.m_root_next = head;
            head.m_root_prev = stream;
        }
        
        head = stream;
    }
    
	void remove(Stream stream) 
    {
        Stream root_prev, root_next;
        
        root_prev = stream.m_root_prev;
        root_next = stream.m_root_next;
        
        if (root_prev) {
            root_prev.m_root_next = m_root_next;
            
            if (root_next) {
                root_next.m_root_prev = root_prev;
            }
        } else {
            if (root_next) {
                root_next.m_root_prev = null;
            }
            
            head = root_next;
        }
        
        stream.m_root_prev = null;
        stream.m_root_next = null;
    }
    
    void removeAll() {
        Stream si, next;
        
        for (si = head; si;) {
            next = si.root_next;
            
            si.root_prev = null;
            si.root_next = null;
            
            si = next;
        }
        
        head = null;
    }

    Stream head;
    int num_streams;
};

class Stream {

    this(int stream_id,
		 StreamFlags flags,
		 StreamState http2_stream_state;
		 StreamState initial_state;
		 int weight,
		 StreamRoots roots,
		 int remote_initial_window_size,
         int local_initial_window_size,
         void *stream_user_data) 
	{
        http2_map_entry_init(&m_map_entry, stream_id);
        m_stream_id = stream_id;
        m_flags = flags;
        m_state = initial_state;
        m_shut_flags = HTTP2_SHUT_NONE;
        m_stream_user_data = stream_user_data;
        m_item = null;
        m_remote_window_size = remote_initial_window_size;
        m_local_window_size = local_initial_window_size;
        m_recv_window_size = 0;
        m_consumed_size = 0;
        m_recv_reduction = 0;
        
        m_dep_prev = null;
        m_dep_next = null;
        m_sib_prev = null;
        m_sib_next = null;
        
        m_closed_prev = null;
        m_closed_next = null;
        
        m_dpri = StreamDPRI.NO_ITEM;
        m_num_substreams = 1;
        m_weight = weight;
        m_effective_weight = m_weight;
        m_sum_dep_weight = 0;
        m_sum_norest_weight = 0;
        m_sum_top_weight = 0;
        
        m_roots = roots;
        m_root_prev = null;
        m_root_next = null;
        
        m_http_flags = HTTP2_HTTP_FLAG_NONE;
        m_content_length = -1;
        m_recv_content_length = 0;
        m_status_code = -1;
    }
    
    /*
     * Disallow either further receptions or transmissions, or both.
     * |flag| is bitwise OR of one or more of ShutdownFlag.
     */
    void http2_stream_shutdown( ShutdownFlag flag) {
        m_shut_flags |= flag;
    }
    
    static int stream_push_item( http2_session *session) {
        int rv;
        http2_outbound_item *item;
        
        assert(m_item);
        assert(m_item.queued == 0);
        
        item = m_item;
        
        /* If item is now sent, don't push it to the queue.  Otherwise, we
     may push same item twice. */
        if (session.aob.item == item) {
            return 0;
        }
        
        if (item.weight > m_effective_weight) {
            item.weight = m_effective_weight;
        }
        
        item.cycle = session.last_cycle;
        
        switch (item.frame.hd.type) {
            case HTTP2_DATA:
                rv = http2_pq_push(&session.ob_da_pq, item);
                break;
            case HTTP2_HEADERS:
                if (m_state == HTTP2_STREAM_RESERVED) {
                    rv = http2_pq_push(&session.ob_ss_pq, item);
                } else {
                    rv = http2_pq_push(&session.ob_pq, item);
                }
                break;
            default:
                /* should not reach here */
                assert(0);
        }
        
        if (rv != 0) {
            return rv;
        }
        
        item.queued = 1;
        
        return 0;
    }
    
    Stream stream_first_sib(Stream stream) 
    {
        for (; m_sib_prev; stream = m_sib_prev)
            ;
        
        return stream;
    }
    
    Stream stream_last_sib(Stream stream) 
    {
        for (; m_sib_next; stream = m_sib_next)
            ;
        
        return stream;
    }
    
    Stream stream_update_dep_length(Stream stream, size_t delta) 
    {
        m_num_substreams += delta;
        
        stream = stream_first_sib(stream);
        
        if (m_dep_prev) {
            return stream_update_dep_length(m_dep_prev, delta);
        }
        
        return stream;
    }
    
    /*
     * Computes distributed weight of a stream of the |weight| under the
     * |stream| if |stream| is removed from a dependency tree.  The result
     * is computed using m_weight rather than
     * m_effective_weight.
     */
    int http2_stream_dep_distributed_weight(int weight) {
        weight = m_weight * weight / m_sum_dep_weight;
        
        return max(1, weight);
    }
    
    /*
 * Computes effective weight of a stream of the |weight| under the
 * |stream|.  The result is computed using m_effective_weight
 * rather than m_weight.  This function is used to determine
 * weight in dependency tree.
 */
    int http2_stream_dep_distributed_effective_weight(
        int weight) {
        if (m_sum_norest_weight == 0) {
            return m_effective_weight;
        }
        
        weight = m_effective_weight * weight / m_sum_norest_weight;
        
        return max(1, weight);
    }
    
    static int stream_dep_distributed_top_effective_weight(int weight) {
        if (m_sum_top_weight == 0) {
            return m_effective_weight;
        }
        
        weight = m_effective_weight * weight / m_sum_top_weight;
        
        return http2_max(1, weight);
    }
    
    static void stream_update_dep_set_rest(http2_stream *stream);
    
    /* Updates effective_weight of descendant streams in subtree of
   |stream|.  We assume that m_effective_weight is already set
   right. */
    static void stream_update_dep_effective_weight(http2_stream *stream) {
        http2_stream *si;
        
        DEBUGF(fprintf(stderr, "stream: update_dep_effective_weight "
                "stream(%p)=%d, weight=%d, sum_norest_weight=%d, "
                "sum_top_weight=%d\n",
                stream, m_stream_id, m_weight,
                m_sum_norest_weight, m_sum_top_weight));
        
        /* m_sum_norest_weight == 0 means there is no
     StreamDPRI.TOP under stream */
        if (m_dpri != StreamDPRI.NO_ITEM ||
            m_sum_norest_weight == 0) {
            return;
        }
        
        /* If there is no direct descendant whose dpri is
     StreamDPRI.TOP, indirect descendants have the chance to
     send data, so recursively set weight for descendants. */
        if (m_sum_top_weight == 0) {
            for (si = m_dep_next; si; si = si.sib_next) {
                if (si.dpri != StreamDPRI.REST) {
                    si.effective_weight =
                        http2_stream_dep_distributed_effective_weight(stream, si.weight);
                }
                
                stream_update_dep_effective_weight(si);
            }
            return;
        }
        
        /* If there is at least one direct descendant whose dpri is
     StreamDPRI.TOP, we won't give a chance to indirect
     descendants, since closed or blocked stream's weight is
     distributed among its siblings */
        for (si = m_dep_next; si; si = si.sib_next) {
            if (si.dpri == StreamDPRI.TOP) {
                si.effective_weight =
                    stream_dep_distributed_top_effective_weight(stream, si.weight);
                
                DEBUGF(fprintf(stderr, "stream: stream=%d top eweight=%d\n",
                        si.stream_id, si.effective_weight));
                
                continue;
            }
            
            if (si.dpri == StreamDPRI.NO_ITEM) {
                DEBUGF(fprintf(stderr, "stream: stream=%d no_item, ignored\n",
                        si.stream_id));
                
                /* Since we marked StreamDPRI.TOP under si, we make
         them StreamDPRI.REST again. */
                stream_update_dep_set_rest(si.dep_next);
            } else {
                DEBUGF(
                    fprintf(stderr, "stream: stream=%d rest, ignored\n", si.stream_id));
            }
        }
    }
    
    static void stream_update_dep_set_rest(http2_stream *stream) {
        if (stream == null) {
            return;
        }
        
        DEBUGF(fprintf(stderr, "stream: stream=%d is rest\n", m_stream_id));
        
        if (m_dpri == StreamDPRI.REST) {
            return;
        }
        
        if (m_dpri == StreamDPRI.TOP) {
            m_dpri = StreamDPRI.REST;
            
            stream_update_dep_set_rest(m_sib_next);
            
            return;
        }
        
        stream_update_dep_set_rest(m_sib_next);
        stream_update_dep_set_rest(m_dep_next);
    }
    
    /*
 * Performs dfs starting |stream|, search stream which can become
 * StreamDPRI.TOP and set its dpri.
 */
    static void stream_update_dep_set_top(http2_stream *stream) {
        http2_stream *si;
        
        if (m_dpri == StreamDPRI.TOP) {
            return;
        }
        
        if (m_dpri == StreamDPRI.REST) {
            DEBUGF(
                fprintf(stderr, "stream: stream=%d item is top\n", m_stream_id));
            
            m_dpri = StreamDPRI.TOP;
            
            return;
        }
        
        for (si = m_dep_next; si; si = si.sib_next) {
            stream_update_dep_set_top(si);
        }
    }
    
    /*
 * Performs dfs starting |stream|, and dueue stream whose dpri is
 * StreamDPRI.TOP and has not been queued yet.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *     Out of memory.
 */
    static int stream_update_dep_queue_top(
        http2_session *session) {
        int rv;
        http2_stream *si;
        
        if (m_dpri == StreamDPRI.REST) {
            return 0;
        }
        
        if (m_dpri == StreamDPRI.TOP) {
            if (!m_item.queued) {
                DEBUGF(fprintf(stderr, "stream: stream=%d enqueue\n", m_stream_id));
                rv = stream_push_item(stream, session);
                
                if (rv != 0) {
                    return rv;
                }
            }
            
            return 0;
        }
        
        for (si = m_dep_next; si; si = si.sib_next) {
            rv = stream_update_dep_queue_top(si, session);
            
            if (rv != 0) {
                return rv;
            }
        }
        
        return 0;
    }
    
    /*
 * Updates m_sum_norest_weight and m_sum_top_weight
 * recursively.  We have to gather effective sum of weight of
 * descendants.  If m_dpri == StreamDPRI.NO_ITEM, we
 * have to go deeper and check that any of its descendants has dpri
 * value of StreamDPRI.TOP.  If so, we have to add weight of
 * its direct descendants to m_sum_norest_weight.  To make this
 * work, this function returns 1 if any of its descendants has dpri
 * value of StreamDPRI.TOP, otherwise 0.
 *
 * Calculating m_sum_top-weight is very simple compared to
 * m_sum_norest_weight.  It just adds up the weight of direct
 * descendants whose dpri is StreamDPRI.TOP.
 */
    static int stream_update_dep_sum_norest_weight(http2_stream *stream) {
        http2_stream *si;
        int rv;
        
        m_sum_norest_weight = 0;
        m_sum_top_weight = 0;
        
        if (m_dpri == StreamDPRI.TOP) {
            return 1;
        }
        
        if (m_dpri == StreamDPRI.REST) {
            return 0;
        }
        
        rv = 0;
        
        for (si = m_dep_next; si; si = si.sib_next) {
            
            if (stream_update_dep_sum_norest_weight(si)) {
                rv = 1;
                m_sum_norest_weight += si.weight;
            }
            
            if (si.dpri == StreamDPRI.TOP) {
                m_sum_top_weight += si.weight;
            }
        }
        
        return rv;
    }
    
    static int stream_update_dep_on_attach_item(
        http2_session *session) {
        http2_stream *root_stream;
        
        m_dpri = StreamDPRI.REST;
        
        stream_update_dep_set_rest(m_dep_next);
        
        root_stream = http2_stream_get_dep_root(stream);
        
        DEBUGF(fprintf(stderr, "root=%p, stream=%p\n", root_stream, stream));
        
        stream_update_dep_set_top(root_stream);
        
        stream_update_dep_sum_norest_weight(root_stream);
        stream_update_dep_effective_weight(root_stream);
        
        return stream_update_dep_queue_top(root_stream, session);
    }
    
    static int stream_update_dep_on_detach_item(
        http2_session *session) {
        http2_stream *root_stream;
        
        m_dpri = StreamDPRI.NO_ITEM;
        
        root_stream = http2_stream_get_dep_root(stream);
        
        stream_update_dep_set_top(root_stream);
        
        stream_update_dep_sum_norest_weight(root_stream);
        stream_update_dep_effective_weight(root_stream);
        
        return stream_update_dep_queue_top(root_stream, session);
    }
    
    /*
 * Attaches |item| to |stream|.  Updates dpri members in this
 * dependency tree.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *     Out of memory
 */
    int http2_stream_attach_item(
        http2_outbound_item *item,
        http2_session *session) {
        assert((m_flags & StreamFlags.DEFERRED_ALL) == 0);
        assert(m_item == null);
        
        DEBUGF(fprintf(stderr, "stream: stream=%d attach item=%p\n",
                m_stream_id, item));
        
        m_item = item;
        
        return stream_update_dep_on_attach_item(stream, session);
    }
    
    /*
 * Detaches |m_item|.  Updates dpri members in this dependency
 * tree.  This function does not free |m_item|.  The caller must
 * free it.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * HTTP2_ERR_NOMEM
 *     Out of memory
 */
    int http2_stream_detach_item(
        http2_session *session) {
        DEBUGF(fprintf(stderr, "stream: stream=%d detach item=%p\n",
                m_stream_id, m_item));
        
        m_item = null;
        m_flags &= ~StreamFlags.DEFERRED_ALL;
        
        return stream_update_dep_on_detach_item(stream, session);
    }
    
    /*
	 * Defer |m_item|.  We won't call this function in the situation
	 * where |m_item| == null.  The |flags| is bitwise OR of zero or
	 * more of StreamFlags.DEFERRED_USER and
	 * StreamFlags.DEFERRED_FLOW_CONTROL.  The |flags| indicates
	 * the reason of this action.
	 *
	 * This function returns 0 if it succeeds, or one of the following
	 * negative error codes:
	 *
	 * HTTP2_ERR_NOMEM
	 *     Out of memory
	 */
    int http2_stream_defer_item( ubyte flags,
        http2_session *session) {
        assert(m_item);
        
        DEBUGF(fprintf(stderr, "stream: stream=%d defer item=%p cause=%02x\n",
                m_stream_id, m_item, flags));
        
        m_flags |= flags;
        
        return stream_update_dep_on_detach_item(stream, session);
    }
    
    /*
 * Put back deferred data in this stream to active state.  The |flags|
 * are one or more of bitwise OR of the following values:
 * StreamFlags.DEFERRED_USER and
 * StreamFlags.DEFERRED_FLOW_CONTROL and given masks are
 * cleared if they are set.  So even if this function is called, if
 * one of flag is still set, data does not become active.
 */
    int http2_stream_resume_deferred_item( ubyte flags,
        http2_session *session) {
        assert(m_item);
        
        DEBUGF(fprintf(stderr, "stream: stream=%d resume item=%p flags=%02x\n",
                m_stream_id, m_item, flags));
        
        m_flags &= ~flags;
        
        if (m_flags & StreamFlags.DEFERRED_ALL) {
            return 0;
        }
        
        return stream_update_dep_on_attach_item(stream, session);
    }
    
    /*
 * Returns nonzero if item is deferred by whatever reason.
 */
    int http2_stream_check_deferred_item(http2_stream *stream) {
        return m_item && (m_flags & StreamFlags.DEFERRED_ALL);
    }
    
    /*
 * Returns nonzero if item is deferred by flow control.
 */
    int http2_stream_check_deferred_by_flow_control(http2_stream *stream) {
        return m_item &&
            (m_flags & StreamFlags.DEFERRED_FLOW_CONTROL);
    }
    
    static int update_initial_window_size(int *window_size_ptr,
        int new_initial_window_size,
        int old_initial_window_size) {
        long new_window_size = (long)(*window_size_ptr) +
            new_initial_window_size - old_initial_window_size;
        if (INT32_MIN > new_window_size ||
            new_window_size > HTTP2_MAX_WINDOW_SIZE) {
            return -1;
        }
        *window_size_ptr = (int)new_window_size;
        return 0;
    }
    
    /*
 * Updates the remote window size with the new value
 * |new_initial_window_size|. The |old_initial_window_size| is used to
 * calculate the current window size.
 *
 * This function returns 0 if it succeeds or -1. The failure is due to
 * overflow.
 */
    int http2_stream_update_remote_initial_window_size(
         int new_initial_window_size,
        int old_initial_window_size) {
        return update_initial_window_size(&m_remote_window_size,
            new_initial_window_size,
            old_initial_window_size);
    }
    
    /*
 * Updates the local window size with the new value
 * |new_initial_window_size|. The |old_initial_window_size| is used to
 * calculate the current window size.
 *
 * This function returns 0 if it succeeds or -1. The failure is due to
 * overflow.
 */
    int http2_stream_update_local_initial_window_size(
         int new_initial_window_size,
        int old_initial_window_size) {
        return update_initial_window_size(&m_local_window_size,
            new_initial_window_size,
            old_initial_window_size);
    }
    
    /*
     * Call this function if promised stream |stream| is replied with
     * HEADERS.  This function makes the state of the |stream| to
     * OPENED.
     */
    void http2_stream_promise_fulfilled(http2_stream *stream) {
		m_state = StreamState.OPENED;
        m_flags &= ~StreamFlags.PUSH;
    }
    
    /*
     * Returns the stream positioned in root of the dependency tree the
     * |stream| belongs to.
     */
    Stream http2_stream_get_dep_root(Stream stream) {
        for (;;) {
            if (m_sib_prev) {
                stream = m_sib_prev;
                
                continue;
            }
            
            if (m_dep_prev) {
                stream = m_dep_prev;
                
                continue;
            }
            
            break;
        }
        
        return stream;
    }
    
    /*
     * Returns nonzero if |target| is found in subtree of |stream|.
     */
    int http2_stream_dep_subtree_find(Stream target) {
        if (stream == null) {
            return 0;
        }
        
        if (stream == target) {
            return 1;
        }
        
        if (http2_stream_dep_subtree_find(m_sib_next, target)) {
            return 1;
        }
        
        return http2_stream_dep_subtree_find(m_dep_next, target);
    }
    
    /*
     * Makes the |stream| depend on the |dep_stream|.  This dependency is
     * exclusive.  All existing direct descendants of |dep_stream| become
     * the descendants of the |stream|.  This function assumes
     * |m_data| is null and no dpri members are changed in this
     * dependency tree.
     */
    void http2_stream_dep_insert(Stream dep_stream) {
        Stream si;
        Stream root_stream;
        
        assert(m_item == null);
        
        DEBUGF(fprintf(stderr,
                "stream: dep_insert dep_stream(%p)=%d, stream(%p)=%d\n",
                dep_stream, dep_stream.stream_id, stream, m_stream_id));
        
        m_sum_dep_weight = dep_stream.sum_dep_weight;
        dep_stream.sum_dep_weight = m_weight;
        
        if (dep_stream.dep_next) {
            for (si = dep_stream.dep_next; si; si = si.sib_next) {
                m_num_substreams += si.num_substreams;
            }
            
            m_dep_next = dep_stream.dep_next;
            m_dep_next.dep_prev = stream;
        }
        
        dep_stream.dep_next = stream;
        m_dep_prev = dep_stream;
        
        root_stream = stream_update_dep_length(dep_stream, 1);
        
        stream_update_dep_sum_norest_weight(root_stream);
        stream_update_dep_effective_weight(root_stream);
        
        ++m_roots.num_streams;
    }
    
    static void link_dep(Stream dep_stream, Stream stream) {
        dep_stream.dep_next = stream;
        m_dep_prev = dep_stream;
    }
    
    static void link_sib(Stream prev_stream, Stream stream) {
        prev_stream.sib_next = stream;
        m_sib_prev = prev_stream;
    }
    
    static void insert_link_dep(Stream dep_stream, Stream stream) {
        http2_stream *sib_next;
        
        assert(m_sib_prev == null);
        
        sib_next = dep_stream.dep_next;
        
        link_sib(stream, sib_next);
        
        sib_next.dep_prev = null;
        
        link_dep(dep_stream, stream);
    }
    
    void unlink_sib() {
        Stream prev, *next, *dep_next;
        
        prev = m_sib_prev;
        dep_next = m_dep_next;
        
        assert(prev);
        
        if (dep_next) {
            /*
             *  prev--stream(--sib_next--...)
             *         |
             *        dep_next
             */
            dep_next.dep_prev = null;
            
            link_sib(prev, dep_next);
            
            if (m_sib_next) {
                link_sib(stream_last_sib(dep_next), m_sib_next);
            }
        } else {
            /*
             *  prev--stream(--sib_next--...)
             */
            next = m_sib_next;
            
            prev.sib_next = next;
            
            if (next) {
                next.sib_prev = prev;
            }
        }
    }
    
    static void unlink_dep() {
        Stream prev, next, dep_next;
        
        prev = m_dep_prev;
        dep_next = m_dep_next;
        
        assert(prev);
        
        if (dep_next) {
            /*
             * prev
             *   |
             * stream(--sib_next--...)
             *   |
             * dep_next
             */
            link_dep(prev, dep_next);
            
            if (m_sib_next) {
                link_sib(stream_last_sib(dep_next), m_sib_next);
            }
        } else if (m_sib_next) {
            /*
             * prev
             *   |
             * stream--sib_next
             */
            next = m_sib_next;
            
            next.sib_prev = null;
            
            link_dep(prev, next);
        } else {
            prev.dep_next = null;
        }
    }
    
    /*
     * Makes the |stream| depend on the |dep_stream|.  This dependency is
     * not exclusive.  This function assumes |m_data| is null and no
     * dpri members are changed in this dependency tree.
     */
    void http2_stream_dep_add(Stream dep_stream) {
        Stream root_stream;
        
        assert(m_item == null);
        
        DEBUGF(fprintf(stderr, "stream: dep_add dep_stream(%p)=%d, stream(%p)=%d\n",
                dep_stream, dep_stream.stream_id, stream, m_stream_id));
        
        root_stream = stream_update_dep_length(dep_stream, 1);
        
        dep_stream.sum_dep_weight += m_weight;
        
        if (dep_stream.dep_next == null) {
            link_dep(dep_stream, stream);
        } else {
            insert_link_dep(dep_stream, stream);
        }
        
        stream_update_dep_sum_norest_weight(root_stream);
        stream_update_dep_effective_weight(root_stream);
        
        ++m_roots.num_streams;
    }
    
    /*
     * Removes the |stream| from the current dependency tree.  This
     * function assumes |m_data| is null.
     */
    void http2_stream_dep_remove(Stream stream) {
        Stream prev, next, dep_prev, si, root_stream;
        int sum_dep_weight_delta;
        
        root_stream = null;
        
        DEBUGF(fprintf(stderr, "stream: dep_remove stream(%p)=%d\n", stream,
                m_stream_id));
        
        /* Distribute weight of |stream| to direct descendants */
        sum_dep_weight_delta = -m_weight;
        
        for (si = m_dep_next; si; si = si.sib_next) {
            si.weight = http2_stream_dep_distributed_weight(stream, si.weight);
            
            sum_dep_weight_delta += si.weight;
        }
        
        prev = stream_first_sib(stream);
        
        dep_prev = prev.dep_prev;
        
        if (dep_prev) {
            root_stream = stream_update_dep_length(dep_prev, -1);
            
            dep_prev.sum_dep_weight += sum_dep_weight_delta;
        }
        
        if (m_sib_prev) {
            unlink_sib(stream);
        } else if (m_dep_prev) {
            unlink_dep(stream);
        } else {
            http2_stream_roots_remove(m_roots, stream);
            
            /* stream is a root of tree.  Removing stream makes its
                descendants a root of its own subtree. */
            
            for (si = m_dep_next; si;) {
                next = si.sib_next;
                
                si.dep_prev = null;
                si.sib_prev = null;
                si.sib_next = null;
                
                /* We already distributed weight of |stream| to this. */
                si.effective_weight = si.weight;
                
                http2_stream_roots_add(si.roots, si);
                
                si = next;
            }
        }
        
        if (root_stream) {
            stream_update_dep_sum_norest_weight(root_stream);
            stream_update_dep_effective_weight(root_stream);
        }
        
        m_num_substreams = 1;
        m_sum_dep_weight = 0;
        
        m_dep_prev = null;
        m_dep_next = null;
        m_sib_prev = null;
        m_sib_next = null;
        
        --m_roots.num_streams;
    }
    
    /*
     * Makes the |stream| depend on the |dep_stream|.  This dependency is
     * exclusive.  Updates dpri members in this dependency tree.
     *
     * This function returns 0 if it succeeds, or one of the following
     * negative error codes:
     *
     * HTTP2_ERR_NOMEM
     *     Out of memory
     */
    int http2_stream_dep_insert_subtree(Stream dep_stream, Session session) {
        Stream last_sib;
        Stream dep_next;
        Stream root_stream;
        size_t delta_substreams;
        
        DEBUGF(fprintf(stderr, "stream: dep_insert_subtree dep_stream(%p)=%d "
                "stream(%p)=%d\n",
                dep_stream, dep_stream.stream_id, stream, m_stream_id));
        
        delta_substreams = m_num_substreams;
        
        stream_update_dep_set_rest(stream);
        
        if (dep_stream.dep_next) {
            /* dep_stream.num_substreams includes dep_stream itself */
            m_num_substreams += dep_stream.num_substreams - 1;
            
            m_sum_dep_weight += dep_stream.sum_dep_weight;
            dep_stream.sum_dep_weight = m_weight;
            
            dep_next = dep_stream.dep_next;
            
            stream_update_dep_set_rest(dep_next);
            
            link_dep(dep_stream, stream);
            
            if (m_dep_next) {
                last_sib = stream_last_sib(m_dep_next);
                
                link_sib(last_sib, dep_next);
                
                dep_next.dep_prev = null;
            } else {
                link_dep(stream, dep_next);
            }
        } else {
            link_dep(dep_stream, stream);
            
            assert(dep_stream.sum_dep_weight == 0);
            dep_stream.sum_dep_weight = m_weight;
        }
        
        root_stream = stream_update_dep_length(dep_stream, delta_substreams);
        
        stream_update_dep_set_top(root_stream);
        
        stream_update_dep_sum_norest_weight(root_stream);
        stream_update_dep_effective_weight(root_stream);
        
        return stream_update_dep_queue_top(root_stream, session);
    }
    
    
    /*
     * Makes the |stream| depend on the |dep_stream|.  This dependency is
     * not exclusive.  Updates dpri members in this dependency tree.
     *
     * This function returns 0 if it succeeds, or one of the following
     * negative error codes:
     *
     * HTTP2_ERR_NOMEM
     *     Out of memory
     */
    int http2_stream_dep_add_subtree(Stream dep_stream, Stream stream, Session session) {
        Stream root_stream;
        
        DEBUGF(fprintf(stderr, "stream: dep_add_subtree dep_stream(%p)=%d "
                "stream(%p)=%d\n",
                dep_stream, dep_stream.stream_id, stream, m_stream_id));
        
        stream_update_dep_set_rest(stream);
        
        if (dep_stream.dep_next) {
            dep_stream.sum_dep_weight += m_weight;
            
            insert_link_dep(dep_stream, stream);
        } else {
            link_dep(dep_stream, stream);
            
            assert(dep_stream.sum_dep_weight == 0);
            dep_stream.sum_dep_weight = m_weight;
        }
        
        root_stream = stream_update_dep_length(dep_stream, m_num_substreams);
        
        stream_update_dep_set_top(root_stream);
        
        stream_update_dep_sum_norest_weight(root_stream);
        stream_update_dep_effective_weight(root_stream);
        
        return stream_update_dep_queue_top(root_stream, session);
    }
    
    /*
     * Removes subtree whose root stream is |stream|.  Removing subtree
     * does not change dpri values.  The effective_weight of streams in
     * removed subtree is not updated.
     *
     * This function returns 0 if it succeeds, or one of the following
     * negative error codes:
     *
     * HTTP2_ERR_NOMEM
     *     Out of memory
     */
    void http2_stream_dep_remove_subtree(Stream stream) {
        Stream prev, next, dep_prev, root_stream;
        
        DEBUGF(fprintf(stderr, "stream: dep_remove_subtree stream(%p)=%d\n", stream,
                m_stream_id));
        
        if (m_sib_prev) {
            prev = m_sib_prev;
            
            prev.sib_next = m_sib_next;
            if (prev.sib_next) {
                prev.sib_next.sib_prev = prev;
            }
            
            prev = stream_first_sib(prev);
            
            dep_prev = prev.dep_prev;
            
        } else if (m_dep_prev) {
            dep_prev = m_dep_prev;
            next = m_sib_next;
            
            dep_prev.dep_next = next;
            
            if (next) {
                next.dep_prev = dep_prev;
                
                next.sib_prev = null;
            }
            
        } else {
            http2_stream_roots_remove(m_roots, stream);
            
            dep_prev = null;
        }
        
        if (dep_prev) {
            dep_prev.sum_dep_weight -= m_weight;
            
            root_stream = stream_update_dep_length(dep_prev, -m_num_substreams);
            
            stream_update_dep_sum_norest_weight(root_stream);
            stream_update_dep_effective_weight(root_stream);
        }
        
        m_sib_prev = null;
        m_sib_next = null;
        m_dep_prev = null;
    }
    
    /*
     * Makes the |stream| as root.  Updates dpri members in this
     * dependency tree.
     *
     * This function returns 0 if it succeeds, or one of the following
     * negative error codes:
     *
     * HTTP2_ERR_NOMEM
     *     Out of memory
     */
    int http2_stream_dep_make_root(http2_stream *stream,
        http2_session *session) {
        DEBUGF(fprintf(stderr, "stream: dep_make_root stream(%p)=%d\n", stream,
                m_stream_id));
        
        http2_stream_roots_add(m_roots, stream);
        
        stream_update_dep_set_rest(stream);
        
        m_effective_weight = m_weight;
        
        stream_update_dep_set_top(stream);
        
        stream_update_dep_sum_norest_weight(stream);
        stream_update_dep_effective_weight(stream);
        
        return stream_update_dep_queue_top(stream, session);
    }
    
    /*
     * Makes the |stream| as root and all existing root streams become
     * direct children of |stream|.
     *
     * This function returns 0 if it succeeds, or one of the following
     * negative error codes:
     *
     * HTTP2_ERR_NOMEM
     *     Out of memory
     */
    int http2_stream_dep_all_your_stream_are_belong_to_us(Session session)
    {
        Stream first, *si;
        
        DEBUGF(fprintf(stderr, "stream: ALL YOUR STREAM ARE BELONG TO US "
                "stream(%p)=%d\n",
                stream, m_stream_id));
        
        first = m_roots.head;
        
        /* stream must not be include in m_roots.head list */
        assert(first != stream);
        
        if (first) {
            http2_stream *prev;
            
            prev = first;
            
            DEBUGF(fprintf(stderr, "stream: root stream(%p)=%d\n", first,
                    first.stream_id));
            
            m_sum_dep_weight += first.weight;
            m_num_substreams += first.num_substreams;
            
            for (si = first.root_next; si; si = si.root_next) {
                
                assert(si != stream);
                
                DEBUGF(
                    fprintf(stderr, "stream: root stream(%p)=%d\n", si, si.stream_id));
                
                m_sum_dep_weight += si.weight;
                m_num_substreams += si.num_substreams;
                
                link_sib(prev, si);
                
                prev = si;
            }
            
            if (m_dep_next) {
                http2_stream *sib_next;
                
                sib_next = m_dep_next;
                
                sib_next.dep_prev = null;
                
                link_sib(first, sib_next);
                link_dep(stream, prev);
            } else {
                link_dep(stream, first);
            }
        }
        
        http2_stream_roots_remove_all(m_roots);
        
        return http2_stream_dep_make_root(stream, session);
    }
    
    /*
     * Returns nonzero if |stream| is in any dependency tree.
     */
    int http2_stream_in_dep_tree() {
        return m_dep_prev || m_dep_next || m_sib_prev ||
               m_sib_next || m_root_next || m_root_prev ||
                m_roots.head == this;
    }


private:
    /// Stream ID
    int m_id;

    /// Intrusive Map
    nghttp2_map_entry m_map_entry;

    /// Pointers to form dependency tree.  If multiple streams depend on a stream, only one stream (left most) has non-null dep_prev 
    /// which points to the stream it depends on. The remaining streams are linked using sib_prev and sib_next.  
    /// The stream which has non-null dep_prev always null sib_prev.  The right most stream has null sib_next.  If this stream is
    /// a root of dependency tree, dep_prev and sib_prev are null.
    Stream m_dep_prev, m_dep_next;
    Stream m_sib_prev, m_sib_next;

    /// pointers to track dependency tree root streams.  This is doubly-linked list and first element is pointed by roots.head.
    Stream m_root_prev, m_root_next;
    /* When stream is kept after closure, it may be kept in doubly
     linked list pointed by nghttp2_session closed_stream_head.
     closed_next points to the next stream object if it is the element
     of the list. */
    Stream m_closed_prev, m_closed_next;

    /// pointer to roots, which tracks dependency tree roots
    StreamRoots m_roots;

    /// The arbitrary data provided by user for this stream.
    void *m_stream_user_data;

    /// Item to send
    OutboundItem m_item;

    /// categorized priority of this stream.  Only stream bearing $(D TOP) can send item.
    StreamDPRI m_dpri;

    /// the number of streams in subtree 
    size_t m_num_substreams;

    /// Current remote window size. This value is computed against the current initial window size of remote endpoint. 
    int m_remote_window_size;

    /// Keep track of the number of bytes received without WINDOW_UPDATE.
    /// This could be negative after submitting negative value to WINDOW_UPDATE
    int m_recv_window_size;

    /// The number of bytes consumed by the application and now is subject to WINDOW_UPDATE.  
    /// This is only used when auto WINDOW_UPDATE is turned off.
    int m_consumed_size;

    /// The amount of recv_window_size cut using submitting negative value to WINDOW_UPDATE
    int m_recv_reduction;

    /// window size for local flow control. It is initially set to INITIAL_WINDOW_SIZE and could be increased/decreased by
    /// submitting WINDOW_UPDATE. See nghttp2_submit_window_update().
    int m_local_window_size;

    /// weight of this stream 
    int m_weight;

    /// effective weight of this stream in belonging dependency tree
    int m_effective_weight;

    /// sum of weight (not effective_weight) of direct descendants
    int m_sum_dep_weight;

    /// sum of weight of direct descendants which have at least one descendant with dpri == $(D StreamDPRI.TOP).  We use this value to calculate effective weight.
    int m_sum_norest_weight;

    /// sum of weight of direct descendants whose dpri value is $(D StreamDPRI.TOP)
    int m_sum_top_weight;

    StreamState m_state;

    /// This is bitwise-OR of 0 or more of nghttp2_stream_flag.
    StreamFlags m_flags;

    /// Bitwise OR of zero or more ShutdownFlag values
    ShutdownFlag m_shut_flags;

    /// Content-Length of request/response body. -1 if unknown.
    long m_content_length;

    /// Received body so far 
    long m_recv_content_length;

    /// status code from remote server
    short m_status_code;

    /// Bitwise OR of zero or more nghttp2_http_flag values 
    HTTPFlags m_http_flags;
}
