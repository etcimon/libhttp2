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
import libhttp2.session;
import std.algorithm : max;

const MAX_DEP_TREE_LENGTH = 100;

struct StreamRoots
{

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
            next = si.m_root_next;
            
            si.m_root_prev = null;
            si.m_root_next = null;
            
            si = next;
        }
        
        head = null;
    }

    Stream head;
    int num_streams;
}

class Stream {

    this(int stream_id,
		 StreamFlags flags,
		 StreamState initial_state,
		 int weight,
		 StreamRoots roots,
		 int remote_initial_window_size,
         int local_initial_window_size,
         void *stream_user_data) 
	{
        m_stream_id = stream_id;
        m_flags = flags;
        m_state = initial_state;
        m_weight = weight;
        m_effective_weight = m_weight;
		m_roots = roots;
		m_remote_window_size = remote_initial_window_size;
		m_local_window_size = local_initial_window_size;
		m_stream_user_data = stream_user_data;
    }
    
    /*
     * Disallow either further receptions or transmissions, or both.
     * |flag| is bitwise OR of one or more of ShutdownFlag.
     */
    void shutdown(ShutdownFlag flag)
	{
        m_shut_flags |= flag;
    }

    /*
     * Computes distributed weight of a stream of the |weight| under the
     * $(D Stream) if $(D Stream) is removed from a dependency tree.  The result
     * is computed using m_weight rather than m_effective_weight.
     */
    int distributedWeight(int weight) 
	{
        weight = m_weight * weight / m_sum_dep_weight;
        
        return max(1, weight);
    }
    
    /*
	 * Computes effective weight of a stream of the |weight| under the
	 * $(D Stream).  The result is computed using m_effective_weight
	 * rather than m_weight.  This function is used to determine
	 * weight in dependency tree.
	 */
    int distributedEffectiveWeight(int weight) {
        if (m_sum_norest_weight == 0)
            return m_effective_weight;        
        weight = m_effective_weight * weight / m_sum_norest_weight;
        
        return max(1, weight);
    }
    

    
    /*
	 * Attaches |item| to $(D Stream).  Updates dpri members in this
	 * dependency tree.
	 */
    void attachItem(OutboundItem item, Session session) 
	{
        assert((m_flags & StreamFlags.DEFERRED_ALL) == 0);
        assert(!m_item);
        
        DEBUGF(fprintf(stderr, "stream: stream=%d attach item=%p\n",
                m_stream_id, item));
        
        m_item = item;
        
		stream.updateOnAttachItem(session);
    }
    
    /*
	 * Detaches |m_item|.  Updates dpri members in this dependency
	 * tree.  This function does not free |m_item|.  The caller must
	 * free it.
	 */
    void detachItem(Session session) 
	{
        DEBUGF(fprintf(stderr, "stream: stream=%d detach item=%p\n",
                m_stream_id, m_item));
        
        m_item = null;
        m_flags &= ~StreamFlags.DEFERRED_ALL;
        
		stream.updateDepOnDetachItem(session);
    }
    
    /*
	 * Defer |m_item|.  We won't call this function in the situation
	 * where |m_item| is null.  The |flags| is bitwise OR of zero or
	 * more of StreamFlags.DEFERRED_USER and
	 * StreamFlags.DEFERRED_FLOW_CONTROL.  The |flags| indicates
	 * the reason of this action.
	 */
    void deferItem(StreamFlags flags, Session session) 
	{
        assert(m_item);
        
        DEBUGF(fprintf(stderr, "stream: stream=%d defer item=%p cause=%02x\n",
                m_stream_id, m_item, flags));
        
        m_flags |= flags;
        
		updateDepOnDetachItem(session);
    }
    
    /*
	 * Put back deferred data in this stream to active state.  The |flags|
	 * are one or more of bitwise OR of the following values:
	 * StreamFlags.DEFERRED_USER and
	 * StreamFlags.DEFERRED_FLOW_CONTROL and given masks are
	 * cleared if they are set.  So even if this function is called, if
	 * one of flag is still set, data does not become active.
	 */
    void resumeDeferredItem(StreamFlags flag, Session session)
	{
        assert(m_item);
        
        DEBUGF(fprintf(stderr, "stream: stream=%d resume item=%p flags=%02x\n",
                m_stream_id, m_item, flags));
        
        m_flags &= ~flags;
        
        if (m_flags & StreamFlags.DEFERRED_ALL) {
            return 0;
        }
        
		stream.updateOnAttachItem(session);
    }
    
    /*
	 * Returns nonzero if item is deferred by whatever reason.
	 */
    bool isItemDeferred() 
	{
        return m_item && (m_flags & StreamFlags.DEFERRED_ALL);
    }
    
    /*
	 * Returns nonzero if item is deferred by flow control.
	 */
    bool isDeferredByFlowControl() 
	{
        return m_item && (m_flags & StreamFlags.DEFERRED_FLOW_CONTROL);
    }

    
    /*
	 * Updates the remote window size with the new value
	 * |new_initial_window_size|. The |old_initial_window_size| is used to
	 * calculate the current window size.
	 *
	 * This function returns true if it succeeds or false. The failure is due to
	 * overflow.
	 */
    bool updateRemoteInitialWindowSize(int new_initial_window_size, int old_initial_window_size)
	{
		return updateInitialWindowSize(m_remote_window_size, new_initial_window_size, old_initial_window_size);
    }
    
    /*
	 * Updates the local window size with the new value
	 * |new_initial_window_size|. The |old_initial_window_size| is used to
	 * calculate the current window size.
	 *
	 * This function returns true if it succeeds or false. The failure is due to
	 * overflow.
	 */
    bool updateLocalInitialWindowSize(int new_initial_window_size, int old_initial_window_size) 
	{
		return updateInitialWindowSize(m_local_window_size, new_initial_window_size, old_initial_window_size);
    }
    
    /*
     * Call this function if promised stream $(D Stream) is replied with
     * HEADERS.  This function changes the state of the $(D Stream) to
     * OPENED.
     */
    void promiseFulfilled() {
		m_state = StreamState.OPENED;
        m_flags &= ~StreamFlags.PUSH;
    }
    
    /*
     * Returns the stream positioned in root of the dependency tree the
     * $(D Stream) belongs to.
     */
    Stream getRoot() {
		Stream stream = this;
        for (;;) {
            if (stream.m_sib_prev) {
                stream = stream.m_sib_prev;
                
                continue;
            }
            
            if (stream.m_dep_prev) {
                stream = m_dep_prev;
                
                continue;
            }
            
            break;
        }
        
        return stream;
    }
    
    /*
     * Returns true if |target| is found in subtree of $(D Stream).
     */
    bool subtreeContains(Stream target) {
        if (!stream)
            return false;
        
        if (stream is target)
            return true;
        
		if (m_sib_next.subtreeContains(target))
            return true;
        
		return m_dep_next.subtreeContains(target);
    }
    
    /*
     * Makes the $(D Stream) depend on the |dep_stream|.  This dependency is
     * exclusive.  All existing direct descendants of |dep_stream| become
     * the descendants of the $(D Stream).  This function assumes
     * |m_data| is null and no dpri members are changed in this
     * dependency tree.
     */
    void insert(Stream stream) {
        Stream si;
        Stream root_stream;
        
        assert(!m_item);
        
        DEBUGF(fprintf(stderr,
                "stream: dep_insert dep_stream(%p)=%d, stream(%p)=%d\n",
				this, m_stream_id, stream, stream.m_stream_id));
        
		stream.m_sum_dep_weight = m_sum_dep_weight;
		m_sum_dep_weight = stream.m_weight;
        
		if (m_dep_next) {
			for (si = m_dep_next; si; si = si.m_sib_next) {
                stream.m_num_substreams += si.m_num_substreams;
            }
            
			stream.m_dep_next = m_dep_next;
            stream.m_dep_next.m_dep_prev = stream;
        }
        
		m_dep_next = stream;
        stream.m_dep_prev = this;
        
		root_stream = updateLength(1);
        
		root_stream.updateSumNorestWeight();
		root_stream.updateEffectiveWeight();
        
        ++stream.m_roots.num_streams;
    }
     
    /*
     * Makes the $(D Stream) depend on the |dep_stream|.  This dependency is
     * not exclusive.  This function assumes |m_data| is null and no
     * dpri members are changed in this dependency tree.
     */
    void add(Stream stream) {
        Stream root_stream;
        
        assert(!stream.m_item);
        
        DEBUGF(fprintf(stderr, "stream: dep_add dep_stream(%p)=%d, stream(%p)=%d\n", this, m_stream_id, stream, stream.m_stream_id));
        
        root_stream = updateLength(1);
        
		m_sum_dep_weight += stream.m_weight;
        
        if (!m_dep_next) {
            linkDependency(stream);
        } else {
            insertLinkDependency(stream);
        }
        
		root_stream.updateSumNorestWeight();
		root_stream.updateEffectiveWeight();
        
        ++stream.m_roots.num_streams;
    }
    
    /*
     * Removes the $(D Stream) from the current dependency tree.  This
     * function assumes |m_data| is null.
     */
	void remove() {
        Stream prev, next, dep_prev, si, root_stream;
        int sum_dep_weight_delta;
        
        DEBUGF(fprintf(stderr, "stream: dep_remove stream(%p)=%d\n", this, m_stream_id));
        
        /* Distribute weight of $(D Stream) to direct descendants */
        sum_dep_weight_delta = -m_weight;
        
        for (si = m_dep_next; si; si = si.m_sib_next) {
            si.m_weight = distributedWeight(si.m_weight);
            
            sum_dep_weight_delta += si.m_weight;
        }
        
        prev = firstSibling();
        
        dep_prev = prev.dep_prev;
        
        if (dep_prev) {
            root_stream = updateLength(dep_prev, -1);
            
            dep_prev.sum_dep_weight += sum_dep_weight_delta;
        }
        
        if (m_sib_prev) {
            unlinkSibling();
        } else if (m_dep_prev) {
            unlinkDependency();
        } else {
            m_roots.remove(this);
            
            /* stream is a root of tree.  Removing stream makes its
                descendants a root of its own subtree. */
            
            for (si = m_dep_next; si;) {
                next = si.m_sib_next;
                
                si.m_dep_prev = null;
                si.m_sib_prev = null;
                si.m_sib_next = null;
                
                /* We already distributed weight of $(D Stream) to this. */
                si.m_effective_weight = si.m_weight;
                
                si.m_roots.add(si);
                
                si = next;
            }
        }
        
        if (root_stream) {
			root_stream.updateSumNorestWeight();
			root_stream.updateEffectiveWeight();
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
     * Makes the $(D Stream) depend on the |dep_stream|.  This dependency is
     * exclusive.  Updates dpri members in this dependency tree.
     */
    void insertSubtree(Stream stream, Session session) {
        Stream last_sib;
        Stream dep_next;
        Stream root_stream;
        size_t delta_substreams;
        
        DEBUGF(fprintf(stderr, "stream: dep_insert_subtree dep_stream(%p)=%d "
                "stream(%p)=%d\n",
                this, m_stream_id, stream, stream.m_stream_id));
        
		delta_substreams = stream.m_num_substreams;
        
		stream.updateSetRest();
        
        if (m_dep_next) {
            /* m_num_substreams includes dep_stream itself */
			stream.m_num_substreams += m_num_substreams - 1;
            
			stream.m_sum_dep_weight += m_sum_dep_weight;
			m_sum_dep_weight = stream.m_weight;
            
            dep_next = m_dep_next;
            
			dep_next.updateSetRest();
            
            linkDependency(stream);
            
			if (stream.m_dep_next) {
				last_sib = stream.m_dep_next.lastSibling();
                
				last_sib.linkSibling(dep_next);
                
                dep_next.dep_prev = null;
            } else {
                stream.linkDependency(dep_next);
            }
        } else {
            linkDependency(stream);
            
            assert(m_sum_dep_weight == 0);
			m_sum_dep_weight = stream.m_weight;
        }
        
        root_stream = updateLength(delta_substreams);
        
		root_stream.updateSetTop();
        
		root_stream.updateSumNorestWeight();
		root_stream.updateEffectiveWeight();
        
		root_stream.updateQueueTop(session);
    }
    
    
    /*
     * Makes the $(D Stream) depend on the |dep_stream|.  This dependency is
     * not exclusive.  Updates dpri members in this dependency tree.
     */
    void addSubtree(Stream stream, Session session) 
	{
        Stream root_stream;
        
        DEBUGF(fprintf(stderr, "stream: dep_add_subtree dep_stream(%p)=%d "
                "stream(%p)=%d\n",
                this, m_stream_id, stream, stream.m_stream_id));
        
        stream.updateSetRest();
        
        if (m_dep_next) {
            m_sum_dep_weight += stream.m_weight;
            
            insertLinkDependency(stream);
        } else {
            linkDependency(stream);
            
            assert(m_sum_dep_weight == 0);
			m_sum_dep_weight = stream.m_weight;
        }
        
        root_stream = updateLength(stream.m_num_substreams);
        
		root_stream.updateSetTop();
        
		root_stream.updateSumNorestWeight();
		root_stream.updateEffectiveWeight();
        
		root_stream.updateQueueTop(session);
    }
    
    /*
     * Removes subtree whose root stream is $(D Stream).  Removing subtree
     * does not change dpri values.  The effective_weight of streams in
     * removed subtree is not updated.
     */
    void removeSubtree() 
	{
        Stream prev, next, dep_prev, root_stream;
        
        DEBUGF(fprintf(stderr, "stream: dep_remove_subtree stream(%p)=%d\n", this, m_stream_id));
        
        if (m_sib_prev) {
            prev = m_sib_prev;
            
            prev.m_sib_next = m_sib_next;
            if (prev.m_sib_next) {
                prev.m_sib_next.m_sib_prev = prev;
            }
            
			prev = prev.firstSibling();
            
            dep_prev = prev.m_dep_prev;
            
        } else if (m_dep_prev) {
            dep_prev = m_dep_prev;
            next = m_sib_next;
            
            dep_prev.m_dep_next = next;
            
            if (next) {
                next.m_dep_prev = dep_prev;
                
                next.m_sib_prev = null;
            }
            
        } else {
			m_roots.remove(this);
            
            dep_prev = null;
        }
        
        if (dep_prev) {
            dep_prev.sum_dep_weight -= m_weight;
            
			root_stream = dep_prev.updateLength(-m_num_substreams);
            
			root_stream.updateSumNorestWeight();
			root_stream.updateEffectiveWeight();
        }
        
        m_sib_prev = null;
        m_sib_next = null;
        m_dep_prev = null;
    }
    
    /*
     * Makes the $(D Stream) as root.  Updates dpri members in this
     * dependency tree.
     */
    void makeRoot(Session session)
	{
        DEBUGF(fprintf(stderr, "stream: dep_make_root stream(%p)=%d\n", this, m_stream_id));
        
		m_roots.add(this);
        
        updateSetRest();
        
        m_effective_weight = m_weight;
        
        updateSetTop();
        
        updateSumNorestWeight();
        updateEffectiveWeight();
        
		updateQueueTop(session);
    }
    
    /*
     * Makes the $(D Stream) as root and all existing root streams become
     * direct children of $(D Stream).
     */
	void makeTopmostRoot(Session session)
    {
        Stream first, si;
        
        DEBUGF(fprintf(stderr, "stream: ALL YOUR STREAM ARE BELONG TO US stream(%p)=%d\n", stream, m_stream_id));
        
        first = m_roots.head;
        
        /* stream must not be include in m_roots.head list */
        assert(first !is this);
        
        if (first) {
            Stream prev;
            
            prev = first;
            
            DEBUGF(fprintf(stderr, "stream: root stream(%p)=%d\n", first, first.m_stream_id));
            
            m_sum_dep_weight += first.m_weight;
            m_num_substreams += first.m_num_substreams;
            
            for (si = first.m_root_next; si; si = si.m_root_next) {
                
                assert(si !is stream);
                
                DEBUGF(fprintf(stderr, "stream: root stream(%p)=%d\n", si, si.m_stream_id));
                
                m_sum_dep_weight += si.m_weight;
                m_num_substreams += si.m_num_substreams;
                
				prev.linkSibling(si);
                
                prev = si;
            }
            
            if (m_dep_next) {
                Stream sib_next;
                
                sib_next = m_dep_next;
                
                sib_next.m_dep_prev = null;
                
				first.linkSibling(sib_next);
				linkDependency(prev);
            } else {
				linkDependency(first);
            }
        }
        
        m_roots.removeAll();
        
		makeRoot(session);
    }
    
    /*
     * Returns nonzero if $(D Stream) is in any dependency tree.
     */
    int inDepTree() {
        return m_dep_prev || m_dep_next || m_sib_prev ||
               m_sib_next || m_root_next || m_root_prev ||
               m_roots.head is this;
    }

private:


	bool updateInitialWindowSize(ref int window_size, int new_initial_window_size, int old_initial_window_size)
	{
		int new_window_size = window_size + new_initial_window_size - old_initial_window_size;
		if (int.min > new_window_size || new_window_size > MAX_WINDOW_SIZE)
			return false;
		
		window_size = new_window_size;

		return true;
	}

	void pushItem(Session session) 
	{
		OutboundItem item;
		
		assert(m_item);
		assert(m_item.queued == 0);
		
		item = m_item;
		
		/* If item is now sent, don't push it to the queue.  Otherwise, we may push same item twice. */
		if (session.aob.item is item)
			return;
		
		if (item.weight > m_effective_weight)
			item.weight = m_effective_weight;
		
		item.cycle = session.last_cycle;
		
		switch (item.frame.hd.type) {
			case FrameType.DATA:
				session.ob_da_pq.push(item);
				break;
			case FrameType.HEADERS:
				if (m_state == StreamState.RESERVED)
					session.ob_ss_pq.push(item);
				else
					session.ob_pq.push(item);
				break;
			default:
				/* should not reach here */
				assert(0);
		}
		
		item.queued = 1;
	}

	int distributedTopEffectiveWeight(int weight) {
		if (m_sum_top_weight == 0)
			return m_effective_weight;

		weight = m_effective_weight * weight / m_sum_top_weight;

		return max(1, weight);
	}
	
	/* Updates effective_weight of descendant streams in subtree of $(D Stream).  We assume that m_effective_weight is already set right. */
	void updateEffectiveWeight()
	{
		Stream si;
		
		DEBUGF(fprintf(stderr, "stream: update_dep_effective_weight "
				"stream(%p)=%d, weight=%d, sum_norest_weight=%d, "
				"sum_top_weight=%d\n",
				this, m_stream_id, m_weight,
				m_sum_norest_weight, m_sum_top_weight));
		
		/* m_sum_norest_weight == 0 means there is no StreamDPRI.TOP under stream */
		if (m_dpri != StreamDPRI.NO_ITEM ||
			m_sum_norest_weight == 0) {
			return;
		}
		
		/* If there is no direct descendant whose dpri is StreamDPRI.TOP, indirect descendants have
		 * the chance to send data, so recursively set weight for descendants. */
		if (m_sum_top_weight == 0) {
			for (si = m_dep_next; si; si = si.m_sib_next) {
				if (si.m_dpri != StreamDPRI.REST) {
					si.m_effective_weight =
						distributedEffectiveWeight(si.m_weight);
				}
				
				updateEffectiveWeight(si);
			}
			return;
		}
		
		/* If there is at least one direct descendant whose dpri is
		   StreamDPRI.TOP, we won't give a chance to indirect
		   descendants, since closed or blocked stream's weight is
		   distributed among its siblings */
		for (si = m_dep_next; si; si = si.m_sib_next) {
			if (si.m_dpri == StreamDPRI.TOP) {
				si.m_effective_weight = distributedTopEffectiveWeight(si.m_weight);				
				DEBUGF(fprintf(stderr, "stream: stream=%d top eweight=%d\n", si.m_stream_id, si.m_effective_weight));
				
				continue;
			}
			
			if (si.m_dpri == StreamDPRI.NO_ITEM) {
				DEBUGF(fprintf(stderr, "stream: stream=%d no_item, ignored\n", si.m_stream_id));
				
				/* Since we marked StreamDPRI.TOP under si, we make them StreamDPRI.REST again. */
				si.m_dep_next.updateSetRest();
			} else {
				DEBUGF(fprintf(stderr, "stream: stream=%d rest, ignored\n", si.m_stream_id));
			}
		}
	}
	
	void updateSetRest() 
	{
		
		DEBUGF(fprintf(stderr, "stream: stream=%d is rest\n", m_stream_id));
		
		if (m_dpri == StreamDPRI.REST)
			return;
		
		if (m_dpri == StreamDPRI.TOP) 
		{
			m_dpri = StreamDPRI.REST;
			
			m_sib_next.updateSetRest();
			
			return;
		}

		m_sib_next.updateSetRest();
		m_dep_next.updateSetRest();
	}
	
	/*
	 * Performs dfs starting $(D Stream), search stream which can become
	 * StreamDPRI.TOP and set its dpri.
	 */
	void updateSetTop() 
	{
		Stream si;
		
		if (m_dpri == StreamDPRI.TOP)
			return;
		
		if (m_dpri == StreamDPRI.REST) 
		{
			DEBUGF(fprintf(stderr, "stream: stream=%d item is top\n", m_stream_id));
			
			m_dpri = StreamDPRI.TOP;
			
			return;
		}
		
		for (si = m_dep_next; si; si = si.m_sib_next)
			si.updateSetTop();

	}
	
	/*
	 * Performs dfs starting $(D Stream), and queue stream whose dpri is
	 * StreamDPRI.TOP and has not been queued yet.
	 */
	void updateQueueTop(Session session)
	{
		Stream si;
		
		if (m_dpri == StreamDPRI.REST) 
			return;
		
		if (m_dpri == StreamDPRI.TOP) {
			if (!m_item.queued) {
				DEBUGF(fprintf(stderr, "stream: stream=%d enqueue\n", m_stream_id));
				pushItem(session);
			}
			
			return;
		}
		
		for (si = m_dep_next; si; si = si.m_sib_next)
			si.updateQueueTop(session);
		

	}
	
	/*
	 * Updates m_sum_norest_weight and m_sum_top_weight
	 * recursively.  We have to gather effective sum of weight of
	 * descendants.  If m_dpri == StreamDPRI.NO_ITEM, we
	 * have to go deeper and check that any of its descendants has dpri
	 * value of StreamDPRI.TOP.  If so, we have to add weight of
	 * its direct descendants to m_sum_norest_weight.  To make this
	 * work, this function returns true if any of its descendants has dpri
	 * value of StreamDPRI.TOP, otherwise false.
	 *
	 * Calculating m_sum_top-weight is very simple compared to
	 * m_sum_norest_weight.  It just adds up the weight of direct
	 * descendants whose dpri is StreamDPRI.TOP.
	 */
	bool updateSumNorestWeight() 
	{
		Stream si;
		bool ret;
		
		m_sum_norest_weight = 0;
		m_sum_top_weight = 0;
		
		if (m_dpri == StreamDPRI.TOP) 
			return true;
		
		if (m_dpri == StreamDPRI.REST)
			return false;
		
		ret = false;
		
		for (si = m_dep_next; si; si = si.m_sib_next) {
			
			if (si.updateSumNorestWeight()) {
				ret = true;
				m_sum_norest_weight += si.m_weight;
			}
			
			if (si.m_dpri == StreamDPRI.TOP)
				m_sum_top_weight += si.m_weight;
		}
		
		return ret;
	}
	
	void updateOnAttachItem(Session session) 
	{
		Stream root_stream;
		
		m_dpri = StreamDPRI.REST;
		
		m_dep_next.updateSetRest();
		
		root_stream = getRoot();
		
		DEBUGF(fprintf(stderr, "root=%p, stream=%p\n", root_stream, this));
		
		root_stream.updateSetTop();
		
		root_stream.updateSumNorestWeight();
		root_stream.updateEffectiveWeight();
		
		root_stream.updateQueueTop(session);
	}
	
	void updateDepOnDetachItem(Session session) {
		Stream root_stream;
		
		m_dpri = StreamDPRI.NO_ITEM;

		root_stream = getRoot();
		
		root_stream.updateSetTop();

		root_stream.updateSumNorestWeight();
		root_stream.updateEffectiveWeight();
		
		root_stream.updateQueueTop(session);
	}

	void linkDependency(Stream stream) {
		m_dep_next = stream;
		stream.m_dep_prev = this;
	}
	
	void linkSibling(Stream stream) 
	{
		m_sib_next = stream;
		stream.m_sib_prev = this;
	}
	
	void insertLinkDependency(Stream stream)
	{
		Stream sib_next;
		
		assert(!stream.m_sib_prev);
		
		sib_next = m_dep_next;
		
		stream.linkSibling(sib_next);
		
		sib_next.dep_prev = null;
		
		linkDependency(stream);
	}

	Stream firstSibling() 
	{
		Stream stream = this;
		for (; stream.sib_prev; stream = stream.sib_prev)
			continue;
		
		return stream;
	}
	
	Stream lastSibling()
	{
		Stream stream = this;
		for (; stream.sib_next; stream = stream.sib_next)
			continue;

		return stream;
	}
	
	Stream updateLength(size_t delta) 
	{
		m_num_substreams += delta;

		Stream stream = firstSibling();
		
		if (stream.m_dep_prev)
			return stream.m_dep_prev.updateLength(delta);

		return stream;
	}

	void unlinkSibling() {
		Stream prev, next, dep_next;
		
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
			
			prev.linkSibling(dep_next);
			
			if (m_sib_next) {
				dep_next.lastSibling().linkSibling(m_sib_next);
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
	
	void unlinkDependency() {
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
			prev.linkDependency(dep_next);
			
			if (m_sib_next) {
				dep_next.lastSibling().linkSibling(m_sib_next);
			}
		} else if (m_sib_next) {
			/*
             * prev
             *   |
             * stream--sib_next
             */
			next = m_sib_next;
			
			next.sib_prev = null;
			
			prev.linkDependency(next);
		} else {
			prev.dep_next = null;
		}
	}

private:
    /// Stream ID
    int m_id;

    /// Pointers to form dependency tree.  If multiple streams depend on a stream, only one stream (left most) has non-null dep_prev 
    /// which points to the stream it depends on. The remaining streams are linked using sib_prev and sib_next.  
    /// The stream which has non-null dep_prev always null sib_prev.  The right most stream has null sib_next.  If this stream is
    /// a root of dependency tree, dep_prev and sib_prev are null.
    Stream m_dep_prev, m_dep_next;
    Stream m_sib_prev, m_sib_next;

    /// pointers to track dependency tree root streams.  This is doubly-linked list and first element is pointed by roots.head.
    Stream m_root_prev, m_root_next;
    /* When stream is kept after closure, it may be kept in doubly
     linked list pointed by Session.closed_stream_head.
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
	StreamDPRI m_dpri = StreamDPRI.NO_ITEM;

    /// the number of streams in subtree 
	size_t m_num_substreams = 1;

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
    /// submitting WINDOW_UPDATE. See submit_window_update().
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

    /// This is bitwise-OR of 0 or more of StreamFlags.
    StreamFlags m_flags;

    /// Bitwise OR of zero or more ShutdownFlag values
	ShutdownFlag m_shut_flags = ShutdownFlag.NONE;

    /// Content-Length of request/response body. -1 if unknown.
	int m_content_length = -1;

    /// Received body so far 
    int m_recv_content_length;

    /// status code from remote server
	short m_status_code = -1;

    /// Bitwise OR of zero or more HTTPFlags values 
	HTTPFlags m_http_flags = HTTPFlags.NONE;

package: // used by Session
	@property int id() { return m_stream_id; }
	@property StreamDPRI dpri() { return m_dpri; }
	@property StreamState state() { return m_state; }
	@property OutboundItem item() { return m_item; }
	@property int effectiveWeight() { return m_effective_weight; }
	@property int remoteWindowSize() { return m_remote_window_size; }
	@property int localWindowSize() { return m_local_window_size; }
	@property ref int recvWindowSize() { return m_recv_window_size; }
	@property void recvWindowSize(int sz) { m_recv_window_size = sz; }
	@property int consumedSize() { return m_consumed_size; }
	@property void* userData() { return m_stream_user_data; }
	@property void userData(void* ptr) { m_stream_user_data = ptr; }
	@property ShutdownFlag shutFlags() { return m_shut_flags; }
	@property HTTPFlags httpFlags() { return m_http_flags; }
	@property StreamFlags flags() { return m_flags; }
	@property int subStreams() { return m_num_substreams; }
	@property void weight(int w) { m_weight = w; }
	@property Stream closedPrev() { return m_closed_prev; }
	@property Stream closedNext() { return m_closed_next; } 
	@property void closedPrev(Stream s) { m_closed_prev = s; }
	@property void closedNext(Stream s) { m_closed_next = s; } 
}
