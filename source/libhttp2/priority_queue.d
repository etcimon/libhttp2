/**
 * Priority Queue
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.priority_queue;

import libhttp2.types;
import libhttp2.frame : OutboundItem;
import memutils.utils;

@trusted nothrow:

/// Implementation of priority queue
struct PriorityQueue
{
@trusted nothrow:
private:
	/// The pointer to the pointer to the item stored 
	OutboundItem*[] m_queue;

	/* The maximum number of items this pq can store. This is
     automatically extended when length is reached to this value. */
	size_t m_capacity;

public:

	this(size_t capacity) // default=128
	{
		m_capacity = capacity;
		m_queue = Mem.alloc!(OutboundItem*[])(capacity);
		m_queue = m_queue.ptr[0 .. 0];
	}

	/// Deallocates any resources allocated.  All stored items are freed by this function.
	void free()
	{
		while (!empty) 
		{
			OutboundItem* item = top;
			item.free();
			Mem.free(item);
			pop();
		}
		if (m_queue)
			Mem.free(m_queue.ptr[0 .. m_capacity]);
		m_queue = null;
		m_capacity = 0;
	}


	/// Adds |item| to the priority queue
	void push(OutboundItem* item)
	{
		if (m_capacity <= m_queue.length)
		{
			size_t len = m_queue.length;
			m_queue = Mem.realloc(m_queue[0 .. m_capacity], m_capacity * 2);
			m_capacity *= 2;
			m_queue = m_queue.ptr[0 .. len];
		}
		m_queue = m_queue.ptr[0 .. m_queue.length + 1];
		m_queue[$-1] = item;
		bubbleUp(m_queue.length - 1);
	}

	
	/*
	 * Pops item at the top of the queue |pq|. The popped item is not
	 * freed by this function.
	 */
	void pop()
	{
		if (m_queue.length == 0) return;

		m_queue[0] = m_queue[$ - 1];
		m_queue = m_queue.ptr[0 .. m_queue.length - 1];
		bubbleDown(0);

	}

	/*
	 * Returns item at the top of the queue |pq|. If the queue is empty,
	 * this function returns NULL.
	 */
	@property OutboundItem* top()
	{
		if (length == 0) {
			return null;
		} else {
			return m_queue[0];
		}
	}

	/*
	 * Returns true if the queue is empty.
	 */
	@property bool empty() const {
		return m_queue.length == 0;
	}


	/*
	 * Returns the number of items in the queue |pq|.
	 */
	@property size_t length() const {
		return m_queue.length;
	}

	/// Iterates over each item in the PriorityQueue and reorders it
	int opApply(scope int delegate(OutboundItem* ob) nothrow del) {
		
		if (m_queue.length == 0)
			return 0;
		
		// assume the ordering will change
		scope(exit) {
			for (size_t i = m_queue.length; i > 0; --i) {
				bubbleDown(i - 1);
			}
		}
		
		foreach (ob; m_queue) {
			if (auto ret = del(ob))
				return ret;
		}
		
		return 0;
	}

	/// Iterates over each item in the PriorityQueue
	int opApply(scope int delegate(const OutboundItem* ob) nothrow del) const {
		foreach (const ob; m_queue) {
			if (auto ret = del(ob))
				return ret;
		}
		return 0;
	}

private:
	void swap(size_t i, size_t j) {
		OutboundItem* t = m_queue[i];
		m_queue[i] = m_queue[j];
		m_queue[j] = t;
	}

	void bubbleUp(size_t index) {
		if (index == 0) {
			return;
		} else {
			size_t parent = (index - 1) / 2;
			if (compare(m_queue[parent], m_queue[index]) > 0) {
				swap(parent, index);
				bubbleUp(parent);
			}
		}
	}

	void bubbleDown(size_t index) {
		size_t lchild = index * 2 + 1;
		size_t minindex = index;
		size_t i, j;
		for (i = 0; i < 2; ++i) {
			j = lchild + i;
			if (j >= m_queue.length) {
				break;
			}
			if (compare(m_queue[minindex], m_queue[j]) > 0) {
				minindex = j;
			}
		}
		if (minindex != index) {
			swap(index, minindex);
			bubbleDown(minindex);
		}
	}
package:
	static int compare(in OutboundItem* lhs, in OutboundItem* rhs) 
	{
		if (lhs.cycle == rhs.cycle) {
			if (lhs.weight == rhs.weight) {
				return (lhs.seq < rhs.seq) ? -1 : ((lhs.seq > rhs.seq) ? 1 : 0);
			}
			
			/* Larger weight has higher precedence */
			return rhs.weight - lhs.weight;
		}
		
		return (lhs.cycle < rhs.cycle) ? -1 : 1;
	}

}