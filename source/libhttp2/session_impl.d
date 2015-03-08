/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
 * Copyright (c) 2015 Etienne Cimon
 * 
 * License: MIT
 */
module libhttp2.session_impl;

import libhttp2.session;
import libhttp2.frame;
import libhttp2.stream;
import libhttp2.types;

int http2_session_on_push_promise_received(Session session, Frame frame) 
{
    ErrorCode rv;
    Stream stream;
    Stream promised_stream;
    PrioritySpec pri_spec;
    
    if (frame.hd.stream_id == 0) {
        return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: stream_id == 0");
    }
    if (is_server || session.local_settings.enable_push == 0) {
        return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: push disabled");
    }
    if (session.goaway_flags) {
        /* We just dicard PUSH_PROMISE after GOAWAY is sent or
       received. */
        return ErrorCode.IGN_HEADER_BLOCK;
    }
    
    if (!isMyStreamId(frame.hd.stream_id)) {
        return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: invalid stream_id");
    }
    
    if (!session_is_new_peer_stream_id(session,
            frame.push_promise.promised_stream_id)) {
        /* The spec says if an endpoint receives a PUSH_PROMISE with
	       illegal stream ID is subject to a connection error of type
	       PROTOCOL_ERROR. */
        return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: invalid promised_stream_id");
    }
    session.last_recv_stream_id = frame.push_promise.promised_stream_id;
    stream = getStream(frame.hd.stream_id);
    if (!stream || stream.state == StreamState.CLOSING) {
        if (!stream) {
            if (idleStreamDetect(frame.hd.stream_id)) {
                return handleInflateInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: stream in idle");
            }
        }
        addRstStream(frame.push_promise.promised_stream_id, FrameError.REFUSED_STREAM);
        return ErrorCode.IGN_HEADER_BLOCK;
    }
    if (stream.shutFlags & ShutdownFlag.RD) {
        if (session.policy.on_invalid_frame_recv_callback) {
            if (session.policy.on_invalid_frame_recv_callback(session, frame, FrameError.PROTOCOL_ERROR) != 0) {
                return ErrorCode.CALLBACK_FAILURE;
            }
        }
        addRstStream(frame.push_promise.promised_stream_id, FrameError.PROTOCOL_ERROR);
        return ErrorCode.IGN_HEADER_BLOCK;
    }
    
    /* TODO: It is unclear reserved stream depends on associated stream with or without exclusive flag set */
    http2_priority_spec_init(&pri_spec, stream.id, DEFAULT_WEIGHT, 0);
    
    promised_stream = openStream(frame.push_promise.promised_stream_id, StreamFlags.NONE, &pri_spec, StreamState.RESERVED, null);
    
    session.last_proc_stream_id = session.last_recv_stream_id;
    if (!callOnHeaders(frame))
		return ErrorCode.CALLBACK_FAILURE;
    return 0;
}

int session_process_push_promise_frame(Session session)
{
    ErrorCode rv;
    InboundFrame *iframe = &session.iframe;
    Frame frame = &iframe.frame;
    
    rv = http2_frame_unpack_push_promise_payload(
        &frame.push_promise, iframe.sbuf[]);
    
    if (rv != 0) {
        return terminateSessionWithReason(FrameError.PROTOCOL_ERROR, "PUSH_PROMISE: could not unpack");
    }
    
    return http2_session_on_push_promise_received(session, frame);
}

int http2_session_on_ping_received(Session session, Frame frame) 
{
    int rv = 0;
    if (frame.hd.stream_id != 0) {
        return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "PING: stream_id != 0");
    }
    if ((frame.hd.flags & FrameFlags.ACK) == 0 && !isClosing()) {
        /* Peer sent ping, so ping it back */
        rv = http2_session_add_ping(session, FrameFlags.ACK, frame.ping.opaque_data);
        if (rv != 0) {
            return rv;
        }
    }
	bool ok = callOnFrame(frame);
	if (!ok)
		return ErrorCode.CALLBACK_FAILURE;
	return 0;
}

int session_process_ping_frame(Session session)
{
    InboundFrame *iframe = &session.iframe;
    Frame frame = &iframe.frame;
    
    http2_frame_unpack_ping_payload(&frame.ping, iframe.sbuf[]);
    
    return http2_session_on_ping_received(session, frame);
}

int http2_session_on_goaway_received(Session session, Frame frame) 
{
    ErrorCode rv;
    
    if (frame.hd.stream_id != 0) {
        return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "GOAWAY: stream_id != 0");
    }
    /* Spec says Endpoints MUST NOT increase the value they send in the
     last stream identifier. */
    if ((frame.goaway.last_stream_id > 0 && !isMyStreamId(session, frame.goaway.last_stream_id)) ||
        session.remote_last_stream_id < frame.goaway.last_stream_id) {
        return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "GOAWAY: invalid last_stream_id");
    }
    
    session.goaway_flags |= GoAwayFlags.RECV;
    
    session.remote_last_stream_id = frame.goaway.last_stream_id;
	bool ok = callOnFrame(frame);
	if (!ok)
		return ErrorCode.CALLBACK_FAILURE;
    
	return closeStreamOnGoAway(frame.goaway.last_stream_id, 0);
}

int session_process_goaway_frame(Session session) 
{
    InboundFrame *iframe = &session.iframe;
    Frame frame = &iframe.frame;
    
    http2_frame_unpack_goaway_payload(&frame.goaway, iframe.sbuf[], iframe.lbuf[]);
    
    http2_buf_wrap_init(&iframe.lbuf, null, 0);
    
    return http2_session_on_goaway_received(session, frame);
}

int session_on_connection_window_update_received(Session session, Frame frame) 
{
    /* Handle connection-level flow control */
    if (frame.window_update.window_size_increment == 0) {
        return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, null);
    }
    
    if (MAX_WINDOW_SIZE - frame.window_update.window_size_increment < session.remote_window_size) {
        return handleInvalidConnection(frame, FrameError.FLOW_CONTROL_ERROR, null);
    }
    session.remote_window_size += frame.window_update.window_size_increment;
    
	bool ok = callOnFrame(frame);
	if (!ok)
		return ErrorCode.CALLBACK_FAILURE;
	return 0;
}

int session_on_stream_window_update_received(Session session, Frame frame) 
{
    ErrorCode rv;
    Stream stream;
    stream = getStream(frame.hd.stream_id);
    if (!stream) {
        if (idleStreamDetect(frame.hd.stream_id))
		{
            return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "WINDOW_UPDATE to idle stream");
        }
        return 0;
    }
	if (isReservedRemote(stream)) {
        return handleInvalidConnection(frame, FrameError.PROTOCOL_ERROR, "WINDOW_UPADATE to reserved stream");
    }
    if (frame.window_update.window_size_increment == 0) {
		return handleInvalidStream(frame, FrameError.PROTOCOL_ERROR);
    }
    if (MAX_WINDOW_SIZE - frame.window_update.window_size_increment < stream.remoteWindowSize)
	{
        return handleInvalidStream(frame, FrameError.FLOW_CONTROL_ERROR);
    }
    stream.remoteWindowSize += frame.window_update.window_size_increment;
    
    if (stream.remoteWindowSize > 0 && stream.isDeferredByFlowControl())        
		stream.resumeDeferredItem(StreamFlags.DEFERRED_FLOW_CONTROL, session);
	bool ok = callOnFrame(frame);
	if (!ok)
		return ErrorCode.CALLBACK_FAILURE;
	return 0;
}

int http2_session_on_window_update_received(Session session, Frame frame) 
{
    if (frame.hd.stream_id == 0) {
        return session_on_connection_window_update_received(session, frame);
    } else {
        return session_on_stream_window_update_received(session, frame);
    }
}

int session_process_window_update_frame(Session session) 
{
    InboundFrame *iframe = &session.iframe;
    Frame frame = &iframe.frame;
    
    http2_frame_unpack_window_update_payload(&frame.window_update, iframe.sbuf[]);
    
    return http2_session_on_window_update_received(session, frame);
}

/* int get_error_code_from_lib_error_code(int lib_error_code) */
/* { */
/*   switch(lib_error_code) { */
/*   case ErrorCode.HEADER_COMP: */
/*     return FrameError.COMPRESSION_ERROR; */
/*   case ErrorCode.FRAME_SIZE_ERROR: */
/*     return FrameError.FRAME_SIZE_ERROR; */
/*   default: */
/*     return FrameError.PROTOCOL_ERROR; */
/*   } */
/* } */

int http2_session_on_data_received(Session session, Frame frame) 
{
    int rv = 0;
    int call_cb = 1;
    Stream stream;
    
    /* We don't call on_frame_recv_callback if stream has been closed
     already or being closed. */
    stream = getStream(frame.hd.stream_id);
    if (!stream || stream.state == StreamState.CLOSING) {
        /* This should be treated as stream error, but it results in lots
       of RST_STREAM. So just ignore frame against nonexistent stream
       for now. */
        return 0;
    }
    
    if (isHTTPMessagingEnabled() && (frame.hd.flags & FrameFlags.END_STREAM)) {
        if (http2_http_on_remote_end_stream(stream) != 0) {
            call_cb = 0;
			addRstStream(stream.id, FrameError.PROTOCOL_ERROR);
        }
    }
    
    if (call_cb) {
        bool ok = callOnFrame(frame);
        if (!ok) {
            return ErrorCode.CALLBACK_FAILURE;
        }
    }
    
    if (frame.hd.flags & FrameFlags.END_STREAM) {
        stream.shutdown(ShutdownFlag.RD);
		rv = closeStreamIfShutRdWr(stream);
        if (isFatal(rv)) {
            return rv;
        }
    }
    return 0;
}

/* For errors, this function only returns FATAL error. */
int session_process_data_frame(Session session) 
{
    ErrorCode rv;
    Frame public_data_frame = &session.iframe.frame;
    rv = http2_session_on_data_received(session, public_data_frame);
    if (isFatal(rv)) {
        return rv;
    }
    return 0;
}

/*
 * Now we have SETTINGS synchronization, flow control error can be
 * detected strictly. If DATA frame is received with length > 0 and
 * current received window size + delta length is strictly larger than
 * local window size, it is subject to FLOW_CONTROL_ERROR, so return
 * -1. Note that local_window_size is calculated after SETTINGS ACK is
 * received from peer, so peer must honor this limit. If the resulting
 * recv_window_size is strictly larger than MAX_WINDOW_SIZE,
 * return -1 too.
 */
int adjust_recv_window_size(int *recv_window_size_ptr, size_t delta, int local_window_size) 
{
    if (*recv_window_size_ptr > local_window_size - cast(int)delta ||
        *recv_window_size_ptr > MAX_WINDOW_SIZE - cast(int)delta) {
        return -1;
    }
    *recv_window_size_ptr += delta;
    return 0;
}

/*
 * Accumulates received bytes |delta_size| for stream-level flow
 * control and decides whether to send WINDOW_UPDATE to that stream.
 * If OptionFlags.NO_AUTO_WINDOW_UPDATE is set, WINDOW_UPDATE will not
 * be sent.
 */
void session_update_recv_stream_window_size(Session session, Stream stream, size_t delta_size, int send_window_update) 
{
    ErrorCode rv;
    rv = adjust_recv_window_size(&stream.recvWindowSize, delta_size, stream.localWindowSize);
    if (rv != 0) {
		addRstStream(stream.id, FrameError.FLOW_CONTROL_ERROR);
		return;
    }
    /* We don't have to send WINDOW_UPDATE if the data received is the
     last chunk in the incoming stream. */
    if (send_window_update && !(session.opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE)) {
        /* We have to use local_settings here because it is the constraint
       the remote endpoint should honor. */
        if (http2_should_send_window_update(stream.localWindowSize, stream.recvWindowSize)) {
            rv = http2_session_add_window_update(session, FrameFlags.NONE, stream.id, stream.recvWindowSize);
            if (rv == 0) {
                stream.recvWindowSize = 0;
            } else {
                return rv;
            }
        }
    }
    return 0;
}

/*
 * Accumulates received bytes |delta_size| for connection-level flow
 * control and decides whether to send WINDOW_UPDATE to the
 * connection.  If OptionFlags.NO_AUTO_WINDOW_UPDATE is set,
 * WINDOW_UPDATE will not be sent.
 */
void session_update_recv_connection_window_size(Session session, size_t delta_size) 
{
    ErrorCode rv;
    rv = adjust_recv_window_size(&session.recv_window_size, delta_size, session.local_window_size);
    if (rv != 0) {
        return terminateSession(FrameError.FLOW_CONTROL_ERROR);
    }
    if (!(session.opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE))
	{
        
        if (http2_should_send_window_update(session.local_window_size, session.recv_window_size)) 
		{
            /* Use stream ID 0 to update connection-level flow control window */
            rv = http2_session_add_window_update(session, FrameFlags.NONE, 0, session.recv_window_size);
            if (rv != 0) {
                return rv;
            }
            
            session.recv_window_size = 0;
        }
    }
    return 0;
}

int session_update_consumed_size(Session session, ref int consumed_size, ref int recv_window_size, int stream_id, size_t delta_size, int local_window_size) 
{
    int recv_size;
    ErrorCode rv;
    
    if (cast(size_t)consumed_size > MAX_WINDOW_SIZE - delta_size)
	{
        return terminateSession(FrameError.FLOW_CONTROL_ERROR);
    }
    
    consumed_size += delta_size;
    
    /* recv_window_size may be smaller than consumed_size, because it
     may be decreased by negative value with
     http2_submit_window_update(). */
    recv_size = min(consumed_size, recv_window_size);
    
    if (http2_should_send_window_update(local_window_size, recv_size)) 
	{
        rv = http2_session_add_window_update(session, FrameFlags.NONE, stream_id, recv_size);
        
        if (rv != 0) {
            return rv;
        }
        
        recv_window_size -= recv_size;
        consumed_size -= recv_size;
    }
    
    return 0;
}

int session_update_stream_consumed_size(Session session, Stream stream, size_t delta_size) 
{
    return session_update_consumed_size(session, &stream.consumedSize, &stream.recvWindowSize, stream.id, delta_size, stream.localWindowSize);
}

int session_update_connection_consumed_size(Session session, size_t delta_size) 
{
    return session_update_consumed_size(session, &session.consumed_size, &session.recv_window_size, 0, delta_size, session.local_window_size);
}

/*
 * Checks that we can receive the DATA frame for stream, which is
 * indicated by |session.iframe.frame.hd.stream_id|. If it is a
 * connection error situation, GOAWAY frame will be issued by this
 * function.
 *
 * If the DATA frame is allowed, returns 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.IGN_PAYLOAD
 *   The reception of DATA frame is connection error; or should be
 *   ignored.
 */
ErrorCode session_on_data_received_fail_fast(Session session) 
{
    ErrorCode rv;
    Stream stream;
    InboundFrame *iframe;
    int stream_id;
    const char *failure_reason;
    uint error_code = FrameError.PROTOCOL_ERROR;
    
    iframe = &session.iframe;
    stream_id = iframe.frame.hd.stream_id;
    
    if (stream_id == 0) {
        /* The spec says that if a DATA frame is received whose stream ID
	       is 0, the recipient MUST respond with a connection error of
	       type PROTOCOL_ERROR. */
        failure_reason = "DATA: stream_id == 0";
        goto fail;
    }
    stream = getStream(stream_id);
    if (!stream) {
        if (idleStreamDetect(stream_id)) 
		{
            failure_reason = "DATA: stream in idle";
            error_code = StreamState.CLOSED;
            goto fail;
        }
        return ErrorCode.IGN_PAYLOAD;
    }
    if (stream.shutFlags & ShutdownFlag.RD) {
        failure_reason = "DATA: stream in half-closed(remote)";
        error_code = StreamState.CLOSED;
        goto fail;
    }
    
    if (isMyStreamId(stream_id)) {
        if (stream.state == StreamState.CLOSING) {
            return ErrorCode.IGN_PAYLOAD;
        }
        if (stream.state != StreamState.OPENED) {
            failure_reason = "DATA: stream not opened";
            goto fail;
        }
        return 0;
    }
    if (stream.state == StreamState.RESERVED) {
        failure_reason = "DATA: stream in reserved";
        goto fail;
    }
    if (stream.state == StreamState.CLOSING) {
        return ErrorCode.IGN_PAYLOAD;
    }
    return 0;
fail:
    rv = terminateSessionWithReason(error_code, failure_reason);
    if (isFatal(rv)) {
        return rv;
    }
    return ErrorCode.IGN_PAYLOAD;
}



/*
 * Returns the number of active streams, which includes streams in
 * reserved state.
 */
size_t session_get_num_active_streams(Session session) {
    return http2_map_size(&session.streams) - session.num_closed_streams;
}

int http2_session_want_read(Session session) {
    size_t num_active_streams;
    
    /* If this flag is set, we don't want to read. The application
     should drop the connection. */
    if (session.goaway_flags & GoAwayFlags.TERM_SENT) {
        return 0;
    }
    
    num_active_streams = session_get_num_active_streams(session);
    
    /* Unless termination GOAWAY is sent or received, we always want to
     read incoming frames. */
    
    if (num_active_streams > 0) {
        return 1;
    }
    
    /* If there is no active streams and GOAWAY has been sent or
     received, we are done with this session. */
    return (session.goaway_flags &
        (GoAwayFlags.SENT | GoAwayFlags.RECV)) == 0;
}

int http2_session_want_write(Session session) {
    size_t num_active_streams;
    
    /* If these flag is set, we don't want to write any data. The
     application should drop the connection. */
    if (session.goaway_flags & GoAwayFlags.TERM_SENT) {
        return 0;
    }
    
    num_active_streams = session_get_num_active_streams(session);
    
    /*
   * Unless termination GOAWAY is sent or received, we want to write
   * frames if there is pending ones. If pending frame is request/push
   * response HEADERS and concurrent stream limit is reached, we don't
   * want to write them.
   */
    
    if (session.aob.item == null && http2_pq_empty(&session.ob_pq) &&
        (http2_pq_empty(&session.ob_da_pq) ||
            session.remote_window_size == 0) &&
        (http2_pq_empty(&session.ob_ss_pq) ||
            session_is_outgoing_concurrent_streams_max(session))) {
        return 0;
    }
    
    if (num_active_streams > 0) {
        return 1;
    }
    
    /* If there is no active streams and GOAWAY has been sent or
     received, we are done with this session. */
    return (session.goaway_flags &
        (GoAwayFlags.SENT | GoAwayFlags.RECV)) == 0;
}

void http2_session_add_ping(Session session, FrameFlags flags, const ubyte *opaque_data) {
    ErrorCode rv;
    OutboundItem item;
    Frame frame;
    http2_mem *mem;
    
    mem = &session.mem;
	item = Mem.alloc!OutboundItem(session);
    
    frame = &item.frame;
    
    http2_frame_ping_init(&frame.ping, flags, opaque_data);
    
    addItem(item);
}

ErrorCode http2_session_add_goaway(Session session, int last_stream_id, FrameError error_code, in ubyte[] opaque_data, ubyte aux_flags) {
    ErrorCode rv;
    OutboundItem item;
    Frame frame;
    ubyte *opaque_data_copy = null;
    http2_goaway_aux_data *aux_data;
    http2_mem *mem;
    
    mem = &session.mem;
    
    if (isMyStreamId(last_stream_id)) {
        return ErrorCode.INVALID_ARGUMENT;
    }
    
    if (opaque_data_len) {
        if (opaque_data_len + 8 > MAX_PAYLOADLEN) {
            return ErrorCode.INVALID_ARGUMENT;
        }
        opaque_data_copy = http2_mem_malloc(mem, opaque_data_len);
        memcpy(opaque_data_copy, opaque_data, opaque_data_len);
    }
    
	item = Mem.alloc!OutboundItem(session);
    
    frame = &item.frame;
    
    /* last_stream_id must not be increased from the value previously
     sent */
    last_stream_id = min(last_stream_id, session.local_last_stream_id);
    
    http2_frame_goaway_init(&frame.goaway, last_stream_id, error_code, opaque_data_copy, opaque_data_len);
    
    aux_data = &item.aux_data.goaway;
    aux_data.flags = aux_flags;
    
    addItem(item);
	return 0;
}

void http2_session_add_window_update(Session session, FrameFlags flags, int stream_id, int window_size_increment) {
    ErrorCode rv;
    OutboundItem item;
    Frame frame;
    http2_mem *mem;
    
    mem = &session.mem;
	item = Mem.alloc!OutboundItem(session);    
    frame = &item.frame;
    
    http2_frame_window_update_init(&frame.window_update, flags, stream_id, window_size_increment);
    
    addItem(item);
}

ErrorCode http2_session_add_settings(Session session, FrameFlags flags, in Setting[] iva) 
{
    OutboundItem item;
    Frame* frame;
    Setting[] iva_copy;
    size_t i;
    ErrorCode rv;
    
    if (flags & FrameFlags.ACK) {
        if (iva.length != 0) {
            return ErrorCode.INVALID_ARGUMENT;
        }
	}
	else if (inflight_iva.length != 0) 
        return ErrorCode.TOO_MANY_INFLIGHT_SETTINGS;
    
    if (!iva.check())
        return ErrorCode.INVALID_ARGUMENT;
    
	item = Mem.alloc!OutboundItem(this);
	scope(failure) Mem.free(item);

    if (iva.length > 0)
        iva_copy = iva.copy();
    else
        iva_copy = null;

	scope(failure) if(iva_copy) Mem.free(iva_copy);

    if ((flags & FrameFlags.ACK) == 0) {
        if (iva.length > 0)
            inflight_iva = iva.copy();
        else
            inflight_iva = null;     
        
    }
    
    frame = &item.frame;
    
    frame.settings = Settings(flags, iva_copy);

    addItem(item);

    /* Extract Setting.MAX_CONCURRENT_STREAMS here and use it to refuse the incoming streams with RST_STREAM. */
	foreach_reverse(ref iv; iva)
	{
		if (iv.id == Setting.MAX_CONCURRENT_STREAMS) {
			pending_local_max_concurrent_stream = iv.value;
			break;
		}

	}
    return 0;
}

int http2_session_pack_data(Session session, http2_bufs *bufs, size_t datamax, Frame frame, DataAuxData *aux_data) {
    ErrorCode rv;
    DataFlags data_flags;
    int payloadlen;
    int padded_payloadlen;
    http2_buf *buf;
    size_t max_payloadlen;
    
    assert(bufs.head == bufs.cur);
    
    buf = &bufs.cur.buf;
    
    if (session.policy.read_length_callback) {
        Stream stream;
        
        stream = getStream(frame.hd.stream_id);
        if (!stream) {
            return ErrorCode.INVALID_ARGUMENT;
        }
        
        payloadlen = session.policy.read_length_callback(session, frame.hd.type, stream.id, session.remote_window_size, stream.remoteWindowSize, session.remote_settings.max_frame_size);
        
        DEBUGF(fprintf(stderr, "send: read_length_callback=%zd\n", payloadlen));
        
		payloadlen = enforceFlowControlLimits(stream, payloadlen);
        
        DEBUGF(fprintf(stderr,
                "send: read_length_callback after flow control=%zd\n",
                payloadlen));
        
        if (payloadlen <= 0) {
            return ErrorCode.CALLBACK_FAILURE;
        }
        
        if (payloadlen > http2_buf_avail(buf)) {
            /* Resize the current buffer(s).  The reason why we do +1 for buffer size is for possible padding field. */
            rv = http2_bufs_realloc(&session.aob.framebufs, FRAME_HDLEN + 1 + payloadlen);
            
            if (rv != 0) {
                DEBUGF(fprintf(stderr, "send: realloc buffer failed rv=%d", rv));
                /* If reallocation failed, old buffers are still in tact.  So use safe limit. */
                payloadlen = datamax;
                
                DEBUGF(
                    fprintf(stderr, "send: use safe limit payloadlen=%zd", payloadlen));
            } else {
                assert(&session.aob.framebufs == bufs);
                
                buf = &bufs.cur.buf;
            }
        }
        datamax = cast(size_t)payloadlen;
    }
    
    /* Current max DATA length is less then buffer chunk size */
    assert(http2_buf_avail(buf) >= cast(int)datamax);
    
    data_flags = DataFlags.NONE;
    payloadlen = aux_data.data_prd.read_callback(session, frame.hd.stream_id, buf.pos, datamax, &data_flags, &aux_data.data_prd.source);
    
    if (payloadlen == ErrorCode.DEFERRED ||
        payloadlen == ErrorCode.TEMPORAL_CALLBACK_FAILURE)
	{
        DEBUGF(fprintf(stderr, "send: DATA postponed due to %s\n", toString(cast(ErrorCode)payloadlen)));
        
        return cast(int)payloadlen;
    }
    
    if (payloadlen < 0 || datamax < cast(size_t)payloadlen) 
	{
        /* This is the error code when callback is failed. */
        return ErrorCode.CALLBACK_FAILURE;
    }
    
    buf.last = buf.pos + payloadlen;
    buf.pos -= FRAME_HDLEN;
    
    /* Clear flags, because this may contain previous flags of previous DATA */
    frame.hd.flags = FrameFlags.NONE;
    
    if (data_flags & DataFlags.EOF) {
        aux_data.eof = 1;
        if (aux_data.flags & FrameFlags.END_STREAM) {
            frame.hd.flags |= FrameFlags.END_STREAM;
        }
    }
    
    frame.hd.length = payloadlen;
    frame.data.padlen = 0;
    
    max_payloadlen = min(datamax, frame.hd.length + MAX_PADLEN);
    
    padded_payloadlen = callSelectPadding(frame, max_payloadlen);
    
    if (isFatal(cast(int)padded_payloadlen)) {
        return cast(int)padded_payloadlen;
    }
    
    frame.data.padlen = padded_payloadlen - payloadlen;
    
    frame.hd.pack(buf.pos);
    
    rv = http2_frame_add_pad(bufs, &frame.hd, frame.data.padlen);
    if (rv != 0) {
        return rv;
    }
    
    return 0;
}

void *http2_session_get_stream_user_data(Session session, int stream_id) {
    Stream stream;
    stream = getStream(stream_id);
    if (stream) {
        return stream.userData;
    } else {
        return null;
    }
}

int http2_session_set_stream_user_data(Session session, int stream_id, void *stream_user_data) {
    Stream stream;
    stream = getStream(stream_id);
    if (!stream)
        return ErrorCode.INVALID_ARGUMENT;
    stream.userData = stream_user_data;
    return 0;
}

int http2_session_resume_data(Session session, int stream_id) {
    ErrorCode rv;
    Stream stream;
    stream = getStream(stream_id);

    if (stream == null || !stream.checkDeferredItem()) 
        return ErrorCode.INVALID_ARGUMENT;
        
    rv = stream.resumeDeferredItem(StreamFlags.DEFERRED_USER, session);
    
    if (isFatal(rv)) {
        return rv;
    }
    
    return rv;
}

size_t http2_session_get_outbound_queue_size(Session session) {
    return http2_pq_size(&session.ob_pq) +
        http2_pq_size(&session.ob_ss_pq) +
            http2_pq_size(&session.ob_da_pq);
}

int http2_session_get_stream_effective_recv_data_length(Session session, int stream_id) {
    Stream stream;
    stream = getStream(stream_id);
    if (stream == null) {
        return -1;
    }
    return stream.recvWindowSize < 0 ? 0 : stream.recvWindowSize;
}

int http2_session_get_stream_effective_local_window_size(Session session, int stream_id) {
    Stream stream;
    stream = getStream(stream_id);
    if (stream == null) {
        return -1;
    }
    return stream.localWindowSize;
}

int http2_session_get_effective_recv_data_length(Session session) {
    return session.recv_window_size < 0 ? 0 : session.recv_window_size;
}

int http2_session_get_effective_local_window_size(Session session) {
    return session.local_window_size;
}

int http2_session_get_stream_remote_window_size(Session session,
    int stream_id) {
    Stream stream;
    
    stream = getStream(stream_id);
    if (stream == null) {
        return -1;
    }
    
    /* stream.remoteWindowSize can be negative when SETTINGS_INITIAL_WINDOW_SIZE is changed. */
    return max(0, stream.remoteWindowSize);
}

int http2_session_get_remote_window_size(Session session) {
    return session.remote_window_size;
}

uint http2_session_get_remote_settings(Session session, SettingsID id) {
    with(Setting) switch (id) {
        case HEADER_TABLE_SIZE:
            return session.remote_settings.header_table_size;
        case ENABLE_PUSH:
            return session.remote_settings.enable_push;
        case MAX_CONCURRENT_STREAMS:
            return session.remote_settings.max_concurrent_streams;
        case INITIAL_WINDOW_SIZE:
            return session.remote_settings.initial_window_size;
        case MAX_FRAME_SIZE:
            return session.remote_settings.max_frame_size;
        case MAX_HEADER_LIST_SIZE:
            return session.remote_settings.max_header_list_size;
    }
    
    assert(0);
}

int http2_session_upgrade(Session session, in ubyte[] settings_payload, void *stream_user_data) 
{
    Stream stream;
    Frame frame;
	Setting[] iva;
    ErrorCode rv;
    PrioritySpec pri_spec;
    
    if ((!is_server && next_stream_id != 1) ||
        (is_server && last_recv_stream_id >= 1)) {
        return ErrorCode.PROTO;
    }

    if (settings_payload.length % FRAME_SETTINGS_ENTRY_LENGTH) {
        return ErrorCode.INVALID_ARGUMENT;
    }

    rv = Settings.unpack(&iv, &niv, settings_payload, settings_payloadlen, mem);
    if (rv != 0) {
        return rv;
    }
    
    if (is_server) {
        frame.hd = FrameHeader(settings_payloadlen, FrameType.SETTINGS, FrameFlags.NONE, 0);
        frame.settings.iv = iv;
        frame.settings.niv = niv;
        rv = onSettings(&frame, 1 /* No ACK */);
    } else {
        rv = http2_submit_settings(session, FrameFlags.NONE, iv, niv);
    }
    http2_mem_free(mem, iv);
    if (rv != 0) {
        return rv;
    }
    
    stream = openStream(1, StreamFlags.NONE, pri_spec, StreamState.OPENING, is_server ? null : stream_user_data);

    if (is_server) {
        stream.shutdown(ShutdownFlag.RD);
        session.last_recv_stream_id = 1;
        session.last_proc_stream_id = 1;
    } else {
        stream.shutdown(ShutdownFlag.WR);
        session.next_stream_id += 2;
    }
    return 0;
}

int http2_session_get_stream_local_close(Session session, int stream_id)
{
    Stream stream;
    
    stream = getStream(stream_id);
    
    if (!stream) {
        return -1;
    }
    
    return (stream.shutFlags & ShutdownFlag.WR) != 0;
}

int http2_session_get_stream_remote_close(Session session, int stream_id) 
{
    Stream stream;
    
    stream = getStream(stream_id);
    
    if (!stream) {
        return -1;
    }
    
    return (stream.shutFlags & ShutdownFlag.RD) != 0;
}

int http2_session_consume(Session session, int stream_id,
    size_t size) {
    ErrorCode rv;
    Stream stream;
    
    if (stream_id == 0) {
        return ErrorCode.INVALID_ARGUMENT;
    }
    
    if (!(session.opt_flags & OptionsMask.NO_AUTO_WINDOW_UPDATE)) {
        return ErrorCode.INVALID_STATE;
    }
    
    rv = session_update_connection_consumed_size(session, size);
    
    if (isFatal(rv)) {
        return rv;
    }
    
    stream = getStream(stream_id);
    
    if (stream) {
        rv = session_update_stream_consumed_size(session, stream, size);
        
        if (isFatal(rv)) {
            return rv;
        }
    }
    
    return 0;
}

int http2_session_set_next_stream_id(Session session, int next_stream_id)
{
    if (next_stream_id < 0 ||
        session.next_stream_id > cast(uint)next_stream_id) {
        return ErrorCode.INVALID_ARGUMENT;
    }
    
    session.next_stream_id = next_stream_id;
    return 0;
}

uint http2_session_get_next_stream_id(Session session) 
{
    return session.next_stream_id;
}

int http2_session_get_last_proc_stream_id(Session session) 
{
    return session.last_proc_stream_id;
}
