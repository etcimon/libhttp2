/*
 * libhttp2 - HTTP/2 D Library
 *
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
 * Copyright (c) 2015 Etienne Cimon
 * 
 * License: MIT
 */
module libhttp2.session;

import libhttp2.types;
import libhttp2.frame;

import memutils.circularbuffer;
import memutils.vector;

alias HTTP2Session = RefCounted!Session;

//http2_optmask
enum Options {
    NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE = 1 << 0,
    NGHTTP2_OPTMASK_RECV_CLIENT_PREFACE = 1 << 1,
    NGHTTP2_OPTMASK_NO_HTTP_MESSAGING = 1 << 2,
}

//http2_outbound_state
enum OutboundState {
    NGHTTP2_OB_POP_ITEM,
    NGHTTP2_OB_SEND_DATA
}

//http2_active_outbound_item
struct ActiveOutboundItem {
    OutboundItem *item;
    Vector!(CircularBuffer!ubyte) framebufs;
    nghttp2_outbound_state state;
}

/// Buffer length for inbound raw byte stream used in nghttp2_session_recv().
const INBOUND_BUFFER_LENGTH = 16384;

//http2_inbound_state
/// Internal state when receiving incoming frame
enum InboundState : ubyte {
    /* Receiving frame header */
    READ_CLIENT_PREFACE,
    READ_FIRST_SETTINGS,
    READ_HEAD,
    READ_NBYTE,
    READ_HEADER_BLOCK,
    IGN_HEADER_BLOCK,
    IGN_PAYLOAD,
    FRAME_SIZE_ERROR,
    READ_SETTINGS,
    READ_GOAWAY_DEBUG,
    EXPECT_CONTINUATION,
    IGN_CONTINUATION,
    READ_PAD_DATA,
    READ_DATA,
    IGN_DATA,
    IGN_ALL,
}

const INBOUND_NUM_IV = 7;

//http2_inbound_frame
struct InboundFrame {
    Frame frame;
    /* Storage for extension frame payload.  frame->ext.payload points
     to this structure to avoid frequent memory allocation. */
    nghttp2_ext_frame_payload ext_frame_payload;
    /* The received SETTINGS entry. The protocol says that we only cares
     about the defined settings ID. If unknown ID is received, it is
     ignored.  We use last entry to hold minimum header table size if
     same settings are multiple times. */
    Setting[INBOUND_NUM_IV] iv;

    /// buffer pointers to small buffer, raw_sbuf 
    CircularBuffer sbuf;

    /// buffer pointers to large buffer, raw_lbuf
    CircularBuffer lbuf;

    /// Large buffer, malloced on demand
    ubyte *raw_lbuf;

    /* The number of entry filled in |iv| */
    size_t niv;
    /* How many bytes we still need to receive for current frame */
    size_t payloadleft;
    /* padding length for the current frame */
    size_t padlen;

    InboundState state;

    /* Small buffer.  Currently the largest contiguous chunk to buffer
     is frame header.  We buffer part of payload, but they are smaller
     than frame header. */
    ubyte[FRAME_HDLEN] raw_sbuf;
}



//http2_settings_storage
struct SettingsStorage {
    uint header_table_size;
    uint enable_push;
    uint max_concurrent_streams;
    uint initial_window_size;
    uint max_frame_size;
    uint max_header_list_size;
}

//http2_goaway_flag
enum GoAwayFlags {
    NGHTTP2_GOAWAY_NONE = 0,
    /* Flag means that connection should be terminated after sending GOAWAY. */
    NGHTTP2_GOAWAY_TERM_ON_SEND = 0x1,
    /* Flag means GOAWAY to terminate session has been sent */
    NGHTTP2_GOAWAY_TERM_SENT = 0x2,
    /* Flag means GOAWAY was sent */
    NGHTTP2_GOAWAY_SENT = 0x4,
    /* Flag means GOAWAY was received */
    NGHTTP2_GOAWAY_RECV = 0x8,
}

//http2_update_window_size_arg
/// Struct used when updating initial window size of each active stream.
struct UpdateWindowSizeArgs{
    HTTP2Session session;
    int new_window_size, old_window_size;
}

//http2_close_stream_on_goaway_arg
struct CloseStreamOnGoAwayArgs {
    HTTP2Session session;

    /// linked list of streams to close
    Stream head;
    int last_stream_id;

    /* nonzero if GOAWAY is sent to peer, which means we are going to
     close incoming streams.  zero if GOAWAY is received from peer and
     we are going to close outgoing streams. */
    int incoming;
}

class Session {
    nghttp2_map /* <nghttp2_stream*> */ streams;
    nghttp2_stream_roots roots;

    /// Priority Queue for outbound frames other than stream-creating HEADERS and DATA
    nghttp2_pq /* <nghttp2_outbound_item*> */ ob_pq;

    /// Priority Queue for outbound stream-creating HEADERS frame
    nghttp2_pq /* <nghttp2_outbound_item*> */ ob_ss_pq;

    /// Priority Queue for DATA frame 
    nghttp2_pq /* <nghttp2_outbound_item*> */ ob_da_pq;

    ActiveOutboundItem aob;
    nghttp2_inbound_frame iframe;
    nghttp2_hd_deflater hd_deflater;
    nghttp2_hd_inflater hd_inflater;
    nghttp2_session_callbacks callbacks;

    /// Sequence number of outbound frame to maintain the order of enqueue if priority is equal.
    long next_seq;

    /** Reset count of nghttp2_outbound_item's weight.  We decrements
        weight each time DATA is sent to simulate resource sharing.  We
        use priority queue and larger weight has the precedence.  If
        weight is reached to lowest weight, it resets to its initial
        weight.  If this happens, other items which have the lower weight
        currently but same initial weight cannot send DATA until item
        having large weight is decreased.  To avoid this, we use this
        cycle variable.  Initally, this is set to 1.  If weight gets
        lowest weight, and if item's cycle == last_cycle, we increments
        last_cycle and assigns it to item's cycle.  Otherwise, just
        assign last_cycle.  In priority queue comparator, we first
        compare items' cycle value.  Lower cycle value has the
        precedence. */
    ulong last_cycle;
    void *user_data;

    /// Points to the latest closed stream.  NULL if there is no closed stream.  
    /// Notes: Only used when session is initialized as server.
    Stream closed_stream_head;

    /// Points to the oldest closed stream.  NULL if there is no closed stream.  
    /// Notes: Only used when session is initialized as server.
    Stream closed_stream_tail;

    /// Points to the latest idle stream.  NULL if there is no idle stream.  
    /// Notes: Only used when session is initialized as server .
    Stream idle_stream_head;

    /// Points to the oldest idle stream.  NULL if there is no idle stream. 
    /// Notes: Only used when session is initialized as server.
    Stream idle_stream_tail;

    /// In-flight SETTINGS values. NULL does not necessarily mean there is no in-flight SETTINGS. 
    nghttp2_settings_entry *inflight_iv;

    /// The number of entries in |inflight_iv|. -1 if there is no in-flight SETTINGS.
    size_t inflight_niv;

    /// The number of outgoing streams. This will be capped by remote_settings.max_concurrent_streams.
    size_t num_outgoing_streams;

    /// The number of incoming streams. This will be capped by local_settings.max_concurrent_streams.
    size_t num_incoming_streams;

    /// The number of closed streams still kept in |streams| hash.  The closed streams can be accessed
    /// through single linked list |closed_stream_head|. 
    /// Notes: The current implementation only keeps incoming streams if session is initialized as server.
    size_t num_closed_streams;

    /// The number of idle streams kept in |streams| hash. The idle streams can be accessed through doubly linked list
    /// |idle_stream_head|.  
    /// Notes: The current implementation only keeps idle streams if session is initialized as server.
    size_t num_idle_streams;

    /// The number of bytes allocated for nvbuf
    size_t nvbuflen;

    /// Next Stream ID. Made unsigned int to detect >= (1 << 31). 
    uint next_stream_id;

    /// The largest stream ID received so far
    int last_recv_stream_id;

    /// The largest stream ID which has been processed in some way. 
    /// Notes: This value will be used as last-stream-id when sending GOAWAY frame.
    int last_proc_stream_id;

    /// Counter of unique ID of PING. Wraps when it exceeds NGHTTP2_MAX_UNIQUE_ID */
    uint next_unique_id;

    /// This is the last-stream-ID we have sent in GOAWAY
    int local_last_stream_id;

    /// This is the value in GOAWAY frame received from remote endpoint.
    int remote_last_stream_id;

    /// Current sender window size. This value is computed against the current initial window size of remote endpoint.
    int remote_window_size;

    /// Keep track of the number of bytes received without WINDOW_UPDATE. This could be negative after
    /// submitting negative value to WINDOW_UPDATE.
    int recv_window_size;

    /// The number of bytes consumed by the application and now is subject to WINDOW_UPDATE. 
    /// Notes: This is only used when auto WINDOW_UPDATE is turned off. 
    int consumed_size;

    /// The amount of recv_window_size cut using submitting negative value to WINDOW_UPDATE
    int recv_reduction;

    /// window size for local flow control. It is initially set to NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE and could be
    /// increased/decreased by submitting WINDOW_UPDATE. See nghttp2_submit_window_update().
    int local_window_size;

    /// Settings value received from the remote endpoint. We just use ID as index. The index = 0 is unused. 
    SettingsStorage remote_settings;

    /// Settings value of the local endpoint.
    SettingsStorage local_settings;

    /// Option flags. This is bitwise-OR of 0 or more of nghttp2_optmask.
    uint opt_flags;

    /// Unacked local SETTINGS_MAX_CONCURRENT_STREAMS value. We use this to refuse the incoming stream if it exceeds this value. 
    uint pending_local_max_concurrent_stream;

    /// Nonzero if the session is server side. 
    ubyte server;

    /// Flags indicating GOAWAY is sent and/or recieved. 
    GoAwayFlags goaway_flags;
};

/**
 * @function
 *
 * Initializes |*option_ptr| with default values.
 *
 * When the application finished using this object, it can use
 * `http2_option_del()` to free its memory.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_option_new(http2_option **option_ptr);

/**
 * @function
 *
 * Frees any resources allocated for |option|.  If |option| is
 * ``NULL``, this function does nothing.
 */
void http2_option_del(http2_option *option);

/**
 * @function
 *
 * This option prevents the library from sending WINDOW_UPDATE for a
 * connection automatically.  If this option is set to nonzero, the
 * library won't send WINDOW_UPDATE for DATA until application calls
 * `http2_session_consume()` to indicate the consumed amount of
 * data.  Don't use `http2_submit_window_update()` for this purpose.
 * By default, this option is set to zero.
 */
void http2_option_set_no_auto_window_update(http2_option *option, int val);

/**
 * @function
 *
 * This option sets the SETTINGS_MAX_CONCURRENT_STREAMS value of
 * remote endpoint as if it is received in SETTINGS frame.  Without
 * specifying this option, before the local endpoint receives
 * SETTINGS_MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
 * endpoint, SETTINGS_MAX_CONCURRENT_STREAMS is unlimited.  This may
 * cause problem if local endpoint submits lots of requests initially
 * and sending them at once to the remote peer may lead to the
 * rejection of some requests.  Specifying this option to the sensible
 * value, say 100, may avoid this kind of issue. This value will be
 * overwritten if the local endpoint receives
 * SETTINGS_MAX_CONCURRENT_STREAMS from the remote endpoint.
 */
void http2_option_set_peer_max_concurrent_streams(http2_option *option,
                                                    uint val);

/**
 * @function
 *
 * By default, nghttp2 library only handles HTTP/2 frames and does not
 * recognize first 24 bytes of client connection preface.  This design
 * choice is done due to the fact that server may want to detect the
 * application protocol based on first few bytes on clear text
 * communication.  But for simple servers which only speak HTTP/2, it
 * is easier for developers if nghttp2 library takes care of client
 * connection preface.
 *
 * If this option is used with nonzero |val|, nghttp2 library checks
 * first 24 bytes client connection preface.  If it is not a valid
 * one, `http2_session_recv()` and `http2_session_mem_recv()` will
 * return error $(D ErrorCode.BAD_PREFACE), which is fatal error.
 */
void http2_option_set_recv_client_preface(http2_option *option, int val);

/**
 * @function
 *
 * By default, nghttp2 library enforces subset of HTTP Messaging rules
 * described in `HTTP/2 specification, section 8
 * <https://tools.ietf.org/html/draft-ietf-httpbis-http2-17#section-8>`_.
 * See `HTTP Messaging`_ section for details.  For those applications
 * who use nghttp2 library as non-HTTP use, give nonzero to |val| to
 * disable this enforcement.
 */
void http2_option_set_no_http_messaging(http2_option *option, int val);

/**
 * @function
 *
 * Initializes |*session_ptr| for client use.  The all members of
 * |callbacks| are copied to |*session_ptr|.  Therefore |*session_ptr|
 * does not store |callbacks|.  The |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :type:`http2_send_callback` must be specified.  If the
 * application code uses `http2_session_recv()`, the
 * :type:`http2_recv_callback` must be specified.  The other members
 * of |callbacks| can be ``NULL``.
 *
 * If this function fails, |*session_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_client_new(Session *session_ptr,
                               in Policy callbacks,
                               void *user_data);

/**
 * @function
 *
 * Initializes |*session_ptr| for server use.  The all members of
 * |callbacks| are copied to |*session_ptr|. Therefore |*session_ptr|
 * does not store |callbacks|.  The |user_data| is an arbitrary user
 * supplied data, which will be passed to the callback functions.
 *
 * The :type:`http2_send_callback` must be specified.  If the
 * application code uses `http2_session_recv()`, the
 * :type:`http2_recv_callback` must be specified.  The other members
 * of |callbacks| can be ``NULL``.
 *
 * If this function fails, |*session_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_server_new(Session *session_ptr,
                                   in Policy callbacks,
                                   void *user_data);

/**
 * @function
 *
 * Like `http2_session_client_new()`, but with additional options
 * specified in the |option|.
 *
 * The |option| can be ``NULL`` and the call is equivalent to
 * `http2_session_client_new()`.
 *
 * This function does not take ownership |option|.  The application is
 * responsible for freeing |option| if it finishes using the object.
 *
 * The library code does not refer to |option| after this function
 * returns.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_client_new2(Session *session_ptr,
                                    in Policy callbacks,
                                    void *user_data, const http2_option *option);

/**
 * @function
 *
 * Like `http2_session_server_new()`, but with additional options
 * specified in the |option|.
 *
 * The |option| can be ``NULL`` and the call is equivalent to
 * `http2_session_server_new()`.
 *
 * This function does not take ownership |option|.  The application is
 * responsible for freeing |option| if it finishes using the object.
 *
 * The library code does not refer to |option| after this function
 * returns.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_server_new2(Session *session_ptr,
                                in Policy callbacks,
                                void *user_data, const http2_option *option);

/**
 * @function
 *
 * Like `http2_session_client_new2()`, but with additional custom
 * memory allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `http2_session_client_new2()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_client_new3(Session *session_ptr,
                                    in Policy callbacks,
                                    void *user_data, const http2_option *option,
                                    http2_mem *mem);

/**
 * @function
 *
 * Like `http2_session_server_new2()`, but with additional custom
 * memory allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `http2_session_server_new2()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_server_new3(Session *session_ptr,
                                    in Policy callbacks,
                                    void *user_data, const http2_option *option,
                                    http2_mem *mem);

/**
 * @function
 *
 * Frees any resources allocated for |session|.  If |session| is
 * ``NULL``, this function does nothing.
 */
void http2_session_del(Session session);

/**
 * @function
 *
 * Sends pending frames to the remote peer.
 *
 * This function retrieves the highest prioritized frame from the
 * outbound queue and sends it to the remote peer.  It does this as
 * many as possible until the user callback
 * :type:`http2_send_callback` returns
 * $(D ErrorCode.WOULDBLOCK) or the outbound queue becomes empty.
 * This function calls several callback functions which are passed
 * when initializing the |session|.  Here is the simple time chart
 * which tells when each callback is invoked:
 *
 * 1. Get the next frame to send from outbound queue.
 *
 * 2. Prepare transmission of the frame.
 *
 * 3. If the control frame cannot be sent because some preconditions
 *    are not met (e.g., request HEADERS cannot be sent after GOAWAY),
 *    :type:`http2_on_frame_not_send_callback` is invoked.  Abort
 *    the following steps.
 *
 * 4. If the frame is HEADERS, PUSH_PROMISE or DATA,
 *    :type:`http2_select_padding_callback` is invoked.
 *
 * 5. If the frame is request HEADERS, the stream is opened here.
 *
 * 6. :type:`http2_before_frame_send_callback` is invoked.
 *
 * 7. :type:`http2_send_callback` is invoked one or more times to
 *    send the frame.
 *
 * 8. :type:`http2_on_frame_send_callback` is invoked.
 *
 * 9. If the transmission of the frame triggers closure of the stream,
 *    the stream is closed and
 *    :type:`http2_on_stream_close_callback` is invoked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.CALLBACK_FAILURE)
 *     The callback function failed.
 */
ErrorCode http2_session_send(Session session);

/**
 * @function
 *
 * Returns the serialized data to send.
 *
 * This function behaves like `http2_session_send()` except that it
 * does not use :type:`http2_send_callback` to transmit data.
 * Instead, it assigns the pointer to the serialized data to the
 * |*data_ptr| and returns its length.  The other callbacks are called
 * in the same way as they are in `http2_session_send()`.
 *
 * If no data is available to send, this function returns 0.
 *
 * This function may not return all serialized data in one invocation.
 * To get all data, call this function repeatedly until it returns 0
 * or one of negative error codes.
 *
 * The assigned |*data_ptr| is valid until the next call of
 * `http2_session_mem_send()` or `http2_session_send()`.
 *
 * The caller must send all data before sending the next chunk of
 * data.
 *
 * This function returns the length of the data pointed by the
 * |*data_ptr| if it succeeds, or one of the following negative error
 * codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
size_t http2_session_mem_send(Session session,
                                 const ubyte **data_ptr);

/**
 * @function
 *
 * Receives frames from the remote peer.
 *
 * This function receives as many frames as possible until the user
 * callback :type:`http2_recv_callback` returns
 * $(D ErrorCode.WOULDBLOCK).  This function calls several
 * callback functions which are passed when initializing the
 * |session|.  Here is the simple time chart which tells when each
 * callback is invoked:
 *
 * 1. :type:`http2_recv_callback` is invoked one or more times to
 *    receive frame header.
 *
 * 2. When frame header is received,
 *    :type:`http2_on_begin_frame_callback` is invoked.
 *
 * 3. If the frame is DATA frame:
 *
 *    1. :type:`http2_recv_callback` is invoked to receive DATA
 *       payload. For each chunk of data,
 *       :type:`http2_on_data_chunk_recv_callback` is invoked.
 *
 *    2. If one DATA frame is completely received,
 *       :type:`http2_on_frame_recv_callback` is invoked.  If the
 *       reception of the frame triggers the closure of the stream,
 *       :type:`http2_on_stream_close_callback` is invoked.
 *
 * 4. If the frame is the control frame:
 *
 *    1. :type:`http2_recv_callback` is invoked one or more times to
 *       receive whole frame.
 *
 *    2. If the received frame is valid, then following actions are
 *       taken.  If the frame is either HEADERS or PUSH_PROMISE,
 *       :type:`http2_on_begin_headers_callback` is invoked.  Then
 *       :type:`http2_on_header_callback` is invoked for each header
 *       name/value pair.  After all name/value pairs are emitted
 *       successfully, :type:`http2_on_frame_recv_callback` is
 *       invoked.  For other frames,
 *       :type:`http2_on_frame_recv_callback` is invoked.  If the
 *       reception of the frame triggers the closure of the stream,
 *       :type:`http2_on_stream_close_callback` is invoked.
 *
 *    3. If the received frame is unpacked but is interpreted as
 *       invalid, :type:`http2_on_invalid_frame_recv_callback` is
 *       invoked.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.EOF)
 *     The remote peer did shutdown on the connection.
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.CALLBACK_FAILURE)
 *     The callback function failed.
 * $(D ErrorCode.BAD_PREFACE)
 *     Invalid client preface was detected.  This error only returns
 *     when |session| was configured as server and
 *     `http2_option_set_recv_client_preface()` is used.
 */
ErrorCode http2_session_recv(Session session);

/**
 * @function
 *
 * Processes data |in| as an input from the remote endpoint.  The
 * |inlen| indicates the number of bytes in the |in|.
 *
 * This function behaves like `http2_session_recv()` except that it
 * does not use :type:`http2_recv_callback` to receive data; the
 * |in| is the only data for the invocation of this function.  If all
 * bytes are processed, this function returns.  The other callbacks
 * are called in the same way as they are in `http2_session_recv()`.
 *
 * In the current implementation, this function always tries to
 * processes all input data unless either an error occurs or
 * $(D ErrorCode.PAUSE) is returned from
 * :type:`http2_on_header_callback` or
 * :type:`http2_on_data_chunk_recv_callback`.  If
 * $(D ErrorCode.PAUSE) is used, the return value includes the
 * number of bytes which was used to produce the data or frame for the
 * callback.
 *
 * This function returns the number of processed bytes, or one of the
 * following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.CALLBACK_FAILURE)
 *     The callback function failed.
 * $(D ErrorCode.BAD_PREFACE)
 *     Invalid client preface was detected.  This error only returns
 *     when |session| was configured as server and
 *     `http2_option_set_recv_client_preface()` is used.
 */
size_t http2_session_mem_recv(Session session, in ubyte[] input);

/**
 * @function
 *
 * Puts back previously deferred DATA frame in the stream |stream_id|
 * to the outbound queue.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The stream does not exist; or no deferred data exist.
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_resume_data(Session session, int stream_id);

/**
 * @function
 *
 * Returns true value if |session| wants to receive data from the
 * remote peer.
 *
 * If both `http2_session_want_read()` and
 * `http2_session_want_write()` return 0, the application should
 * drop the connection.
 */
bool http2_session_want_read(Session session);

/**
 * @function
 *
 * Returns true value if |session| wants to send data to the remote
 * peer.
 *
 * If both `http2_session_want_read()` and
 * `http2_session_want_write()` return 0, the application should
 * drop the connection.
 */
bool http2_session_want_write(Session session);

/**
 * @function
 *
 * Returns stream_user_data for the stream |stream_id|.  The
 * stream_user_data is provided by `http2_submit_request()`,
 * `http2_submit_headers()` or
 * `http2_session_set_stream_user_data()`.  Unless it is set using
 * `http2_session_set_stream_user_data()`, if the stream is
 * initiated by the remote endpoint, stream_user_data is always
 * ``NULL``.  If the stream does not exist, this function returns
 * ``NULL``.
 */
void *http2_session_get_stream_user_data(Session session, int stream_id);

/**
 * @function
 *
 * Sets the |stream_user_data| to the stream denoted by the
 * |stream_id|.  If a stream user data is already set to the stream,
 * it is replaced with the |stream_user_data|.  It is valid to specify
 * ``NULL`` in the |stream_user_data|, which nullifies the associated
 * data pointer.
 *
 * It is valid to set the |stream_user_data| to the stream reserved by
 * PUSH_PROMISE frame.
 *
 * This function returns 0 if it succeeds, or one of following
 * negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The stream does not exist
 */
ErrorCode http2_session_set_stream_user_data(Session session, int stream_id, void *stream_user_data);

/**
 * @function
 *
 * Returns the number of frames in the outbound queue.  This does not
 * include the deferred DATA frames.
 */
size_t http2_session_get_outbound_queue_size(Session session);

/**
 * @function
 *
 * Returns the number of DATA payload in bytes received without
 * WINDOW_UPDATE transmission for the stream |stream_id|.  The local
 * (receive) window size can be adjusted by
 * `http2_submit_window_update()`.  This function takes into account
 * that and returns effective data length.  In particular, if the
 * local window size is reduced by submitting negative
 * window_size_increment with `http2_submit_window_update()`, this
 * function returns the number of bytes less than actually received.
 *
 * This function returns -1 if it fails.
 */
int
http2_session_get_stream_effective_recv_data_length(Session session, int stream_id);

/**
 * @function
 *
 * Returns the local (receive) window size for the stream |stream_id|.
 * The local window size can be adjusted by
 * `http2_submit_window_update()`.  This function takes into account
 * that and returns effective window size.
 *
 * This function returns -1 if it fails.
 */
int
http2_session_get_stream_effective_local_window_size(Session session, int stream_id);

/**
 * @function
 *
 * Returns the number of DATA payload in bytes received without
 * WINDOW_UPDATE transmission for a connection.  The local (receive)
 * window size can be adjusted by `http2_submit_window_update()`.
 * This function takes into account that and returns effective data
 * length.  In particular, if the local window size is reduced by
 * submitting negative window_size_increment with
 * `http2_submit_window_update()`, this function returns the number
 * of bytes less than actually received.
 *
 * This function returns -1 if it fails.
 */
int
http2_session_get_effective_recv_data_length(Session session);

/**
 * @function
 *
 * Returns the local (receive) window size for a connection.  The
 * local window size can be adjusted by
 * `http2_submit_window_update()`.  This function takes into account
 * that and returns effective window size.
 *
 * This function returns -1 if it fails.
 */
int
http2_session_get_effective_local_window_size(Session session);

/**
 * @function
 *
 * Returns the remote window size for a given stream |stream_id|.
 *
 * This is the amount of flow-controlled payload (e.g., DATA) that the
 * local endpoint can send without stream level WINDOW_UPDATE.  There
 * is also connection level flow control, so the effective size of
 * payload that the local endpoint can actually send is
 * min(`http2_session_get_stream_remote_window_size()`,
 * `http2_session_get_remote_window_size()`).
 *
 * This function returns -1 if it fails.
 */
int http2_session_get_stream_remote_window_size(Session session, int stream_id);

/**
 * @function
 *
 * Returns the remote window size for a connection.
 *
 * This function always succeeds.
 */
int http2_session_get_remote_window_size(Session session);

/**
 * @function
 *
 * Returns 1 if local peer half closed the given stream |stream_id|.
 * Returns 0 if it did not.  Returns -1 if no such stream exists.
 */
bool http2_session_get_stream_local_close(Session session,
                                           int stream_id);

/**
 * @function
 *
 * Returns 1 if remote peer half closed the given stream |stream_id|.
 * Returns 0 if it did not.  Returns -1 if no such stream exists.
 */
bool http2_session_get_stream_remote_close(Session session,
                                            int stream_id);

/**
 * @function
 *
 * Signals the session so that the connection should be terminated.
 *
 * The last stream ID is the minimum value between the stream ID of a
 * stream for which :type:`http2_on_frame_recv_callback` was called
 * most recently and the last stream ID we have sent to the peer
 * previously.
 *
 * The |error_code| is the error code of this GOAWAY frame.  The
 * pre-defined error code is one of $(D http2_error_code).
 *
 * After the transmission, both `http2_session_want_read()` and
 * `http2_session_want_write()` return 0.
 *
 * This function should be called when the connection should be
 * terminated after sending GOAWAY.  If the remaining streams should
 * be processed after GOAWAY, use `http2_submit_goaway()` instead.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_session_terminate_session(Session session,
                                      uint error_code);

/**
 * @function
 *
 * Signals the session so that the connection should be terminated.
 *
 * This function behaves like `http2_session_terminate_session()`,
 * but the last stream ID can be specified by the application for fine
 * grained control of stream.  The HTTP/2 specification does not allow
 * last_stream_id to be increased.  So the actual value sent as
 * last_stream_id is the minimum value between the given
 * |last_stream_id| and the last_stream_id we have previously sent to
 * the peer.
 *
 * The |last_stream_id| is peer's stream ID or 0.  So if |session| is
 * initialized as client, |last_stream_id| must be even or 0.  If
 * |session| is initialized as server, |last_stream_id| must be odd or
 * 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |last_stream_id| is invalid.
 */
ErrorCode http2_session_terminate_session2(Session session,
                                       int last_stream_id,
                                       uint error_code);

/**
 * @function
 *
 * Signals to the client that the server started graceful shutdown
 * procedure.
 *
 * This function is only usable for server.  If this function is
 * called with client side session, this function returns
 * $(D ErrorCode.INVALID_STATE).
 *
 * To gracefully shutdown HTTP/2 session, server should call this
 * function to send GOAWAY with last_stream_id (1u << 31) - 1.  And
 * after some delay (e.g., 1 RTT), send another GOAWAY with the stream
 * ID that the server has some processing using
 * `http2_submit_goaway()`.  See also
 * `http2_session_get_last_proc_stream_id()`.
 *
 * Unlike `http2_submit_goaway()`, this function just sends GOAWAY
 * and does nothing more.  This is a mere indication to the client
 * that session shutdown is imminent.  The application should call
 * `http2_submit_goaway()` with appropriate last_stream_id after
 * this call.
 *
 * If one or more GOAWAY frame have been already sent by either
 * `http2_submit_goaway()` or `http2_session_terminate_session()`,
 * this function has no effect.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_STATE)
 *     The |session| is initialized as client.
 */
ErrorCode http2_submit_shutdown_notice(Session session);

/**
 * @function
 *
 * Returns the value of SETTINGS |id| notified by a remote endpoint.
 * The |id| must be one of values defined in
 * $(D http2_settings_id).
 */
uint http2_session_get_remote_settings(Session session,
                                             http2_settings_id id);

/**
 * @function
 *
 * Tells the |session| that next stream ID is |next_stream_id|.  The
 * |next_stream_id| must be equal or greater than the value returned
 * by `http2_session_get_next_stream_id()`.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |next_stream_id| is strictly less than the value
 *     `http2_session_get_next_stream_id()` returns.
 */
ErrorCode http2_session_set_next_stream_id(Session session,
                                       int next_stream_id);

/**
 * @function
 *
 * Returns the next outgoing stream ID.  Notice that return type is
 * uint.  If we run out of stream ID for this session, this
 * function returns 1 << 31.
 */
uint http2_session_get_next_stream_id(Session session);

/**
 * @function
 *
 * Tells the |session| that |size| bytes for a stream denoted by
 * |stream_id| were consumed by application and are ready to
 * WINDOW_UPDATE.  This function is intended to be used without
 * automatic window update (see
 * `http2_option_set_no_auto_window_update()`).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 * $(D ErrorCode.INVALID_STATE)
 *     Automatic WINDOW_UPDATE is not disabled.
 */
ErrorCode http2_session_consume(Session session, int stream_id,
                            size_t size);

/**
 * @function
 *
 * Performs post-process of HTTP Upgrade request.  This function can
 * be called from both client and server, but the behavior is very
 * different in each other.
 *
 * If called from client side, the |settings_payload| must be the
 * value sent in ``HTTP2-Settings`` header field and must be decoded
 * by base64url decoder.  The |settings_payloadlen| is the length of
 * |settings_payload|.  The |settings_payload| is unpacked and its
 * setting values will be submitted using `http2_submit_settings()`.
 * This means that the client application code does not need to submit
 * SETTINGS by itself.  The stream with stream ID=1 is opened and the
 * |stream_user_data| is used for its stream_user_data.  The opened
 * stream becomes half-closed (local) state.
 *
 * If called from server side, the |settings_payload| must be the
 * value received in ``HTTP2-Settings`` header field and must be
 * decoded by base64url decoder.  The |settings_payloadlen| is the
 * length of |settings_payload|.  It is treated as if the SETTINGS
 * frame with that payload is received.  Thus, callback functions for
 * the reception of SETTINGS frame will be invoked.  The stream with
 * stream ID=1 is opened.  The |stream_user_data| is ignored.  The
 * opened stream becomes half-closed (remote).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |settings_payload| is badly formed.
 * $(D ErrorCode.PROTO)
 *     The stream ID 1 is already used or closed; or is not available.
 */
ErrorCode http2_session_upgrade(Session session,
                            const ubyte *settings_payload,
                            size_t settings_payloadlen, void *stream_user_data);

/**
 * @function
 *
 * Serializes the SETTINGS values |iv| in the |buf|.  The size of the
 * |buf| is specified by |buflen|.  The number of entries in the |iv|
 * array is given by |niv|.  The required space in |buf| for the |niv|
 * entries is ``8*niv`` bytes and if the given buffer is too small, an
 * error is returned.  This function is used mainly for creating a
 * SETTINGS payload to be sent with the ``HTTP2-Settings`` header
 * field in an HTTP Upgrade request.  The data written in |buf| is NOT
 * base64url encoded and the application is responsible for encoding.
 *
 * This function returns the number of bytes written in |buf|, or one
 * of the following negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |iv| contains duplicate settings ID or invalid value.
 *
 * $(D ErrorCode.INSUFF_BUFSIZE)
 *     The provided |buflen| size is too small to hold the output.
 */
size_t http2_pack_settings_payload(ubyte[] buf, const ref Setting[] iv);

/**
 * @function
 *
 * Returns string describing the |lib_error_code|.  The
 * |lib_error_code| must be one of the $(D ErrorCode).
 */
string http2_strerror(ErrorCode lib_error_code);

/**
 * @function
 *
 * Initializes |pri_spec| with the |stream_id| of the stream to depend
 * on with |weight| and its exclusive flag.  If |exclusive| is
 * nonzero, exclusive flag is set.
 *
 * The |weight| must be in [$(D HTTP2_MIN_WEIGHT),
 * $(D HTTP2_MAX_WEIGHT)], inclusive.
 */
void http2_priority_spec_init(ref PrioritySpec pri_spec, Stream stream_id, int weight, int exclusive);

/**
 * @function
 *
 * Initializes |pri_spec| with the default values.  The default values
 * are: stream_id = 0, weight = :macro:`HTTP2_DEFAULT_WEIGHT` and
 * exclusive = 0.
 */
void http2_priority_spec_default_init(http2_priority_spec *pri_spec);

/**
 * @function
 *
 * Returns nonzero if the |pri_spec| is filled with default values.
 */
bool http2_priority_spec_check_default(const http2_priority_spec *pri_spec);

/**
 * @function
 *
 * Submits HEADERS frame and optionally one or more DATA frames.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * means the default priority (see
 * `http2_priority_spec_default_init()`).  To specify the priority,
 * use `http2_priority_spec_init()`.  If |pri_spec| is not ``NULL``,
 * this function will copy its data members.
 *
 * The `pri_spec->weight` must be in [$(D HTTP2_MIN_WEIGHT),
 * $(D HTTP2_MAX_WEIGHT)], inclusive.  If `pri_spec->weight` is
 * strictly less than $(D HTTP2_MIN_WEIGHT), it becomes
 * $(D HTTP2_MIN_WEIGHT).  If it is strictly greater than
 * $(D HTTP2_MAX_WEIGHT), it becomes $(D HTTP2_MAX_WEIGHT).
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * HTTP/2 specification has requirement about header fields in the
 * request HEADERS.  See the specification for more details.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames.  In this case, a method that allows
 * request message bodies
 * (http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9) must
 * be specified with ``:method`` key in |nva| (e.g. ``POST``).  This
 * function does not take ownership of the |data_prd|.  The function
 * copies the members of the |data_prd|.  If |data_prd| is ``NULL``,
 * HEADERS have END_STREAM set.  The |stream_user_data| is data
 * associated to the stream opened by this request and can be an
 * arbitrary pointer, which can be retrieved later by
 * `http2_session_get_stream_user_data()`.
 *
 * This function returns assigned stream ID if it succeeds, or one of
 * the following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.STREAM_ID_NOT_AVAILABLE)
 *     No stream ID is available because maximum stream ID was
 *     reached.
 *
 * .. warning::
 *
 *   This function returns assigned stream ID if it succeeds.  But
 *   that stream is not opened yet.  The application must not submit
 *   frame to that stream ID before
 *   :type:`http2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
ErrorCode http2_submit_request(Session session,
                               const http2_priority_spec *pri_spec,
                               const http2_nv *nva, size_t nvlen,
                               in DataProvider data_prd,
                               void *stream_user_data);

/**
 * @function
 *
 * Submits response HEADERS frame and optionally one or more DATA
 * frames against the stream |stream_id|.
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * HTTP/2 specification has requirement about header fields in the
 * response HEADERS.  See the specification for more details.
 *
 * If |data_prd| is not ``NULL``, it provides data which will be sent
 * in subsequent DATA frames.  This function does not take ownership
 * of the |data_prd|.  The function copies the members of the
 * |data_prd|.  If |data_prd| is ``NULL``, HEADERS will have
 * END_STREAM flag set.
 *
 * This method can be used as normal HTTP response and push response.
 * When pushing a resource using this function, the |session| must be
 * configured using `http2_session_server_new()` or its variants and
 * the target stream denoted by the |stream_id| must be reserved using
 * `http2_submit_push_promise()`.
 *
 * To send non-final response headers (e.g., HTTP status 101), don't
 * use this function because this function half-closes the outbound
 * stream.  Instead, use `http2_submit_headers()` for this purpose.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 *
 * .. warning::
 *
 *   Calling this function twice for the same stream ID may lead to
 *   program crash.  It is generally considered to a programming error
 *   to commit response twice.
 */
ErrorCode http2_submit_response(Session session, int stream_id,
                            const http2_nv *nva, size_t nvlen,
                            in DataProvider data_prd);

/**
 * @function
 *
 * Submits HEADERS frame. The |flags| is bitwise OR of the
 * following values:
 *
 * * $(D FrameFlags.END_STREAM)
 *
 * If |flags| includes $(D FrameFlags.END_STREAM), this frame has
 * END_STREAM flag set.
 *
 * The library handles the CONTINUATION frame internally and it
 * correctly sets END_HEADERS to the last sequence of the PUSH_PROMISE
 * or CONTINUATION frame.
 *
 * If the |stream_id| is -1, this frame is assumed as request (i.e.,
 * request HEADERS frame which opens new stream).  In this case, the
 * assigned stream ID will be returned.  Otherwise, specify stream ID
 * in |stream_id|.
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * means the default priority (see
 * `http2_priority_spec_default_init()`).  To specify the priority,
 * use `http2_priority_spec_init()`.  If |pri_spec| is not ``NULL``,
 * this function will copy its data members.
 *
 * The `pri_spec->weight` must be in [$(D HTTP2_MIN_WEIGHT),
 * $(D HTTP2_MAX_WEIGHT)], inclusive.  If `pri_spec->weight` is
 * strictly less than $(D HTTP2_MIN_WEIGHT), it becomes
 * $(D HTTP2_MIN_WEIGHT).  If it is strictly greater than
 * $(D HTTP2_MAX_WEIGHT), it becomes $(D HTTP2_MAX_WEIGHT).
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * The |stream_user_data| is a pointer to an arbitrary data which is
 * associated to the stream this frame will open.  Therefore it is
 * only used if this frame opens streams, in other words, it changes
 * stream state from idle or reserved to open.
 *
 * This function is low-level in a sense that the application code can
 * specify flags directly.  For usual HTTP request,
 * `http2_submit_request()` is useful.
 *
 * This function returns newly assigned stream ID if it succeeds and
 * |stream_id| is -1.  Otherwise, this function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.STREAM_ID_NOT_AVAILABLE)
 *     No stream ID is available because maximum stream ID was
 *     reached.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 *
 * .. warning::
 *
 *   This function returns assigned stream ID if it succeeds and
 *   |stream_id| is -1.  But that stream is not opened yet.  The
 *   application must not submit frame to that stream ID before
 *   :type:`http2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
ErrorCode http2_submit_headers(Session session, ubyte flags,
                               int stream_id,
                               const http2_priority_spec *pri_spec,
                               const http2_nv *nva, size_t nvlen,
                               void *stream_user_data);

/**
 * @function
 *
 * Submits one or more DATA frames to the stream |stream_id|.  The
 * data to be sent are provided by |data_prd|.  If |flags| contains
 * $(D FrameFlags.END_STREAM), the last DATA frame has END_STREAM
 * flag set.
 *
 * This function does not take ownership of the |data_prd|.  The
 * function copies the members of the |data_prd|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.DATA_EXIST)
 *     DATA has been already submitted and not fully processed yet.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 * $(D ErrorCode.STREAM_CLOSED)
 *     The stream was alreay closed; or the |stream_id| is invalid.
 *
 * .. note::
 *
 *   Currently, only one data is allowed for a stream at a time.
 *   Submitting data more than once before first data is finished
 *   results in $(D ErrorCode.DATA_EXIST) error code.  The
 *   earliest callback which tells that previous data is done is
 *   :type:`http2_on_frame_send_callback`.  In side that callback,
 *   new data can be submitted using `http2_submit_data()`.  Of
 *   course, all data except for last one must not have
 *   $(D FrameFlags.END_STREAM) flag set in |flags|.
 */
ErrorCode http2_submit_data(Session session, FrameFlags flags, int stream_id, in DataProvider data_prd);

/**
 * @function
 *
 * Submits PRIORITY frame to change the priority of stream |stream_id|
 * to the priority specification |pri_spec|.
 *
 * The |flags| is currently ignored and should be
 * $(D FrameFlags.NONE).
 *
 * The |pri_spec| is priority specification of this request.  ``NULL``
 * is not allowed for this function. To specify the priority, use
 * `http2_priority_spec_init()`.  This function will copy its data
 * members.
 *
 * The `pri_spec->weight` must be in [$(D HTTP2_MIN_WEIGHT),
 * $(D HTTP2_MAX_WEIGHT)], inclusive.  If `pri_spec->weight` is
 * strictly less than $(D HTTP2_MIN_WEIGHT), it becomes
 * $(D HTTP2_MIN_WEIGHT).  If it is strictly greater than
 * $(D HTTP2_MAX_WEIGHT), it becomes $(D HTTP2_MAX_WEIGHT).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0; or the |pri_spec| is NULL; or trying to
 *     depend on itself.
 */
ErrorCode http2_submit_priority(Session session, ubyte flags, int stream_id, const ref PrioritySpec pri_spec);

/**
 * @function
 *
 * Submits RST_STREAM frame to cancel/reject the stream |stream_id|
 * with the error code |error_code|.
 *
 * The pre-defined error code is one of $(D http2_error_code).
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0.
 */
ErrorCode http2_submit_rst_stream(Session session, int stream_id, FrameError error_code);

/**
 * @function
 *
 * Stores local settings and submits SETTINGS frame.  The |iv| is the
 * pointer to the array of :type:`http2_settings_entry`.  The |niv|
 * indicates the number of :type:`http2_settings_entry`.
 *
 * This function does not take ownership of the |iv|.  This function
 * copies all the elements in the |iv|.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than HTTP2_MAX_WINDOW_SIZE,
 * RST_STREAM is issued against such a stream.
 *
 * SETTINGS with $(D FrameFlags.ACK) is automatically submitted
 * by the library and application could not send it at its will.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |iv| contains invalid value (e.g., initial window size
 *     strictly greater than (1 << 31) - 1.
 * $(D ErrorCode.TOO_MANY_INFLIGHT_SETTINGS)
 *     There is already another in-flight SETTINGS.  Note that the
 *     current implementation only allows 1 in-flight SETTINGS frame
 *     without ACK flag set.
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_submit_settings(Session session, in Setting[] iv);

/**
 * @function
 *
 * Submits PUSH_PROMISE frame.
 *
 * The |stream_id| must be client initiated stream ID.
 *
 * The |nva| is an array of name/value pair :type:`http2_nv` with
 * |nvlen| elements.  The application is responsible to include
 * required pseudo-header fields (header field whose name starts with
 * ":") in |nva| and must place pseudo-headers before regular header
 * fields.
 *
 * This function creates copies of all name/value pairs in |nva|.  It
 * also lower-cases all names in |nva|.  The order of elements in
 * |nva| is preserved.
 *
 * The |promised_stream_user_data| is a pointer to an arbitrary data
 * which is associated to the promised stream this frame will open and
 * make it in reserved state.  It is available using
 * `http2_session_get_stream_user_data()`.  The application can
 * access it in :type:`http2_before_frame_send_callback` and
 * :type:`http2_on_frame_send_callback` of this frame.
 *
 * The client side is not allowed to use this function.
 *
 * To submit response headers and data, use
 * `http2_submit_response()`.
 *
 * This function returns assigned promised stream ID if it succeeds,
 * or one of the following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.PROTO)
 *     This function was invoked when |session| is initialized as
 *     client.
 * $(D ErrorCode.STREAM_ID_NOT_AVAILABLE)
 *     No stream ID is available because maximum stream ID was
 *     reached.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |stream_id| is 0; The |stream_id| does not designate stream
 *     that peer initiated.
 *
 * .. warning::
 *
 *   This function returns assigned promised stream ID if it succeeds.
 *   But that stream is not opened yet.  The application must not
 *   submit frame to that stream ID before
 *   :type:`http2_before_frame_send_callback` is called for this
 *   frame.
 *
 */
ErrorCode http2_submit_push_promise(Session session, int stream_id, in NVPair[] nva, void *promised_stream_user_data);

/**
 * @function
 *
 * Submits PING frame.  You don't have to send PING back when you
 * received PING frame.  The library automatically submits PING frame
 * in this case.
 *
 * The |flags| is currently ignored and should be
 * $(D FrameFlags.NONE).
 *
 * If the |opaque_data| is non ``NULL``, then it should point to the 8
 * bytes array of memory to specify opaque data to send with PING
 * frame.  If the |opaque_data| is ``NULL``, zero-cleared 8 bytes will
 * be sent as opaque data.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_submit_ping(Session session, ubyte flags, const ubyte *opaque_data);

/**
 * @function
 *
 * Submits GOAWAY frame with the last stream ID |last_stream_id| and
 * the error code |error_code|.
 *
 * The pre-defined error code is one of $(D http2_error_code).
 *
 * The |flags| is currently ignored and should be
 * $(D FrameFlags.NONE).
 *
 * The |last_stream_id| is peer's stream ID or 0.  So if |session| is
 * initialized as client, |last_stream_id| must be even or 0.  If
 * |session| is initialized as server, |last_stream_id| must be odd or
 * 0.
 *
 * The HTTP/2 specification says last_stream_id must not be increased
 * from the value previously sent.  So the actual value sent as
 * last_stream_id is the minimum value between the given
 * |last_stream_id| and the last_stream_id previously sent to the
 * peer.
 *
 * If the |opaque_data| is not ``NULL`` and |opaque_data_len| is not
 * zero, those data will be sent as additional debug data.  The
 * library makes a copy of the memory region pointed by |opaque_data|
 * with the length |opaque_data_len|, so the caller does not need to
 * keep this memory after the return of this function.  If the
 * |opaque_data_len| is 0, the |opaque_data| could be ``NULL``.
 *
 * After successful transmission of GOAWAY, following things happen.
 * All incoming streams having strictly more than |last_stream_id| are
 * closed.  All incoming HEADERS which starts new stream are simply
 * ignored.  After all active streams are handled, both
 * `http2_session_want_read()` and `http2_session_want_write()`
 * return 0 and the application can close session.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.INVALID_ARGUMENT)
 *     The |opaque_data_len| is too large; the |last_stream_id| is
 *     invalid.
 */
ErrorCode http2_submit_goaway(Session session, ubyte flags,
                          int last_stream_id, uint error_code,
                          const ubyte *opaque_data, size_t opaque_data_len);

/**
 * @function
 *
 * Returns the last stream ID of a stream for which
 * :type:`http2_on_frame_recv_callback` was invoked most recently.
 * The returned value can be used as last_stream_id parameter for
 * `http2_submit_goaway()` and
 * `http2_session_terminate_session2()`.
 *
 * This function always succeeds.
 */
void http2_session_get_last_proc_stream_id(Session session);

/**
 * @function
 *
 * Submits WINDOW_UPDATE frame.
 *
 * The |flags| is currently ignored and should be
 * $(D FrameFlags.NONE).
 *
 * If the |window_size_increment| is positive, the WINDOW_UPDATE with
 * that value as window_size_increment is queued.  If the
 * |window_size_increment| is larger than the received bytes from the
 * remote endpoint, the local window size is increased by that
 * difference.
 *
 * If the |window_size_increment| is negative, the local window size
 * is decreased by -|window_size_increment|.  If automatic
 * WINDOW_UPDATE is enabled
 * (`http2_option_set_no_auto_window_update()`), and the library
 * decided that the WINDOW_UPDATE should be submitted, then
 * WINDOW_UPDATE is queued with the current received bytes count.
 *
 * If the |window_size_increment| is 0, the function does nothing and
 * returns 0.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.FLOW_CONTROL)
 *     The local window size overflow or gets negative.
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_submit_window_update(Session session, ubyte flags,
                                 int stream_id,
                                 int window_size_increment);

/**
 * @function
 *
 * Compares ``lhs->name`` of length ``lhs->namelen`` bytes and
 * ``rhs->name`` of length ``rhs->namelen`` bytes.  Returns negative
 * integer if ``lhs->name`` is found to be less than ``rhs->name``; or
 * returns positive integer if ``lhs->name`` is found to be greater
 * than ``rhs->name``; or returns 0 otherwise.
 */
int http2_nv_compare_name(const http2_nv *lhs, const http2_nv *rhs);

/**
 * @function
 *
 * A helper function for dealing with NPN in client side or ALPN in
 * server side.  The |in| contains peer's protocol list in preferable
 * order.  The format of |in| is length-prefixed and not
 * null-terminated.  For example, ``HTTP-draft-04/2.0`` and
 * ``http/1.1`` stored in |in| like this::
 *
 *     in[0] = 17
 *     in[1..17] = "HTTP-draft-04/2.0"
 *     in[18] = 8
 *     in[19..26] = "http/1.1"
 *     inlen = 27
 *
 * The selection algorithm is as follows:
 *
 * 1. If peer's list contains HTTP/2 protocol the library supports,
 *    it is selected and returns 1. The following step is not taken.
 *
 * 2. If peer's list contains ``http/1.1``, this function selects
 *    ``http/1.1`` and returns 0.  The following step is not taken.
 *
 * 3. This function selects nothing and returns -1 (So called
 *    non-overlap case).  In this case, |out| and |outlen| are left
 *    untouched.
 *
 * Selecting ``HTTP-draft-04/2.0`` means that ``HTTP-draft-04/2.0`` is
 * written into |*out| and its length (which is 17) is assigned to
 * |*outlen|.
 *
 * For ALPN, refer to
 * https://tools.ietf.org/html/draft-ietf-tls-applayerprotoneg-05
 *
 * See http://technotes.googlecode.com/git/nextprotoneg.html for more
 * details about NPN.
 *
 * For NPN, to use this method you should do something like::
 *
 *     static int select_next_proto_cb(SSL* ssl,
 *                                     unsigned char **out,
 *                                     unsigned char *outlen,
 *                                     const unsigned char *in,
 *                                     unsigned int inlen,
 *                                     void *arg)
 *     {
 *         int rv;
 *         rv = http2_select_next_protocol(out, outlen, in, inlen);
 *         if(rv == 1) {
 *             ((MyType*)arg)->http2_selected = 1;
 *         }
 *         return SSL_TLSEXT_ERR_OK;
 *     }
 *     ...
 *     SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, my_obj);
 *
 */
int http2_select_next_protocol(ref char[] output, in char[] input);

/**
 * @function
 *
 * Returns a pointer to a http2_info struct with version information
 * about the run-time library in use.  The |least_version| argument
 * can be set to a 24 bit numerical value for the least accepted
 * version number and if the condition is not met, this function will
 * return a ``NULL``.  Pass in 0 to skip the version checking.
 */
http2_info *http2_version(int least_version);

/**
 * @function
 *
 * Returns true if the $(D RV) library error code
 * |lib_error| is fatal.
 */
bool http2_is_fatal(int lib_error);

/**
 * @function
 *
 * Returns true if HTTP header field name |name| of length |len| is
 * valid according to http://tools.ietf.org/html/rfc7230#section-3.2
 *
 * Because this is a header field name in HTTP2, the upper cased alphabet
 * is treated as error.
 */
bool http2_check_header_name(const ubyte *name, size_t len);

/**
 * @function
 *
 * Returns true if HTTP header field value |value| of length |len|
 * is valid according to
 * http://tools.ietf.org/html/rfc7230#section-3.2
 */
bool http2_check_header_value(const ubyte *value, size_t len);


/**
 * @function
 *
 * Initializes |*deflater_ptr| for deflating name/values pairs.
 *
 * The |deflate_hd_table_bufsize_max| is the upper bound of header
 * table size the deflater will use.
 *
 * If this function fails, |*deflater_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_hd_deflate_new(http2_hd_deflater **deflater_ptr,
                           size_t deflate_hd_table_bufsize_max);

/**
 * @function
 *
 * Like `http2_hd_deflate_new()`, but with additional custom memory
 * allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `http2_hd_deflate_new()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 */
ErrorCode http2_hd_deflate_new2(http2_hd_deflater **deflater_ptr,
                            size_t deflate_hd_table_bufsize_max,
                            http2_mem *mem);

/**
 * @function
 *
 * Deallocates any resources allocated for |deflater|.
 */
void http2_hd_deflate_del(http2_hd_deflater *deflater);

/**
 * @function
 *
 * Changes header table size of the |deflater| to
 * |settings_hd_table_bufsize_max| bytes.  This may trigger eviction
 * in the dynamic table.
 *
 * The |settings_hd_table_bufsize_max| should be the value received in
 * SETTINGS_HEADER_TABLE_SIZE.
 *
 * The deflater never uses more memory than
 * ``deflate_hd_table_bufsize_max`` bytes specified in
 * `http2_hd_deflate_new()`.  Therefore, if
 * |settings_hd_table_bufsize_max| > ``deflate_hd_table_bufsize_max``,
 * resulting maximum table size becomes
 * ``deflate_hd_table_bufsize_max``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_hd_deflate_change_table_size(http2_hd_deflater *deflater,
                                         size_t settings_hd_table_bufsize_max);

/**
 * @function
 *
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the |buf| of length |buflen|.
 *
 * If |buf| is not large enough to store the deflated header block,
 * this function fails with $(D ErrorCode.INSUFF_BUFSIZE).  The
 * caller should use `http2_hd_deflate_bound()` to know the upper
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
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.HEADER_COMP)
 *     Deflation process has failed.
 * $(D ErrorCode.INSUFF_BUFSIZE)
 *     The provided |buflen| size is too small to hold the output.
 */
ErrorCode http2_hd_deflate_hd(http2_hd_deflater *deflater, ubyte[] buf, in NVPair[] nva);

/**
 * @function
 *
 * Returns an upper bound on the compressed size after deflation of
 * |nva| of length |nvlen|.
 */
size_t http2_hd_deflate_bound(http2_hd_deflater *deflater,
                                const http2_nv *nva, size_t nvlen);

/**
 * @function
 *
 * Initializes |*inflater_ptr| for inflating name/values pairs.
 *
 * If this function fails, |*inflater_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_hd_inflate_new(http2_hd_inflater **inflater_ptr);

/**
 * @function
 *
 * Like `http2_hd_inflate_new()`, but with additional custom memory
 * allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `http2_hd_inflate_new()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 */
ErrorCode http2_hd_inflate_new2(http2_hd_inflater **inflater_ptr,
                            http2_mem *mem);

/**
 * @function
 *
 * Deallocates any resources allocated for |inflater|.
 */
void http2_hd_inflate_del(http2_hd_inflater *inflater);

/**
 * @function
 *
 * Changes header table size in the |inflater|.  This may trigger
 * eviction in the dynamic table.
 *
 * The |settings_hd_table_bufsize_max| should be the value transmitted
 * in SETTINGS_HEADER_TABLE_SIZE.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 */
ErrorCode http2_hd_inflate_change_table_size(http2_hd_inflater *inflater,
                                         size_t settings_hd_table_bufsize_max);

/**
 * @function
 *
 * Inflates name/value block stored in |in| with length |inlen|.  This
 * function performs decompression.  For each successful emission of
 * header name/value pair, $(D HTTP2_HD_INFLATE_EMIT) is set in
 * |*inflate_flags| and name/value pair is assigned to the |nv_out|
 * and the function returns.  The caller must not free the members of
 * |nv_out|.
 *
 * The |nv_out| may include pointers to the memory region in the |in|.
 * The caller must retain the |in| while the |nv_out| is used.
 *
 * The application should call this function repeatedly until the
 * ``(*inflate_flags) & HTTP2_HD_INFLATE_FINAL`` is nonzero and
 * return value is non-negative.  This means the all input values are
 * processed successfully.  Then the application must call
 * `http2_hd_inflate_end_headers()` to prepare for the next header
 * block input.
 *
 * The caller can feed complete compressed header block.  It also can
 * feed it in several chunks.  The caller must set |in_final| to
 * true if the given input is the last block of the compressed
 * header.
 *
 * This function returns the number of bytes processed if it succeeds,
 * or one of the following negative error codes:
 *
 * $(D ErrorCode.NOMEM)
 *     Out of memory.
 * $(D ErrorCode.HEADER_COMP)
 *     Inflation process has failed.
 * $(D ErrorCode.BUFFER_ERROR)
 *     The heder field name or value is too large.
 *
 * Example follows::
 *
 *     int inflate_header_block(http2_hd_inflater *hd_inflater,
 *                              ubyte *in, size_t inlen, int final)
 *     {
 *         size_t rv;
 *
 *         for(;;) {
 *             http2_nv nv;
 *             int inflate_flags = 0;
 *
 *             rv = http2_hd_inflate_hd(hd_inflater, &nv, &inflate_flags,
 *                                        in, inlen, final);
 *
 *             if(rv < 0) {
 *                 fprintf(stderr, "inflate failed with error code %zd", rv);
 *                 return -1;
 *             }
 *
 *             in += rv;
 *             inlen -= rv;
 *
 *             if(inflate_flags & HTTP2_HD_INFLATE_EMIT) {
 *                 fwrite(nv.name, nv.namelen, 1, stderr);
 *                 fprintf(stderr, ": ");
 *                 fwrite(nv.value, nv.valuelen, 1, stderr);
 *                 fprintf(stderr, "\n");
 *             }
 *             if(inflate_flags & HTTP2_HD_INFLATE_FINAL) {
 *                 http2_hd_inflate_end_headers(hd_inflater);
 *                 break;
 *             }
 *             if((inflate_flags & HTTP2_HD_INFLATE_EMIT) == 0 &&
 *                inlen == 0) {
 *                break;
 *             }
 *         }
 *
 *         return 0;
 *     }
 *
 */
size_t http2_hd_inflate_hd(http2_hd_inflater *inflater, Vector!NVPair nv_out, ref InflateFlag inflate_flags, ubyte[] input, bool in_final);

/**
 * @function
 *
 * Signals the end of decompression for one header block.
 *
 * This function returns 0 if it succeeds. Currently this function
 * always succeeds.
 */
void http2_hd_inflate_end_headers(http2_hd_inflater *inflater);



/*
 * Returns true if |stream_id| is initiated by local endpoint.
 */
bool nghttp2_session_is_my_stream_id(Session session,
	int32_t stream_id);

/*
 * Initializes |item|.  No memory allocation is done in this function.
 * Don't call nghttp2_outbound_item_free() until frame member is
 * initialized.
 */
void nghttp2_session_outbound_item_init(Session session,
	nghttp2_outbound_item *item);

/*
 * Adds |item| to the outbound queue in |session|.  When this function
 * succeeds, it takes ownership of |item|. So caller must not free it
 * on success.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.STREAM_CLOSED
 *     Stream already closed (DATA frame only)
 */
ErrorCode nghttp2_session_add_item(Session session,
	nghttp2_outbound_item *item);

/*
 * Adds RST_STREAM frame for the stream |stream_id| with the error
 * code |error_code|. This is a convenient function built on top of
 * nghttp2_session_add_frame() to add RST_STREAM easily.
 *
 * This function simply returns 0 without adding RST_STREAM frame if
 * given stream is in NGHTTP2_STREAM_CLOSING state, because multiple
 * RST_STREAM for a stream is redundant.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 */
ErrorCode nghttp2_session_add_rst_stream(Session session, int32_t stream_id,
	uint32_t error_code);

/*
 * Adds PING frame. This is a convenient functin built on top of
 * nghttp2_session_add_frame() to add PING easily.
 *
 * If the |opaque_data| is not NULL, it must point to 8 bytes memory
 * region of data. The data pointed by |opaque_data| is copied. It can
 * be NULL. In this case, 8 bytes NULL is used.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 */
ErrorCode nghttp2_session_add_ping(Session session, uint8_t flags,
	const uint8_t *opaque_data);

/*
 * Adds GOAWAY frame with the last-stream-ID |last_stream_id| and the
 * error code |error_code|. This is a convenient function built on top
 * of nghttp2_session_add_frame() to add GOAWAY easily.  The
 * |aux_flags| are bitwise-OR of one or more of
 * nghttp2_goaway_aux_flag.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.INVALID_ARGUMENT
 *     The |opaque_data_len| is too large.
 */
ErrorCode nghttp2_session_add_goaway(Session session, int32_t last_stream_id,
	uint32_t error_code, const uint8_t *opaque_data,
	size_t opaque_data_len, uint8_t aux_flags);

/*
 * Adds WINDOW_UPDATE frame with stream ID |stream_id| and
 * window-size-increment |window_size_increment|. This is a convenient
 * function built on top of nghttp2_session_add_frame() to add
 * WINDOW_UPDATE easily.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 */
ErrorCode nghttp2_session_add_window_update(Session session, uint8_t flags,
	int32_t stream_id,
	int32_t window_size_increment);

/*
 * Adds SETTINGS frame.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 */
ErrorCode nghttp2_session_add_settings(Session session, uint8_t flags,
	const nghttp2_settings_entry *iv, size_t niv);

/*
 * Creates new stream in |session| with stream ID |stream_id|,
 * priority |pri_spec| and flags |flags|.  The |flags| is bitwise OR
 * of nghttp2_stream_flag.  Since this function is called when initial
 * HEADERS is sent or received, these flags are taken from it.  The
 * state of stream is set to |initial_state|. The |stream_user_data|
 * is a pointer to the arbitrary user supplied data to be associated
 * to this stream.
 *
 * If |initial_state| is NGHTTP2_STREAM_RESERVED, this function sets
 * NGHTTP2_STREAM_FLAG_PUSH flag set.
 *
 * This function returns a pointer to created new stream object, or
 * NULL.
 */
Stream nghttp2_session_open_stream(Session session,
	int32_t stream_id, uint8_t flags,
	PrioritySpec pri_spec,
	nghttp2_stream_state initial_state,
	void *stream_user_data);

/*
 * Closes stream whose stream ID is |stream_id|. The reason of closure
 * is indicated by the |error_code|. When closing the stream,
 * on_stream_close_callback will be called.
 *
 * If the session is initialized as server and |stream| is incoming
 * stream, stream is just marked closed and this function calls
 * nghttp2_session_keep_closed_stream() with |stream|.  Otherwise,
 * |stream| will be deleted from memory.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory
 * ErrorCode.INVALID_ARGUMENT
 *     The specified stream does not exist.
 * ErrorCode.CALLBACK_FAILURE
 *     The callback function failed.
 */
ErrorCode nghttp2_session_close_stream(Session session, int32_t stream_id,
	uint32_t error_code);

/*
 * Deletes |stream| from memory.  After this function returns, stream
 * cannot be accessed.
 *
 */
void nghttp2_session_destroy_stream(Session session,
	Stream stream);

/*
 * Tries to keep incoming closed stream |stream|.  Due to the
 * limitation of maximum number of streams in memory, |stream| is not
 * closed and just deleted from memory (see
 * nghttp2_session_destroy_stream).
 */
void nghttp2_session_keep_closed_stream(Session session,
	Stream stream);

/*
 * Appends |stream| to linked list |session->idle_stream_head|.  We
 * apply fixed limit for list size.  To fit into that limit, one or
 * more oldest streams are removed from list as necessary.
 */
void nghttp2_session_keep_idle_stream(Session session,
	Stream stream);

/*
 * Detaches |stream| from idle streams linked list.
 */
void nghttp2_session_detach_idle_stream(Session session,
	Stream stream);

/*
 * Deletes closed stream to ensure that number of incoming streams
 * including active and closed is in the maximum number of allowed
 * stream.  If |offset| is nonzero, it is decreased from the maximum
 * number of allowed stream when comparing number of active and closed
 * stream and the maximum number.
 */
void nghttp2_session_adjust_closed_stream(Session session,
	ssize_t offset);

/*
 * Deletes idle stream to ensure that number of idle streams is in
 * certain limit.
 */
void nghttp2_session_adjust_idle_stream(Session session);

/*
 * If further receptions and transmissions over the stream |stream_id|
 * are disallowed, close the stream with error code NGHTTP2_NO_ERROR.
 *
 * This function returns 0 if it
 * succeeds, or one of the following negative error codes:
 *
 * ErrorCode.INVALID_ARGUMENT
 *     The specified stream does not exist.
 */
ErrorCode nghttp2_session_close_stream_if_shut_rdwr(Session session,
	Stream stream);

ErrorCode nghttp2_session_end_request_headers_received(Session session,
	nghttp2_frame *frame,
	Stream stream);

ErrorCode nghttp2_session_end_response_headers_received(Session session,
	nghttp2_frame *frame,
	Stream stream);

ErrorCode nghttp2_session_end_headers_received(Session session,
	nghttp2_frame *frame,
	Stream stream);

ErrorCode nghttp2_session_on_request_headers_received(Session session,
	nghttp2_frame *frame);

ErrorCode nghttp2_session_on_response_headers_received(Session session,
	nghttp2_frame *frame,
	Stream stream);

ErrorCode nghttp2_session_on_push_response_headers_received(Session session,
	nghttp2_frame *frame,
	Stream stream);

/*
 * Called when HEADERS is received, assuming |frame| is properly
 * initialized.  This function does first validate received frame and
 * then open stream and call callback functions.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.IGN_HEADER_BLOCK
 *     Frame was rejected and header block must be decoded but
 *     result must be ignored.
 * ErrorCode.CALLBACK_FAILURE
 *     The read_callback failed
 */
ErrorCode nghttp2_session_on_headers_received(Session session,
	nghttp2_frame *frame,
	Stream stream);

/*
 * Called when PRIORITY is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.CALLBACK_FAILURE
 *     The read_callback failed
 */
ErrorCode nghttp2_session_on_priority_received(Session session,
	nghttp2_frame *frame);

/*
 * Called when RST_STREAM is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory
 * ErrorCode.CALLBACK_FAILURE
 *     The read_callback failed
 */
ErrorCode nghttp2_session_on_rst_stream_received(Session session,
	nghttp2_frame *frame);

/*
 * Called when SETTINGS is received, assuming |frame| is properly
 * initialized. If |noack| is non-zero, SETTINGS with ACK will not be
 * submitted. If |frame| has NGFrameFlags.ACK flag set, no SETTINGS
 * with ACK will not be submitted regardless of |noack|.
 *
 * This function returns 0 if it succeeds, or one the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory
 * ErrorCode.CALLBACK_FAILURE
 *     The read_callback failed
 */
ErrorCode nghttp2_session_on_settings_received(Session session,
	nghttp2_frame *frame, int noack);

/*
 * Called when PUSH_PROMISE is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.IGN_HEADER_BLOCK
 *     Frame was rejected and header block must be decoded but
 *     result must be ignored.
 * ErrorCode.CALLBACK_FAILURE
 *     The read_callback failed
 */
ErrorCode nghttp2_session_on_push_promise_received(Session session,
	nghttp2_frame *frame);

/*
 * Called when PING is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.CALLBACK_FAILURE
 *   The callback function failed.
 */
ErrorCode nghttp2_session_on_ping_received(Session session,
	nghttp2_frame *frame);

/*
 * Called when GOAWAY is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.CALLBACK_FAILURE
 *   The callback function failed.
 */
ErrorCode nghttp2_session_on_goaway_received(Session session,
	nghttp2_frame *frame);

/*
 * Called when WINDOW_UPDATE is recieved, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.CALLBACK_FAILURE
 *   The callback function failed.
 */
ErrorCode nghttp2_session_on_window_update_received(Session session,
	nghttp2_frame *frame);

/*
 * Called when DATA is received, assuming |frame| is properly
 * initialized.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.CALLBACK_FAILURE
 *   The callback function failed.
 */
ErrorCode nghttp2_session_on_data_received(Session session,
	nghttp2_frame *frame);

/*
 * Returns nghttp2_stream* object whose stream ID is |stream_id|.  It
 * could be NULL if such stream does not exist.  This function returns
 * NULL if stream is marked as closed.
 */
Stream nghttp2_session_get_stream(Session session,
	int32_t stream_id);

/*
 * This function behaves like nghttp2_session_get_stream(), but it
 * returns stream object even if it is marked as closed or in
 * NGHTTP2_STREAM_IDLE state.
 */
Stream nghttp2_session_get_stream_raw(Session session,
	int32_t stream_id);

/*
 * Packs DATA frame |frame| in wire frame format and stores it in
 * |bufs|.  Payload will be read using |aux_data->data_prd|.  The
 * length of payload is at most |datamax| bytes.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.DEFERRED
 *     The DATA frame is postponed.
 * ErrorCode.TEMPORAL_CALLBACK_FAILURE
 *     The read_callback failed (stream error).
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.CALLBACK_FAILURE
 *     The read_callback failed (session error).
 */
ErrorCode nghttp2_session_pack_data(Session session, nghttp2_bufs *bufs,
	size_t datamax, nghttp2_frame *frame,
	nghttp2_data_aux_data *aux_data);

/*
 * Returns top of outbound frame queue. This function returns NULL if
 * queue is empty.
 */
nghttp2_outbound_item *nghttp2_session_get_ob_pq_top(Session session);

/*
 * Pops and returns next item to send. If there is no such item,
 * returns NULL.  This function takes into account max concurrent
 * streams. That means if session->ob_pq is empty but
 * session->ob_ss_pq has item and max concurrent streams is reached,
 * then this function returns NULL.
 */
nghttp2_outbound_item *
	nghttp2_session_pop_next_ob_item(Session session);

/*
 * Returns next item to send. If there is no such item, this function
 * returns NULL.  This function takes into account max concurrent
 * streams. That means if session->ob_pq is empty but
 * session->ob_ss_pq has item and max concurrent streams is reached,
 * then this function returns NULL.
 */
nghttp2_outbound_item *
	nghttp2_session_get_next_ob_item(Session session);

/*
 * Updates local settings with the |iv|. The number of elements in the
 * array pointed by the |iv| is given by the |niv|.  This function
 * assumes that the all settings_id member in |iv| are in range 1 to
 * NGHTTP2_SETTINGS_MAX, inclusive.
 *
 * While updating individual stream's local window size, if the window
 * size becomes strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
 * RST_STREAM is issued against such a stream.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory
 */
ErrorCode nghttp2_session_update_local_settings(Session session,
	nghttp2_settings_entry *iv,
	size_t niv);

/*
 * Re-prioritize |stream|. The new priority specification is
 * |pri_spec|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory
 */
ErrorCode nghttp2_session_reprioritize_stream(Session session, Stream stream, in PrioritySpec pri_spec);

/*
 * Terminates current |session| with the |error_code|.  The |reason|
 * is NULL-terminated debug string.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * ErrorCode.NOMEM
 *     Out of memory.
 * ErrorCode.INVALID_ARGUMENT
 *     The |reason| is too long.
 */
ErrorCode nghttp2_session_terminate_session_with_reason(Session session,
	uint32_t error_code,
	const char *reason);


private:

/*
 * Returns non-zero if the number of outgoing opened streams is larger
 * than or equal to
 * remote_settings.max_concurrent_streams.
 */
bool session_is_outgoing_concurrent_streams_max(Session session) {
    return session->remote_settings.max_concurrent_streams <=
        session->num_outgoing_streams;
}

/*
 * Returns non-zero if the number of incoming opened streams is larger
 * than or equal to
 * local_settings.max_concurrent_streams.
 */
bool session_is_incoming_concurrent_streams_max(Session session) {
    return session->local_settings.max_concurrent_streams <=
        session->num_incoming_streams;
}

/*
 * Returns non-zero if the number of incoming opened streams is larger
 * than or equal to
 * session->pending_local_max_concurrent_stream.
 */
bool session_is_incoming_concurrent_streams_pending_max(Session session) {
    return session->pending_local_max_concurrent_stream <=
        session->num_incoming_streams;
}

/*
 * Returns non-zero if |lib_error| is non-fatal error.
 */
bool is_non_fatal(int lib_error) {
    return lib_error < 0 && lib_error > NGHTTP2_ERR_FATAL;
}

bool http2_is_fatal(int lib_error) { return lib_error < NGHTTP2_ERR_FATAL; }

bool session_enforce_http_messaging(Session session) {
    return (session->opt_flags & NGHTTP2_OPTMASK_NO_HTTP_MESSAGING) == 0;
}

/*
 * Returns nonzero if |frame| is trailer headers.
 */
bool session_trailer_headers(Session session,
    nghttp2_stream *stream,
    nghttp2_frame *frame) {
    if (!stream || frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }
    if (session->server) {
        return frame->headers.cat == NGHTTP2_HCAT_HEADERS;
    }
    
    return frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
        (stream->http_flags & NGHTTP2_HTTP_FLAG_EXPECT_FINAL_RESPONSE) == 0;
}

/* Returns nonzero if the |stream| is in reserved(remote) state */
bool state_reserved_remote(Session session,
    nghttp2_stream *stream) {
    return stream->state == NGHTTP2_STREAM_RESERVED &&
        !nghttp2_session_is_my_stream_id(session, stream->stream_id);
}

/* Returns nonzero if the |stream| is in reserved(local) state */
bool state_reserved_local(Session session,
    nghttp2_stream *stream) {
    return stream->state == NGHTTP2_STREAM_RESERVED &&
        nghttp2_session_is_my_stream_id(session, stream->stream_id);
}

/*
 * Checks whether received stream_id is valid.  This function returns
 * 1 if it succeeds, or 0.
 */
bool session_is_new_peer_stream_id(Session session,
    int32_t stream_id) {
    return stream_id != 0 &&
        !nghttp2_session_is_my_stream_id(session, stream_id) &&
            session->last_recv_stream_id < stream_id;
}
