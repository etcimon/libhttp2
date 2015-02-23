module libhttp2.policy;

import libhttp2.types;
import libhttp2.frame;
import libhttp2.session;

alias HTTP2SessionPolicy = Policy;

package:
interface Policy
{
    /**
     * Callback function invoked when |session| wants to send data to the
     * remote peer.  The implementation of this function must send at most
     * |length| bytes of data stored in |data|.  
     * It must return the number of bytes sent if
     * it succeeds.  If it cannot send any single byte without blocking,
     * it must return $(D ErrorCode.WOULDBLOCK).  For other errors,
     * it must return $(D ErrorCode.CALLBACK_FAILURE).  
     *
     * This callback is required if the application uses
     * `http2_session_send()` to send data to the remote endpoint.  If
     * the application uses solely `http2_session_mem_send()` instead,
     * this callback function is unnecessary.
     */
    size_t write(Session session, in ubyte[] data);
    
    /**
     * Callback function invoked when |session| wants to receive data from
     * the remote peer.  The implementation of this function must read at
     * most |length| bytes of data and store it in |buf|.  
     * 
     * It must return the number of
     * bytes written in |buf| if it succeeds.  If it cannot read any
     * single byte without blocking, it must return
     * $(D ErrorCode.WOULDBLOCK).  If it gets EOF before it reads any
     * single byte, it must return $(D ErrorCode.EOF).  For other
     * errors, it must return $(D ErrorCode.CALLBACK_FAILURE).
     * Returning 0 is treated as $(D ErrorCode.WOULDBLOCK). 
     *
     * This callback is required if the application uses
     * `http2_session_recv()` to receive data from the remote endpoint.
     * If the application uses solely `http2_session_mem_recv()`
     * instead, this callback function is unnecessary.
     */
    size_t read(Session session, ref ubyte[] data);

    /**
     * Callback function invoked by `http2_session_recv()` when a frame
     * is received.  The |user_data| pointer is the third argument passed
     * in to the call to `http2_session_client_new()` or
     * `http2_session_server_new()`.
     *
     * If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
     * member of their data structure are always ``NULL`` and 0
     * respectively.  The header name/value pairs are emitted via
     * :type:`http2_on_header_callback`.
     *
     * For HEADERS, PUSH_PROMISE and DATA frames, this callback may be
     * called after stream is closed (see :type:`http2_on_stream_close_callback`). 
     *
     * Only HEADERS and DATA frame can signal the end of incoming data.
     * If ``frame->hd.flags & FrameFlags.END_STREAM`` is nonzero, the
     * |frame| is the last frame from the remote peer in this stream.
     *
     * This callback won't be called for CONTINUATION frames.
     * HEADERS/PUSH_PROMISE + CONTINUATIONs are treated as single frame.
     *
     * If nonzero value is returned, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_mem_recv()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrame(Session session, const Frame frame);

    /**
     * Callback function invoked by `http2_session_recv()` when an
     * invalid non-DATA frame is received.  The |error_code| indicates the
     * error.  It is usually one of the $(D FrameError) but
     * that is not guaranteed.  When this callback function is invoked,
     * the library automatically submits either RST_STREAM or GOAWAY
     * frame.  
     *
     * If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
     * member of their data structure are always ``NULL`` and 0
     * respectively.
     *
     * If this callback returns false, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_send()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onInvalidFrame(Session session, const Frame frame, FrameError error_code);


    /**
     * Callback function invoked when a chunk of data in DATA frame is
     * received.  The |stream_id| is the stream ID this DATA frame belongs
     * to.  The |flags| is the flags of DATA frame which this data chunk
     * is contained.  ``(flags & FrameFlags.END_STREAM) != 0`` does not
     * necessarily mean this chunk of data is the last one in the stream.
     * You should use :type:`http2_on_frame_recv_callback` to know all
     * data frames are received. 
     *
     * If the application uses `http2_session_mem_recv()`, it can return
     * $(D ErrorCode.PAUSE) to make `http2_session_mem_recv()`
     * return without processing further input bytes.  The memory by
     * pointed by the |data| is retained until
     * `http2_session_mem_recv()` or `http2_session_recv()` is called.
     * The application must retain the input bytes which was used to
     * produce the |data| parameter, because it may refer to the memory
     * region included in the input bytes.
     *
     * If this callback returns false, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_mem_recv()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onDataChunk(Session session, FrameFlags flags, in Stream stream, in ubyte[] data);

    /**
     * Callback function invoked just before the non-DATA frame |frame| is
     * sent.  
     *
     * The implementation of this function must return true if it succeeds.
     * If this callback returns false, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_send()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrameReady(Session session, const Frame frame);

    /**
     * Callback function invoked when a frame header is received.  The
     * |hd| points to received frame header.
     *
     * Unlike :type:`http2_on_frame_recv_callback`, this callback will
     * also be called when frame header of CONTINUATION frame is received.
     *
     * If both :type:`http2_on_begin_frame_callback` and
     * :type:`http2_on_begin_headers_callback` are set and HEADERS or
     * PUSH_PROMISE is received, :type:`http2_on_begin_frame_callback`
     * will be called first.
     *
     * The implementation of this function must return true if it succeeds.
     * If nonzero value is returned, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_mem_recv()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrameHeader(Session session, const FrameHeader hd);

    /**
     * Callback function invoked after the frame |frame| is sent.  
     * 
     * If this callback returns false, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_send()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrameSent(Session session, const Frame frame);

    /**
     * Callback function invoked after the non-DATA frame |frame| is not
     * sent because of the error.  The error is indicated by the
     * |error_code|, which is one of the values defined in
     * $(D ErrorCode).  
     *
     * If this callback returns false, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_send()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrameFailure(Session session, const Frame frame, ErrorCode error_code);

    /**
     * Callback function invoked when the stream |stream_id| is closed.
     * The reason of closure is indicated by the |error_code|.  The
     * |error_code| is usually one of $(D ErrorCode), but that
     * is not guaranteed. 
     *
     * This function is also called for a stream in reserved state.
     *
     * If this callback returns false, it is treated as fatal error and
     * `http2_session_recv()` and `http2_session_send()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onStreamExit(Session session, in Stream stream, ErrorCode error_code);

    /**
     * Callback function invoked when the reception of header block in
     * HEADERS or PUSH_PROMISE is started.  Each header name/value pair
     * will be emitted by :type:`http2_on_header_callback`.
     *
     * The ``frame->hd.flags`` may not have
     * $(D FrameFlags.END_HEADERS) flag set, which indicates that one
     * or more CONTINUATION frames are involved.  But the application does
     * not need to care about that because the header name/value pairs are
     * emitted transparently regardless of CONTINUATION frames.
     *
     * If this callback returns false, stream fails with `ErrorCode.CALLBACK_FAILURE`
     */
    bool onHeaders(Session session, in Frame frame);

    /**
     * Callback function invoked when a header name/value pair is received
     * for the |frame|.  The |name| of length |namelen| is header name.
     * The |value| of length |valuelen| is header value.  The |flags| is
     * bitwise OR of one or more of :type:`http2_nv_flag`.
     *
     * If $(D HTTP2_NV_FLAG_NO_INDEX) is set in |flags|, the receiver
     * must not index this name/value pair when forwarding it to the next
     * hop.  More specifically, "Literal Header Field never Indexed"
     * representation must be used in HPACK encoding.
     *
     * When this callback is invoked, ``frame->hd.type`` is either
     * $(D FrameFlags.HEADERS) or $(D FrameFlags.PUSH_PROMISE).  After all
     * header name/value pairs are processed with this callback, and no
     * error has been detected, :type:`http2_on_frame_recv_callback`
     * will be invoked.  If there is an error in decompression,
     * :type:`http2_on_frame_recv_callback` for the |frame| will not be
     * invoked.
     *
     * The |value| may be ``NULL`` if the |valuelen| is 0.
     *
     * Please note that unless `http2_option_set_no_http_messaging()` is
     * used, nghttp2 library does perform validation against the |name|
     * and the |value| using `http2_check_header_name()` and
     * `http2_check_header_value()`.  In addition to this, libhttp2
     * performs vaidation based on HTTP Messaging rule, which is briefly
     * explained in `HTTP Messaging`_ section.
     *
     * If the application uses `http2_session_mem_recv()`, it can return
     * $(D ErrorCode.PAUSE) to make `http2_session_mem_recv()`
     * return without processing further input bytes.  The memory pointed
     * by |frame|, |name| and |value| parameters are retained until
     * `http2_session_mem_recv()` or `http2_session_recv()` is called.
     * The application must retain the input bytes which was used to
     * produce these parameters, because it may refer to the memory region
     * included in the input bytes.
     *
     * Returning $(D ErrorCode.TEMPORAL_CALLBACK_FAILURE) will close
     * the stream by issuing RST_STREAM with
     * $(D HTTP2_INTERNAL_ERROR).  In this case,
     * :type:`http2_on_frame_recv_callback` will not be invoked.  If a
     * different error code is desirable, use
     * `http2_submit_rst_stream()` with a desired error code and then
     * return $(D ErrorCode.TEMPORAL_CALLBACK_FAILURE).
     *
     * The implementation of this function must return true if it succeeds.
     * It may return $(D ErrorCode.PAUSE) or
     * $(D ErrorCode.TEMPORAL_CALLBACK_FAILURE).  For other critical
     * failures, it must return $(D ErrorCode.CALLBACK_FAILURE).  If
     * the other nonzero value is returned, it is treated as
     * $(D ErrorCode.CALLBACK_FAILURE).  If
     * $(D ErrorCode.CALLBACK_FAILURE) is returned,
     * `http2_session_recv()` and `http2_session_mem_recv()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    ErrorCode onHeader(Session session, const Frame frame, in ubyte[] name, in ubyte[] value, ubyte flags);

    /**
     * Callback function invoked when the library asks application how
     * many padding bytes are required for the transmission of the
     * |frame|.  The application must choose the total length of payload
     * including padded bytes in range [frame->hd.length, max_payloadlen],
     * inclusive.  Choosing number not in this range will be treated as
     * $(D ErrorCode.CALLBACK_FAILURE).  Returning
     * ``frame->hd.length`` means no padding is added.  Returning
     * $(D ErrorCode.CALLBACK_FAILURE) will make
     * `http2_session_send()` function immediately return
     * $(D ErrorCode.CALLBACK_FAILURE).
     */
    size_t selectPaddingLength(Session session, const Frame frame, size_t max_payloadlen);

    /**
     * Callback function invoked when library wants to get max length of
     * data to send data to the remote peer.  The implementation of this
     * function should return a value in the following range.  [1,
     * min(|session_remote_window_size|, |stream_remote_window_size|,
     * |remote_max_frame_size|)].  If a value greater than this range is
     * returned than the max allow value will be used.  Returning a value
     * smaller than this range is treated as
     * $(D ErrorCode.CALLBACK_FAILURE).  The |frame_type| is provided
     * for future extensibility and identifies the type of frame (see
     * :type:`http2_frame_type`) for which to get the length for.
     * Currently supported frame types are: $(D HTTP2_DATA).
     *
     * This callback can be used to control the length in bytes for which
     * :type:`http2_data_source_read_callback` is allowed to send to the
     * remote endpoint.  This callback is optional.  Returning
     * $(D ErrorCode.CALLBACK_FAILURE) will signal the entire session
     * failure..
     */
    size_t maxFrameSize(Session session, FrameType frame_type, Stream stream, 
                        int session_remote_window_size, int stream_remote_window_size, 
                        uint remote_max_frame_size);


}