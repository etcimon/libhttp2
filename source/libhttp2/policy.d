module libhttp2.policy;

import libhttp2.types;
import libhttp2.frame;
import libhttp2.session;

alias HTTP2SessionPolicy = Policy;

package:
abstract class Policy
{

////////////////// Protocol ////////////////////////

    /**
     * Callback function invoked when Session wants to send data to the
     * remote peer.  The implementation of this function must send at most
     * |data.length| bytes of data stored in |data|.  
     * It must return the number of bytes sent if
     * it succeeds.  If it cannot send any single byte without blocking,
     * it must return $(D ErrorCode.WOULDBLOCK).  For other errors,
     * it must return $(D ErrorCode.CALLBACK_FAILURE).  
     *
     * This callback is required if the application uses
     * $(D Session.send) to send data to the remote endpoint.  If
     * the application uses solely $(D Session.memSend) instead,
     * this callback function is unnecessary.
     */
    int write(in ubyte[] data);
    
    /**
     * Callback function invoked when Session wants to receive data from
     * the remote peer.  The implementation of this function must read at
     * most |data.length| bytes of data and store it in |data|.  
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
     * $(D Session.recv) to receive data from the remote endpoint.
     * If the application uses solely `http2_session_mem_recv()`
     * instead, this callback function is unnecessary.
     */
    int read(out ubyte[] data);

	/**
     * Callback function invoked when the stream |stream_id| is closed.
     * The reason of closure is indicated by the |error_code|.  The
     * |error_code| is usually one of $(D ErrorCode), but that
     * is not guaranteed. 
     *
     * This function is also called for a stream in reserved state.
     *
     * If this callback returns false, it is treated as fatal error and
     * $(D Session.recv) and $(D Session.send) functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
	bool onStreamExit(int stream_id, ErrorCode error_code);

/////////////////// Receiving ////////////////////////

    /**
     * Callback function invoked by $(D Session.recv) when a frame
     * is received.  The |user_data| pointer is the third argument passed
     * in to the call to `http2_session_client_new()` or
     * `http2_session_server_new()`.
     *
     * If frame is HEADERS or PUSH_PROMISE, the ``nva`` 
     * member of their data structure are always ``NULL`` and 0
     * respectively.  The header fields are emitted via
     * $(D onFrameHeader).
     *
     * For HEADERS, PUSH_PROMISE and DATA frames, this callback may be
     * called after stream is closed (see :type:`http2_on_stream_close_callback`). 
     *
     * Only HEADERS and DATA frame can signal the end of incoming data.
     * If ``frame.hd.flags & FrameFlags.END_STREAM`` is nonzero, the
     * |frame| is the last frame from the remote peer in this stream.
     *
     * This callback won't be called for CONTINUATION frames.
     * HEADERS/PUSH_PROMISE + CONTINUATIONs are treated as single frame.
     *
     * If false value is returned, it is treated as fatal error and
     * $(D Session.recv) and $(D Session.memRecv) functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrame(in Frame frame);

	/**
     * Callback function invoked when a frame header is received.  The
     * |hd| points to received frame header.
     *
     * Unlike $(D Policy.onFrame), this callback will
     * also be called when frame header of CONTINUATION frame is received.
     *
     * If both $(D Policy.onFrameHeader) and
     * :type:`http2_on_begin_headers_callback` are set and HEADERS or
     * PUSH_PROMISE is received, :type:`http2_on_begin_frame_callback`
     * will be called first.
     *
     * The implementation of this function must return true if it succeeds.
     * If false value is returned, it is treated as fatal error and
     * $(D Session.recv) and `http2_session_mem_recv()` functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
	bool onFrameHeader(in FrameHeader hd);

	/**
     * Callback function invoked when the reception of header block in
     * HEADERS or PUSH_PROMISE is started.  Each header header field
     * will be emitted by :type:`http2_on_header_callback`.
     *
     * The ``frame.hd.flags`` may not have
     * $(D FrameFlags.END_HEADERS) flag set, which indicates that one
     * or more CONTINUATION frames are involved.  But the application does
     * not need to care about that because the header fields are
     * emitted transparently regardless of CONTINUATION frames.
     *
     * If this callback returns false, stream fails with `ErrorCode.CALLBACK_FAILURE`
     */
	bool onHeaders(in Frame frame);


	/**
     * Callback function invoked when a header header field is received
     * for the |frame|.  The |hf.name| of length |hf.name.length| is header name.
     * The |hf.value| of length |hf.value.length| is header value.  The |hf.flags| 
     * is a $(D HeaderFlag).
     *
     * If $(D HeaderFlag.NO_INDEX) is set in |hf.flags|, the receiver
     * must not index this header field when forwarding it to the next
     * hop.  More specifically, "Literal Header Field never Indexed"
     * representation must be used in HPACK encoding.
     *
     * When this callback is invoked, $(D frame.hd.type) is either
     * $(D FrameFlags.HEADERS) or $(D FrameFlags.PUSH_PROMISE).  After all
     * header fields are processed with this callback, and no
     * error has been detected, $(D Policy.onFrame) will be invoked.  
     * If there is an error in decompression, $(D Policy.onFrame) for the |frame| 
     * will not be invoked.
     *
     * The |value| may be null if the |value.length| is 0.
     *
     * Please note that unless `http2_option_set_no_http_messaging()` is
     * used, nghttp2 library does perform validation against |hf.name|
     * and |hf.value| using `hf.validateName()` and
     * `hf.validateValue()`.  In addition to this, libhttp2
     * performs vaidation based on HTTP Messaging rule, which is briefly
     * explained in `HTTP Messaging`_ section.
     *
     * If the application uses $(D Session.memRecv), it can enable
     * $(D pause) to make $(D Session.memRecv) return without processing 
     * further input bytes.  The memory pointed by |frame|, |name| and |value|
     * parameters are retained until $(D Session.memRecv) or $(D Session.recv) is called.
     * The application must retain the input bytes which was used to
     * produce these parameters, because it may refer to the memory region
     * included in the input bytes.
     *
     * Enabling $(D rst_stream) will close  the stream by issuing RST_STREAM with 
     * $(D FrameError.INTERNAL_ERROR).  In this case, $(D Policy.onFrame) will 
     * not be invoked.  If a different error code is desirable, use
     * `http2_submit_rst_stream()` with a desired error code and then
     * set $(D rst_stream) to true.
     *
     * The implementation of this function must return true if it succeeds.
     * If false is returned, it is treated as $(D ErrorCode.CALLBACK_FAILURE) and
     * in this case, $(D Session.recv) or $(D Session.memRecv) functions immediately 
     * return $(D ErrorCode.CALLBACK_FAILURE).
     */
	bool onHeaderField(in Frame frame, HeaderField hf, ref bool pause, ref bool rst_stream);

	/**
     * Callback function invoked when a chunk of data in DATA frame is
     * received.  The |stream_id| is the stream this DATA frame belongs
     * to. The |flags| is the flags of DATA frame which this data chunk
     * is contained.  ``(flags & FrameFlags.END_STREAM) != 0`` does not
     * necessarily mean this chunk of data is the last one in the stream.
     * You should use $(D Policy.onFrame) to determine that all data 
     * frames are received. 
     *
     * 
     * The memory pointed by the |data| is not copied within $(D Session.memRecv)
     * or $(D Session.recv), so the data provider controls its lifetime. This
     * can be either $(D Policy.read) for $(D Session.recv), or a $(D ubyte[])
     * slice from the one provided to $(D Session.memRecv)
     * 
     * If the application uses $(D Session.memRecv), it can set |pause|
     * to make $(D Session.memRecv) return without processing further input bytes. 
     * 
     * If the function returns false, $(D Session.memRecv) or $(D Session.recv)
     * would return with $(D ErrorCode.CALLBACK_FAILURE).
     */
	bool onDataChunk(FrameFlags flags, int stream_id, in ubyte[] data, ref bool pause);

    /**
     * Callback function invoked by $(D Session.recv) when an
     * invalid non-DATA frame is received.  The |error_code| indicates the
     * error.  It is usually one of the $(D FrameError) but
     * that is not guaranteed.  When this callback function is invoked,
     * the library automatically submits either RST_STREAM or GOAWAY
     * frame.  
     *
     * If frame is HEADERS or PUSH_PROMISE, the ``hfa``
     * member of thee data structure is always ``null``
     *
     * If this callback returns false, it is treated as fatal error and
     * $(D Session.recv) and $(D Session.send) functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onInvalidFrame(in Frame frame, FrameError error_code);

/////////////////// Sending /////////////////////////

	/**
     * Callback function invoked after the non-DATA frame |frame| is not
     * sent because of the error.  The error is indicated by the
     * |error_code|, which is one of the values defined in
     * $(D ErrorCode).  
     *
     * If this callback returns false, it is treated as fatal error and
     * $(D Session.recv) and $(D Session.send) functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
	bool onFrameFailure(in Frame frame, ErrorCode error_code);

    /**
     * Callback function invoked just before the non-DATA frame |frame| is
     * sent.  
     *
     * The implementation of this function must return true if it succeeds.
     * If this callback returns false, it is treated as fatal error and
     * $(D Session.recv) and $(D Session.send) functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrameReady(in Frame frame); // send

    /**
     * Callback function invoked after the frame |frame| is sent.  
     * 
     * If this callback returns false, it is treated as fatal error and
     * $(D Session.recv) and $(D Session.send) functions
     * immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    bool onFrameSent(in Frame frame); // send

    /**
     * Callback function invoked when the library asks application how
     * many padding bytes are required for the transmission of the
     * |frame|.  The application must choose the total length of payload
     * including padded bytes in range [frame.hd.length, max_payloadlen],
     * inclusive.  Choosing number not in this range will be treated as
     * $(D ErrorCode.CALLBACK_FAILURE).  Returning ``frame.hd.length`` 
     * means no padding is added.  Returning $(D ErrorCode.CALLBACK_FAILURE) will make
     * $(D Session.send()) function immediately return $(D ErrorCode.CALLBACK_FAILURE).
     */
    int selectPaddingLength(in Frame frame, int max_payloadlen)
	{
		return frame.hd.length;
	}

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
    int maxFrameSize(FrameType frame_type, int stream_id,  int session_remote_window_size, int stream_remote_window_size, uint remote_max_frame_size);


}