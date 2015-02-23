/*
 * libhttp2 - HTTP/2 D Library
 *
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
 * Copyright (c) 2015 Etienne Cimon
 * 
 * License: MIT
 */
module libhttp2.types;

import libhttp2.constants;
import memutils.refcounted;


/// Return values used in this library.  The code range is [-999, -500], inclusive.
enum ErrorCode : int {
    OK = 0,

	/// Invalid argument passed.
    INVALID_ARGUMENT = -501,

	/// Out of buffer space.
	BUFFER_ERROR = -502,

	/// The specified protocol version is not supported.
	UNSUPPORTED_VERSION = -503,

	/// Used as a return value from http2_send_callback and http2_recv_callback
	/// to indicate that the operation would block.
	WOULDBLOCK = -504,

	/// General protocol error
	PROTO = -505,

	/// The frame is invalid.
	INVALID_FRAME = -506,

	/// The peer performed a shutdown on the connection.
	EOF = -507,

	/// Used as a return value from http2_data_source_read_callback to indicate that data
    /// transfer is postponed.  See http2_data_source_read_callback` for details.
	DEFERRED = -508,

	/// Stream ID has reached the maximum value.  Therefore no stream ID is available.
	STREAM_ID_NOT_AVAILABLE = -509,

	/// The stream is already closed; or the stream ID is invalid.
	STREAM_CLOSED = -510,

	/// RST_STREAM has been added to the outbound queue.  The stream is in closing state.
	STREAM_CLOSING = -511,

	/// The transmission is not allowed for this stream (e.g., a frame with END_STREAM flag set has already sent).
	STREAM_SHUT_WR = -512,

	/// The stream ID is invalid.
	INVALID_STREAM_ID = -513,

	/// The state of the stream is not valid (e.g., DATA cannot be sent to the stream if response HEADERS has not been sent).
	INVALID_STREAM_STATE = -514,
	/// Another DATA frame has already been deferred.
	/// 
	DEFERRED_DATA_EXIST = -515,

	/// Starting new stream is not allowed (e.g., GOAWAY has been sent and/or received).
	START_STREAM_NOT_ALLOWED = -516,
	/**
   * GOAWAY has already been sent.
   */
	GOAWAY_ALREADY_SENT = -517,

	/**
   * The received frame contains the invalid header block (e.g., There
   * are duplicate header names; or the header names are not encoded
   * in US-ASCII character set and not lower cased; or the header name
   * is zero-length string; or the header value contains multiple
   * in-sequence NUL bytes).
   */
	INVALID_HEADER_BLOCK = -518,

	/// Indicates that the context is not suitable to perform the requested operation.
	INVALID_STATE = -519,

	/// The user callback function failed due to the temporal error.
	TEMPORAL_CALLBACK_FAILURE = -521,

	/// The length of the frame is invalid, either too large or too small.
	FRAME_SIZE_ERROR = -522,

	/// Header block inflate/deflate error.
	HEADER_COMP = -523,

	/// Flow control error
	FLOW_CONTROL = -524,

	/// Insufficient buffer size given to function.
	INSUFF_BUFSIZE = -525,

	/// Callback was paused by the application
	PAUSE = -526,

	/// There are too many in-flight SETTING frame and no more transmission of SETTINGS is allowed.
	TOO_MANY_INFLIGHT_SETTINGS = -527,

	/// The server push is disabled.
	PUSH_DISABLED = -528,

	/// DATA frame for a given stream has been already submitted and has not been fully processed yet.
	DATA_EXIST = -529,

	/// The current session is closing due to a connection error or http2_session_terminate_session() is called.
	SESSION_CLOSING = -530,

	/**
    * The errors < FATAL mean that the library is under unexpected condition and processing was terminated (e.g.,
    * out of memory).  If application receives this error code, it must stop using that :type:`http2_session` object and only allowed
    * operation for that object is deallocate it using http2_session_del().
    */
	FATAL = -900,

	/// Out of memory.  This is a fatal error.
	NOMEM = -901,

	/// The user callback function failed.  This is a fatal error.
	CALLBACK_FAILURE = -902,

	/// Invalid connection preface was received and further processing is not possible.
	BAD_PREFACE = -903
}

//http2_nv_flag
/// The flags for header field name/value pair.
enum NVFlags : ubyte 
{
	/// No flag set.
	NONE = 0,

	/**
    * Indicates that this name/value pair must not be indexed ("Literal
    * Header Field never Indexed" representation must be used in HPACK
    * encoding).  Other implementation calls this bit as "sensitive".
    */
	NO_INDEX = 0x01
}

//http2_nv
/// The name/value pair, which mainly used to represent header fields.
struct NVPair 
{
	string name;
	string value;
	NVFlags flags;
}

//http2_frame_type
/// The frame types in HTTP/2 specification.
enum FrameType : ubyte
{
	DATA = 0,
	HEADERS = 0x01,
    PRIORITY = 0x02,
	RST_STREAM = 0x03,
	SETTINGS = 0x04,
	PUSH_PROMISE = 0x05,
    PING = 0x06,
	GOAWAY = 0x07,
	WINDOW_UPDATE = 0x08,
	CONTINUATION = 0x09
}

//http2_flag
/// The flags for HTTP/2 frames.  This enum defines all flags for all frames.
enum FrameFlags : ubyte 
{
	NONE = 0,
	END_STREAM = 0x01,
	END_HEADERS = 0x04,
	ACK = 0x01,
	PADDED = 0x08,
	PRIORITY = 0x20
}

//http2_ext_frame_type
/// The extension frame types.
 /*
 * TODO: The assigned frame types were carried from draft-12, and now
 * actually TBD.
 */
enum ExtFrameType : ubyte {
	/// The ALTSVC extension frame.
	ALTSVC = 0x0a
}

// http2_error_code
/// The status codes for the RST_STREAM and GOAWAY frames.
enum FrameError : uint
{
	NO_ERROR = 0x00,
	PROTOCOL_ERROR = 0x01,
	INTERNAL_ERROR = 0x02,
	FLOW_CONTROL_ERROR = 0x03,
	TIMEOUT = 0x04,
	STREAM_CLOSED = 0x05,
	FRAME_SIZE_ERROR = 0x06,
	REFUSED_STREAM = 0x07,
	CANCEL = 0x08,
	COMPRESSION_ERROR = 0x09,
	CONNECT_ERROR = 0x0a,
	ENHANCE_YOUR_CALM = 0x0b,
	INADEQUATE_SECURITY = 0x0c,
	HTTP_1_1_REQUIRED = 0x0d
}

//http2_frame_hd
struct FrameHeader 
{
	/// The length after this header
	size_t length;
	Stream stream;
	FrameType type;
	FrameFlags flags;
    /// 0
	ubyte reserved;
}

//http2_data_source
/// This union represents the some kind of data source passed to nghttp2_data_source_read_callback
union DataSource
{
    /// The integer field, suitable for a file descriptor.
    int fd;
    
    /// The pointer to an arbitrary object.
    void *ptr;
}

/**
 * Callback function invoked when the library wants to read data from
 * the |source|.  The read data is sent in the stream |stream_id|.
 * The implementation of this function must read at most |length|
 * bytes of data from |source| (or possibly other places) and store
 * them in |buf| and return number of data stored in |buf|.  If EOF is
 * reached, set $(D DataFlags.EOF)
 *
 * If the application wants to postpone DATA frames (e.g.,
 * asynchronous I/O, or reading data blocks for long time), it is
 * achieved by returning $(D Error.DEFERRED) without reading
 * any data in this invocation.  The library removes DATA frame from
 * the outgoing queue temporarily.  To move back deferred DATA frame
 * to outgoing queue, call `http2_session_resume_data()`.  In case
 * of error, there are 2 choices. Returning
 * $(D Error.TEMPORAL_CALLBACK_FAILURE) will close the stream
 * by issuing RST_STREAM with $(D FrameError.INTERNAL_ERROR).  If a
 * different error code is desirable, use
 * `http2_submit_rst_stream()` with a desired error code and then
 * return $(D Error.TEMPORAL_CALLBACK_FAILURE).  Returning
 * $(D Error.CALLBACK_FAILURE) will signal the entire session
 * failure.
 */
alias ReadCallback = size_t delegate(Session session, int stream_id, ubyte[] buf, ref DataFlags data_flags, DataSource source);

//DataProvider
/// This struct represents the data source and the way to read a chunk of data from it.
class DataProvider {
    DataSource source;
    ReadCallback read_callback;
}


/// The flags used to set in |data_flags| output parameter in http2_data_source_read_callback
enum DataFlags : ubyte
{
	/// No flag set.
	NONE = 0,

	/// Indicates EOF was sensed.
	EOF = 0x01
}

//http2_headers_category
/**
 * The category of HEADERS, which indicates the role of the frame.  In
 * HTTP/2 spec, request, response, push response and other arbitrary
 * headers (e.g., trailers) are all called just HEADERS.  To give the
 * application the role of incoming HEADERS frame, we define several
 * categories.
 */
enum HeadersCategory : ubyte
{
	/// The HEADERS frame is opening new stream, which is analogous to SYN_STREAM in SPDY.
	REQUEST = 0,

	/// The HEADERS frame is the first response headers, which is analogous to SYN_REPLY in SPDY.
	RESPONSE = 1,

	/// The HEADERS frame is the first headers sent against reserved stream.
	PUSH_RESPONSE = 2,

	/**
    * The HEADERS frame which does not apply for the above categories,
    * which is analogous to HEADERS in SPDY.  If non-final response
    * (e.g., status 1xx) is used, final response HEADERS frame will be
    * categorized here.
    */
	HEADERS = 3
}


// http2_data
/// The DATA frame.  The received data is delivered via http2_on_data_chunk_recv_callback
struct Data
{
    FrameHeader hd;
    /// The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
    size_t padlen;
}


// http2_headers
/// The HEADERS frame.  It has the following members:
struct Headers
{    
    FrameHeader hd;

    /// The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
    size_t padlen;

    /// The priority specification
    PrioritySpec pri_spec;

    /// The name/value pairs.
    NVPair[] nva;

    /// The category of this HEADERS frame.
    HeadersCategory cat;
}

//http2_priority
/// The PRIORITY frame.  It has the following members:
struct Priority {
    FrameHeader hd;
    PrioritySpec pri_spec;
}

//http2_rst_stream
/// The RST_STREAM frame.  It has the following members:
struct Reset {
    
    FrameHeader hd;

    /// The error code.  See :type:`nghttp2_error_code`.
    StatusCode error_code;
}


//http2_settings_entry
struct Setting {
	alias SettingCode = ubyte;
	/// Notes: If we add SETTINGS, update the capacity of HTTP2_INBOUND_NUM_IV as well
	enum : SettingCode {
		HEADER_TABLE_SIZE = 0x01,
		ENABLE_PUSH = 0x02,
		MAX_CONCURRENT_STREAMS = 0x03,
		INITIAL_WINDOW_SIZE = 0x04,
		MAX_FRAME_SIZE = 0x05,
		MAX_HEADER_LIST_SIZE = 0x06
	}
	/// The SETTINGS ID.
    SettingCode id;
    uint value;
}

/// The SETTINGS frame
struct Settings {
    FrameHeader hd;
    Setting[] settings;
}

//http2_push_promise
/// The PUSH_PROMISE frame.  
struct PushPromise {    
    FrameHeader hd;

    /// The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
    size_t padlen;

    /// The name/value pairs.
    NVPair[] nva;

    /// The promised stream ID
    Stream promised;

    /// 0
    ubyte reserved;
}

// http2_ping
/// The PING frame.
struct Ping {    
    FrameHeader hd;
    ubyte[8] opaque_data;
}

//http2_goaway
/// The GOAWAY frame. 
struct GoAway {
    FrameHeader hd;
    Stream last;
    FrameError error_code;
    /// The additional debug data
    ubyte[] opaque_data;
    /// 0
    ubyte reserved;
}

//http2_window_update
/// The WINDOW_UPDATE frame.
struct WindowUpdate {    
    FrameHeader hd;

    int window_size_increment;

    /// 0
    ubyte reserved;
}

//http2_extension
/// The extension frame.
struct Extension {    
    FrameHeader hd;

    /**
   * The pointer to extension payload.  The exact pointer type is
   * determined by hd.type.
   *
   * If hd.type == ALTSVC it is a pointer to http2_ext_altsvc
   */
    void *payload;
}

// http2_ext_altsvc
/// The ALTSVC extension frame payload.  It has following members:
struct ExtALTSVC {
	ubyte[] protocol_id;
	ubyte[] host;
	ubyte[] origin;
	uint max_age;
	ushort port;
}

//http2_frame
/*
 * This union includes all frames to pass them to various function
 * calls as http2_frame type.  The CONTINUATION frame is omitted
 * from here because the library deals with it internally.
 */
union FrameUnion {
	FrameHeader hd;
	Data data;
	Headers headers;
	Priority priority;
	Reset rst_stream;
	Settings settings;
	PushPromise push_promise;
	Ping ping;
	GoAway goaway;
	WindowUpdate window_update;
	Extension ext;
}

alias Frame = RefCounted!FrameUnion;
