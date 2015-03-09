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
import libhttp2.helpers;
import memutils.refcounted;
import memutils.utils;

alias Mem = ThreadMem;

/// Return values used in this library.  The code range is [-999, -500], inclusive.
enum ErrorCode : int {
    OK = 0,

	ERROR = -1,

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

/*
 * Returns string describing the |error_code|.  The |error_code| must be one of the $(D ErrorCode).
 */
string toString(ErrorCode error_code) {
	with(ErrorCode) final switch (error_code) {
		case OK:
			return "Success";
		case ERROR:
			return "Unknown error";
		case INVALID_ARGUMENT:
			return "Invalid argument";
		case BUFFER_ERROR:
			return "Out of buffer space";
		case UNSUPPORTED_VERSION:
			return "Unsupported SPDY version";
		case WOULDBLOCK:
			return "Operation would block";
		case PROTO:
			return "Protocol error";
		case INVALID_FRAME:
			return "Invalid frame octets";
		case EOF:
			return "EOF";
		case DEFERRED:
			return "Data transfer deferred";
		case STREAM_ID_NOT_AVAILABLE:
			return "No more Stream ID available";
		case STREAM_CLOSED:
			return "Stream was already closed or invalid";
		case STREAM_CLOSING:
			return "Stream is closing";
		case STREAM_SHUT_WR:
			return "The transmission is not allowed for this stream";
		case INVALID_STREAM_ID:
			return "Stream ID is invalid";
		case INVALID_STREAM_STATE:
			return "Invalid stream state";
		case DEFERRED_DATA_EXIST:
			return "Another DATA frame has already been deferred";
		case SESSION_CLOSING:
			return "The current session is closing";
		case START_STREAM_NOT_ALLOWED:
			return "request HEADERS is not allowed";
		case GOAWAY_ALREADY_SENT:
			return "GOAWAY has already been sent";
		case INVALID_HEADER_BLOCK:
			return "Invalid header block";
		case INVALID_STATE:
			return "Invalid state";
		case TEMPORAL_CALLBACK_FAILURE:
			return "The user callback function failed due to the temporal error";
		case FRAME_SIZE_ERROR:
			return "The length of the frame is invalid";
		case HEADER_COMP:
			return "Header compression/decompression error";
		case FLOW_CONTROL:
			return "Flow control error";
		case INSUFF_BUFSIZE:
			return "Insufficient buffer size given to function";
		case PAUSE:
			return "Callback was paused by the application";
		case TOO_MANY_INFLIGHT_SETTINGS:
			return "Too many inflight SETTINGS";
		case PUSH_DISABLED:
			return "Server push is disabled by peer";
		case DATA_EXIST:
			return "DATA frame already exists";
		case NOMEM:
			return "Out of memory";
		case CALLBACK_FAILURE:
			return "The user callback function failed";
		case BAD_PREFACE:
			return "Received bad connection preface";
	}
}

/// The flag for a header field.
enum HeaderFlag : ubyte 
{
	/// No flag set.
	NONE = 0,

	/**
    * Indicates that this header field must not be indexed ("Literal
    * Header Field never Indexed" representation must be used in HPACK
    * encoding).  Other implementation calls this bit as "sensitive".
    */
	NO_INDEX = 0x01
}

//http2_nv
/// The header field, which mainly used to represent HTTP headers.
struct HeaderField 
{
	string name;
	string value;
	HeaderFlag flag = HeaderFlag.NONE;

	bool opEquals(ref HeaderField other) {
		return name == other.name && value == other.value;
	}

	/**
	* Returns true if HTTP header field name |name| of length |len| is
	* valid according to http://tools.ietf.org/html/rfc7230#section-3.2
	*
	* Because this is a header field name in HTTP2, the upper cased alphabet
	* is treated as error.
	*/
	bool validateName() {
		ubyte* pos = name.ptr;
		size_t len = name.length;
		if (len == 0)
			return false;

		if (*pos == ':') {
			if (name.length == 1)
				return false;
			++pos;
			--len;
		}

		for (const ubyte* last = pos + len; pos != last; ++pos) {
			if (!VALID_HD_NAME_CHARS[*pos]) {
				return false;
			}
		}
		return true;
	}

	/*
	 * Returns true if HTTP header field value |value| of length |len|
	 * is valid according to http://tools.ietf.org/html/rfc7230#section-3.2
	 */
	bool validateValue() {
		ubyte* pos = value.ptr;
		size_t len = value.length;

		for (const ubyte* last = pos + len; pos != last; ++pos) {
			if (!VALID_HD_VALUE_CHARS[*pos]) {
				return false;
			}
		}
		return true;
	}

	import libhttp2.stream : Stream;
	/// Validate a request header
	bool validateRequestHeader(Stream stream, bool trailer) {
		int token;
		
		if (name[0] == ':') 
			if (trailer || (stream.http_flags & HTTPFlags.PSEUDO_HEADER_DISALLOWED)) 
				return false;
		
		token = parseToken(hf.name, hf.namelen);
		
		with(Token) switch (token) {
			case _AUTHORITY:
				if (!validatePseudoHeader(stream, HTTPFlags._AUTHORITY)) {
					return false;
				}
				break;
			case _METHOD:
				if (!validatePseudoHeader(stream, HTTPFlags._METHOD)) {
					return false;
				}
				if (value == "HEAD") {
					stream.http_flags |= HTTPFlags.METH_HEAD;
				} else if (value == "CONNECT") {
					if (stream.stream_id % 2 == 0) {
						/* we won't allow CONNECT for push */
						return false;
					}
					stream.http_flags |= HTTPFlags.METH_CONNECT;
					if (stream.http_flags & (HTTPFlags._PATH | HTTPFlags._SCHEME)) 
						return false;
					
				}
				break;
			case _PATH:
				if (stream.http_flags & HTTPFlags.METH_CONNECT) {
					return false;
				}
				if (!validatePseudoHeader(stream, HTTPFlags._PATH)) {
					return false;
				}
				break;
			case _SCHEME:
				if (stream.http_flags & HTTPFlags.METH_CONNECT) {
					return false;
				}
				if (!validatePseudoHeader(stream, HTTPFlags._SCHEME)) {
					return false;
				}
				break;
			case HOST:
				if (!validatePseudoHeader(stream, HTTPFlags.HOST)) {
					return false;
				}
				break;
			case CONTENT_LENGTH: {
				if (stream.content_length != -1) 
					return false;
				import std.conv : parse;
				stream.content_length = parse!uint(value);
				if (stream.content_length == -1) 
					return false;
				break;
			}
				/* disallowed header fields */
			case CONNECTION:
			case KEEP_ALIVE:
			case PROXY_CONNECTION:
			case TRANSFER_ENCODING:
			case UPGRADE:
				return -1;
			case TE:
				import std.string : icmp;
				if (icmp(value, "trailers") != 0)
					return false;
				break;
			default:
				if (name[0] == ':')
					return false;
		}
		if (name[0] != ':')
			stream.http_flags |= HTTPFlags.PSEUDO_HEADER_DISALLOWED;		
		
		return true;
	}

	bool validateResponseHeader(Stream stream, int trailer) 
	{
		import std.conv : parse;
		int token;
		
		if (name[0] == ':') {
			if (trailer || (stream.http_flags & HTTPFlags.PSEUDO_HEADER_DISALLOWED)) {
				return false;
			}
		}
		
		token = parseToken(name);
		
		with(Token) switch (token) {
			case _STATUS: {
				if (!validatePseudoHeader(stream, HTTPFlags._STATUS)) {
					return false;
				}
				if (value.length != 3) {
					return false;
				}
				stream.status_code = parse!uint(value);
				if (stream.status_code == -1)
					return false;
				break;
			}
			case CONTENT_LENGTH: {
				if (stream.content_length != -1) {
					return false;
				}
				stream.content_length = parse!uint(value);
				if (stream.content_length == -1) {
					return false;
				}
				break;
			}
				/* disallowed header fields */
			case CONNECTION:
			case KEEP_ALIVE:
			case PROXY_CONNECTION:
			case TRANSFER_ENCODING:
			case UPGRADE:
				return false;
			case TE:
				import std.string : icmp;
				if (icmp("trailers", value) != 0) {
					return false;
				}
				break;
			default:
				if (name[0] == ':') {
					return false;
				}
		}
		
		if (name[0] != ':') {
			stream.http_flags |= HTTPFlags.PSEUDO_HEADER_DISALLOWED;
		}
		
		return 0;
	}
private:	
	bool validatePseudoHeader(Stream stream, HTTPFlags flag) {
		if (stream.http_flags & flag) {
			return false;
		}
		if (lws(value)) {
			return false;
		}
		stream.http_flags |= flag;
		return true;
	}

	bool lws(in ubyte[] s) {
		size_t i;
		for (i = 0; i < s.length; ++i)
			if (s.ptr[i] != ' ' && s.ptr[i] != '\t')
				return false;
		return true;
	}
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
 * achieved by setting $(D pause) without reading
 * any data in this invocation.  The library removes DATA frame from
 * the outgoing queue temporarily.  To move back deferred DATA frame
 * to outgoing queue, call `resumeData()`.  
 * 
 * In case of error, there are 2 choices.
 * Setting $(D rst_stream=true) will close the stream by issuing RST_STREAM with 
 * $(D FrameError.INTERNAL_ERROR).  If a different error code is desirable, 
 * use `http2_submit_rst_stream()`  with a desired error code and then
 * set $(D rst_stream) to true. 
 * 
 * Returning false will signal $(D Error.CALLBACK_FAILURE), aborting the entire session.
 */
alias ReadCallback = bool delegate(int stream_id, ubyte[] buf, ref DataFlags data_flags, DataSource source, ref bool pause, ref bool rst_stream);

//DataProvider
/// This struct represents the data source and the way to read a chunk of data from it.
struct DataProvider {
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


/// nghttp2_stream_state
/**
 * If local peer is stream initiator:
 * OPENING : upon sending request HEADERS
 * OPENED : upon receiving response HEADERS
 * CLOSING : upon queuing RST_STREAM
 *
 * If remote peer is stream initiator:
 * OPENING : upon receiving request HEADERS
 * OPENED : upon sending response HEADERS
 * CLOSING : upon queuing RST_STREAM
 */
enum StreamState : ubyte {
	/// Initial state
	INITIAL,
	
	/// For stream initiator: request HEADERS has been sent, but response HEADERS has not been received yet. 
	/// For receiver: request HEADERS has been received, but it does not send response HEADERS yet. 
	OPENING,
	
	/// For stream initiator: response HEADERS is received. For receiver: response HEADERS is sent.
	OPENED,
	
	/// RST_STREAM is received, but somehow we need to keep stream in memory.
	CLOSING,
	
	/// PUSH_PROMISE is received or sent
	RESERVED,
	
	/// Stream is created in this state if it is used as anchor in dependency tree.
	IDLE
}

//http2_shut_flag
enum ShutdownFlag {
	NONE = 0,
	
	/// Indicates further receptions will be disallowed.
	RD = 0x01,
	
	/// Indicates further transmissions will be disallowed.
	WR = 0x02,
	
	/// Indicates both further receptions and transmissions will be disallowed.
	RDWR = RD | WR
}

//http2_stream_flag
enum StreamFlags : ubyte {
	NONE = 0,
	
	/// Indicates that this stream is pushed stream and not opened yet.
	PUSH = 0x01,
	
	/// Indicates that this stream was closed
	CLOSED = 0x02,
	
	/// Indicates the item is deferred due to flow control.
	DEFERRED_FLOW_CONTROL = 0x04,
	
	/// Indicates the item is deferred by user callback
	DEFERRED_USER = 0x08,
	
	/// bitwise OR of DEFERRED_FLOW_CONTROL and DEFERRED_USER. */
	DEFERRED_ALL = 0x0c    
}

//http2_http_flag
/// HTTP related flags to enforce HTTP semantics
enum HTTPFlags {
	NONE = 0,
	
	/// header field seen so far 
	_AUTHORITY = 1,
	_PATH = 1 << 1,
	_METHOD = 1 << 2,
	_SCHEME = 1 << 3,
	
	/// host is not pseudo header, but we require either host or :authority 
	HOST = 1 << 4,
	_STATUS = 1 << 5,
	
	/// required header fields for HTTP request except for CONNECT method.
	REQ_HEADERS = _METHOD | _PATH | _SCHEME,
	PSEUDO_HEADER_DISALLOWED = 1 << 6,
	
	/* HTTP method flags */
	METH_CONNECT = 1 << 7,
	METH_HEAD = 1 << 8,
	METH_ALL =
	METH_CONNECT | METH_HEAD,
	
	/* set if final response is expected */
	EXPECT_FINAL_RESPONSE = 1 << 9,
}

enum StreamDPRI {
	NONE = 0,
	NO_ITEM = 0x01,
	TOP = 0x02,
	REST = 0x04
}

/// HTTP Tokens
enum Token : int {
	ERROR = -1,
	_AUTHORITY = 0,
	_METHOD,
	_PATH,
	_SCHEME,
	_STATUS,
	CONNECTION,
	CONTENT_LENGTH,
	HOST,
	KEEP_ALIVE,
	PROXY_CONNECTION,
	TE,
	TRANSFER_ENCODING,
	UPGRADE,
	MAXIDX,
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
	
	void unpack(in ubyte* payload) {
		id = read!ushort(payload);
		value = read!uint(&payload[2]);
	}
}

alias SettingsID = Setting.SettingCode;