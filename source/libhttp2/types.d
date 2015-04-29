/**
 * Types
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.types;

import libhttp2.constants;
import libhttp2.helpers;
import std.conv : to;
import memutils.refcounted;
import memutils.utils;

alias Mem = ThreadMem;
void LOGF(ARGS...)(ARGS args) {
	import std.stdio: writefln;
	static if (DEBUG)
		writefln(args);
}

void logDebug(ARGS...)(ARGS args) {
	import std.stdio: writeln;
	static if (DEBUG)
		writeln("D: ", args);
}

/// Return values used in this library.  The code range is [-999, -500], inclusive.
enum ErrorCode : int {
    OK = 0,

	ERROR = -1,
	CREDENTIAL_PENDING = -101,
	IGN_HEADER_BLOCK = -103,

	/*
     * Invalid HTTP header field was received but it can be treated as
     * if it was not received because of compatibility reasons.
    */
	IGN_HTTP_HEADER = -105,

	IGN_PAYLOAD = -104,
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

	/// Used as a return value from DataProvider to indicate that data
    /// transfer is postponed.  See DataProvider for details.
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

	/// Invalid HTTP header field was received and stream is going to be closed.
	HTTP_HEADER = -531,

	/**
    * The errors < FATAL mean that the library is under unexpected condition and processing was terminated (e.g.,
    * out of memory).  If application receives this error code, it must stop using that $(D Session) object and only allowed
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
	with(ErrorCode) switch (error_code) {
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
		default: return error_code.to!string;
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

/// The header field, which mainly used to represent HTTP headers.
struct HeaderField 
{
	immutable(char)[] name;
	immutable(char)[] value;

	HeaderFlag flag = HeaderFlag.NONE;

	bool opEquals()(auto ref HeaderField other) const {
		return name == other.name && value == other.value;
	}

	void free() {
		if (name.length > 0)
			Mem.free(name);
		if (value.length > 0)
			Mem.free(value);
		name = null;
		value = null;
	}

	/**
	* Returns true if HTTP header field name |name| of length |len| is
	* valid according to http://tools.ietf.org/html/rfc7230#section-3.2
	*
	* Because this is a header field name in HTTP2, the upper cased alphabet
	* is treated as error.
	*/
	bool validateName() {
		immutable(char)* pos = name.ptr;
		size_t len = name.length;
		if (len == 0)
			return false;

		if (*pos == ':') {
			if (name.length == 1)
				return false;
			++pos;
			--len;
		}

		for (const immutable(char)* last = pos + len; pos != last; ++pos) {
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
		immutable(char)* pos = value.ptr;
		size_t len = value.length;

		for (const immutable(char)* last = pos + len; pos != last; ++pos) {
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
			if (trailer || (stream.httpFlags & HTTPFlags.PSEUDO_HEADER_DISALLOWED)) 
				return false;
		
		token = parseToken(name);
		
		with(Token) switch (token) {
			case _AUTHORITY:
				if (!validatePseudoHeader(stream, HTTPFlags._AUTHORITY)) 
					return false;

				break;
			case _METHOD:
				if (!validatePseudoHeader(stream, HTTPFlags._METHOD)) 
					return false;
				
				switch (value.length)
				{
					case 4:

						if (value == "HEAD") {
							stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.METH_HEAD);
						} 
						break;
					case 7:
						switch (value[6])
						{
							case 'T':
								if (value == "CONNECT") {
									if (stream.id % 2 == 0) {
										/* we won't allow CONNECT for push */
										return false;
									}
									stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.METH_CONNECT);
									if (stream.httpFlags & (HTTPFlags._PATH | HTTPFlags._SCHEME)) 
										return false;
								}
								break;

							case 'S':
								if (value == "OPTIONS") {
									stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.METH_OPTIONS);
								}
								break;
							default:
								break;
						}
						break;
					default:
						break;
				}
				break;
			case _PATH:
				if (stream.httpFlags & HTTPFlags.METH_CONNECT) {
					return false;
				}
				if (!validatePseudoHeader(stream, HTTPFlags._PATH)) {
					return false;
				}
				if (value[0] == '/') {
					stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.PATH_REGULAR);
				} else if (value.length == 1 && value[0] == '*') {
					stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.PATH_ASTERISK);
				}
				break;
			case _SCHEME:
				if (stream.httpFlags & HTTPFlags.METH_CONNECT) {
					return false;
				}
				if (!validatePseudoHeader(stream, HTTPFlags._SCHEME)) {
					return false;
				}
				if ((value.length == 4 && memieq("http".ptr, value.ptr, 4)) ||
					(value.length == 5 && memieq("https".ptr, value.ptr, 5))) {
					stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.SCHEME_HTTP);
				}
				break;
			case HOST:
				if (!validatePseudoHeader(stream, HTTPFlags.HOST)) {
					return false;
				}
				break;
			case CONTENT_LENGTH: {
				if (stream.contentLength != -1) 
					return false;
				import std.conv : parse;
				stream.contentLength = parse!long(value);
				if (stream.contentLength == -1) 
					return false;
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
				if (icmp(value, "trailers") != 0)
					return false;
				break;
			default:
				if (name[0] == ':')
					return false;
		}
		if (name[0] != ':')
			stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.PSEUDO_HEADER_DISALLOWED);		
		
		return true;
	}

	bool validateResponseHeader(Stream stream, int trailer) 
	{
		import std.conv : parse;
		int token;
		
		if (name[0] == ':') {
			if (trailer || (stream.httpFlags & HTTPFlags.PSEUDO_HEADER_DISALLOWED)) {
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
				stream.statusCode = cast(short)parse!uint(value);
				if (stream.statusCode == -1)
					return false;
				break;
			}
			case CONTENT_LENGTH: {
				if (stream.contentLength != -1) {
					return false;
				}
				stream.contentLength = parse!long(value);
				if (stream.contentLength == -1) {
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
			stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | HTTPFlags.PSEUDO_HEADER_DISALLOWED);
		}
		
		return true;
	}
private:	
	bool validatePseudoHeader(Stream stream, HTTPFlags flag) {
		if (stream.httpFlags & flag) {
			return false;
		}
		if (lws(value)) {
			return false;
		}
		stream.httpFlags = cast(HTTPFlags)(stream.httpFlags | flag);
		return true;
	}

	bool lws(in string s) {
		size_t i;
		for (i = 0; i < s.length; ++i)
			if (s.ptr[i] != ' ' && s.ptr[i] != '\t')
				return false;
		return true;
	}
}


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

/**
 * Callback function invoked when the library wants to read data from
 * the source.  The read data is sent in the stream |stream_id|.
 * The implementation of this function must read at most |length|
 * bytes of data from |source| (or possibly other places) and store
 * them in |buf| and return number of data stored in |buf|.  If EOF is
 * reached, set $(D DataFlags.EOF)
 *
 * Sometime it is desirable to avoid copying data into |buf| and let
 * application to send data directly.  To achieve this, set
 * `DataFlags.NO_COPY` to |data_flags| (and possibly
 * other flags, just like when we do copy), and return the number of
 * bytes to send without copying data into |buf|.  The library, seeing
 * `DataFlags.NO_COPY`, will invoke `Connector.writeData`.  
 * The application must send complete DATA frame in that callback.
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
alias DataProvider = int delegate(ubyte[] buf, ref DataFlags data_flags);

/// The flags used to set in |data_flags| output parameter in DataSource.read_callback
enum DataFlags : ubyte
{
	/// No flag set.
	NONE = 0,

	/// Indicates EOF was sensed.
	EOF = 0x01,
	/// Indicates that END_STREAM flag must not be set 
	/// even if EOF is set. Usually this flag is used to send
	/// trailer header fields with `submitRequest()` or `submitResponse()`
	/// Note: unused at the moment
	NO_END_STREAM = 0x02,
	/// Indicates that application will send complete DATA frame
	/// in `Connector.writeData`
	NO_COPY = 0x04
}

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

enum ShutdownFlag {
	NONE = 0,
	
	/// Indicates further receptions will be disallowed.
	RD = 0x01,
	
	/// Indicates further transmissions will be disallowed.
	WR = 0x02,
	
	/// Indicates both further receptions and transmissions will be disallowed.
	RDWR = RD | WR
}

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
	METH_OPTIONS = 1 << 9,
	METH_ALL = METH_CONNECT | METH_HEAD | METH_OPTIONS,
	/* :path category */
	/* path starts with "/" */
	PATH_REGULAR = 1 << 10,
	/* path "*" */
	PATH_ASTERISK = 1 << 11,
	/* scheme */
	/* "http" or "https" scheme */
	SCHEME_HTTP = 1 << 12,

	/* set if final response is expected */
	EXPECT_FINAL_RESPONSE = 1 << 13,
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

struct Setting {
	alias SettingCode = ushort;
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

	void unpack(in ubyte[] payload) {
		id = read!ushort(payload);
		value = read!uint(payload[2 .. $]);
	}
}

alias SettingsID = Setting.SettingCode;

