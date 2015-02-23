module libhttp2.constants;

/// Version of this library
const VERSION = "0.2";

/// The protocol version identification string of this library supports. 
/// This identifier is used if HTTP/2 is used over TLS.
const PROTOCOL_VERSION_ID = "h2-14";

/**
 * Use this to verify compatibility if dynamic linking is involved.
*/
struct LibInfo {
	int age = 1; // This is the version of this struct
	string version_str = VERSION;
	string proto_str = PROTOCOL_VERSION_ID;
}

/**
* The seriazlied form of ALPN protocol identifier this library
* supports.  Notice that first byte is the length of following
* protocol identifier.  This is the same wire format of `TLS ALPN
* extension <https://tools.ietf.org/html/rfc7301>`_.  This is useful
* to process incoming ALPN tokens in wire format.
*/
const PROTOCOL_ALPN = "\x5h2-14";

/// The protocol version identification string of this library supports. 
/// This identifier is used if HTTP/2 is used over cleartext TCP.
const CLEARTEXT_PROTOCOL_VERSION_ID = "h2c-14";

/// The default weight of stream dependency.
const DEFAULT_WEIGHT = 16;

/// The maximum weight of stream dependency.
const MAX_WEIGHT = 256;

/// The minimum weight of stream dependency.
const MIN_WEIGHT = 1;

/// The maximum window size
const MAX_WINDOW_SIZE = int.max;

/// The initial window size for stream level flow control.
const INITIAL_WINDOW_SIZE = ushort.max;

/// The initial window size for connection level flow control.
const INITIAL_CONNECTION_WINDOW_SIZE = ushort.max;

/// Default maximum concurrent streams.
const INITIAL_MAX_CONCURRENT_STREAMS = ((1U << 31) - 1);

/// The default header table size.
const DEFAULT_HEADER_TABLE_SIZE = (1U << 12);

/// The client connection preface.
const CLIENT_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";