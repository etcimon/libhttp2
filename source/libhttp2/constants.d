module libhttp2.constants;

/// Version of this library
const VERSION = "0.2";

/// The protocol version identification string of this library supports. 
/// This identifier is used if HTTP/2 is used over TLS.
const PROTOCOL_VERSION_ID = "h2-14";

/**
 * Use this to verify compatibility if dynamic linking is involved.
*/
struct LibInfo
{
	int age = 1; // This is the version of this struct
	string version_str = VERSION;
	string proto_str = PROTOCOL_VERSION_ID;
}

public static LibInfo g_lib_info;

package:

/// Enables READ_FIRST_SETTINGS in Session
int ENABLE_FIRST_SETTING_CHECK = 1;

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
const INITIAL_MAX_CONCURRENT_STREAMS = ((1u << 31) - 1);

/// The default header table size.
const DEFAULT_HEADER_TABLE_SIZE = (1 << 12);

/// The client connection preface.
const CLIENT_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Buffer length for inbound raw byte stream used in $(D Session.recv).
const INBOUND_BUFFER_LENGTH = 16384;

const INBOUND_NUM_IV = 7;


const STREAM_ID_MASK = ((1u << 31) - 1);
const PRI_GROUP_ID_MASK = ((1u << 31) - 1);
const PRIORITY_MASK = ((1u << 31) - 1);
const WINDOW_SIZE_INCREMENT_MASK = ((1u << 31) - 1);
const SETTINGS_ID_MASK = ((1 << 24) - 1);

/* The number of bytes of frame header. */
const FRAME_HDLEN = 9;

const MAX_FRAME_SIZE_MAX = ((1 << 24) - 1);
const MAX_FRAME_SIZE_MIN = (1 << 14);

const MAX_PAYLOADLEN = 16384;

/* The one frame buffer length for tranmission.  We may use several of
   them to support CONTINUATION.  To account for Pad Length field, we
   allocate extra 1 byte, which saves extra large memcopying. */
const FRAMEBUF_CHUNKLEN = (FRAME_HDLEN + 1 + MAX_PAYLOADLEN);

/// Number of inbound buffer
const FRAMEBUF_MAX_NUM = 5;

/// The default length of DATA frame payload.
const DATA_PAYLOADLEN = MAX_FRAME_SIZE_MIN;

/// Maximum headers payload length, calculated in compressed form.
/// This applies to transmission only.
const MAX_HEADERSLEN = 65536;

/// The number of bytes for each SETTINGS entry
const FRAME_SETTINGS_ENTRY_LENGTH = 6;

/// The maximum header table size in $(D Setting.HEADER_TABLE_SIZE)
const MAX_HEADER_TABLE_SIZE = ((1u << 31) - 1);

/// Length of priority related fields in HEADERS/PRIORITY frames
const PRIORITY_SPECLEN = 5;

/// Maximum length of padding in bytes.
const MAX_PADLEN = 256;

/// A bit higher weight for non-DATA frames
const OB_EX_WEIGHT = 300;

/// Higher weight for SETTINGS
const OB_SETTINGS_WEIGHT = 301;

/// Highest weight for PING
const OB_PING_WEIGHT = 302;