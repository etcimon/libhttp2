/**
 * Constants
 * 
 * Copyright:
 * (C) 2012-2015 Tatsuhiro Tsujikawa
 * (C) 2014-2015 Etienne Cimon
 *
 * License: 
 * Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
 * Consult the provided LICENSE.md file for details
 */
module libhttp2.constants;

version(unittest)
	const TEST_ALL = true;
else
	const TEST_ALL = false;
const DEBUG = false;

/// Version of this library
const VERSION = "0.2.0";

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
version(unittest) const ENABLE_FIRST_SETTING_CHECK = false;
else const ENABLE_FIRST_SETTING_CHECK = true;
/**
* The seriazlied form of ALPN protocol identifier this library
* supports.  Notice that first byte is the length of following
* protocol identifier.  This is the same wire format of `TLS ALPN
* extension <https://tools.ietf.org/html/rfc7301>`_.  This is useful
* to process incoming ALPN tokens in wire format.
*/
const PROTOCOL_ALPN = `\x5h2-14`;

const HTTP_1_1_ALPN = `\x8http/1.1`;

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

__gshared immutable immutable(char)[] VALID_HD_NAME_CHARS = [
	0 /* NUL  */, 0 /* SOH  */, 0 /* STX  */, 0 /* ETX  */, 0 /* EOT  */,
	0 /* ENQ  */, 0 /* ACK  */, 0 /* BEL  */, 0 /* BS   */, 0 /* HT   */,
	0 /* LF   */, 0 /* VT   */, 0 /* FF   */, 0 /* CR   */, 0 /* SO   */,
	0 /* SI   */, 0 /* DLE  */, 0 /* DC1  */, 0 /* DC2  */, 0 /* DC3  */,
	0 /* DC4  */, 0 /* NAK  */, 0 /* SYN  */, 0 /* ETB  */, 0 /* CAN  */,
	0 /* EM   */, 0 /* SUB  */, 0 /* ESC  */, 0 /* FS   */, 0 /* GS   */,
	0 /* RS   */, 0 /* US   */, 0 /* SPC  */, 1 /* !    */, 0 /* "    */,
	1 /* #    */, 1 /* $    */, 1 /* %    */, 1 /* &    */, 1 /* '    */,
	0 /* (    */, 0 /* )    */, 1 /* *    */, 1 /* +    */, 0 /* ,    */,
	1 /* -    */, 1 /* .    */, 0 /* /    */, 1 /* 0    */, 1 /* 1    */,
	1 /* 2    */, 1 /* 3    */, 1 /* 4    */, 1 /* 5    */, 1 /* 6    */,
	1 /* 7    */, 1 /* 8    */, 1 /* 9    */, 0 /* :    */, 0 /* ;    */,
	0 /* <    */, 0 /* =    */, 0 /* >    */, 0 /* ?    */, 0 /* @    */,
	0 /* A    */, 0 /* B    */, 0 /* C    */, 0 /* D    */, 0 /* E    */,
	0 /* F    */, 0 /* G    */, 0 /* H    */, 0 /* I    */, 0 /* J    */,
	0 /* K    */, 0 /* L    */, 0 /* M    */, 0 /* N    */, 0 /* O    */,
	0 /* P    */, 0 /* Q    */, 0 /* R    */, 0 /* S    */, 0 /* T    */,
	0 /* U    */, 0 /* V    */, 0 /* W    */, 0 /* X    */, 0 /* Y    */,
	0 /* Z    */, 0 /* [    */, 0 /* \    */, 0 /* ]    */, 1 /* ^    */,
	1 /* _    */, 1 /* `    */, 1 /* a    */, 1 /* b    */, 1 /* c    */,
	1 /* d    */, 1 /* e    */, 1 /* f    */, 1 /* g    */, 1 /* h    */,
	1 /* i    */, 1 /* j    */, 1 /* k    */, 1 /* l    */, 1 /* m    */,
	1 /* n    */, 1 /* o    */, 1 /* p    */, 1 /* q    */, 1 /* r    */,
	1 /* s    */, 1 /* t    */, 1 /* u    */, 1 /* v    */, 1 /* w    */,
	1 /* x    */, 1 /* y    */, 1 /* z    */, 0 /* {    */, 1 /* |    */,
	0 /* }    */, 1 /* ~    */, 0 /* DEL  */, 0 /* 0x80 */, 0 /* 0x81 */,
	0 /* 0x82 */, 0 /* 0x83 */, 0 /* 0x84 */, 0 /* 0x85 */, 0 /* 0x86 */,
	0 /* 0x87 */, 0 /* 0x88 */, 0 /* 0x89 */, 0 /* 0x8a */, 0 /* 0x8b */,
	0 /* 0x8c */, 0 /* 0x8d */, 0 /* 0x8e */, 0 /* 0x8f */, 0 /* 0x90 */,
	0 /* 0x91 */, 0 /* 0x92 */, 0 /* 0x93 */, 0 /* 0x94 */, 0 /* 0x95 */,
	0 /* 0x96 */, 0 /* 0x97 */, 0 /* 0x98 */, 0 /* 0x99 */, 0 /* 0x9a */,
	0 /* 0x9b */, 0 /* 0x9c */, 0 /* 0x9d */, 0 /* 0x9e */, 0 /* 0x9f */,
	0 /* 0xa0 */, 0 /* 0xa1 */, 0 /* 0xa2 */, 0 /* 0xa3 */, 0 /* 0xa4 */,
	0 /* 0xa5 */, 0 /* 0xa6 */, 0 /* 0xa7 */, 0 /* 0xa8 */, 0 /* 0xa9 */,
	0 /* 0xaa */, 0 /* 0xab */, 0 /* 0xac */, 0 /* 0xad */, 0 /* 0xae */,
	0 /* 0xaf */, 0 /* 0xb0 */, 0 /* 0xb1 */, 0 /* 0xb2 */, 0 /* 0xb3 */,
	0 /* 0xb4 */, 0 /* 0xb5 */, 0 /* 0xb6 */, 0 /* 0xb7 */, 0 /* 0xb8 */,
	0 /* 0xb9 */, 0 /* 0xba */, 0 /* 0xbb */, 0 /* 0xbc */, 0 /* 0xbd */,
	0 /* 0xbe */, 0 /* 0xbf */, 0 /* 0xc0 */, 0 /* 0xc1 */, 0 /* 0xc2 */,
	0 /* 0xc3 */, 0 /* 0xc4 */, 0 /* 0xc5 */, 0 /* 0xc6 */, 0 /* 0xc7 */,
	0 /* 0xc8 */, 0 /* 0xc9 */, 0 /* 0xca */, 0 /* 0xcb */, 0 /* 0xcc */,
	0 /* 0xcd */, 0 /* 0xce */, 0 /* 0xcf */, 0 /* 0xd0 */, 0 /* 0xd1 */,
	0 /* 0xd2 */, 0 /* 0xd3 */, 0 /* 0xd4 */, 0 /* 0xd5 */, 0 /* 0xd6 */,
	0 /* 0xd7 */, 0 /* 0xd8 */, 0 /* 0xd9 */, 0 /* 0xda */, 0 /* 0xdb */,
	0 /* 0xdc */, 0 /* 0xdd */, 0 /* 0xde */, 0 /* 0xdf */, 0 /* 0xe0 */,
	0 /* 0xe1 */, 0 /* 0xe2 */, 0 /* 0xe3 */, 0 /* 0xe4 */, 0 /* 0xe5 */,
	0 /* 0xe6 */, 0 /* 0xe7 */, 0 /* 0xe8 */, 0 /* 0xe9 */, 0 /* 0xea */,
	0 /* 0xeb */, 0 /* 0xec */, 0 /* 0xed */, 0 /* 0xee */, 0 /* 0xef */,
	0 /* 0xf0 */, 0 /* 0xf1 */, 0 /* 0xf2 */, 0 /* 0xf3 */, 0 /* 0xf4 */,
	0 /* 0xf5 */, 0 /* 0xf6 */, 0 /* 0xf7 */, 0 /* 0xf8 */, 0 /* 0xf9 */,
	0 /* 0xfa */, 0 /* 0xfb */, 0 /* 0xfc */, 0 /* 0xfd */, 0 /* 0xfe */,
	0 /* 0xff */
];

__gshared immutable const(ubyte)[] VALID_HD_VALUE_CHARS = [
	0 /* NUL  */, 0 /* SOH  */, 0 /* STX  */, 0 /* ETX  */, 0 /* EOT  */,
	0 /* ENQ  */, 0 /* ACK  */, 0 /* BEL  */, 0 /* BS   */, 1 /* HT   */,
	0 /* LF   */, 0 /* VT   */, 0 /* FF   */, 0 /* CR   */, 0 /* SO   */,
	0 /* SI   */, 0 /* DLE  */, 0 /* DC1  */, 0 /* DC2  */, 0 /* DC3  */,
	0 /* DC4  */, 0 /* NAK  */, 0 /* SYN  */, 0 /* ETB  */, 0 /* CAN  */,
	0 /* EM   */, 0 /* SUB  */, 0 /* ESC  */, 0 /* FS   */, 0 /* GS   */,
	0 /* RS   */, 0 /* US   */, 1 /* SPC  */, 1 /* !    */, 1 /* "    */,
	1 /* #    */, 1 /* $    */, 1 /* %    */, 1 /* &    */, 1 /* '    */,
	1 /* (    */, 1 /* )    */, 1 /* *    */, 1 /* +    */, 1 /* ,    */,
	1 /* -    */, 1 /* .    */, 1 /* /    */, 1 /* 0    */, 1 /* 1    */,
	1 /* 2    */, 1 /* 3    */, 1 /* 4    */, 1 /* 5    */, 1 /* 6    */,
	1 /* 7    */, 1 /* 8    */, 1 /* 9    */, 1 /* :    */, 1 /* ;    */,
	1 /* <    */, 1 /* =    */, 1 /* >    */, 1 /* ?    */, 1 /* @    */,
	1 /* A    */, 1 /* B    */, 1 /* C    */, 1 /* D    */, 1 /* E    */,
	1 /* F    */, 1 /* G    */, 1 /* H    */, 1 /* I    */, 1 /* J    */,
	1 /* K    */, 1 /* L    */, 1 /* M    */, 1 /* N    */, 1 /* O    */,
	1 /* P    */, 1 /* Q    */, 1 /* R    */, 1 /* S    */, 1 /* T    */,
	1 /* U    */, 1 /* V    */, 1 /* W    */, 1 /* X    */, 1 /* Y    */,
	1 /* Z    */, 1 /* [    */, 1 /* \    */, 1 /* ]    */, 1 /* ^    */,
	1 /* _    */, 1 /* `    */, 1 /* a    */, 1 /* b    */, 1 /* c    */,
	1 /* d    */, 1 /* e    */, 1 /* f    */, 1 /* g    */, 1 /* h    */,
	1 /* i    */, 1 /* j    */, 1 /* k    */, 1 /* l    */, 1 /* m    */,
	1 /* n    */, 1 /* o    */, 1 /* p    */, 1 /* q    */, 1 /* r    */,
	1 /* s    */, 1 /* t    */, 1 /* u    */, 1 /* v    */, 1 /* w    */,
	1 /* x    */, 1 /* y    */, 1 /* z    */, 1 /* {    */, 1 /* |    */,
	1 /* }    */, 1 /* ~    */, 0 /* DEL  */, 1 /* 0x80 */, 1 /* 0x81 */,
	1 /* 0x82 */, 1 /* 0x83 */, 1 /* 0x84 */, 1 /* 0x85 */, 1 /* 0x86 */,
	1 /* 0x87 */, 1 /* 0x88 */, 1 /* 0x89 */, 1 /* 0x8a */, 1 /* 0x8b */,
	1 /* 0x8c */, 1 /* 0x8d */, 1 /* 0x8e */, 1 /* 0x8f */, 1 /* 0x90 */,
	1 /* 0x91 */, 1 /* 0x92 */, 1 /* 0x93 */, 1 /* 0x94 */, 1 /* 0x95 */,
	1 /* 0x96 */, 1 /* 0x97 */, 1 /* 0x98 */, 1 /* 0x99 */, 1 /* 0x9a */,
	1 /* 0x9b */, 1 /* 0x9c */, 1 /* 0x9d */, 1 /* 0x9e */, 1 /* 0x9f */,
	1 /* 0xa0 */, 1 /* 0xa1 */, 1 /* 0xa2 */, 1 /* 0xa3 */, 1 /* 0xa4 */,
	1 /* 0xa5 */, 1 /* 0xa6 */, 1 /* 0xa7 */, 1 /* 0xa8 */, 1 /* 0xa9 */,
	1 /* 0xaa */, 1 /* 0xab */, 1 /* 0xac */, 1 /* 0xad */, 1 /* 0xae */,
	1 /* 0xaf */, 1 /* 0xb0 */, 1 /* 0xb1 */, 1 /* 0xb2 */, 1 /* 0xb3 */,
	1 /* 0xb4 */, 1 /* 0xb5 */, 1 /* 0xb6 */, 1 /* 0xb7 */, 1 /* 0xb8 */,
	1 /* 0xb9 */, 1 /* 0xba */, 1 /* 0xbb */, 1 /* 0xbc */, 1 /* 0xbd */,
	1 /* 0xbe */, 1 /* 0xbf */, 1 /* 0xc0 */, 1 /* 0xc1 */, 1 /* 0xc2 */,
	1 /* 0xc3 */, 1 /* 0xc4 */, 1 /* 0xc5 */, 1 /* 0xc6 */, 1 /* 0xc7 */,
	1 /* 0xc8 */, 1 /* 0xc9 */, 1 /* 0xca */, 1 /* 0xcb */, 1 /* 0xcc */,
	1 /* 0xcd */, 1 /* 0xce */, 1 /* 0xcf */, 1 /* 0xd0 */, 1 /* 0xd1 */,
	1 /* 0xd2 */, 1 /* 0xd3 */, 1 /* 0xd4 */, 1 /* 0xd5 */, 1 /* 0xd6 */,
	1 /* 0xd7 */, 1 /* 0xd8 */, 1 /* 0xd9 */, 1 /* 0xda */, 1 /* 0xdb */,
	1 /* 0xdc */, 1 /* 0xdd */, 1 /* 0xde */, 1 /* 0xdf */, 1 /* 0xe0 */,
	1 /* 0xe1 */, 1 /* 0xe2 */, 1 /* 0xe3 */, 1 /* 0xe4 */, 1 /* 0xe5 */,
	1 /* 0xe6 */, 1 /* 0xe7 */, 1 /* 0xe8 */, 1 /* 0xe9 */, 1 /* 0xea */,
	1 /* 0xeb */, 1 /* 0xec */, 1 /* 0xed */, 1 /* 0xee */, 1 /* 0xef */,
	1 /* 0xf0 */, 1 /* 0xf1 */, 1 /* 0xf2 */, 1 /* 0xf3 */, 1 /* 0xf4 */,
	1 /* 0xf5 */, 1 /* 0xf6 */, 1 /* 0xf7 */, 1 /* 0xf8 */, 1 /* 0xf9 */,
	1 /* 0xfa */, 1 /* 0xfb */, 1 /* 0xfc */, 1 /* 0xfd */, 1 /* 0xfe */,
	1 /* 0xff */
];
