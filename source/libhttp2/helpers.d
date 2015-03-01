module libhttp2.helpers;

import std.bitmanip : bigEndianToNative, nativeToBigEndian;

void write(T)(out ubyte* buf, T n) {
	auto x = nativeToBigEndian(n);
	memcpy(buf.ptr, x.ptr, T.sizeof);
}

T read(T = uint)(in ubyte* buf) {
	return bigEndianToNative(buf[0 .. T.sizeof]);
}
