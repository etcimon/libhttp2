module libhttp2.helpers;
import std.bitmanip : bigEndianToNative, nativeToBigEndian;

void write(T)(out ubyte[] buf, T n) {
	auto x = nativeToBigEndian(n);
	memcpy(buf.ptr, x.ptr, ushort.sizeof);
}

T read(T = uint)(in ubyte[] data) {
	return bigEndianToNative(data[0 .. T.sizeof]);
}