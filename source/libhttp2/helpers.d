module libhttp2.helpers;

import std.bitmanip : bigEndianToNative, nativeToBigEndian;
import libhttp2.types : NVPair, Setting, Mem;
import std.c.string : memcpy;
import std.string : toLowerInPlace;

void write(T)(out ubyte* buf, T n) {
	auto x = nativeToBigEndian(n);
	memcpy(buf.ptr, x.ptr, T.sizeof);
}

T read(T = uint)(in ubyte* buf) {
	return bigEndianToNative(buf[0 .. T.sizeof]);
}


NVPair[] copy(ref NVPair[] nva) {
	if (nva.length == 0)
		return null;

	NVPair[] ret = Mem.alloc!(NVPair[])(nva.length);

	foreach (size_t i, ref NVPair nv; nva) {
		ret[i].flags = nv.flags;
		ret[i].name = Mem.copy(nv.name);
		toLowerInPlace(ret[i].name);
		ret[i].value = Mem.copy(nv.value);
	}
	return ret;
}

/*
 * Makes copy of |iv| and return the copy. This function returns the 
 * copy if it succeeds, or null.
 */
Setting[] copy(in Setting[] iv) {
	if (iv.length == 0)
		return null;

	return Mem.copy(iv);
}
