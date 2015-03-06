module libhttp2.helpers;

import std.bitmanip : bigEndianToNative, nativeToBigEndian;
import libhttp2.types : HeaderField, Setting, Mem;
import std.c.string : memcpy;
import std.string : toLowerInPlace;

void write(T)(out ubyte* buf, T n) {
	auto x = nativeToBigEndian(n);
	memcpy(buf.ptr, x.ptr, T.sizeof);
}

T read(T = uint)(in ubyte* buf) {
	return bigEndianToNative(buf[0 .. T.sizeof]);
}


HeaderField[] copy(ref HeaderField[] hfa) {
	if (hfa.length == 0)
		return null;

	HeaderField[] ret = Mem.alloc!(HeaderField[])(hfa.length);

	foreach (size_t i, ref HeaderField hf; hfa) {
		ret[i].flag = hf.flag;
		ret[i].name = Mem.copy(hf.name);
		toLowerInPlace(ret[i].name);
		ret[i].value = Mem.copy(hf.value);
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
