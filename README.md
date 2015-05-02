[![Build Status](https://travis-ci.org/etcimon/libhttp2.svg)](https://travis-ci.org/etcimon/libhttp2)

# libhttp2 

### About

libhttp2 is an HTTP/2 library written completely in D, translated from nghttp2. It aims at having an object-oriented API
suitable for native D development. It also takes advantage of safer primitives and more runtime checks to avoid flaws.
Although D is a garbage collected language, this library runs exclusively on manual memory allocations via [memutils](https://github.com/etcimon/memutils).

It can be used in a client/server through my vibe.d fork in the [http2-botan branch](https://github.com/etcimon/vibe.d/tree/http2-botan). 

### Tests

The library itself is tested in depth using the same unit tests as nghttp2. 

### Getting Started

The documentation is currently entirely contained within the source code. This library is very low-level and thus
must be understood in depth (along with the HTTP/2 specs) before integrating it to a project. ie. Read the sources

### Copyrights

(C) 2012-2015 Tatsuhiro Tsujikawa
(C) 2014-2015 Etienne Cimon

Distributed under the terms of the MIT license with an additional section 1.2 of the curl/libcurl project. 
Consult the provided LICENSE.md file for details
