#!/bin/bash

CFLAGS="-Werror"

if [ $CC = "clang" ]; then
	CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
fi

./autogen.sh && ./configure && make CFLAGS="$FLAGS"
