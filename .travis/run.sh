#!/bin/bash

set -e

CFLAGS="-Werror -Wall -Wdeclaration-after-statement -Wvla"

if [ "$CC" = "clang" ]; then
	CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument -Wno-error=unused-function"
fi

CFLAGS="$CFLAGS -DNL_MORE_ASSERTS=1000"

export CFLAGS
./autogen.sh
./configure
make -j 5
make -j 5 check
