#!/bin/bash

set -e

CFLAGS="-Werror -Wall -Wdeclaration-after-statement"

if [ "$CC" = "clang" ]; then
	CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument -Wno-error=unused-function"
fi

export CFLAGS
./autogen.sh
./configure
make -j 5
make -j 5 check
