#!/bin/bash

if [ ! -f `dirname $0`/"module.mk" ]; then
	touch `dirname $0`/module.mk
fi

if [ ! -f `dirname $0`/"devel-vender.sh" ]; then
	touch `dirname $0`/devel-vender.sh
fi

sh `dirname $0`/devel-vender.sh
