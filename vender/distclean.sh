#!/bin/bash

if [ ! -f `dirname $0`/"distclean-vender.sh" ]; then
	touch `dirname $0`/distclean-vender.sh
fi

sh `dirname $0`/distclean-vender.sh
