#!/bin/bash

if [ ! -f `dirname $0`/"deps-vender.sh" ]; then
	touch `dirname $0`/deps-vender.sh
fi

sh `dirname $0`/deps-vender.sh
