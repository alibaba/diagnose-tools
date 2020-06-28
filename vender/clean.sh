#!/bin/bash

if [ ! -f `dirname $0`/"clean-vender.sh" ]; then
	touch `dirname $0`/clean-vender.sh
fi

sh `dirname $0`/clean-vender.sh
