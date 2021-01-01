#!/bin/sh
#****************************************************************#
# ScriptName: presure.sh
# Author: baoyou.xie@linux.alibaba.com
# Create Date: 2020-02-15 15:53
# Modify Author: baoyou.xie@linux.alibaba.com
# Modify Date: 2020-02-15 15:53
# Function:
#***************************************************************#
CUR_DIR=$(dirname $0)

while :; do
	date > presure.log
	echo ${CUR_DIR}/test.sh >> presure.log
	sh ${CUR_DIR}/test.sh >> presure.log
	sleep 1
done
