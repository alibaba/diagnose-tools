#!/bin/sh
#****************************************************************#
# ScriptName: test.sh
# Author: baoyou.xie@linux.alibaba.com
# Create Date: 2020-02-15 15:53
# Modify Author: baoyou.xie@linux.alibaba.com
# Modify Date: 2020-02-15 15:53
# Function:
#***************************************************************#

if [ -f "`pwd`/SOURCE/diagnose-tools/diagnose-tools" ]; then
	diag_="`pwd`/SOURCE/diagnose-tools/diagnose-tools"
	DIAG_BINPATH="`pwd`/SOURCE/diagnose-tools/diagnose-tools"
else
	diag_="diagnose-tools"
	DIAG_BINPATH=`whereis diagnose-tools | awk '{printf $2}'`
fi

declare -a __all_case=(["1"]="sys-delay" ["2"]="sys-cost" ["3"]="sched-delay" \
			["4"]="irq-delay" ["5"]="irq-stats" ["6"]="irq-trace" \
			["7"]="load-monitor" ["8"]="run-trace" ["9"]="perf" \
			["10"]="kprobe" ["11"]="uprobe" ["12"]="utilization" \
			["13"]="exit-monitor" ["14"]="mutex-monitor" ["15"]="exec-monitor" \
			["16"]="proc-monitor" ["17"]="runq-info" \
			["18"]="alloc-load" ["19"]="alloc-top" ["20"]="high-order"\
			["21"]="drop-packet" ["22"]="tcp-retrans" ["23"]="ping-delay" \
			["24"]="rw-top" ["25"]="fs-shm" ["26"]="fs-orphan" ["27"]="df-du" \
			["28"]="fs-cache" ["999"]="kern-demo" )

sys_delay() {
	eval "$diag_ sys-delay --deactivate --activate='style=0' --test --report --deactivate --settings"
	eval "$diag_ sys-delay --deactivate --activate='style=1' --test --report --deactivate" | tee sys-delay.log
	eval "$diag_ flame --input=sys-delay.log --output=sys-delay.svg"
	echo "火焰图位于sys-delay.svg"
}

sys_cost() {
	eval "$diag_ sys-cost --deactivate --activate=verbose=1"
	sleep 2
	eval "$diag_ sys-cost --deactivate"
	eval "$diag_ sys-cost --report | tee sys-cost.log"
	cat sys-cost.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > sys-cost.count.svg
	cat sys-cost.log | awk '{if (substr($1,1,2) == "*#") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > sys-cost.cost.svg
}

sched_delay() {
        eval "$diag_ sched-delay --deactivate --activate --settings"
        sleep 1
        eval "$diag_ sched-delay --report"
        eval "$diag_ sched-delay --deactivate"
}

irq_delay() {
	eval "$diag_ irq-delay --deactivate --activate --test --report --deactivate --settings" | tee irq-delay.log
	eval "$diag_ flame --input=irq-delay.log --output=irq-delay.svg"
	echo "火焰图位于irq-delay.svg"
}

irq_stats() {
	eval "$diag_ irq-stats --deactivate --activate --settings"
	sleep 1
	eval "$diag_ irq-stats --report --deactivate"
}

irq_trace() {
	eval "$diag_ irq-trace --deactivate --activate='irq=1 sirq=5 timer=5' --settings"
	sleep 1
	eval "$diag_ irq-trace --report --deactivate"
}

load_monitor() {
	eval "$diag_ load-monitor --deactivate --activate='style=1 load=1' --settings"
	sleep 2
	eval "$diag_ load-monitor --report --deactivate" | tee load-monitor.log
	eval "$diag_ flame --input=load-monitor.log --output=load-monitor.svg"
	echo "火焰图位于load-monitor.svg"

#	eval "$diag_ load-monitor --style=0"
#	eval "$diag_ load-monitor --activate"
#	eval "$diag_ load-monitor --load=1"
#	sleep 10
#	eval "$diag_ load-monitor --report"
#	eval "$diag_ load-monitor --deactivate"
}

run_trace() {
	eval "$diag_ run-trace --deactivate --activate='timer-us=10' --test --report --deactivate --settings" | tee run-trace.log
	cat run-trace.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > run-trace.svg
	echo "火焰图位于run-trace.svg"

	TEST_ADDR="`objdump -s -d $DIAG_BINPATH | grep '<_ZL6mytestv>:' | awk '{printf $1}' | tr '[a-z]' '[A-Z]'`"
        TEST_OFFSET=`echo "obase=10; ibase=16; $TEST_ADDR - 400000" | bc`
	TEST_END=$[$TEST_OFFSET+10]

	eval "$diag_ test-run-trace --type=2 --count=10 &"
	TEST_PID=`ps aux | grep diagnose-tools | grep test-run-trace | awk '{printf $2}'`

	eval "$diag_ run-trace --uprobe=\"tgid=$TEST_PID start-file=$DIAG_BINPATH start-offset=$TEST_OFFSET stop-file=$DIAG_BINPATH stop-offset=$TEST_END\" --activate --settings"
	
	sleep 10
	eval "$diag_ run-trace --report --deactivate" | tee run-trace.log
}

perf() {
	eval "$diag_ perf --deactivate --activate='style=1 idle=1 bvt=1' --settings"
	sleep 1
	eval "$diag_ perf --report --deactivate" | tee perf.log
	eval "$diag_ flame --input=perf.log --output=perf.svg"
	echo "火焰图位于perf.svg"

	eval "$diag_ perf --deactivate --activate='style=0 idle=1 bvt=1'"
	sleep 1
	eval "$diag_ perf --report --deactivate"
}

kprobe() {
	eval "$diag_ kprobe --deactivate --activate='probe=hrtimer_interrupt'"
	sleep 1
	eval "$diag_ kprobe --report --deactivate --settings" | tee kprobe.log
	eval "$diag_ flame --input=kprobe.log --output=kprobe.svg"
        echo "火焰图位于kprobe.svg"
}

uprobe() {
	#eval "$diag_ uprobe --comm=sleep --activate=file=/usr/bin/sleep,offset=4848 --settings"
	#sleep .2
	#eval "$diag_ uprobe --report --deactivate"
	addr="`objdump -s -d /usr/diagnose-tools/bin/uprobe.out  | grep "<mytest3>:" | awk '{printf $1}' | tr '[a-z]' '[A-Z]'`"
	offset=`echo "obase=10; ibase=16; $addr - 400000" | bc`
	
	eval "$diag_ uprobe --deactivate --activate='verbose=1 file=/usr/diagnose-tools/bin/uprobe.out offset=$offset' --settings"
	/usr/diagnose-tools/bin/uprobe.out &
	sleep 2
	eval "$diag_ uprobe --report --deactivate"
}

utilization() {
	eval "$diag_ utilization --deactivate --activate='style=1 sample=1' --settings"
	sleep 1
	eval "$diag_ utilization --report --deactivate"
	eval "$diag_ utilization --deactivate --activate='style=2 sample=1' --settings"
	sleep 1
	eval "$diag_ utilization --report --deactivate"

	sleep 5
	eval "$diag_ utilization --deactivate --activate='sample=1'"
	sleep 1
	eval "$diag_ utilization --report --deactivate" | tee utilization.log
	cat utilization.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.cpu.svg
	cat utilization.log | awk '{if (substr($1,1,2) == "*#") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.mem.svg
	cat utilization.log | awk '{if (substr($1,1,2) == "*^") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.wild.svg
	echo "火焰图位于：utilization.cpu.svg、utilization.mem.svg、utilization.wild.svg"
}

exit_monitor() {
	eval "$diag_ exit-monitor --deactivate --activate='comm=diagnose-tools' --settings"
	diagnose-tools exit-monitor --test
	sleep .2
	eval "$diag_ exit-monitor --report --deactivate"
}

mutex_monitor() {
	eval "$diag_ mutex-monitor --deactivate --activate='style=0' --test --report --deactivate --settings"
	eval "$diag_ mutex-monitor --deactivate --activate='style=1' --test --report --deactivate"
}

exec_monitor() {
	eval "$diag_ exec-monitor --deactivate --activate"
	sleep 1
	eval "$diag_ exec-monitor --report --deactivate --settings"
}

proc_monitor() {
	eval "$diag_ proc-monitor --deactivate --activate='detail=1' --test --report --deactivate --settings"
}

runq_info() {
	eval "$diag_ runq-info --deactivate --activate"
	sleep 1
	eval "$diag_ runq-info --report --deactivate --settings"
}

alloc_load() {
	eval "$diag_ alloc-load --deactivate --activate"
	sleep 1
	eval "$diag_ alloc-load --report --deactivate --settings"
}

alloc_top() {
	eval "$diag_ alloc-top --deactivate --activate='top=20'"
	sleep 1
	eval "$diag_ alloc-top --report --deactivate --settings"
}

high_order() {
	eval "$diag_ high-order --deactivate --activate='order=2' --test"
	sleep 1
	eval "$diag_ high-order --report --deactivate --settings"
}

drop_packet() {
	eval "$diag_ drop-packet --deactivate --activate"
	ping www.baidu.com -c 1 > /dev/null
	sleep 1
	eval "$diag_ drop-packet --report --deactivate --settings"
}

tcp_retrans() {
	eval "$diag_ tcp-retrans --deactivate --activate='verbose=1'"
	wget http://www.baidu.com:9999 -o /dev/null &
	sleep 2
	eval "$diag_ tcp-retrans --report --deactivate --settings"
}

ping_delay() {
	#eval "$diag_ ping-delay --verbose=1 --activate --settings"
	#ping www.baidu.com -c 2
	#eval "$diag_ ping-delay --report"
	#eval "$diag_ ping-delay --deactivate"

	eval "$diag_ ping-delay --deactivate --activate='verbose=0' --settings"
	ping www.baidu.com -c 2
	eval "$diag_ ping-delay --report"
	eval "$diag_ ping-delay --deactivate"
}

rw_top() {
	dd of=./apsarapangu.data if=/dev/zero bs=10M count=1
	losetup /dev/loop0 ./apsarapangu.data
	mkfs -t ext4 /dev/loop0
	mount /dev/loop0 /apsarapangu/
	eval "$diag_ rw-top --deactivate -activate=\"perf=1 verbose=1\" --settings"
	echo test: `date` >> /apsarapangu/diagnose-tools.1.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	sleep 1
	eval "$diag_ rw-top --report --deactivate" | tee rw-top.log
        eval "$diag_ flame --input=rw-top.log --output=rw-top.svg"
        echo "火焰图位于rw-top.svg"
	umount /dev/loop0
	losetup -d /dev/loop0
	rm ./apsarapangu.data
}

fs_shm() {
	eval "$diag_ fs-shm --deactivate --activate --settings"
	echo test: `date` >> /run/diagnose-tools.log
	sleep 1
	eval "$diag_ fs-shm --report --deactivate"
}

fs_orphan() {
	eval "$diag_ fs-orphan --deactivate --activate='dev=sdb' --settings --report --deactivate --settings"
}

df_du() {
	eval "$diag_ df-du --deactivate --activate --report='file=/apsarapangu/a.data' --settings"
}

fs_cache() {
	eval "$diag_ fs-cache --deactivate --activate --report --settings"
}

call_sub_cmd() {
	func=$1
	func=${func//-/_}
	shift 1
	eval "$func $*"
}

main() {
	if [ $# -eq 0 ]; then
		for key in ${!__all_case[@]}; do
			SUB_CMD=${__all_case[$key]}
			type ${SUB_CMD//-/_} > /dev/null 2>&1
			if [ $? -ne 0 ]; then
				echo "testcase $SUB_CMD is not exists"
			else
				echo "start testcase $SUB_CMD"
				call_sub_cmd $SUB_CMD
			fi
		done
	else
		for key in ${!__all_case[@]}; do
			if [ "$1" = ${__all_case[$key]} ]; then
				call_sub_cmd $1
				exit 0
			elif [ "$1" = $key ]; then
				echo "start testcase ${__all_case[$key]}"
				call_sub_cmd ${__all_case[$key]}
				exit 0
			fi
		done

		echo "testcase $1 is not exists"
	fi
}

main $*
