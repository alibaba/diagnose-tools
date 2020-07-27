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
	DIAG_CMD="`pwd`/SOURCE/diagnose-tools/diagnose-tools"
	DIAG_BINPATH="`pwd`/SOURCE/diagnose-tools/diagnose-tools"
else
	DIAG_CMD="diagnose-tools"
	DIAG_BINPATH=`whereis diagnose-tools | awk '{printf $2}'`
fi

declare -a __all_case=(["1"]="sys-delay" ["2"]="sys-cost" ["3"]="sched-delay" \
			["4"]="irq-delay" ["5"]="irq-stats" ["6"]="irq-trace" \
			["7"]="load-monitor" ["8"]="run-trace" ["9"]="perf" \
			["10"]="kprobe" ["11"]="uprobe" ["12"]="utilization" \
			["13"]="exit-monitor" ["14"]="mutex-monitor" ["15"]="exec-monitor" \
			["16"]="alloc-top" ["17"]="high-order"\
			["18"]="drop-packet" ["19"]="tcp-retrans" ["20"]="ping-delay" \
			["21"]="rw-top" ["22"]="fs-shm" ["23"]="fs-orphan" \
			["24"]="fs-cache" ["25"]="task-info" ["26"]="reboot" \
			["100"]="cpu-loop" ["999"]="kern-demo" )

sys_delay() {
	eval "$DIAG_CMD sys-delay --deactivate --activate='style=0' --test --report --deactivate --settings"
	eval "$DIAG_CMD sys-delay --deactivate --activate='style=1' --test --report --deactivate" | tee sys-delay.log
	eval "$DIAG_CMD flame --input=sys-delay.log --output=sys-delay.svg"
	echo "火焰图位于sys-delay.svg"
}

sys_cost() {
	eval "$DIAG_CMD sys-cost --deactivate --activate=verbose=1"
	sleep 2
	eval "$DIAG_CMD sys-cost --deactivate"
	eval "$DIAG_CMD sys-cost --report | tee sys-cost.log"
	cat sys-cost.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > sys-cost.count.svg
	cat sys-cost.log | awk '{if (substr($1,1,2) == "*#") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > sys-cost.cost.svg
}

sched_delay() {
        eval "$DIAG_CMD sched-delay --deactivate --activate --settings"
        sleep 1
        eval "$DIAG_CMD sched-delay --report"
        eval "$DIAG_CMD sched-delay --deactivate"
}

irq_delay() {
	eval "$DIAG_CMD irq-delay --deactivate --activate --test --report --deactivate --settings" | tee irq-delay.log
	eval "$DIAG_CMD flame --input=irq-delay.log --output=irq-delay.svg"
	echo "火焰图位于irq-delay.svg"
}

irq_stats() {
	eval "$DIAG_CMD irq-stats --deactivate --activate --settings"
	sleep 1
	eval "$DIAG_CMD irq-stats --report --deactivate"
}

irq_trace() {
	eval "$DIAG_CMD irq-trace --deactivate --activate='irq=1 sirq=5 timer=5' --settings"
	sleep 1
	eval "$DIAG_CMD irq-trace --report --deactivate"
}

load_monitor() {
	eval "$DIAG_CMD load-monitor --deactivate --activate='style=1 load=1' --settings"
	sleep 2
	eval "$DIAG_CMD load-monitor --report --deactivate" | tee load-monitor.log
	eval "$DIAG_CMD flame --input=load-monitor.log --output=load-monitor.svg"
	echo "火焰图位于load-monitor.svg"

#	eval "$DIAG_CMD load-monitor --style=0"
#	eval "$DIAG_CMD load-monitor --activate"
#	eval "$DIAG_CMD load-monitor --load=1"
#	sleep 10
#	eval "$DIAG_CMD load-monitor --report"
#	eval "$DIAG_CMD load-monitor --deactivate"
}

run_trace() {
	eval "$DIAG_CMD run-trace --deactivate --activate='timer-us=10' --test --report --deactivate --settings" | tee run-trace.log
	cat run-trace.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > run-trace.svg
	echo "火焰图位于run-trace.svg"

	TEST_ADDR="`objdump -s -d $DIAG_BINPATH | grep '<_ZL6mytestv>:' | awk '{printf $1}' | tr '[a-z]' '[A-Z]'`"
        TEST_OFFSET=`echo "obase=10; ibase=16; $TEST_ADDR - 400000" | bc`
	TEST_END=$[$TEST_OFFSET+10]

	eval "$DIAG_CMD test-run-trace --type=2 --count=10 &"
	TEST_PID=`ps aux | grep diagnose-tools | grep test-run-trace | awk '{printf $2}'`

	eval "$DIAG_CMD run-trace --uprobe=\"tgid=$TEST_PID start-file=$DIAG_BINPATH start-offset=$TEST_OFFSET stop-file=$DIAG_BINPATH stop-offset=$TEST_END\" --activate --settings"
	
	sleep 10
	eval "$DIAG_CMD run-trace --report --deactivate" | tee run-trace.log
}

perf() {
	eval "$DIAG_CMD perf --deactivate --activate='style=1 idle=1 bvt=1' --settings"
	sleep 1
	eval "$DIAG_CMD perf --report --deactivate" | tee perf.log
	eval "$DIAG_CMD flame --input=perf.log --output=perf.svg"
	echo "火焰图位于perf.svg"

	eval "$DIAG_CMD perf --deactivate --activate='style=0 idle=1 bvt=1'"
	sleep 1
	eval "$DIAG_CMD perf --report --deactivate"
}

kprobe() {
	eval "$DIAG_CMD kprobe --deactivate --activate='probe=hrtimer_interrupt'"
	sleep 1
	eval "$DIAG_CMD kprobe --report --deactivate --settings" | tee kprobe.log
	eval "$DIAG_CMD flame --input=kprobe.log --output=kprobe.svg"
        echo "火焰图位于kprobe.svg"
}

uprobe() {
	#eval "$DIAG_CMD uprobe --comm=sleep --activate=file=/usr/bin/sleep,offset=4848 --settings"
	#sleep .2
	#eval "$DIAG_CMD uprobe --report --deactivate"
	addr="`objdump -s -d $DIAG_BINPATH  | grep "<mytest3>:" | awk '{printf $1}' | tr '[a-z]' '[A-Z]'`"
	offset=`echo "obase=10; ibase=16; $addr - 400000" | bc`
	
	eval "$DIAG_CMD uprobe --deactivate --activate='verbose=1 file=$DIAG_BINPATH offset=$offset' --settings"
	eval "$DIAG_CMD test-run-trace --type=2 &"
	sleep 2
	eval "$DIAG_CMD uprobe --report --deactivate"
}

utilization() {
	eval "$DIAG_CMD utilization --deactivate --activate='style=1 sample=1' --settings"
	sleep 1
	eval "$DIAG_CMD utilization --report --deactivate"
	eval "$DIAG_CMD utilization --deactivate --activate='style=2 sample=1' --settings"
	sleep 1
	eval "$DIAG_CMD utilization --report --deactivate"

	sleep 5
	eval "$DIAG_CMD utilization --deactivate --activate='sample=1'"
	sleep 1
	eval "$DIAG_CMD utilization --report --deactivate" | tee utilization.log
	cat utilization.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.cpu.svg
	cat utilization.log | awk '{if (substr($1,1,2) == "*#") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.mem.svg
	cat utilization.log | awk '{if (substr($1,1,2) == "*^") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.wild.svg
	echo "火焰图位于：utilization.cpu.svg、utilization.mem.svg、utilization.wild.svg"
}

exit_monitor() {
	eval "$DIAG_CMD exit-monitor --deactivate --activate='comm=diagnose-tools' --settings"
	diagnose-tools exit-monitor --test
	sleep .2
	eval "$DIAG_CMD exit-monitor --report --deactivate"
}

mutex_monitor() {
	eval "$DIAG_CMD mutex-monitor --deactivate --activate='style=0' --test --report --deactivate --settings"
	eval "$DIAG_CMD mutex-monitor --deactivate --activate='style=1' --test --report --deactivate"
}

exec_monitor() {
	eval "$DIAG_CMD exec-monitor --deactivate --activate"
	sleep 1
	eval "$DIAG_CMD exec-monitor --report --deactivate --settings"
}

alloc_top() {
	eval "$DIAG_CMD alloc-top --deactivate --activate='top=20'"
	sleep 1
	eval "$DIAG_CMD alloc-top --report --deactivate --settings"
}

high_order() {
	eval "$DIAG_CMD high-order --deactivate --activate='order=2' --test"
	sleep 1
	eval "$DIAG_CMD high-order --report --deactivate --settings"
}

drop_packet() {
	eval "$DIAG_CMD drop-packet --deactivate --activate"
	ping www.baidu.com -c 1 > /dev/null
	sleep 1
	eval "$DIAG_CMD drop-packet --report --deactivate --settings"
}

tcp_retrans() {
	eval "$DIAG_CMD tcp-retrans --deactivate --activate='verbose=1'"
	wget http://www.baidu.com:9999 -o /dev/null &
	sleep 2
	eval "$DIAG_CMD tcp-retrans --report --deactivate --settings"
}

ping_delay() {
	#eval "$DIAG_CMD ping-delay --verbose=1 --activate --settings"
	#ping www.baidu.com -c 2
	#eval "$DIAG_CMD ping-delay --report"
	#eval "$DIAG_CMD ping-delay --deactivate"

	eval "$DIAG_CMD ping-delay --deactivate --activate='verbose=0' --settings"
	ping www.baidu.com -c 2
	eval "$DIAG_CMD ping-delay --report"
	eval "$DIAG_CMD ping-delay --deactivate"
}

rw_top() {
	dd of=./apsarapangu.data if=/dev/zero bs=10M count=1
	losetup /dev/loop0 ./apsarapangu.data
	mkfs -t ext4 /dev/loop0
	mount /dev/loop0 /apsarapangu/
	eval "$DIAG_CMD rw-top --deactivate -activate=\"perf=1 verbose=1\" --settings"
	echo test: `date` >> /apsarapangu/diagnose-tools.1.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	sleep 1
	eval "$DIAG_CMD rw-top --report --deactivate" | tee rw-top.log
        eval "$DIAG_CMD flame --input=rw-top.log --output=rw-top.svg"
        echo "火焰图位于rw-top.svg"
	umount /dev/loop0
	losetup -d /dev/loop0
	rm ./apsarapangu.data
}

fs_shm() {
	eval "$DIAG_CMD fs-shm --deactivate --activate --settings"
	echo test: `date` >> /run/diagnose-tools.log
	sleep 1
	eval "$DIAG_CMD fs-shm --report --deactivate"
}

fs_orphan() {
	eval "$DIAG_CMD fs-orphan --deactivate --activate='dev=sdb' --settings --report --deactivate --settings"
}

fs_cache() {
	eval "$DIAG_CMD fs-cache --deactivate --activate --report --settings"
}

task_info() {
	eval "$DIAG_CMD task-info --pid=1 --report"
}

cpu_loop() {
	for i in `seq $1`; do
		sh -c "while :; do echo ok > /dev/null; done" &
	done
}

reboot() {
	eval "$DIAG_CMD reboot --verbose=1 --activate --settings"
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
				call_sub_cmd $*
				exit 0
			elif [ "$1" = $key ]; then
				echo "start testcase ${__all_case[$key]}"
				shift 1
				call_sub_cmd ${__all_case[$key]} $*
				exit 0
			fi
		done

		echo "testcase $1 is not exists"
	fi
}

main $*
