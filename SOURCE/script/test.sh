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
			["27"]="net-bandwidth" ["28"]="sig-info" ["999"]="kern-demo" )

sys_delay() {
	eval "$DIAG_CMD sys-delay --deactivate --activate='style=0' --test --report --deactivate --settings" > sys-delay.log
	eval "$DIAG_CMD sys-delay --deactivate --activate='style=1' --test --report --deactivate" > sys-delay.log
	eval "$DIAG_CMD flame --input=sys-delay.log --output=sys-delay.svg"
	echo "火焰图位于sys-delay.svg"
}

sys_cost() {
	eval "$DIAG_CMD sys-cost --deactivate --activate=verbose=1"
	sleep 2
	eval "$DIAG_CMD sys-cost --deactivate"
	eval "$DIAG_CMD sys-cost --report" > sys-cost.log
	cat sys-cost.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > sys-cost.count.svg
	cat sys-cost.log | awk '{if (substr($1,1,2) == "*#") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > sys-cost.cost.svg
}

sched_delay() {
        eval "$DIAG_CMD sched-delay --deactivate --activate --settings"
        sleep 1
        eval "$DIAG_CMD sched-delay --report" > sched_delay.log
        eval "$DIAG_CMD sched-delay --deactivate"
}

irq_delay() {
	eval "$DIAG_CMD irq-delay --deactivate --activate --test --report --deactivate --settings" > irq-delay.log
	eval "$DIAG_CMD flame --input=irq-delay.log --output=irq-delay.svg"
	echo "火焰图位于irq-delay.svg"
}

irq_stats() {
	eval "$DIAG_CMD irq-stats --deactivate --activate --settings"
	sleep 1
	eval "$DIAG_CMD irq-stats --report --deactivate" > irq_stats.log
}

irq_trace() {
	eval "$DIAG_CMD irq-trace --deactivate --activate='irq=1 sirq=5 timer=5' --settings"
	sleep 1
	eval "$DIAG_CMD irq-trace --report --deactivate" > irq_trace.log
}

load_monitor() {
	eval "$DIAG_CMD load-monitor --deactivate --activate='style=1 load=1' --settings"
	sleep 1
	eval "$DIAG_CMD load-monitor --report --deactivate" > load-monitor.log
	eval "$DIAG_CMD load-monitor --deactivate --activate='style=1 load=1 mass=1' --settings"
	sleep 5
	eval "$DIAG_CMD load-monitor --report --deactivate" > load-monitor.log

	eval "$DIAG_CMD flame --input=load-monitor.log --output=load-monitor.svg"
	echo "火焰图位于load-monitor.svg"

	eval "$DIAG_CMD load-monitor --deactivate --activate='style=1 load=1' --settings"
	sleep 2
	eval "$DIAG_CMD load-monitor --report='json=1 flame=0'" > load-monitor.json
	eval "$DIAG_CMD load-monitor --deactivate"
#	eval "$DIAG_CMD load-monitor --style=0"
#	eval "$DIAG_CMD load-monitor --activate"
#	eval "$DIAG_CMD load-monitor --load=1"
#	sleep 10
#	eval "$DIAG_CMD load-monitor --report"
#	eval "$DIAG_CMD load-monitor --deactivate"
}

run_trace() {
	eval "$DIAG_CMD run-trace --deactivate --activate='timer-us=10' --test --report --deactivate --settings" > run-trace.log
	cat run-trace.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > run-trace.svg
	echo "火焰图位于run-trace.svg"

	TEST_ADDR="`objdump -s -d $DIAG_BINPATH | grep '<mytest>:' | awk '{printf $1}' | tr '[a-z]' '[A-Z]'`"
        TEST_OFFSET=`echo "obase=10; ibase=16; $TEST_ADDR - 400000" | bc`
	TEST_END=$[$TEST_OFFSET+10]

	eval "$DIAG_CMD test-run-trace --type=2 --count=10 &"
	TEST_PID=`ps aux | grep diagnose-tools | grep test-run-trace | awk '{printf $2}'`

	eval "$DIAG_CMD run-trace --uprobe=\"tgid=$TEST_PID start-file=$DIAG_BINPATH start-offset=$TEST_OFFSET stop-file=$DIAG_BINPATH stop-offset=$TEST_END\" --activate=\"raw-stack=1\" --settings"
	
	sleep 10
	eval "$DIAG_CMD run-trace --report --deactivate" > run-trace.log
}

perf() {
	eval "$DIAG_CMD perf --deactivate --activate='raw-stack=0 style=2 idle=1 bvt=1' --settings"

	files=""
	for i in `seq 10`; do
		sleep 1
		file="perf.${i}.raw"
		files+="${file}\n"
    		eval "$DIAG_CMD perf --report=\"out=$file\""
	done
	time eval "systemd-run --scope -p MemoryLimit=500M $DIAG_CMD --debug perf --report=\"console=1\"" > perf.log << EOF
`echo -e "${files}"`
EOF

	eval "$DIAG_CMD perf --deactivate --activate='raw-stack=0 style=2 idle=1 bvt=1' --settings"
	sleep 1
	time eval "systemd-run --scope -p MemoryLimit=500M $DIAG_CMD perf --report=\"json=1 flame=0\"" > perf.json

	eval "$DIAG_CMD perf --deactivate"

	eval "$DIAG_CMD flame --input=perf.log --output=perf.svg"
        echo "火焰图位于perf.svg"
}

kprobe() {
	eval "$DIAG_CMD kprobe --deactivate --activate='probe=hrtimer_interrupt'"
        files=""
        for i in `seq 10`; do
                sleep 1
                file="__kprobe.${i}.raw"
                files+="${file}\n"
                eval "$DIAG_CMD kprobe --report=\"out=$file\""
        done
        eval "systemd-run --scope -p MemoryLimit=500M $DIAG_CMD kprobe --report=\"console=1\"" > kprobe.log << EOF
`echo -e "${files}"`
EOF

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
	eval "$DIAG_CMD uprobe --report --deactivate" > uprobe.log
}

utilization() {
	eval "$DIAG_CMD utilization --deactivate --activate='style=1 sample=1' --settings"
	sleep 1
	eval "$DIAG_CMD utilization --report --deactivate" > utilization.log
	eval "$DIAG_CMD utilization --deactivate --activate='style=2 sample=1' --settings"
	sleep 1
	eval "$DIAG_CMD utilization --report --deactivate" > utilization.log

	sleep 5
	eval "$DIAG_CMD utilization --deactivate --activate='sample=1'"
	sleep 1
	eval "$DIAG_CMD utilization --report --deactivate" > utilization.log
	cat utilization.log | awk '{if (substr($1,1,2) == "**") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.cpu.svg
	cat utilization.log | awk '{if (substr($1,1,2) == "*#") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.mem.svg
	cat utilization.log | awk '{if (substr($1,1,2) == "*^") {print substr($0, 3)}}' | /usr/diagnose-tools/flame-graph/flamegraph.pl > utilization.wild.svg
	echo "火焰图位于：utilization.cpu.svg、utilization.mem.svg、utilization.wild.svg"
}

exit_monitor() {
	eval "$DIAG_CMD exit-monitor --deactivate --activate='comm=diagnose-tools' --settings"
	diagnose-tools exit-monitor --test
	sleep .2
	eval "$DIAG_CMD exit-monitor --report --deactivate" > exit_monitor.log
}

mutex_monitor() {
	eval "$DIAG_CMD mutex-monitor --deactivate --activate='style=0' --test --report --deactivate --settings" > mutex_monitor.log
	eval "$DIAG_CMD mutex-monitor --deactivate --activate='style=1' --test --report --deactivate" > mutex_monitor.log
}

exec_monitor() {
	eval "$DIAG_CMD exec-monitor --deactivate --activate"
	sleep 1
	eval "$DIAG_CMD exec-monitor --report --deactivate --settings" > exec_monitor.log
}

alloc_top() {
	eval "$DIAG_CMD alloc-top --deactivate --activate='top=20'"
	sleep 1
	eval "$DIAG_CMD alloc-top --report --deactivate --settings" > alloc_top.log
}

high_order() {
	eval "$DIAG_CMD high-order --deactivate --activate='order=2' --test"
	sleep 1
	eval "$DIAG_CMD high-order --report --deactivate --settings" > high_order.log
}

drop_packet() {
	eval "$DIAG_CMD drop-packet --deactivate --activate"
	ping www.baidu.com -c 1 > /dev/null
	sleep 1
	eval "$DIAG_CMD drop-packet --report --deactivate --settings" > drop_packet.log
}

tcp_retrans() {
	eval "$DIAG_CMD tcp-retrans --deactivate --activate='verbose=1'"
	wget http://www.baidu.com:9999 -o /dev/null &
	sleep 2
	eval "$DIAG_CMD tcp-retrans --report --deactivate --settings" > tcp_retrans.log
}

ping_delay() {
	#eval "$DIAG_CMD ping-delay --verbose=1 --activate --settings"
	#ping www.baidu.com -c 2
	#eval "$DIAG_CMD ping-delay --report"
	#eval "$DIAG_CMD ping-delay --deactivate"

	eval "$DIAG_CMD ping-delay --deactivate --activate='verbose=0' --settings"
	ping www.baidu.com -c 2
	eval "$DIAG_CMD ping-delay --report" > ping_delay.log
	eval "$DIAG_CMD ping-delay --deactivate"
}

rw_top() {
	mkdir /apsarapangu
	eval "$DIAG_CMD rw-top --deactivate -activate=\"raw-stack=0 perf=1 verbose=1\" --settings"
	echo test: `date` >> /apsarapangu/diagnose-tools.1.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	echo test: `date` >> /apsarapangu/diagnose-tools.2.log
	sleep 1
	
	files=""
        for i in `seq 2`; do
                sleep 1
                file="rw-top.${i}.raw"
                files+="${file}\n"
                eval "$DIAG_CMD rw-top --report=\"out=$file\""
        done

        eval "$DIAG_CMD rw-top --report=\"console=1\"" > rw-top.1.log << EOF
`echo -e ${files}`
EOF
        eval "$DIAG_CMD flame --input=rw-top.1.log --output=rw-top.1.svg"
        echo "火焰图位于rw-top.1.svg"

	
	ls -l rw-top.*.raw |awk '{print $NF}' > rw-top.txt
        eval "$DIAG_CMD rw-top --report=\"inlist=rw-top.txt\"" > rw-top.2.log

        eval "$DIAG_CMD flame --input=rw-top.2.log --output=rw-top.2.svg"
        echo "火焰图位于rw-top.2.svg"
}

fs_shm() {
	eval "$DIAG_CMD fs-shm --deactivate --activate --settings"
	echo test: `date` >> /run/diagnose-tools.log
	sleep 1
	eval "$DIAG_CMD fs-shm --report --deactivate" > fs_shm.log
}

fs_orphan() {
	eval "$DIAG_CMD fs-orphan --deactivate --activate='dev=sdb' --settings --report --deactivate --settings" > fs_orphan.log
}

fs_cache() {
	eval "$DIAG_CMD fs-cache --deactivate --activate --report --settings" > fs_cache.log
}

task_info() {
	eval "$DIAG_CMD task-info --pid=1 --report" > task_info.log
}

cpu_loop() {
	for i in `seq $1`; do
		sh -c "while :; do echo ok > /dev/null; done" &
	done
}

reboot() {
	eval "$DIAG_CMD reboot --verbose=1 --activate --settings"
}

net_bandwidth() {
	eval "$DIAG_CMD net-bandwidth --deactivate --activate"
	ping www.baidu.com -c 1 > /dev/null
	sleep 1
	eval "$DIAG_CMD net-bandwidth --report='testcount=2' --deactivate --settings" > net_bandwidth.log
}

sig_info() {
	eval "$DIAG_CMD sig-info --deactivate --activate='signum=9,11' --settings"
	sleep 1
	eval "$DIAG_CMD sig-info --report" > sig_info.log
}

task_monitor() {
	eval "$DIAG_CMD task-monitor --deactivate --activate='task.a=1 task.r=1 task.d=1 interval=100' --settings"
	sleep 1
	eval "$DIAG_CMD task-monitor --report" > task_monitor.log
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
