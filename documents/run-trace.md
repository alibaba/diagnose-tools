##  run-trace
本功能监控统计多个进程或者线程的运行状况，以及用户态/内核态热点调用链。
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools run-trace --help
```
结果如下：
```
    run-trace usage:
        --help run-trace help info
        --activate
            verbose VERBOSE
            threshold default THRESHOLD(MS), you may set special value in code
            threshold-us default THRESHOLD(US)
            buf-size-k set buf size(k) for per-thread
            timer-us perf timer(us)
        --deactivate
        --settings print settings.
        --report dump log with text.
        --test testcase for run-trace.
        --set-syscall PID SYSCALL THRESHOLD monitor special syscall
        --clear-syscall PID do not monitor syscall
        --uprobe set uprobe to start/stop trace.
```
###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools run-trace --activate
```
在激活本功能时，可用参数为：
* verbose VERBOSE 设置输出信息的级别，目前未用。
* threshold 该参数设置监控阀值，单位是ms。默认值是500。当用户态应用在一段代码中运行超过阀值，就会详细的输出这段代码超时的详细信息。应用程序可以传递参数指定自己想要监控的阀值，将忽略此设置。
* threshold-us 该参数设置监控阀值，单位是us。此参数优先级高于threshold参数。
* timer-us 指定采样周期，单位是us。如果指定此参数，将定期采集当前线程的行为。
* buf-size-k 设置每个线程的监控缓冲区大小，默认为200K，最大可以上调到10M。单位为K。
例如，如下命令将设置采样周期为10us，以及输出级别为1：
```
diagnose-tools run-trace --activate='timer-us=10 verbose=1'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    阀值(us)：500000
    输出级别：1
    TIMER_US：10
    BUF-SIZE-K：0
```
如果失败，将输出：
```
功能设置失败，返回值：-16
    阀值(us)：500000
    输出级别：1
    TIMER_US：10
    BUF-SIZE-K：0
```
###  设置参数
--set-syscall 设置将对哪个进程监控哪个系统调用，以及其监控阀值。在不同的环境中，同一个系统调用的编号并不相同。可以使用/usr/diagnose-tools/get_sys_call.sh脚本来获得某个系统调用号。例如下面的命令将获得open系统调用的编号：
```
sh /usr/diagnose-tools/get_sys_call.sh open
```
   	--clear-syscall 清除要监控的进程，不再对其系统调用进行监控。
--uprobe 设置用户态探针位置。例如：
--uprobe="tgid=`pgrep run-trace.out | head -1` start-file=/usr/diagnose-tools/bin/run-trace.out start-offset=1875 stop-file=/usr/diagnose-tools/bin/run-trace.out stop-offset=1885"
该命令会监控run-trace.out文件，并在其偏移1875地方设置探针，开始对RT进行计时，并在第1885的地方再次设置探针，结束对RT进行计时。
这样，就不需要修改应用程序就可以监控其run-trace结果了。
例如，如下命令将监控阀值编号为1234的进程的第35号系统调用，其监控阀值为900ms：
```
diagnose-tools run-trace --set-syscall="1234 35 900"
```
如果成功，将输出：
```
set-syscall for run-trace: pid 1234, syscall 35, threshold 900ms, ret is 0
```
如果失败，将输出：
```
set-syscall for run-trace: pid 1234, syscall 35, threshold 900ms, ret is -1
```
如下命令将清除编号为1234的进程监控，不再对其所有系统调用进行监控：
```
diagnose-tools run-trace --clear-syscall="1234"
```
如果成功，将输出：
```
clear-syscall for run-trace: pid 1234, ret is 0
```
如果失败，将输出：
```
clear-syscall for run-trace: pid 1234, ret is -1
```
###  测试用例
运行如下命令运行测试用例，以查看本功能是否正常：
```
sh /usr/diagnose-tools/test.sh run-trace
```

###  应用改造
一般情况下，需要修改应用程序，也不需要重启应用程序。
有3种方式对应用程序的RT进行监控。
其中一种方式是监控应用的某个系统调用RT高。这种情况不需要对应用进程改造。
另一种方式是监控应用程序某一段代码的RT超时，需要应用程序在计算RT开始和结束的地方，按照diagnose-tools工具的要求来修改应用程序。
C代码示例如下：
```
	for (i = 0; i < count; i++) {
		syscall(ALI_DIAG_RUN_TRACE_START, 100);
		sleep(1);
		sleep(1);
		syscall(ALI_DIAG_RUN_TRACE_STOP);
	}
```
其中syscall(ALI_DIAG_RUN_TRACE_START, 100)启动run-trace监控功能，这样run-trace就会开始对当前程序进行监控，如果在syscall(ALI_DIAG_RUN_TRACE_STOP)之前，程序运行时间超过100ms，将记录下系统日志。
syscall(ALI_DIAG_RUN_TRACE_STOP)告诉run-trace结束监控。如果在启动/结束之间的运行时间超过100ms，就会输出警告信息。

你也可以写一段java代码来告诉run-trace启动/结束监控：
```
static class ali_diagnose_settings
	{
		static void start_run_trace()
		{
			FileOutputStream out = null;

			try {
				File file = new File("/proc/ali-linux/diagnose/kern/run-trace-settings");
				if (file.exists()) {
					out = new FileOutputStream("/proc/ali-linux/diagnose/kern/run-trace-settings");
					out.write("start 100\n\0".getBytes());
					out.write(0);
					out.write(System.getProperty("line.separator").getBytes());
				}
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				if (out != null) {
					try {
						out.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}

		static void stop_run_trace()
		{
			FileOutputStream out = null;

			try {
				File file = new File("/proc/ali-linux/diagnose/kern/run-trace-settings");
				if (file.exists()) {
					out = new FileOutputStream("/proc/ali-linux/diagnose/kern/run-trace-settings");
					out.write("stop\n".getBytes());
					out.write(0);
					out.write(System.getProperty("line.separator").getBytes());
				}
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				if (out != null) {
					try {
						out.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}
	}
```
当然了，在Java中，也可以通过JNI的方式来调用syscall，来告诉run-trace启动/结束监控。
第三种方法是利用btrace或者uprobe功能，直接在应用程序中挂接钩子，这样就不需要对应用程序进行修改了。
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools run-trace --settings
```
结果如下：
```
功能设置：
    是否激活：×
    阀值(ms)：500
    输出级别：0
    线程监控项：0
    系统调用监控项：0
```
###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools run-trace --report
```
该命令会以文件的方式输出监控结果。一般情况下，业务同学不应当使用此命令。应当使用网页来查看监控结果。
每次输出结果后，历史数据将被清空。

###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools run-trace --deactivate
```
如果成功，将输出：
```
run-trace is not activated
```
如果失败，将输出：
```
deactivate run-trace fail, ret is -1
```
