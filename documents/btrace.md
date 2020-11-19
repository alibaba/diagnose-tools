##  btrace

btrace类似arthas，但是由于btrace可以定义脚本，所以在使用上相对arthas更加灵活，在某些arthas无法解决的场景，可以考虑使用btrace进行定位，其帮助文档位于:
https://github.com/btraceio/btrace/wiki/BTrace-Annotations?spm=ata.13261165.0.0.249b2086sNijQN
注意：本机需要指定JAVA_HOME环境变量，供btrace使用，同时btrace内部提供了比较多的samples脚本:
```
export JAVA_HOME=/opt/taobao/java/
```
### 示例：查看ThreadPoolExecutor初始化的堆栈
用法：
```
./bin/btrace 2184 ./samples/ThreadPoolExecutorInit.class  > /tmp/init.log
```
代码：
```
$more ThreadPoolExecutorInit.java
package samples;

import com.sun.btrace.BTraceUtils;
import com.sun.btrace.annotations.BTrace;
import com.sun.btrace.annotations.OnMethod;
import com.sun.btrace.annotations.ProbeClassName;
import com.sun.btrace.annotations.ProbeMethodName;

import static com.sun.btrace.BTraceUtils.println;

@BTrace public class ThreadPoolExecutorInit {


    @OnMethod(
            clazz = "java.util.concurrent.ThreadPoolExecutor",
            method = "<init>"
    )
    public static void logOnInit(@ProbeClassName String probeClass, @ProbeMethodName String probeMethod){
        println("==== " +  probeClass + " " + probeMethod);

        BTraceUtils.Threads.jstack();

        println("==== ================================");
    }

}
```
### 示例：btrace使用diagnose-tools脚本

在btrace中使用diagnose-tools脚本进行排查定位，在进入com.taobao.tair.comm.TairClientFactory.createClient 的时候开始开启btrace，在该接口返回后退出btrace
注意使用unsafe=true 才可以在btrace脚本中调用外部代码，同时指定需要将btrace 增加启动参数： -Dcom.sun.btrace.unsafe=true ， 开启非安全模式后，方可执行非安全脚本
```
./bin/btrace 3496 ./samples/BtraceMain.java
```
代码：
```
package com.sun.btrace.samples;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.sun.btrace.BTraceUtils;
import com.sun.btrace.annotations.*;

@BTrace(unsafe=true)
public class BtraceMain {

    @OnMethod(clazz = "com.taobao.tair.comm.TairClientFactory", method = "createClient")
    public static void start_run_trace() {
        FileOutputStream out = null;

        try {
            File file = new File("/proc/ali-linux/diagnose/kern/run-trace-settings");
            if (file.exists()) {
                out = new FileOutputStream("/proc/ali-linux/diagnose/kern/run-trace-settings");
                out.write("start\0".getBytes());
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

        BTraceUtils.print("enter");
    }
}
```
