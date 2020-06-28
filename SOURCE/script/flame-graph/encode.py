import sys
import json

g_time_tag=""
g_perf_id=""

def encode(strtmp):
    global g_time_tag
    global g_perf_id

    detail=strtmp[1]
    time_stamp=(strtmp[2])
    time_sec=str(int(float(time_stamp)))
    perf_id=str(strtmp[3].strip())
    msg_str=strtmp[5]

    if (("" == g_time_tag) and ("" == g_perf_id)):
        g_time_tag=time_sec
        g_perf_id=perf_id

    if (perf_id == g_perf_id):
        time_sec=g_time_tag
    else:
        g_time_tag=time_sec
        g_perf_id=perf_id

    try:
        msg=eval(msg_str.encode("utf-8"))
    except Exception, e:
        return

    if 'task' not in msg:
        return

    task=msg['task']

    if 'cgroup' not in task or 'comm' not in task or 'tgid' not in task:
        return

    if 'container_tgid' not in task or 'state' not in task:
        return

    cgroup=task["cgroup"]

    comm=task['comm']
    tgid=str(task['tgid'])
    container_tgid=str(task['container_tgid'])
    state=task['state']

    strstack="id="+perf_id+",time="+time_sec+" "+tgid +" 0 [00]\n"
    if "kern_stack" in task:
        stack_info=(task['kern_stack'])
        for stack in stack_info:
            strstack+="        0xffffffffffffffff @"+((stack.strip('\n')))+" ([kernel.kallsyms])\n"
    if "user_stack" in task:
        stack_info=(task['user_stack'])
        for stack in stack_info:
            strstack+="        0xffffffffffffffff ~"+((stack.strip('\n')))+" ([symbol])\n"

    strstack+="        0xffffffffffffffff *"+comm+" (UNKNOWN)\n"
    if "proc_chains" in task:
        stack_info=(task['proc_chains'])
        for stack in stack_info:
            strstack+="        0xffffffffffffffff ^"+(stack)+" (UNKNOWN)\n"

    strstack+="        0xffffffffffffffff #CGROUP:["+cgroup+"] (UNKNOWN)\n"
    print strstack
    return

def store_log(data):
    result=[]
    info=dict()
    for line in data:
        line=line.strip('\n')
        if not line:
            continue

        strtmp=line.split('|')
        if (len(strtmp) != 6):
            continue

        encode(strtmp)

    return

f=open(sys.argv[1])
lines=f.readlines()
f.close()
store_log(lines)
