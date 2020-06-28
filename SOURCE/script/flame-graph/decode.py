import sys
import json

def decode(array):
    title=array[0]
    info=title.split(',')
    if (len(info) != 2 ):
        return ""

    info_id=info[0].split('id=')[1]
    time_sec=info[1].split('time=')[1]

    duplicate_num=0
    user_stack=[]
    kern_stack=[]
    proc_chains=[]
    comm=""
    cgrp=""
    num=len(array)
    for i in(range(1,num)):
        index=num-i
        if index == num -1:
            last=array[index].rsplit(' ',1)
            msg=last[0]
            duplicate_num=int(last[1])
        else:
            msg=array[index]

        if msg.startswith("@"):
            msg_new=msg[msg.find('@')+1:]
            kern_stack.append(msg_new);

        elif msg.startswith("~"):
            msg_new=msg[msg.find('~')+1:]
            user_stack.append(msg_new);

        elif msg.startswith("^"):
            msg_new=msg[msg.find('^')+1:]
            proc_chains.append(msg_new);

        elif msg.startswith("*"):
            msg_new=msg[msg.find('*')+1:]
            comm=msg_new;

        elif msg.startswith("#"):
            msg_new=msg[msg.find('#')+1:]
            cgrp=msg_new.split('CGROUP:[')[1].split(']')[0];

    task=dict()

    if cgrp:
        task['cgroup']=cgrp

    if kern_stack:
        task["kern_stack"]=kern_stack

    if user_stack:
        task["user_stack"]=user_stack

    if proc_chains:
        task["proc_chains"]=proc_chains

    if comm:
        task['comm']=comm


    out=dict()
    out["task"]=task
    out['tv_sec']=time_sec
    out['id']=info_id
    out['seq']=0

    if duplicate_num != 0:
        out['duplicate_num']=duplicate_num

    newline="diagnose-tools | perf | "+time_sec+" | "+info_id+" | 0 | "+json.dumps(out)
    return newline

def decode_log(data):

    result=[]
    info=dict()
    for line in data:
        line=line.strip('\n')
        if not line:
            continue

        array=line.split(';')
        if len(array) < 1:
            continue

        json_str=decode(array)
        if json_str:
            print json_str
    
    return

f=open(sys.argv[1])
lines=f.readlines()
f.close()

decode_log(lines)
