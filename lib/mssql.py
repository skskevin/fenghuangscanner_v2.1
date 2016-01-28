#coding=utf-8
import time
import threading
from printers import printPink,printGreen
from multiprocessing.dummy import Pool
import socket
socket.setdefaulttimeout(8)
import pymssql



def mssql_connect(ip,username,password,port):
    crack =0
    try:
        db=pymssql.connect(host=str(ip)+','+str(port),user=username,password=password)
        if db:
            crack=1
        db.close()
    except Exception, e:
        lock.acquire()
        print "%s sql service 's %s:%s login fail " %(ip,username,password)
        lock.release()
    return crack


def mssq1(ip,port):
        try:
            d=open('conf/mssql.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                flag=mssql_connect(ip,username,password,port)
                if flag==2:
                    break

                if flag==1:
                    lock.acquire()
                    printGreen("%s mssql at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s mssql at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break

                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass


def mssql_main(ipdict,threads):
    printPink("crack sql serice  now...")
    print "[*] start crack sql serice  %s" % time.ctime()
    starttime=time.time()
    pool=Pool(threads)
    global lock
    lock = threading.Lock()
    global result
    result=[]

    for ip in ipdict['mssql']:
        pool.apply_async(func=mssq1,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()

    print "[*] stop crack sql serice  %s" % time.ctime()
    print "[*] crack sql serice  done,it has Elapsed time:%s " % (time.time()-starttime)
    return result