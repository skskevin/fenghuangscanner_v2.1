#coding=utf-8
import time
import threading
from multiprocessing.dummy import Pool
import socket
socket.setdefaulttimeout(8)
from printers import printPink,printGreen
from ftplib import FTP



def ftp_connect(ip,username,password,port):
    crack=0
    try:
        ftp=FTP()
        ftp.connect(ip,str(port))
        ftp.login(user=username,passwd=password)
        crack=1
        ftp.close()
    except Exception,e:
        lock.acquire()
        print "%s ftp service 's %s:%s login fail " %(ip,username,password)
        lock.release()
        pass
    return crack


def ftp_l(ip,port):
        try:
            d=open('conf/ftp.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                if ftp_connect(ip,username,password,port)==1:
                    lock.acquire()
                    printGreen("%s ftp at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s ftp at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass

def ftp_main(ipdict,threads):
    printPink("crack ftp  now...")
    print "[*] start crack ftp  %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()
    global result
    result=[]

    pool=Pool(threads)

    for ip in ipdict['ftp']:
        pool.apply_async(func=ftp_l,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()

    print "[*] stop ftp serice  %s" % time.ctime()
    print "[*] crack ftp done,it has Elapsed time:%s " % (time.time()-starttime)
    return result