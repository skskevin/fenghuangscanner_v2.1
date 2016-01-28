#coding=utf-8
import time
import threading
from printers import printPink,printRed,printGreen
from multiprocessing.dummy import Pool
import socket
socket.setdefaulttimeout(8)
import pymongo


def mongoDB_connect(ip,username,password,port):
    crack=0
    try:
        connection=pymongo.Connection(ip,port)
        db=connection.admin
        db.collection_names()
        lock.acquire()
        printRed('%s mongodb service at %s allow login Anonymous login!!\r\n' %(ip,port))
        result.append('%s mongodb service at %s allow login Anonymous login!!\r\n' %(ip,port))
        lock.release()
        crack=1

    except Exception,e:
        if e[0]=='database error: not authorized for query on admin.system.namespaces':
            try:
                db.authenticate(username,password)
                crack=2
            except Exception,e:
                lock.acquire()
                print "%s mongodb service 's %s:%s login fail " %(ip,username,password)
                lock.release()
                crack=3

        else:
            printRed('%s mongodb service at %s not connect' %(ip,port))
            crack=4
    return crack



def mongoDB(ip,port):
        try:
            d=open('conf/mongodb.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                flag=mongoDB_connect(ip,username,password,port)
                if flag in [1,4]:
                    break

                if flag==2:
                    lock.acquire()
                    printGreen("%s mongoDB at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s mongoDB at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass


def mongoDB_main(ipdict,threads):
    printPink("crack mongodb  now...")
    print "[*] start crack mongodb  %s" % time.ctime()
    starttime=time.time()
    global lock
    lock = threading.Lock()
    global result
    result=[]

    pool=Pool(threads)

    for ip in ipdict['mongodb']:
        pool.apply_async(func=mongoDB,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()
    print "[*] stop mongoDB serice  %s" % time.ctime()
    print "[*] crack mongoDB done,it has Elapsed time:%s " % (time.time()-starttime)
    return result