#coding=utf-8
import time
import threading
from printers import printPink,printGreen
from multiprocessing.dummy import Pool
import MySQLdb

def mysql_connect(ip,username,password,port):
    crack =0
    try:
        db=MySQLdb.connect(ip,username,password,port=port)
        if db:
            crack=1
        db.close()
    except Exception, e:
        if e[0]==1045:
            lock.acquire()
            print "%s mysql's %s:%s login fail" %(ip,username,password)
            lock.release()
        else:
            lock.acquire()
            print "connect %s mysql service at %s login fail " %(ip,port)
            lock.release()
            crack=2
        pass
    return crack

def mysq1(ip,port):
        try:
            d=open('conf/mysql.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                flag=mysql_connect(ip,username,password,port)
                if flag==2:
                    break

                if flag==1:
                    lock.acquire()
                    printGreen("%s mysql at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s mysql at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass

def mysql_main(ipdict,threads):
    printPink("crack mysql now...")
    print "[*] start crack mysql %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()

    global result
    result=[]

    pool=Pool(threads)
    for ip in ipdict['mysql']:
        pool.apply_async(func=mysq1,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()


    print "[*] stop crack mysql %s" % time.ctime()
    print "[*] crack mysql done,it has Elapsed time:%s " % (time.time()-starttime)
    return result