#coding=utf-8
import time
import threading
from threading import Thread
from printers import printPink,printGreen
from Queue import Queue
import redis

def redisexp():
    while True:
        ip,port=sp.get()
        try:
            r=redis.Redis(host=ip,port=port,db=0,socket_timeout=8)
            r.dbsize()
            lock.acquire()
            printGreen('%s redis service at %s allow login Anonymous login!!\r\n' %(ip,port))
            result.append('%s redis service at %s allow login Anonymous login!!\r\n' %(ip,port))
            lock.release()
        except Exception,e:
            print e
            pass
        sp.task_done()



def redis_main(ipdict,threads):
    printPink("crack redis  now...")
    print "[*] start crack redis  %s" % time.ctime()
    starttime=time.time()
    global sp
    sp=Queue()
    global lock
    lock = threading.Lock()
    global result
    result=[]

    for i in xrange(threads):
        t = Thread(target=redisexp)
        t.setDaemon(True)
        t.start()

    for ip in ipdict['redis']:
        sp.put((str(ip).split(':')[0],int(str(ip).split(':')[1])))

    sp.join()

    print "[*] stop redis serice  %s" % time.ctime()
    print "[*] crack redis done,it has Elapsed time:%s " % (time.time()-starttime)
    return result