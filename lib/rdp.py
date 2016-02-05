#coding=utf-8
import time,re
import threading
from printers import printPink,printGreen
from multiprocessing.dummy import Pool
from subprocess import Popen, PIPE

def rdp_connect(ip,username,password):
    crack =0
    try:
        p=Popen(['hydra','-l',username, '-p',password,ip,'rdp','-t 4' ],stdout=PIPE)

        m = re.search(r'(\d)\svalid password[s]? found', p.stdout.read())

        try:
            if m.group(1) == '1':
                crack=1
            else:
                lock.acquire()
                print "%s login fail (port:3389)" %(ip)
                lock.release()
                crack=2
        except Exception,e:
            print "Regular Expression Error"
            print e

    except Exception, e:
        print "hydra exec failed or need to install thc-hydra！"
        print e

    return crack

def rdp_1(ip,port):
        try:
            d=open('conf/rdp.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                flag=rdp_connect(ip,username,password)
                if flag==2:
                    continue

                if flag==1:
                    lock.acquire()
                    printGreen("%s  at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s  at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass

def rdp_main(ipdict,threads):
    printPink("crack msrdp now...")
    print "[*] start crack msrdp %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()

    global result
    result=[]
    pool=Pool(threads)
    for ip in ipdict['msrdp']:
        pool.apply_async(func=rdp_1,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()


    print "[*] stop crack msrdp %s" % time.ctime()
    print "[*] crack msrdp done,it has Elapsed time:%s " % (time.time()-starttime)
    return result
