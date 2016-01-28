__author__ = 'wilson'
import requests
import base64
from printers import printPink,printGreen
import threading
import time
import socket
from multiprocessing.dummy import Pool
socket.setdefaulttimeout(8)

def tomcat_connect(ip,port,username,password):
    try:
        url='http://'+ip+':'+str(port)
        url_get=url+'/manager/html'
        creak=0
        r=requests.get(url_get,timeout=8)
        if r.status_code==401:
            header={}
            login_pass=username+':'+password
            header['Authorization']='Basic '+base64.encodestring(login_pass)
            r=requests.get(url_get,headers=header,timeout=8)
            if r.status_code==200:
                result.append("%s tomcat service at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                lock.acquire()
                printGreen("%s tomcat service at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                lock.release()
                creak=1
            else:
                lock.acquire()
                print "%s tomcat service 's %s:%s login fail " %(ip,username,password)
                lock.release()
        else:
            lock.acquire()
            print 'not find tomcat login page!'
            lock.release()
            creak=2

    except Exception,e:
        print e
        pass
    return creak


def t0mcat(ip,port):
        try:
            d=open('conf/tomcat.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                flag=tomcat_connect(ip,port,username,password)
                if flag==1:
                    break
                if flag==2:
                    break
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass



def tomcat_main(ipdict,threads):

    printPink("crack tomcat_main  now...")
    print "[*] start crack tomcat_main  %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()
    global result
    result=[]

    pool=Pool(threads)

    for ip in ipdict['http']:
        pool.apply_async(func=t0mcat,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()

    print "[*] stop tomcat serice  %s" % time.ctime()
    print "[*] crack tomcat done,it has Elapsed time:%s " % (time.time()-starttime)
    return result