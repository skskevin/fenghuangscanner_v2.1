#coding=utf-8
import time
import threading
from printers import printPink,printGreen
import socket
from multiprocessing.dummy import Pool
socket.setdefaulttimeout(8)
import ldap


def ldap_connect(ip,username,password,port):
    creak=0
    try:
        ldappath='ldap://'+ip+':'+port+'/'
        l = ldap.initialize(ldappath)
        re=l.simple_bind(username,password)
        if re==1:
            creak=1

    except Exception,e:
        print e
        if e[0]['desc']=="Can't contact LDAP server":
            creak=2
        pass

    return creak

def ldap_creak(ip,port):
        try:
            d=open('conf/ldapd.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                flag=ldap_connect(ip,username,password,port)
                if flag==2:
                    lock.acquire()
                    printGreen("%s ldap at %s can't connect\r\n" %(ip,port))
                    lock.release()
                    break

                if flag==1:
                    lock.acquire()
                    printGreen("%s ldap at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s ldap at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break
                else:
                    lock.acquire()
                    print "%s ldap service 's %s:%s login fail " %(ip,username,password)
                    lock.release()
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass

def ldap_main(ipdict,threads):
    printPink("crack ldap  now...")
    print "[*] start ldap  %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()
    global result
    result=[]


    pool=Pool(threads)

    for ip in ipdict['ldap']:
        pool.apply_async(func=ldap_creak,args=(str(ip).split(':')[0],str(ip).split(':')[1]))
    pool.close()
    pool.join()

    print "[*] stop ldap serice  %s" % time.ctime()
    print "[*] crack ldap done,it has Elapsed time:%s " % (time.time()-starttime)
    return result