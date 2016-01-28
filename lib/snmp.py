#coding=utf-8
import time
import threading
from printers import printPink,printGreen
from multiprocessing.dummy import Pool
import socket
socket.setdefaulttimeout(8)
from pysnmp.entity.rfc3413.oneliner import cmdgen

def snmp_connect(ip,key):
    crack =0
    try:
        errorIndication, errorStatus, errorIndex, varBinds =\
            cmdgen.CommandGenerator().getCmd(
                cmdgen.CommunityData('my-agent',key, 0),
                cmdgen.UdpTransportTarget((ip, 161)),
                (1,3,6,1,2,1,1,1,0)
            )
        if varBinds:
            crack=1
    except:
        pass
    return crack

def snmp_l(ip,port):
        try:
            d=open('conf/snmp.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                flag=snmp_connect(ip,key=data)
                if flag==1:
                    lock.acquire()
                    printGreen("%s snmp  has weaken password!!-----%s\r\n" %(ip,data))
                    result.append("%s snmp  has weaken password!!-----%s\r\n" %(ip,data))
                    lock.release()
                    break
                else:
                    lock.acquire()
                    print "test %s snmp's scan fail" %(ip)
                    lock.release()
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass

def snmp_main(pinglist,threads):
    printPink("crack snmp now...")
    print "[*] start crack snmp %s" % time.ctime()
    starttime=time.time()
    global lock
    lock = threading.Lock()
    global result
    result=[]

    pool=Pool(threads)

    for ip in pinglist:
        pool.apply_async(func=snmp_l,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()

    print "[*] stop crack snmp %s" % time.ctime()
    print "[*] crack snmp done,it has Elapsed time:%s " % (time.time()-starttime)
    return result