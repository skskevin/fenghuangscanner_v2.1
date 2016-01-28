#coding=utf-8
__author__ = 'wilson'
import ctypes,sys
import argparse
import socket
import time
import re
import platform
import threading
from threading import Thread
from lib.printers import printPink,printRed,printGreen
from Queue import Queue
from IPy import IP
try:
    from subprocess import Popen, PIPE
    lowversion=False
except:
    lowversion=True

from lib.mysql import mysql_main
from lib.mssql import mssql_main
from lib.ftp import ftp_main
from lib.smb import smb_main
from lib.ssh import ssh_main
from lib.web import web_main
from lib.tomcat import tomcat_main
from lib.vnc import vnc_main
from lib.snmp import snmp_main
from lib.pop3 import pop_main
from lib.rsync import rsync_main
from lib.ldapd import ldap_main
from lib.mongodb import mongoDB_main
from lib.postgres import postgres_main
from lib.redisexp import redis_main
from lib.ssltest import openssl_main
from lib.rdp import rdp_main

import _mssql
import uuid




socket.setdefaulttimeout(10)  #设置了全局默认超时时间
#变量定义
PROBES=[
    '\r\n\r\n',
    'GET / HTTP/1.0\r\n\r\n',
    'GET / \r\n\r\n',
    '\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08',
    '\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
    '\x03\0\0\x0b\x06\xe0\0\0\0\0\0',
    '\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0',
    '\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98',
    '\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0',
    '< NTP/1.2 >\n',
    '< NTP/1.1 >\n',
    '< NTP/1.0 >\n',
    '\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))',
    '\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
    '\0\0\0\0\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20\x01\x04\0\0\0\x10\x39\x7a\0\x01\0\0\0\0\0\0\0\0\0\0\x01\x0c\0\0\0\0\0\0\x0c\0\0\0\x0c\0\0\0\x04',
    '\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0\x53\x51\x4c\x44\x42\x32\x52\x41\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f',
    '\x41\0\0\0\x3a\x30\0\0\xff\xff\xff\xff\xd4\x07\0\0\0\0\0\0test.$cmd\0\0\0\0\0\xff\xff\xff\xff\x1b\0\0\0\x01serverStatus\0\0\0\0\0\0\0\xf0\x3f\0'
    ]

SIGNS=[
    'redis|^.*-ERR unknown command^.*',
    'mongodb|^.*version.....([\.\d]+)',
    'pop3|.*POP3.*',
    'pop3|.*pop3.*',
    'ssh|SSH-2.0-OpenSSH.*',
    'ssh|SSH-1.0-OpenSSH.*',
    'ssh|.*ssh.*',
    'netbios|^\x79\x08.*BROWSE',
    'netbios|^\x79\x08.\x00\x00\x00\x00',
    'netbios|^\x05\x00\x0d\x03',
    'netbios|^\x83\x00',
    'netbios|^\x82\x00\x00\x00',
    'netbios|\x83\x00\x00\x01\x8f',
    'backdoor-fxsvc|^500 Not Loged in',
    'backdoor-shell|GET: command',
    'backdoor-shell|sh: GET:',
    'bachdoor-shell|[a-z]*sh: .* command not found',
    'backdoor-shell|^bash[$#]',
    'backdoor-shell|^sh[$#]',
    'backdoor-cmdshell|^Microsoft Windows .* Copyright .*>',
    'dell-openmanage|^\x4e\x00\x0d',
    'finger|^\r\n	Line	  User',
    'finger|Line	 User',
    'finger|Login name: ',
    'finger|Login.*Name.*TTY.*Idle',
    'finger|^No one logged on',
    'finger|^\r\nWelcome',
    'finger|^finger:',
    'finger|^must provide username',
    'finger|finger: GET: ',
    'ftp|^220.*\n331',
    'ftp|^220.*\n530',
    'ftp|^220.*FTP',
    'ftp|^220 .* Microsoft .* FTP',
    'ftp|^220 Inactivity timer',
    'ftp|^220 .* UserGate',
    'ftp|^220(.*?)',
    'http|^HTTP.*',
    'http|^HTTP/0.',
    'http|^HTTP/1.',
    'http|<HEAD>.*<BODY>',
    'http|<HTML>.*',
    'http|<html>.*',
    'http|<!DOCTYPE.*',
    'http|^Invalid requested URL ',
    'http|.*<?xml',
    'http|^HTTP/.*\nServer: Apache/1',
    'http|^HTTP/.*\nServer: Apache/2',
    'http|.*Microsoft-IIS.*',
    'http|^HTTP/.*\nServer: Microsoft-IIS',
    'http|^HTTP/.*Cookie.*ASPSESSIONID',
    'http|^<h1>Bad Request .Invalid URL.</h1>',
    'http-jserv|^HTTP/.*Cookie.*JServSessionId',
    'http-weblogic|^HTTP/.*Cookie.*WebLogicSession',
    'http-vnc|^HTTP/.*VNC desktop',
    'http-vnc|^HTTP/.*RealVNC/',
    'ldap|^\x30\x0c\x02\x01\x01\x61',
    'ldap|^\x30\x32\x02\x01',
    'ldap|^\x30\x33\x02\x01',
    'ldap|^\x30\x38\x02\x01',
    'ldap|^\x30\x84',
    'ldap|^\x30\x45',
    'ldap|^\x30.*',
    'smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
    'msrdp|^\x03\x00\x00\x0b',
    'msrdp|^\x03\x00\x00\x11',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
    'msrdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
    'msrdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
    'msrdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    'msrdp-proxy|^nmproxy: Procotol byte is not 8\n$',
    'msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    'msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    'mssql|^\x04\x01\0C..\0\0\xaa\0\0\0/\x0f\xa2\x01\x0e.*',
    'mssql|^\x05\x6e\x00',
    'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\0\x25\0\0\x01\0\0\0\x15\0\x06\x01.*',
    'mssql|^\x04\x01\x00\x25\x00\x00\x01.*',
    'mysql|^\x19\x00\x00\x00\x0a',
    'mysql|^\x2c\x00\x00\x00\x0a',
    'mysql|hhost \'',
    'mysql|khost \'',
    'mysql|mysqladmin',
    'mysql|(.*)5(.*)log',
    'mysql|(.*)4(.*)log',
    'mysql|whost \'',
    'mysql|^\(\x00\x00',
    'mysql|this MySQL',
    'mysql|^N\x00',
    'mysql|(.*)mysql(.*)',
    'mssql|;MSSQLSERVER;',
    'nagiosd|Sorry, you \(.*are not among the allowed hosts...',
    'nessus|< NTP 1.2 >\x0aUser:',
    'oracle|\(ERROR_STACK=\(ERROR=\(CODE=',
    'oracle|\(ADDRESS=\(PROTOCOL=',
    'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    'oracle-https|^220- ora',
    'oracle-rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
    'oracle-rmi|^\x4e\x00\x09',
    'postgres|Invalid packet length',
    'postgres|^EFATAL',
    'rlogin|login: ',
    'rlogin|rlogind: ',
    'rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
    'rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    'rpc|\x01\x86\xa0',
    'rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
    'rpc|^\x80\x00\x00',
    'rsync|^@RSYNCD:.*',
    'smux|^\x41\x01\x02\x00',
    'snmp|\x70\x75\x62\x6c\x69\x63\xa2',
    'snmp|\x41\x01\x02',
    'socks|^\x05[\x00-\x08]\x00',
    'ssh|^SSH-',
    'ssh|^SSH-.*openssh',
    'sybase|^\x04\x01\x00',
    'telnet|^\xff\xfd',
    'telnet-disabled|Telnet is disabled now',
    'telnet|^\xff\xfe',
    'telnet|^xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd.*',
    'tftp|^\x00[\x03\x05]\x00',
    'uucp|^login: password: ',
    'vnc|^RFB.*',
    'webmin|.*MiniServ',
    'webmin|^0\.0\.0\.0:.*:[0-9]',
    'websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
    'db2|.*SQLDB2RA'
]


#获取ip列表函数
def getips(ip):
        try:
            iplist=[]
            ips=IP(ip)
            for i in ips:
                iplist.append(str(i))
            return iplist
        except:
            printRed("[!] not a valid ip given. you should put ip like 192.168.1.0/24, 192.168.0.0/16")
            exit()


#获取端口
def getports(user_ports):
    if user_posts=='':
        ports=[21,22,23,80,81,443,389,445,873,1043,1433,1434,1521,2601,2604,3306,3307,3128,3389,4440,4848,5432,5900,5901,5902,5903,6082,6379,7001,7002,8080,8888,8090,8000,8081,8088,8089,9000,9080,9043,9090,9091,9200,11211,22022,22222,27017,28017,50060]
        #21 -- ftp
        #22 -- ssh
        #23 --telnet
        #389-ldap
        #875--rsync
        #2601,2604---zebra ---路由器
        #3128 ----squid
        #4440 rundeck---web
        #4848 GlassFish--web
        #6082  varnish
        #6379 redic
        #7001,7002  weblogic
        #9000--fcgi --- fcig php执行
        #9200--elasticsearch ---代码执行
        #9043 --websphere
        #11211  memcache  --直接访问端口
        #50060 hadoop--web


    else:
        try:
            ports=[]
            if user_posts.find(",")>0:
                for port in user_posts.split(','):
                    ports.append(int(port))

            elif user_posts.find("-")>0:
                startport=int(user_posts.split('-')[0])
                endport=int(user_posts.split('-')[1])
                for i in xrange(startport,endport+1):
                    ports.append(i)
            else:
                ports.append(int(user_posts))


        except :
            printRed('[!] not a valid ports given. you should put ip like 22,80,1433 or 22-1000')
            exit()
    return ports



#ping扫描函数
def pinger():
    global lock

    while True:
        global pinglist
        ip=q.get()
        if platform.system()=='Linux':
            p=Popen(['ping','-c 2',ip],stdout=PIPE)
            m = re.search('(\d)\sreceived', p.stdout.read())
            try:
                if m.group(1)!='0':
                    pinglist.append(ip)
                    lock.acquire()
                    printRed("%s is live!!\r\n" % ip)
                    lock.release()
            except:pass

        if platform.system()=='Darwin':
            import commands
            p=commands.getstatusoutput("ping -c 2 "+ip)
            m = re.findall('ttl', p[1])
            try:
                if m:
                    pinglist.append(ip)
                    lock.acquire()
                    printRed("%s is live!!\r\n" % ip)
                    lock.release()
            except:pass

        if platform.system()=='Windows':
            p=Popen('ping -n 2 ' + ip, stdout=PIPE)
            m = re.findall('TTL', p.stdout.read())
            if m:
                pinglist.append(ip)
                lock.acquire()
                printRed("%s is live!!\r\n" % ip)
                lock.release()
        q.task_done()


#扫端口及其对应服务类型函数
def scanports():
    global signs,lock
    while True:
        ip,port=sp.get()
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #判断端口的服务类型
        service='Unknown'
        try:
            s.connect((ip,port))
        except:
            sp.task_done()
            continue

        try:
            result = s.recv(256)
            service=matchbanner(result,signs)
        except:
            for probe in PROBES:
                try:
                    s.close()
                    sd=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sd.settimeout(5)
                    sd.connect((ip,port))
                    sd.send(probe)
                except:
                    continue
                try:
                    result=sd.recv(256)
                    service=matchbanner(result,signs)
                    if service!='Unknown':
                        break
                except:
                    continue
        if service not in ipdict:
            ipdict[service]=[]
            ipdict[service].append(ip+':'+str(port))
            lock.acquire()
            printRed("%s opening %s\r\n" %(ip,port))
            lock.release()
        else:
            ipdict[service].append(ip+':'+str(port))
            lock.acquire()
            printRed("%s opening %s\r\n" %(ip,port))
            lock.release()

        sp.task_done()

def prepsigns():
    signlist=[]
    for item in SIGNS:
        (label,pattern)=item.split('|',2)
        sign=(label,pattern)
        signlist.append(sign)
    return signlist

def matchbanner(banner,slist):
    for item in slist:
        p=re.compile(item[1])
        if p.search(banner)!=None:
            return item[0]
    return 'Unknown'

def write_file(file,contents):
    f2 = open(file,'a')
    f2.write(contents)
    f2.close()



if __name__ == '__main__':
    #接受cmd参数
    parser = argparse.ArgumentParser(description='ports&*weak password scanner. teams:xdsec.  author: wilson ')
    parser.add_argument('--ip',action="store",required=True,dest="ip",type=str,help='ip like 192.168.1.0/24 or 192.168.0.0/16')
    parser.add_argument('--f',action="store",required=False,dest="path",type=str,default='result/result.txt',help='get you results in this file')
    parser.add_argument("--threads",action="store",required=False,dest="threads",type=int,default=50,help='Maximum threads, default 50')
    parser.add_argument("--P",action="store",required=False,dest="isping",type=str,default='yes',help='--P not mean no ping frist,default yes')
    parser.add_argument("--p",action="store",required=False,dest="user_ports",type=str,default='',help='--p scan ports;like 21,80,445 or 22-1000')

    args = parser.parse_args()
    ip = args.ip
    file=args.path
    threads=args.threads
    isping=args.isping
    user_posts=args.user_ports

    #获取ip列表
    ips=getips(ip)

    #获取port列表
    posts=getports(user_posts)


    print "Scanning for live machines..."
    starttime=time.time()
    friststarttime=time.time()
    print "[*] start Scanning at %s" % time.ctime()
    #isping=='no' 就禁ping扫描
    #默认ping 扫描
    if isping=='yes':
        if lowversion==True:
            print "your python may not support ping ,please update python to 2.7"
            exit()
        pinglist=[]
        q=Queue()
        lock = threading.Lock()

        for i in xrange(threads):
            t = Thread(target=pinger)
            t.setDaemon(True)
            t.start()

        for ip in ips:
            q.put(ip)
        q.join()

    else:
        pinglist=ips

    if len(pinglist)==0:
        print "not find any live machine - -|||"
        exit()

    print "[*] Scanning for live machines done,it has Elapsed time:%s " % (time.time()-starttime)


#=========================我是分割线=============================================#

#多线程扫描端口，并且识别出端口是什么类型服务
    print "Scanning ports now..."
    print "[*] start Scanning live machines' ports at %s" % time.ctime()
    starttime=time.time()
    sp=Queue()
    lock = threading.Lock()
    #signs 匹配端口对应的服务
    global signs
    signs=prepsigns()

    #端口对应服务  放到一个ipdict[service]字典中
    global ipdict
    ipdict={}
    ipdict['ldap']=[]
    ipdict['mysql']=[]
    ipdict['mssql']=[]
    ipdict['ftp']=[]
    ipdict['ssh']=[]
    ipdict['smb']=[]
    ipdict['vnc']=[]
    ipdict['pop3']=[]
    ipdict['rsync']=[]
    ipdict['http']=[]
    ipdict['mongodb']=[]
    ipdict['postgres']=[]
    ipdict['redis']=[]
    ipdict['msrdp']=[]
    ipdict['Unknown']=[]


    for i in xrange(threads):
        st=Thread(target=scanports)
        st.setDaemon(True)
        st.start()

    for scanip in pinglist:
        for port in posts:
            sp.put((scanip,port))
    sp.join()

    print "[*] Scanning ports done,it has Elapsed time:%s " % (time.time()-starttime)

    #将服务端口 信息 记录文件
    for name in ipdict.keys():
        if len(ipdict[name]):
            contents=str(name)+' service has:\n'+'       '+str(ipdict[name])+'\n'
            write_file(contents=contents,file=file)

#=========================我是分割线=============================================#

#处理没有识别的服务

    try:
        for ip in ipdict['Unknown']:
            if str(ip).split(':')[1]=='389':
                ipdict['ldap'].append(ip)
            if str(ip).split(':')[1]=='445':
                ipdict['smb'].append(ip)
            if str(ip).split(':')[1] in ['3306','3307','3308','3309']:
                ipdict['mysql'].append(ip)
            if str(ip).split(':')[1]=='1433':
                ipdict['mssql'].append(ip)
            if str(ip).split(':')[1]=='22':
                ipdict['ssh'].append(ip)
            if str(ip).split(':')[1]=='27017':
                ipdict['mongodb'].append(ip)
            if str(ip).split(':')[1]=='5432':
                ipdict['postgres'].append(ip)
            if str(ip).split(':')[1]=='873':
                ipdict['rsync'].append(ip)
            if str(ip).split(':')[1]=='6379':
                ipdict['redis'].append(ip)
            if str(ip).split(':')[1]=='3389':
                ipdict['msrdp'].append(ip)
            if str(ip).split(':')[1] in ['80','81','443','8080','4848','7001','7002','8080','8888','8090','8000','8081','8088','8089','9000','9080','9043','9090','9091','9200','50060']:
                ipdict['http'].append(ip)
    except Exception,e:
        print e
        pass


#处理被识别为http的mongo
    for ip in ipdict['http']:
        if str(ip).split(':')[1]=='27017':
            ipdict['http'].remove(ip)
            ipdict['mongodb'].append(ip)



#=========================我是分割线=============================================#

    result={}
    write_file(contents='\r\nvluns&&weaken password:\n',file=file)

    try:
    #多线程爆破mysql弱口令
        if len(ipdict['mysql']):
                result['mysql']=mysql_main(ipdict,threads)
                for i in xrange(len(result['mysql'])):
                    write_file(contents=result['mysql'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破mssql弱口令
        if len(ipdict['mssql']):
                result['mssql']=mssql_main(ipdict,threads)
                for i in xrange(len(result['mssql'])):
                    write_file(contents=result['mssql'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破ftp弱口令
        if len(ipdict['ftp']):
                result['ftp']=ftp_main(ipdict,threads)
                for i in xrange(len(result['ftp'])):
                    write_file(contents=result['ftp'][i],file=file)
    
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破windows 弱口令
        result['msrdp']=rdp_main(ipdict,threads)
        for i in xrange(len(result['msrdp'])):
            write_file(contents=result['msrdp'][i],file=file)

    except Exception,e:
        print e
        pass

    
    try:
    #多线程爆破smb弱口令&&ms08_067探测
        if len(ipdict['smb']):
                result['smb']=smb_main(ipdict,threads)
                for i in xrange(len(result['smb'])):
                    write_file(contents=result['smb'][i],file=file)
    except Exception,e:
        print e
        pass
    
    try:
    #多线程爆破ssh弱口令
        if len(ipdict['ssh']):
                result['ssh']=ssh_main(ipdict,threads)
                for i in xrange(len(result['ssh'])):
                    write_file(contents=result['ssh'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破vnc弱口令
        if len(ipdict['vnc']):
                result['vnc']=vnc_main(ipdict,threads)
                for i in xrange(len(result['vnc'])):
                    write_file(contents=result['vnc'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破pop3弱口令
        if len(ipdict['pop3']):
                result['pop3']=pop_main(ipdict,threads)
                for i in xrange(len(result['pop3'])):
                    write_file(contents=result['pop3'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破rsync弱口令
        if len(ipdict['rsync']):
                result['rsync']=rsync_main(ipdict,threads)
                for i in xrange(len(result['rsync'])):
                    write_file(contents=result['rsync'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破ldap弱口令
        if len(ipdict['ldap']):
                result['ldap']=ldap_main(ipdict,threads)
                for i in xrange(len(result['ldap'])):
                    write_file(contents=result['ldap'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程检测redis 匿名登入
        if len(ipdict['redis']):
                result['redis']=redis_main(ipdict,threads)
                for i in xrange(len(result['redis'])):
                    write_file(contents=result['redis'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破mongodb弱口令
        if len(ipdict['mongodb']):
                result['mongodb']=mongoDB_main(ipdict,threads)
                for i in xrange(len(result['mongodb'])):
                    write_file(contents=result['mongodb'][i],file=file)
    except Exception,e:
        print e
        pass

    try:
    #多线程爆破postgres弱口令
        if len(ipdict['postgres']):
                result['postgres']=postgres_main(ipdict,threads)
                for i in xrange(len(result['postgres'])):
                    write_file(contents=result['postgres'][i],file=file)
    except Exception,e:
        print e
        pass


    try:
    #多线程爆破snmp弱口令
        result['snmp']=snmp_main(pinglist,threads)
        for i in xrange(len(result['snmp'])):
            write_file(contents=result['snmp'][i],file=file)

    except Exception,e:
        print e
        pass
    
    

    #http bug 多 放到最后了   - -||
    if len(ipdict['http']):
            #多线程 检测 openssl
            try:
                result['ssl']=openssl_main(ipdict,threads)
                for i in xrange(len(result['ssl'])):
                    write_file(contents=result['ssl'][i],file=file)
            except Exception,e:
                print e
                pass
                
            try:
            #多线程 检测 tomcat 弱口令
                result['http-tomcat']=tomcat_main(ipdict,threads)
                for i in xrange(len(result['http-tomcat'])):
                    write_file(contents=result['http-tomcat'][i],file=file)
            except Exception,e:
                print e
                pass

            try:
                #多线程 检测 web
                result['web']=web_main(ipdict,threads)
                for i in xrange(len(result['web'])):
                    write_file(contents=result['web'][i],file=file)
            except Exception,e:
                print e
                pass






    printRed("[*] all has done at %s\r\n" % time.ctime())
    printRed("[*] all has done,it has Elapsed time:%s \r\n" % (time.time()-friststarttime))
    printRed("I have put all you want into %s" % file)
