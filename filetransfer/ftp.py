# coding = utf-8

import ftplib
import os
import socket
from log.PrintLog import ERROR,INFO

class ConnectFtp():

    def __init__(self,server,username,password,port):
        self.username = username
        self.password = password
        self.server = server
        self.port = port

    def uploadFile(self,src_path,dst_path):
        try:
            f = ftplib.FTP()
            f.connect(self.server,self.port,60)
        except (socket.error,socket.gaierror),e:
            ERROR("FTP Error:%s"%str(e))
        try:
            f.login(self.username,self.password)
        except ftplib.error_perm,e:
            ERROR("FTP Error:%s"%str(e))
            f.quit()
            return
        INFO("Successfully login FTP as %s"%self.username)
        try:
            f.cwd(dst_path)
        except ftplib.error_perm:
            #ERROR("FTP Error:%s" % str(e))
            try:
                f.mkd(dst_path)
            except ftplib.error_perm,e:
                ERROR("FTP Error:%s" % str(e))
                f.quit()
                return
            else:
                f.cwd(dst_path)
        filelist = os.listdir(src_path)
        for filename in filelist:
            filepath = os.path.join(src_path,filename)
            if os.path.isdir(filepath):
                os.chdir(filepath)
                flist = os.listdir(filepath)
                for fn in flist:
                    file_handle = open(fn,'rb')
                    try:
                        f.storbinary('STOR %s'%fn,file_handle,8192)
                    except ftplib.error_perm,e:
                        ERROR("FTP Error:%s"%str(e))
                    else:
                        INFO("Complete Uploading %s"%fn)
                    file_handle.close()
                    os.remove(file_handle)
            else:
                os.chdir(src_path)
                file_handle = open(filepath,'rb')
                #dst = os.path.join(dst_path,filename)
                try:
                    f.storbinary('STOR %s'%filename,file_handle,8192)
                except ftplib.error_perm,e:
                    ERROR("FTP Error:%s"%str(e))
                else:
                    INFO("Complete Uploading %s"%filename)
                file_handle.close()
                os.remove(file_handle)
        f.quit()

'''
if __name__ == '__main__':

    src_path = 'C:\Victor\JsonLog\Cowrie\downloads'
    dst_path = 'downloads'
    conn = ConnectFtp('192.168.131.129','myftp','abcd1234',21)
    conn.uploadFile(src_path,dst_path)
    
    
    src_path: /data/cowrie/downloads/    /data/honeytrap/attacks/  /data/dionaea/binaries/ 
    
    
    
    
'''





