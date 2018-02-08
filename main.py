# coding = utf-8
# main program for controlling file transferring and  writing data to MySQL
# Author Victor Dou

import threading
import indb.InDB
import log.PrintLog
import filetransfer.ftp
import readcfg
import os


# thread 1: transfer files to SMB/FTP server
# thread_cowrie: cowrie()
# thread_conpot: conpot()
# thread_honeytrap: honeytrap()
# thread_dionaea: dionaea()
# thread_glastpof: glastopf()

def ftp_upload(source,destination):  # args1 : source path  args2 : destination path
    src_path = source
    dst_path = destination
    ftpserver = readcfg.ftpserver()
    ftpusr = readcfg.ftpusr()
    ftppwd = readcfg.ftppwd()
    ftport = readcfg.ftpport()
    connection = filetransfer.ftp.ConnectFtp(ftpserver,ftpusr,ftppwd,ftport)
    connection.uploadFile(src_path,dst_path)

# write Cowrie's log data to MySQL schema Honeypot( table:Cowrie)
def Data2Cowrie():
    log_path = '/data/cowrie/log/'
    os.chdir(log_path)
    filename = 'cowrie.json'
    if os.path.isfile(filename):
        indb.InDB.cowrie()
    else:
        log.PrintLog.INFO("The log cowrie.json is not exist")

# write Conpot's log data to MySQL schema Honeypot(table:Conpot)
def Data2Conpot():
    log_path = '/data/conpot/log/'
    os.chdir(log_path)
    filename = 'conpot.json'
    if os.path.isfile(filename):
        indb.InDB.conpot()
    else:
        log.PrintLog.INFO("The log conpot.json is not exist")

# write Honeytrap's log data to MySQL schema Honeypot(table:Honeytrap)
def Data2Honeytrap():
    log_path = '/data/honeytrap/log/'
    os.chdir(log_path)
    filename = 'attackers.json'
    if os.path.isfile(filename):
        indb.InDB.honeytrap()
    else:
        log.PrintLog.INFO("The Honeytrap's attackers.json is not exist")

# read Dionaea's data to MySQL schema Dionaea
def Data2Dionaea():
    sql_path = '/data/dionaea/log/'
    os.chdir(sql_path)
    filename = 'dionaea.sqlite'
    if os.path.isfile(filename):
        indb.InDB.dionaea()
    else:
        log.PrintLog.INFO("The dionaea.sqlite is not exist")

# read glastopf's data to MySQL schema glastpof
def Data2Glastpof():
    db_path = '/data/glastopf/db'
    os.chdir(db_path)
    filename = 'glastopf.db'
    if os.path.isfile(filename):
        indb.InDB.glastopf()
    else:log.PrintLog.INFO("The glastpof.db is not exist")


threads = []
thread_cowrie = threading.Thread(target = Data2Cowrie,args = (),name = 'thread-data2cowrie')
threads.append(thread_cowrie)
#thread_conpot = threading.Thread(target = Data2Conpot,args = (),name = 'thread-data2conpot')
#threads.append(thread_conpot)
thread_dionaea = threading.Thread(target = Data2Dionaea,args = (),name = 'thread-data2dionaea')
threads.append(thread_dionaea)
thread_glastpof = threading.Thread(target = Data2Glastpof,args = (),name = 'thread-data2glastpof')
threads.append(thread_glastpof)
thread_honeytrap = threading.Thread(target = Data2Honeytrap,args = (),name = 'thread-data2honeytrap')
threads.append(thread_honeytrap)

thread_file_cowrie = threading.Thread(target = ftp_upload,args = ('/data/cowrie/downloads/','cowrie'),name = 'thread-cowrie-ftp')
threads.append(thread_file_cowrie)
thread_file_dionaea = threading.Thread(target = ftp_upload,args = ('/data/dionaea/binaries/','dionaea'),name = 'thread-dionaea-ftp')
threads.append(thread_file_dionaea)
thread_file_honeytrap = threading.Thread(target = ftp_upload,args = ('/data/honeytrap/attacks/','honeytrap'),name = 'thread-honeytrap-ftp')
threads.append(thread_file_honeytrap)



if __name__ == '__main__':
    try:
        for t in threads:
            t.setDaemon(True)
            t.start()
            t.join()
    except Exception,e:
        log.PrintLog.ERROR("Thread Error:%s"%str(e))

    log.PrintLog.INFO("All threads done!")










