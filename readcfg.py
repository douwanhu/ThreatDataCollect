# coding = utf-8
import ConfigParser

config = ConfigParser.ConfigParser()
f = open('config.cfg', 'r')
config.readfp(f)

def gethost():
    host = config.get('database','host')
    return host
def getport():
    port = config.get('database','port')
    return port
def getusr():
    usr = config.get('database', 'username')
    return usr
def getpwd():
    pwd = config.get('database', 'password')
    return pwd
def ftpserver():
    server = config.get('FTP','server')
    return server
def ftpusr():
    usr = config.get('FTP','username')
def ftppwd():
    pwd = config.get('FTP','password')
def ftpport():
    port = config.get('FTP','port')
    return port