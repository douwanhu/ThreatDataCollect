# coding=utf-8


# export data from dionaea.sqlite and glastopf.db
import sqlite3
from log.PrintLog import ERROR

def connect2sqlite():
    try:
        connection = sqlite3.connect('dionaea.sqlite')
        return connection
    except Exception,e:
        ERROR("Sqlite Dionaea Error:%s" % str(e))

def connect2db():
    try:
        connection = sqlite3.connect('glastopf.db')
        return connection
    except Exception,e:
        ERROR("Sqlite glastopf Error:%s" % str(e))


def get_list_result(curs):
    try:
        result_list = curs.fetchall()
        if len(result_list) > 0:
            return result_list
    except Exception, e:
        ERROR("Sqlite Error:%s" % str(e))

def get_result(curs):
    try:
        destination =''
        result_list = curs.fetchall()
        if len(result_list)> 0:
            for row in result_list:
                for pair in row:
                    destination = pair
        return destination
    except Exception, e:
        ERROR("Sqlite Error:%s" % str(e))

def query_getdata(connection,table):
    try:
        curs = connection.cursor()
        query_str = "select * from %s"%(table)
        curs.execute(query_str)
        result_list = get_list_result(curs)
        return result_list
    except Exception, e:
        ERROR("Sqlite Error:%s" % str(e))

#con = connect2db()
#result_list = query_getdata(con,'events')
#print result_list[0]
