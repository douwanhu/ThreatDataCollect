#author Victor Dou
#Kaspersky Lab Inc.
# -*- coding: utf-8 -*-

import json
import time
from log.PrintLog import INFO
from sqlite.SqliteOperation import connect2sqlite,connect2db,query_getdata
from mysql.MySqlOperation  import *

#db = connect2mysql('Honeypot')
#con2dionaea = connect2mysql('Dionaea')
#con2glastopf = connect2mysql('glastopf')
dionaea_tables = ['connections','dcerpcbinds','dcerpcrequests','dcerpcserviceops',
                  'dcerpcservices','downloads','emu_profiles','emu_services',
                  'logins','mqtt_fingerprints','mqtt_publish_commands','mqtt_subscribe_commands',
                  'mssql_commands','mssql_fingerprints','mysql_command_args','mysql_command_ops',
                  'mysql_commands','offers','p0fs','resolves']
glastopf_tables = ['events','ext','filetype','intext','intitle','inurl','ip_profiles','allinurl']

### import Conpot's json log to MySQL###



def cowrie():
    db = connect2mysql('Honeypot')
    fa=file('/data/cowrie/log/cowrie.json','r')
    for line in fa.readlines():
        dic=json.loads(line)
        session = dic['session']
        eventid = dic['eventid']
        ts = dic['timestamp']
        message = dic['message']
        src_ip = dic['src_ip']
        if dic.has_key('username'):
            usr = dic['username']
        else:
            usr = ""
        if dic.has_key('password'):
            pwd = dic['password']
        else:
            pwd = ""
        if dic.has_key('system'):
            sys = dic['system']
        else:
            sys = ""
        if dic.has_key('src_port'):
            src_port = int(dic['src_port'])
        else:
            src_port = 0
        if dic.has_key('dst_ip'):
            dst_ip = dic['dst_ip']
        else:
            dst_ip = ""
        if dic.has_key('dst_port'):
            dst_port =int(dic['dst_port'])
        else:
            dst_port = 0
        if dic.has_key('input'):
            input = dic['input']
        else:
            input = ""
        db_insert_cowrie(db,session,eventid,ts,message,usr,pwd,sys,src_ip,src_port,dst_ip,dst_port,input)

    INFO('Finish importing json log to Cowrie!')
    fa.close()



### import Conpot's json log to MySQL###

def conpot():
    db = connect2mysql('Honeypot')
    fb = file('/data/conpot/log/conpot.json','r') # fb = file(file_object,'r')
    for line in fb.readlines():
        dic = json.loads(line)
        tz = dic['timestamp']
        srcip = dic['src_ip']
        srcport = dic['src_port']
        etype = dic['event_type']
        dtype = dic['data_type']
        dstip = dic['dst_ip']
        request = dic['request']
        id = dic['id']
        response = dic['response']
        db_insert_conpot(db,tz,srcip,srcport,dstip,etype,dtype,request,id,response)
    INFO("Finish importing json log to Conpot!")
    fb.close()






### import Honeytrap's json log to MySQL###

def honeytrap():
    db = connect2mysql('Honeypot')
    fc = file('/data/honeytrap/log/attackers.json','r')
    for line in fc.readlines():
        dic = json.loads(line)
        isv = dic['is_virtual']
        tz = dic['@timestamp']
        start = dic['start_time']
        end = dic['end_time']
        protocol = dic['attack_connection']['protocol']
        rip = dic['attack_connection']['remote_ip']
        rport = dic['attack_connection']['remote_port']
        lip = dic['attack_connection']['local_ip']
        lport = dic['attack_connection']['local_port']
        payload_md5 = dic['attack_connection']['payload']['md5_hash']
        payload_sha = dic['attack_connection']['payload']['sha512_hash']
        payload_len = dic['attack_connection']['payload']['length']
        payload_dhex = dic['attack_connection']['payload']['data_hex']
        pprotocol = dic['proxy_connection']['protocol']
        prip = dic['proxy_connection']['remote_ip']
        prport = dic['proxy_connection']['remote_port']
        plip = dic['proxy_connection']['local_ip']
        plport = dic['proxy_connection']['local_port']
        ppayload_md5 = dic['proxy_connection']['payload']['md5_hash']
        ppayload_sha = dic['proxy_connection']['payload']['sha512_hash']
        ppayload_len = dic['proxy_connection']['payload']['length']
        ppayload_dhex = dic['proxy_connection']['payload']['data_hex']
        mode = dic['operation_mode']
        count = dic['download_count']
        tries = dic['download_tries']
        downloads = dic['downloads']
        db_insert_honeytrap(db,isv,tz,start,end,protocol,rip,rport,lip,lport,payload_md5,payload_sha,payload_len,payload_dhex,
                        pprotocol,prip,prport,plip,plport,ppayload_md5,ppayload_sha,ppayload_len,ppayload_dhex,mode,count,tries,downloads)
    INFO("Finish importing json log to Honeytrap!")
    fc.close()



### import data to Dionaea###
def dionaea():
    con2dionaea = connect2mysql('Dionaea')
    conn = connect2sqlite()
    diff = get_diff(con2dionaea, 'connections')
    diff_service = get_diff(con2dionaea,'dcerpcservices')
    diff_mysql = get_diff(con2dionaea,'mysql_commands')
    for table in dionaea_tables:
        result_list = query_getdata(conn,table)
        if table == 'connections':
            if (result_list):
                for result in result_list:
                    db_insert_connections(con2dionaea,result[1],result[2],result[3],result[4],result[5],result[7],result[8],result[9],result[10],result[11])
            else:
                continue
        elif table == 'dcerpcbinds':
           if (result_list):
                for result in result_list:
                   db_insert_dcerpcbinds(con2dionaea,result[1]+diff,result[2],result[3])
           else:
               continue
        elif table == 'dcerpcrequests':
            if (result_list):
                for result in result_list:
                    db_insert_dcerpcrequests(con2dionaea,result[1]+diff,result[2],result[3])
            else:
                continue
        elif table == 'dcerpcserviceops':
            if (result_list):
                for result in result_list:
                    db_insert_dcerpcserviceops(con2dionaea,result[1]+diff_service,result[2],result[3],result[4])
            else:
                continue
        elif table == 'dcerpcservices':
            if (result_list):
                for result in result_list:
                    db_insert_dcerpcservices(con2dionaea,result[1],result[2])
            else:
                continue
        elif table == 'downloads':
            if (result_list):
                for result in result_list:
                    db_insert_downloads(con2dionaea,result[1]+diff,result[2],result[3])
            else:
                continue
        elif table == 'emu_profiles':
           if (result_list):
                for result in result_list:
                    db_insert_emu_profiles(con2dionaea,result[1]+diff,result[2])
           else:
               continue
        elif table == 'emu_services':
            if (result_list):
                for result in result_list:
                   db_insert_emu_services(con2dionaea,result[1]+diff,result[2])
            else:
                continue
        elif table == 'logins':
            if (result_list):
                for result in result_list:
                   db_insert_logins(con2dionaea,result[1]+diff,result[2],result[3])
            else:
                continue
        elif table == 'mqtt_fingerprints':
            if (result_list):
                for result in result_list:
                    db_insert_mqtt_fingerprints(con2dionaea,result[1]+diff,result[2],result[3],result[4],result[5],result[6])
            else:
                continue
        elif table == 'mqtt_publish_commands':
            if (result_list):
                for result in result_list:
                    db_insert_mqtt_publish_commands(con2dionaea,result[1]+diff,result[2],result[3])
            else:
                continue
        elif table == 'mqtt_subscribe_commands':
            if (result_list):
                for result in result_list:
                    db_insert_mqtt_subscribe_commands(con2dionaea,result[1]+diff,result[2],result[3])
            else:
                continue
        elif table == 'mssql_commands':
           if (result_list):
                for result in result_list:
                    db_insert_mssql_commands(con2dionaea,result[1]+diff,result[2],result[3])
           else:
               continue
        elif table == 'mssql_fingerprints':
            if (result_list):
                for result in result_list:
                    db_insert_mssql_fingerprints(con2dionaea,result[1]+diff,result[2],result[3],result[4])
            else:
                continue
        elif table == 'mysql_command_args':
            if (result_list):
                for result in result_list:
                    db_insert_mysql_command_args(con2dionaea,result[1]+diff_mysql,result[2],result[3])
            else:
                continue
        elif table == 'mysql_command_ops':
            if (result_list):
                for result in result_list:
                   db_insert_mysql_command_ops(con2dionaea,result[1]+diff_mysql,result[2])
            else:
                continue
        elif table == 'mysql_commands':
            if (result_list):
                for result in result_list:
                    db_insert_mysql_commands(con2dionaea,result[1]+diff,result[2])
            else:
                continue
        elif table == 'offers':
            if(result_list):
                for result in result_list:
                    db_insert_offers(con2dionaea,result[1]+diff,result[2])
            else:
                break

 #       else:
 #           if(result_list):
 #               for result in result_list:
 #                   db_insert_p0fs(con2dionaea,result[1]+diff,result[2],result[3],result[4],result[5],result[6],result[7],result[8],result[9])
 #           else:
 #               break

    INFO("Finish import data to Dionaea!")

### import data to glastopf###
def glastopf():
    con2glastopf = connect2mysql('glastopf')
    conn = connect2db()
    for table in glastopf_tables:
        result_list = query_getdata(conn,table)
        if table == 'events':
            if (result_list):
                for result in result_list:
                    db_insert_events(con2glastopf,result[1],result[2],result[3],result[4],result[5],result[6],result[7],result[8])
            else:
                continue
        elif table == 'ext':
            if (result_list):
                for result in result_list:
                    db_insert_ext(con2glastopf,result[0],result[1],result[2],result[3])
            else:
                continue
        elif table == 'filetype':
            if (result_list):
                for result in result_list:
                    db_insert_filetype(con2glastopf,result[0],result[1],result[2],result[3])
            else:
                continue
        elif table == 'intext':
            if (result_list):
                for result in result_list:
                    db_insert_intext(con2glastopf,result[0],result[1],result[2],result[3])
            else:
                continue
        elif table == 'intitle':
            if (result_list):
                for result in result_list:
                    db_insert_intitle(con2glastopf,result[0],result[1],result[2],result[3])
            else:
                continue
        elif table == 'inurl':
            if (result_list):
                for result in result_list:
                    db_insert_inurl(con2glastopf,result[0],result[1],result[2],result[3])
            else:
                continue
        elif table == 'ip_profiles':
            if (result_list):
                for result in result_list:
                    db_insert_ip_profiles(con2glastopf,result[0],result[1],result[2],result[3],result[4],result[5],result[6],result[7],result[8]
                                      ,result[9],result[10],result[11])
            else:
                continue
        else:
            if (result_list):
                for result in result_list:
                    db_insert_allinurl(con2glastopf,result[0],result[1],result[2],result[3])
            else:
                break
    INFO("Finish import data to glastopf!")


#if __name__ == '__main__':

 #   dionaea()

    #result_list = query_getdata(connect2sqlite(),'mysql_command_args')
    #db_insert_emu_profiles(con2dionaea,result_list[0][2])
    #for result in result_list:
     #   db_insert_mysql_command_args(con2dionaea, result[1], result[2], result[3])
        #print result[3]

