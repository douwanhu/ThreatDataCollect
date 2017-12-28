#author Victor Dou
#Kaspersky Lab Inc.
# -*- coding: utf-8 -*-

import sqlite3
import readcfg
import MySQLdb
from log.PrintLog import ERROR



host = readcfg.gethost()
port = readcfg.getport()
usr = readcfg.getusr()
pwd = readcfg.getpwd()

#print readcfg.gethost()
def connect2mysql(schema):
    try:
        conn = MySQLdb.connect( host=host,port=int(port),user=usr,passwd=pwd,db=schema)
        return conn
    except MySQLdb.Error, e:
        ERROR("MySQL Error:%s" % str(e))



#connection = connect2db()
###############################################
#  insert json log to Honeypot                #
#  insert Conpot's json log to Table Conpot   #
###############################################
def db_insert_conpot(connection,timestamp,src_ip,src_port,dst_ip,event_type,datatype,request,id,response):
    try:
        cur = connection.cursor()
        query_str='insert into Conpot (timestamp,src_ip' \
                  ',src_port,dst_ip,event_type,data_type,request,id,response) values' \
                  '("%s","%s","%d","%s","%s","%s","%s","%s","%s")'%(timestamp,src_ip,src_port,dst_ip,event_type,datatype,request,id,response)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL db_insert_conpot Error:%s" % str(e))

###insert Cowrie's json log to Table Cowrie#####

def db_insert_cowrie(connection,session,eventid,ts,message,usr,pwd,sys,src_ip,src_port,dst_ip,dst_port,input):
    try:
        cur = connection.cursor()
        query_str='insert into Cowrie (session,eventid,timestamp,message,username,password,system,src_ip,src_port,dst_ip,dst_port,input) values' \
                  '("%s","%s","%s","%s","%s","%s","%s","%s","%d","%s","%d","%s")'%(session,eventid,ts,message,usr,pwd,sys,src_ip,src_port,dst_ip,dst_port,input)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL insert_cowrie Error:%s" % str(e))

####insert Honeytrap's json log to Table Honeytrap####

def db_insert_honeytrap(connection,is_virtual,timestamp,start_time,end_time,attack_protocol,
                        remote_ip,remote_port,local_ip,local_port,payload_md5,payload_sha512,payload_len,payload_datahex,
                        proxy_protocaol,proxy_rmip,proxy_rmport,proxy_loip,proxy_loport,proxy_payload_md5,proxy_payload_sha512,
                        proxy_payload_len,proxy_payload_datahex,operation_mode,download_count,download_tries,downloads):
    try:
        cur = connection.cursor()
        query_str = 'insert into Honeytrap (is_virtual,timestamp,start_time,end_time,attack_protocol,' \
                    'remote_ip,remote_port,local_ip,local_port,payload_md5,payload_sha512,payload_len,payload_datahex,' \
                    'proxy_protocol,proxy_rmip,proxy_rmport,proxy_loip,proxy_loport,proxy_payload_md5,proxy_payload_sha512,' \
                    'proxy_payload_len,proxy_payload_datahex,operation_mode,download_count,download_tries,downloads) values' \
                    '("%s","%s","%s","%s","%s","%s","%d","%s","%d","%s","%s","%d","%s","%s","%s","%d","%s","%d","%s","%s","%d","%s","%d","%d","%d","%s")' % (is_virtual,timestamp,start_time,end_time,attack_protocol,remote_ip,remote_port,local_ip,local_port,payload_md5,payload_sha512,payload_len,payload_datahex,proxy_protocaol,proxy_rmip,proxy_rmport,proxy_loip,proxy_loport,proxy_payload_md5,proxy_payload_sha512,proxy_payload_len,proxy_payload_datahex,operation_mode,download_count,download_tries,downloads)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR("MySQL insert_Honeytrap Error:%s" % str(e))

#######################################
# insert sqlites's data to DB Dionaea #
#######################################

#insert data to Table connections

def get_diff(connection,table):
    try:
        curs = connection.cursor()
        query_str = 'select count(*) from %s'%table
        curs.execute(query_str)
        count = curs.fetchall()
        for row in count:
            for result in row:
                return result
    except MySQLdb.Error, e:
        ERROR("MySQL Dionaea_diff Error:%s" % str(e))

def db_insert_connections(connection,con_type,transpport,protocol,timestamp,root,lhost,lport,rhost,rhostname,rport):
    try:
        cur = connection.cursor()
        query_str='insert into connections(connection_type,connection_transport,connection_protocol,connection_timestamp,' \
                  'connection_root,local_host,local_port,remote_host,remote_hostname,remote_port) values ("%s","%s","%s","%d","%d","%s","%d","%s","%s","%d")'\
                  %(con_type,transpport,protocol,timestamp,root,lhost,lport,rhost,rhostname,rport)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_connections Error:%s" % str(e))

#insert data to Table dcerpcbinds

def db_insert_dcerpcbinds(connection,con,uuid,transfersyntax):
    try:
        cur = connection.cursor()
        query_str='insert into dcerpcbinds(connection,dcerpcbind_uuid,dcerpcbind_transfersyntax) values ("%d","%s","%s")'%(con,uuid,transfersyntax)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_dcerpcbinds Error:%s" % str(e))

#isner data to Table dcerpcrequests

def db_insert_dcerpcrequests(connection,con,uuid,opnum):
    try:
        cur = connection.cursor()
        query_str='insert into dcerpcrequests(connection,dcerpcrequest_uuid,dcerpcrequest_opnum) values ("%d","%s","%d")'%(con,uuid,opnum)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_dcerpcrequests Error:%s" % str(e))

#isner data to Table dcerpcserviceops

def db_insert_dcerpcserviceops(connection,dcerpcservice,dcerpcserviceop_opnum,dcerpcserviceop_name,dcerpcserviceop_vuln):
    try:
        cur = connection.cursor()
        query_str='insert into dcerpcserviceops(dcerpcservice,dcerpcserviceop_opnum,dcerpcserviceop_name,dcerpcserviceop_vuln) values ("%d","%d","%s","%s")'%(dcerpcservice,dcerpcserviceop_opnum,dcerpcserviceop_name,dcerpcserviceop_vuln)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_dcerpcserviceops Error:%s" % str(e))

#isner data to Table dcerpcservices

def db_insert_dcerpcservices(connection,dcerpcservice_uuid,dcerpcservice_name):
    try:
        cur = connection.cursor()
        query_str='insert into dcerpcservices(dcerpcservice_uuid,dcerpcservice_name) values ("%s","%s")'%(dcerpcservice_uuid,dcerpcservice_name)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_dcerpcservices Error:%s" % str(e))

#isner data to Table downloads

def db_insert_downloads(connection,con,url,md5):
    try:
        cur = connection.cursor()
        query_str='insert into downloads(connection,download_url,download_md5_hash) values ("%d","%s","%s")'%(con,url,md5)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_downloads Error:%s" % str(e))

#isner data to Table emu_profiles

def db_insert_emu_profiles(connection,conn,profile_json):
    try:
        cur = connection.cursor()
        query_str='insert into emu_profiles(connection,emu_profile_json) values (%d,\'%s\')'%(conn,profile_json)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_emuprofiles Error:%s" % str(e))


#isner data to Table emu_services

def db_insert_emu_services(connection,con,service_url):
    try:
        cur = connection.cursor()
        query_str='insert into emu_services(connection,emu_service_url) values ("%d","%s")'%(con,service_url)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_emuservices Error:%s" % str(e))

#isner data to Table logins

def db_insert_logins(connection,conn,username,password):
    try:
        cur = connection.cursor()
        query_str='insert into logins(connection,login_username,login_password) values ("%d","%s","%s")'%(conn,username,password)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_logins Error:%s" % str(e))

#isner data to Table mqtt_fingerprints

def db_insert_mqtt_fingerprints(connection,con,clientid,willtopic,willmsg,username,password):
    try:
        cur = connection.cursor()
        query_str='insert into mqtt_fingerprints(connection,mqtt_fingerprint_clientid,mqtt_fingerprint_willtopic,mqtt_fingerprint_willmessage,mqtt_fingerprint_username,mqtt_fingerprint_password) values ("%d","%s","%s","%s","%s","%s")'%(con,clientid,willtopic,willmsg,username,password)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_mqtt_fingerprints Error:%s" % str(e))

#isner data to Table mqtt_publish_commands

def db_insert_mqtt_publish_commands(connection,con,topic,msg):
    try:
        cur = connection.cursor()
        query_str='insert into mqtt_publish_commands(connection,mqtt_publish_command_topic,mqtt_publish_command_message) values ("%d","%s","%s")'%(con,topic,msg)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_mqtt_publish_commands Error:%s" % str(e))

#isner data to Table mqtt_subscribe_commands

def db_insert_mqtt_subscribe_commands(connection,con,msgid,topic):
    try:
        cur = connection.cursor()
        query_str='insert into mqtt_subscribe_commands(connection,mqtt_subscribe_command_messageid,mqtt_subscribe_command_topic) values ("%d","%s","%s")'%(con,msgid,topic)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_mqtt_subscribe_commands Error:%s" % str(e))

#insert data to Table mssql_commands

def db_insert_mssql_commands(connection,con,status,cmd):
    try:
        cur = connection.cursor()
        query_str='insert into mssql_commands(connection,mssql_command_status,mssql_command_cmd) values ("%d","%s","%s")'%(con,status,cmd)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_mssql_commands Error:%s" % str(e))

#isner data to Table mssql_fingerprints

def db_insert_mssql_fingerprints(connection,con,host,app,cltint):
    try:
        cur = connection.cursor()
        query_str='insert into mssql_fingerprints(connection,mssql_fingerprint_hostname,mssql_fingerprint_appname,' \
                  'mssql_fingerprint_cltintname) values ("%d","%s","%s","%s")'%(con,host,app,cltint)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_mssql_fingerprints Error:%s" % str(e))

#isner data to Table mysql_command_args

def db_insert_mysql_command_args(connection,cmd,arg_index,arg_data):
    try:
        cur = connection.cursor()
        query_str='insert into mysql_command_args(mysql_command,mysql_command_arg_index,mysql_command_arg_data) values ("%d","%f","%s")'%(cmd,arg_index,arg_data)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        try:
            query_str = 'insert into mysql_command_args(mysql_command,mysql_command_arg_index,mysql_command_arg_data) values ("%d","%f",\'%s\')' % (cmd, arg_index, arg_data)
            cur.execute(query_str)
            cur.close()
            connection.commit()
        except MySQLdb.Error, e:
            print query_str
            ERROR("MySQL Dionaea_mysql_command_args Error:%s" % str(e))
    #else:
        #ERROR( "MySQL Error")

#isner data to Table mysql_command_ops

def db_insert_mysql_command_ops(connection,cmd,op_name):
    try:
        cur = connection.cursor()
        query_str='insert into mysql_command_ops(mysql_command_cmd,mysql_command_op_name) values ("%d","%s")'%(cmd,op_name)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_mysql_command_ops Error:%s" % str(e))

#isner data to Table mysql_commands

def db_insert_mysql_commands(connection,con,command_cmd):
    try:
        cur = connection.cursor()
        query_str='insert into mysql_commands(connection,mysql_command_cmd) values ("%d","%f")'%(con,command_cmd)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_mysql_commands Error:%s" % str(e))

#isner data to Table offers

def db_insert_offers(connection,con,offer_url):
    try:
        cur = connection.cursor()
        query_str='insert into offers(connection,offer_url) values ("%d","%s")'%(con,offer_url)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_offers Error:%s" % str(e))

#isner data to Table p0fs

def db_insert_p0fs(connection,con,gen,uptime,link,detail,tos,dist,nat,fw):
    try:
        cur = connection.cursor()
        query_str='insert into p0fs(connection,p0f_genre,p0f_uptime,p0f_link,p0f_detail,' \
                  'p0f_tos,p0f_dist,p0f_nat,p0f_fw) values ("%d","%s","%d","%s","%s","%s","%d","%d","%d")'%(con,gen,uptime,link,detail,tos,dist,nat,fw)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_p0f Error:%s" % str(e))

#isner data to Table resolves

def db_insert_resolves(connection,con,host,type,result):
    try:
        cur = connection.cursor()
        query_str='insert into resolves(connection,resolve_hostname,resolve_type,resolve_result) values ("%d","%s","%s","%s")'%(con,host,type,result)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL Dionaea_resolves Error:%s" % str(e))

#######################################
# insert sqlites's data to DB glastopf #
#######################################

#isner data to Table events

def db_insert_events(connection,time,source,url,raw,pattern,filename,version,sensorid):
    try:
        cur = connection.cursor()
        query_str='insert into events (time,source,request_url,request_raw,pattern,filename,version,sensorid)' \
                  ' values ("%s","%s","%s","%s","%s","%s","%s","%s")'%(time,source,url,raw,pattern,filename,version,sensorid)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_events Error:%s" % str(e))

#isner data to Table ext

def db_insert_ext(connection,content,count,firstime,lastime):
    try:
        cur = connection.cursor()
        query_str='insert into ext values ("%s","%d","%s","%s")'%(content,count,firstime,lastime)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_ext Error:%s" % str(e))

#isner data to Table filetype

def db_insert_filetype(connection,content,count,firstime,lastime):
    try:
        cur = connection.cursor()
        query_str='insert into filetype values ("%s","%d","%s","%s")'%(content,count,firstime,lastime)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_filetype Error:%s" % str(e))

#isner data to Table intext

def db_insert_intext(connection,content,count,firstime,lastime):
    try:
        cur = connection.cursor()
        query_str='insert into intext values ("%s","%d","%s","%s")'%(content,count,firstime,lastime)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_intext Error:%s" % str(e))

#isner data to Table intitle

def db_insert_intitle(connection,content,count,firstime,lastime):
    try:
        cur = connection.cursor()
        query_str='insert into intitle values ("%s","%d","%s","%s")'%(content,count,firstime,lastime)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_intitle Error:%s" % str(e))

#isner data to Table inurl

def db_insert_inurl(connection,content,count,firstime,lastime):
    try:
        cur = connection.cursor()
        query_str='insert into inurl values ("%s","%d","%s","%s")'%(content,count,firstime,lastime)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_inurl Error:%s" % str(e))

#isner data to Table ip_profiles

def db_insert_ip_profiles(connection,ip,number,name,country_code,requests,scans,prefix,requests_per_scan,avg_scan_duration,scan_time_period,last_event_time,comments):
    try:
        cur = connection.cursor()
        query_str='insert into ip_profiles values ("%s","%s","%s","%s","%d","%d","%s","%f","%f","%f","%s","%s")'\
                  %(ip,number,name,country_code,requests,scans,prefix,requests_per_scan,avg_scan_duration,scan_time_period,last_event_time,comments)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_ip_profiles Error:%s" % str(e))

#isner data to Table allinurl

def db_insert_allinurl(connection,content,count,firstime,lastime):
    try:
        cur = connection.cursor()
        query_str='insert into allinurl values ("%s","%d","%s","%s")'%(content,count,firstime,lastime)
        cur.execute(query_str)
        cur.close()
        connection.commit()
    except MySQLdb.Error, e:
        ERROR( "MySQL glastopf_allinurl Error:%s" % str(e))
