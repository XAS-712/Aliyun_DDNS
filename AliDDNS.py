#!/usr/bin/python
#-*- coding:utf-8 -*-
import datetime
import random
import base64
import hmac
from hashlib import sha1
import urllib2
import urllib
import re
import socket
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def ipaddress():
    opener = urllib.urlopen('http://www.net.cn/static/customercare/yourip.asp')     
    strg = opener.read()
    strg = strg.decode('gbk')
    ipaddr = re.search('\d+\.\d+\.\d+\.\d+',strg).group(0)        
    return ipaddr

def sign(parameters):
    sortedParameters = sorted(parameters.items(), key=lambda parameters: parameters[0])
    canonicalizedQueryString = ''
    for (k, v) in sortedParameters:
        canonicalizedQueryString += '&' + percent_encode(k) + '=' + percent_encode(v)
    stringToSign = 'POST&%2F&' + percent_encode(canonicalizedQueryString[1:])
    h = hmac.new((APPSR + "&"), stringToSign, sha1)
    signature = base64.encodestring(h.digest()).strip()
    return signature

def percent_encode(encodeStr):
    encodeStr = str(encodeStr)
    res = urllib.quote(encodeStr.encode('utf-8'), '')
    res = res.replace('+', '%20')
    res = res.replace('*', '%2A')
    res = res.replace('%7E', '~')
    return res

APPID = "你的AccessKeyId"
APPSR = "你的AccessKeySecret"
ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
Nonce = random.randint(0,9999999999)
RID = ''
domain = '根域名'
Record = '子域名'
val = ipaddress()
val2 = socket.gethostbyname(Record + '.' + domain)
if val==val2:
    print Record + '.' + domain + "的A记录 " + val2 + " 是正确的，未做更改."
    exit()
post = {'Format':'json','Version':'2015-01-09','AccessKeyId':APPID,'SignatureMethod':'HMAC-SHA1','Timestamp':ts,'SignatureVersion':'1.0','SignatureNonce':Nonce,'Action':'UpdateDomainRecord','RecordId':RID,'RR':Record,'Type':'A','Value':val}
signature = sign(post)
post['Signature'] = signature
#print(post)	#For Debug
postdata=urllib.urlencode(post)
try:
    request = urllib2.Request('https://alidns.aliyuncs.com/',postdata)
    response=urllib2.urlopen(request)
    #print response
    print "已成功将" + Record + '.' + domain + "的A记录更新为 " + val + "."
except urllib2.HTTPError,e:
    print e.code
    print e.read()
