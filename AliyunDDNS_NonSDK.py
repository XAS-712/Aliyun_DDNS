# -*- coding: UTF-8 -*-

import time
import hmac
from os import popen
from re import search
from json import loads
from re import compile
from sys import stdout
from hashlib import sha1
from urllib import quote
from requests import post
from random import randint
from urllib2 import urlopen
from urllib2 import Request
from urllib import urlencode
from json import JSONDecoder
from urllib2 import HTTPError
from datetime import datetime
from base64 import encodestring

def AliyunSignature(parameters):
    sortedParameters = sorted(parameters.items(), key=lambda parameters: parameters[0])
    canonicalizedQueryString = ''
    for (k, v) in sortedParameters:
        canonicalizedQueryString += '&' + CharacterEncode(k) + '=' + CharacterEncode(v)
    stringToSign = 'POST&%2F&' + CharacterEncode(canonicalizedQueryString[1:])
    h = hmac.new((Aliyun_API_SECRET + "&"), stringToSign, sha1)
    signature = encodestring(h.digest()).strip()
    return signature
def CharacterEncode(encodeStr):
    encodeStr = str(encodeStr)
    res = quote(encodeStr.encode('utf-8'), '')
    res = res.replace('+', '%20')
    res = res.replace('*', '%2A')
    res = res.replace('%7E', '~')
    return res

Aliyun_API_URL = "https://alidns.aliyuncs.com/"
Aliyun_API_KEYID = ""
Aliyun_API_SECRET = ""	# 这里为 Aliyun AccessKey 信息

Aliyun_API_RR = "www"					# 指代二级域名
Aliyun_API_Domain = "example.org"		# 指代完整域名
Aliyun_API_DomainType = "A"				# 指代记录类型

def AliyunAPIPOST(Aliyun_API_Action):
    Aliyun_API_SD = {
        'Format': 'json',										# 使用 JSON 返回数据，也可使用 XML
        'Version': '2015-01-09',								# 指定所使用的 API 版本号
        'AccessKeyId': Aliyun_API_KEYID,
        'SignatureMethod': 'HMAC-SHA1',							# 目前仅支持该算法
        'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),	# ISO8601 标准的 UTC 时间
        'SignatureVersion': '1.0',								# 签名算法版本为 1.0
        'SignatureNonce': randint(0, 99999999999999),			# 生成随机唯一数
        'Action': Aliyun_API_Action
    }
    return Aliyun_API_SD

def check_record_id(Aliyun_API_RR, Aliyun_API_Domain):
    Aliyun_API_Post = AliyunAPIPOST('DescribeDomainRecords')
    Aliyun_API_Post['DomainName'] = Aliyun_API_Domain
    Aliyun_API_Post['Signature'] = AliyunSignature(Aliyun_API_Post)
    Aliyun_API_Request = Request(Aliyun_API_URL, urlencode(Aliyun_API_Post))
    Aliyun_API_DomainRecords = '';
    try:
        Aliyun_API_Response = urlopen(Aliyun_API_Request)
        Aliyun_API_DomainRecords = Aliyun_API_Response.read()
    except HTTPError, e:
        print e.code
        print e.read()
    result = JSONDecoder().decode(Aliyun_API_DomainRecords)		# 接受返回数据
    result = result['DomainRecords']['Record']	# 缩小数据范围
    times = 0			# 用于检查对应子域名的记录信息
    check = 0			# 用于确认对应子域名的记录信息
    for record_info in result:					# 遍历返回数据
        if record_info['RR'] == Aliyun_API_RR:	# 检查是否匹配
            check = 1; break;					# 确认完成结束
        else:
            times += 1							# 进入下个匹配
    if check:
        result = result[times]['RecordId']		# 返回记录数值
    else:
        result = -1								# 返回失败数值
    return result

def my_ip_direct():
    opener = urlopen('https://wtfismyip.com/text')
    strg = opener.read()
    return strg

def my_ip_json():
    opener = urlopen('https://wtfismyip.com/json')
    strg = loads(opener.read().replace('Fucking', 'Current'))
    return strg['YourCurrentIPAddress']

def my_ip_popen():
    get_ip_method = popen('curl -s pv.sohu.com/cityjson?ie=utf-8')					# 获取外网 IP 地址
    get_ip_responses = get_ip_method.readlines()[0]									# 读取 HTTP 请求值
    get_ip_pattern = compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')		# 正则匹配 IP
    get_ip_value = get_ip_pattern.findall(get_ip_responses)[0]						# 寻找匹配值
    return get_ip_value																# 返回 IP 地址

def my_ip_chinanetwork():
    opener = urlopen('http://www.net.cn/static/customercare/yourip.asp')
    strg = opener.read()
    strg = strg.decode('gbk')
    ipaddr = search('\d+\.\d+\.\d+\.\d+',strg).group(0)
    return ipaddr

def my_ip():
    ip1 = my_ip_direct().replace('\n','')
    ip2 = my_ip_json()
    ip3 = my_ip_popen()
    ip4 = my_ip_chinanetwork()
    # if ip1 == ip2 == ip3 == ip4:
        # print("[Success] Verified IP Address...")
        # return ip + random.randint(0,3)					# 开个玩笑
    # else:
        # print("[FAILED] No-Verified IP Address...")
        # return ip1
    return ip1

def old_ip(Aliyun_API_RecordID):
    Aliyun_API_Post = AliyunAPIPOST('DescribeDomainRecordInfo')
    Aliyun_API_Post['RecordId'] = Aliyun_API_RecordID
    Aliyun_API_Post['Signature'] = AliyunSignature(Aliyun_API_Post)
    Aliyun_API_Request = Request(Aliyun_API_URL, urlencode(Aliyun_API_Post))
    Aliyun_API_Response = urlopen(Aliyun_API_Request)
    result = JSONDecoder().decode(Aliyun_API_Response.read())
    return result['Value']

def add_dns(Aliyun_API_DomainIP):
    Aliyun_API_Post = AliyunAPIPOST('AddDomainRecord')
    Aliyun_API_Post['DomainName'] = Aliyun_API_Domain
    Aliyun_API_Post['RR'] = Aliyun_API_RR
    Aliyun_API_Post['Type'] = Aliyun_API_DomainType
    Aliyun_API_Post['Value'] = Aliyun_API_DomainIP
    Aliyun_API_Post['Signature'] = AliyunSignature(Aliyun_API_Post)
    Aliyun_API_Request = Request(Aliyun_API_URL, urlencode(Aliyun_API_Post))
    Aliyun_API_Response = urlopen(Aliyun_API_Request)

def update_dns(Aliyun_API_RecordID,Aliyun_API_DomainIP):
    Aliyun_API_Post = AliyunAPIPOST('UpdateDomainRecord')
    Aliyun_API_Post['RecordId'] = Aliyun_API_RecordID
    Aliyun_API_Post['RR'] = Aliyun_API_RR
    Aliyun_API_Post['Type'] = Aliyun_API_DomainType
    Aliyun_API_Post['Value'] = Aliyun_API_DomainIP
    Aliyun_API_Post['Signature'] = AliyunSignature(Aliyun_API_Post)
    Aliyun_API_Request = Request(Aliyun_API_URL, urlencode(Aliyun_API_Post))
    Aliyun_API_Response = urlopen(Aliyun_API_Request)

def send_mail(content):
    return post(
        "https://api.mailgun.net/v3/example.org/messages",
        auth=("api", "key-"),
        data={"from": "Your Name <me@mail.example.org>",
            "to": ["i@example.org", "admin@example.org"],
            "subject": "[Python Report] IP update from ISP",
            "text": content})

def get_time():
    return "[" + time.strftime('#%y%m%d-%H:%M', time.localtime(time.time())) + "]"

rc_value = my_ip()
rc_record_id = check_record_id(Aliyun_API_RR, Aliyun_API_Domain);		# 获取记录信息

tips = ""
if rc_record_id < 0:		# 若接受失败数值
    add_dns(rc_value)		# 添加 DNS　解析记录
    tips = get_time() + " DNS Record was added, value [" + rc_value + "]."
else:
    rc_value_old = old_ip(rc_record_id)
    if rc_value == rc_value_old:					# 检查 IP 是否匹配
        tips = get_time() + " Same DNS Record..."	# 跳过 DNS 更新
    else:
        update_dns(rc_record_id,rc_value)  				# 指定 DNS 更新
        tips = get_time() + " DNS Record was updated from [" + rc_value_old + "] to [" + rc_value + "]."
        send_mail(tips)

print tips
