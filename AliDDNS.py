# -*- coding: UTF-8 -*-
# pip install aliyun-python-sdk-domain

import time
import urllib
import subprocess
from os import popen
from json import loads
from re import search
from re import compile
from sys import stdout
from requests import post
from json import JSONDecoder
from datetime import datetime

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest

rc_rr = "@"				# 指代二级域名（子域名，空则使用 @ 代替）
rc_domain = "example.org"		# 指代完整域名，若未配置阿里云 NameServer 解析修改也无效
rc_format = "json"			# 指定返回数据格式，目前本例使用 JSON 数据
rc_type = "A"				# 指定修改记录类型，目前本例使用 A 记录
rc_ttl = "600"				# 指定修改 TTL 值，目前本例使用 600 秒
rc_format = "json"			# 使用 JSON 返回数据，也可以填写为 XML

access_key_id = ""			# 这里为 Aliyun AccessKey 信息
access_key_secret = ""			# 这里为 Aliyun AccessKey 信息

clt = AcsClient(access_key_id, access_key_secret, 'default')

def check_record_id(dns_rr, dns_domain):
    times = 0			# 用于检查对应子域名的记录信息
    check = 0			# 用于确认对应子域名的记录信息
    request = CommonRequest()
    request.set_accept_format('json')                       # 设置返回格式
    request.set_domain('alidns.aliyuncs.com')               # 阿里云服务
    request.set_method('POST')
    request.set_protocol_type('https')
    request.set_version('2015-01-09')
    request.set_action_name('DescribeDomainRecords')
    request.add_query_param('DomainName', rc_domain)        # 设置请求域名
    request.add_query_param('RRKeyWord', rc_rr)
    request.add_query_param('TypeKeyWord', rc_type)
    response = loads(clt.do_action(request))                # 接受返回数据
    result = response['DomainRecords']['Record']	    # 缩小数据范围
    for record_info in result:				    # 遍历返回数据
        if record_info['RR'] == dns_rr:		            # 检查是否匹配
            check = 1; break;				    # 确认完成结束
        else:
            times += 1					    # 进入下个匹配
    if check:
        result = result[times]['RecordId']	            # 返回记录数值
    else:
        result = -1					    # 返回失败数值
    return result

def my_ip_direct():
    opener = urllib.request.urlopen('https://wtfismyip.com/text')
    strg = opener.read()
    return strg

def my_ip_json():
    opener = urllib.request.urlopen('https://wtfismyip.com/json')
    strt = opener.read().decode('utf-8')
    strg = loads(strt.replace('Fucking', 'Current'))
    return strg['YourCurrentIPAddress']

def my_ip_popen():
    get_ip_method = subprocess.Popen('curl -s pv.sohu.com/cityjson?ie=utf-8', shell=True, stdout = subprocess.PIPE)
    get_ip_responses = get_ip_method.stdout.read().decode('utf-8')		        # 读取 HTTP 请求值
    get_ip_pattern = compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')		# 正则匹配 IP
    get_ip_value = get_ip_pattern.findall(get_ip_responses)[0]				# 寻找匹配值
    return get_ip_value																# 返回 IP 地址

def my_ip_chinanetwork():
    opener = urllib.request.urlopen('http://www.net.cn/static/customercare/yourip.asp')
    strg = opener.read()
    strg = strg.decode('gbk')
    ipaddr = search('\d+\.\d+\.\d+\.\d+',strg).group(0)
    return ipaddr

def my_ip():
    ip1 = my_ip_direct().decode(encoding='utf-8').replace('\n', '')
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

def old_ip(dns_record_id):
    request = CommonRequest()
    request.set_accept_format('json')                           # 设置返回格式
    request.set_domain('alidns.aliyuncs.com')
    request.set_method('POST')                                  # 设置记录值
    request.set_protocol_type('https')
    request.set_version('2015-01-09')
    request.set_action_name('DescribeDomainRecordInfo')
    request.add_query_param('RecordId', dns_record_id)
    result = loads(clt.do_action(request))                      # 接受返回数据
    return result['Value']                                      # 返回记录数值

def add_dns(dns_rr, dns_domain, dns_type, dns_value, dns_ttl):
    request = CommonRequest()
    request.set_accept_format('json')                           # 设置返回格式
    request.set_domain('alidns.aliyuncs.com')
    request.set_method('POST')
    request.set_protocol_type('https')
    request.set_version('2015-01-09')
    request.set_action_name('AddDomainRecord')
    request.add_query_param('DomainName', dns_domain)           # 设置请求域名
    request.add_query_param('RR', dns_rr)                       # 设置子域名信息
    request.add_query_param('Type', dns_type)                   # 设置 DNS 类型
    request.add_query_param('Value', dns_value)                 # 设置解析 IP
    response = loads(clt.do_action(request))                    # 发送请求内容
    return response

def update_dns(dns_rr, dns_type, dns_value, dns_record_id, dns_ttl):
    request = CommonRequest()
    request.set_accept_format('json')                           # 设置返回格式
    request.set_domain('alidns.aliyuncs.com')
    request.set_method('POST')
    request.set_protocol_type('https')
    request.set_version('2015-01-09')
    request.set_action_name('UpdateDomainRecord')
    request.add_query_param('RecordId', dns_record_id)          # 设置记录值
    request.add_query_param('RR', dns_rr)                       # 设置子域名信息
    request.add_query_param('Type', dns_type)                   # 设置 DNS 类型
    request.add_query_param('Value', dns_value)                  # 设置解析 IP
    response = loads(clt.do_action(request))                    # 发送请求内容
    return response

def send_mail(content):
    return post(
        "https://api.mailgun.net/v3/example.org/messages",
        auth=("api", "key-"),
        data={"from": "Your Name <me@mail.example.org>",
              "to": ["me@example.org", "admin@example.org"],
              "subject": "[Python Report] IP update from ISP",
              "text": content})

def get_time():
    return "[" + time.strftime('#%y%m%d-%H:%M', time.localtime(time.time())) + "]"

rc_value = my_ip();										# 获取外网 IP 地址
rc_record_id = check_record_id(rc_rr, rc_domain);		# 获取记录信息
tips = get_time();
if(len(str(rc_record_id)) <= 3):								# 若接受失败数值
    tips += " DNS Record was added, value [" + rc_value + "]."
    add_dns(rc_rr, rc_domain, rc_type, rc_value, rc_ttl)		# 添加 DNS　解析记录
    send_mail(tips)
else:
    rc_value_old = old_ip(rc_record_id)
    if rc_value == rc_value_old:						# 检查 IP 是否匹配
        tips += " Same DNS Record..."					# 跳过 DNS 更新
    else:												# 指定 DNS 更新
        tips += " DNS Record was updated from [" + rc_value_old + "] to [" + rc_value + "]."
        update_dns(rc_rr, rc_type, rc_value, rc_record_id, rc_ttl)
        send_mail(tips)
print(tips)
