# -- coding: utf-8 --

import time
from os import popen
import urllib
from re import compile
from sys import stdout
from requests import post
from json import JSONDecoder
from datetime import datetime

from aliyunsdkcore import client
from aliyunsdkalidns.request.v20150109 import AddDomainRecordRequest
from aliyunsdkalidns.request.v20150109 import UpdateDomainRecordRequest
from aliyunsdkalidns.request.v20150109 import DescribeDomainRecordsRequest
from aliyunsdkalidns.request.v20150109 import DescribeDomainRecordInfoRequest

rc_rr = "www"				# 指代二级域名（子域名，空则使用 @ 代替）
rc_domain = "example.org"	# 指代完整域名，若未配置阿里云 NameServer 解析修改也无效
rc_format = "json"			# 指定返回数据格式，目前本例使用 JSON 数据
rc_type = "A"				# 指定修改记录类型，目前本例使用 A 记录
rc_ttl = "600"				# 指定修改 TTL 值，目前本例使用 600 秒
rc_format = "json"			# 使用 JSON 返回数据，也可以填写为 XML

access_key_id = ""						# 这里为 Aliyun AccessKey 信息
access_key_secret = ""	# 这里为 Aliyun AccessKey 信息

clt = client.AcsClient(access_key_id, access_key_secret, 'cn-shanghai')

def check_record_id(dns_rr, dns_domain):
    times = 0			# 用于检查对应子域名的记录信息
    check = 0			# 用于确认对应子域名的记录信息
    request = DescribeDomainRecordsRequest.DescribeDomainRecordsRequest()
    request.set_DomainName(dns_domain)				# 设置请求域名
    request.set_accept_format(rc_format)			# 设置返回格式
    result = clt.do_action_with_exception(request)	# 发送请求内容
    result = JSONDecoder().decode(result)			# 接受返回数据
    result = result['DomainRecords']['Record']		# 缩小数据范围
    for record_info in result:				# 遍历返回数据
        if record_info['RR'] == dns_rr:		# 检查是否匹配
            check = 1; break;				# 确认完成结束
        else:
            times += 1						# 进入下个匹配
    if check:
        result = result[times]['RecordId']	# 返回记录数值
    else:
        result = -1							# 返回失败数值
    return result
  
def my_ip1():
    get_ip_method = popen('curl -s pv.sohu.com/cityjson?ie=utf-8')					# 获取外网 IP 地址
    get_ip_responses = get_ip_method.readlines()[0]									# 读取 HTTP 请求值
    get_ip_pattern = compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')	# 正则匹配 IP
    get_ip_value = get_ip_pattern.findall(get_ip_responses)[0]						# 寻找匹配值
    return get_ip_value																# 返回 IP 地址
  
def my_ip2():
    opener = urllib.urlopen('http://whatismyip.akamai.com')     
    strg = opener.read()  
    return strg
  
def my_ip3():
    opener = urllib.urlopen('http://www.net.cn/static/customercare/yourip.asp')     
    strg = opener.read()
    strg = strg.decode('gbk')
    ipaddr = re.search('\d+\.\d+\.\d+\.\d+',strg).group(0)        
    return ipaddr
  
def my_ip()
#    ip1=my_ip1()
    ip2=my_ip2()
#    ip3=my_ip3()
#    if ip1==ip2==ip3:
#        print("Get IP ... Success.")
#        return ip1
#    else:
#        print("Get IP ... Warning.IPs aren't the same.")
#        return ip2
    return ip2

def old_ip(dns_record_id):
    request = DescribeDomainRecordInfoRequest.DescribeDomainRecordInfoRequest()
    request.set_RecordId(dns_record_id)					# 设置记录值
    request.set_accept_format(rc_format)				# 设置返回格式
    result = clt.do_action_with_exception(request)		# 发送请求内容
    result = JSONDecoder().decode(result)				# 接受返回数据
    return result['Value']								# 返回记录数值

def add_dns(dns_rr, dns_domain, dns_type, dns_value, dns_ttl):
    request = AddDomainRecordRequest.AddDomainRecordRequest()
    request.set_RR(dns_rr)								# 设置子域名信息
    request.set_DomainName(dns_domain)					# 设置请求域名
    request.set_Type(dns_type)							# 设置 DNS 类型
    request.set_Value(dns_value)						# 设置解析 IP
    request.set_TTL(dns_ttl)							# 设置 TTL 时间
    request.set_accept_format(rc_format)				# 设置返回格式
    return clt.do_action_with_exception(request)		# 发送请求内容

def update_dns(dns_rr, dns_type, dns_value, dns_record_id, dns_ttl):
    request = UpdateDomainRecordRequest.UpdateDomainRecordRequest()
    request.set_RR(dns_rr)								# 设置子域名信息
    request.set_Type(dns_type)							# 设置 DNS 类型
    request.set_Value(dns_value)						# 设置解析 IP
    request.set_RecordId(dns_record_id)					# 设置记录值
    request.set_TTL(dns_ttl)							# 设置 TTL 时间
    request.set_accept_format(rc_format)				# 设置返回格式
    return clt.do_action_with_exception(request)		# 发送请求内容

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

rc_value = my_ip()										# 获取外网 IP 地址
rc_record_id = check_record_id(rc_rr, rc_domain);		# 获取记录信息

str = ""
if rc_record_id < 0:											# 若接受失败数值
    add_dns(rc_rr, rc_domain, rc_type, rc_value, rc_ttl)		# 添加 DNS　解析记录
    str = get_time() + " DNS Record was added, value [" + rc_value + "]."
else:
    rc_value_old = old_ip(rc_record_id)
    if rc_value == rc_value_old:								# 检查 IP 是否匹配
        str = get_time() + " Same DNS Record..."	# 跳过 DNS 更新
    else:
        update_dns(rc_rr, rc_type, rc_value, rc_record_id, rc_ttl)										# 指定 DNS 更新
        str = get_time() + " DNS Record was updated from [" + rc_value_old + "] to [" + rc_value + "]."
        send_mail(str)

print str
