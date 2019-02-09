#!/usr/bin/env python
# encoding:utf-8

"""
 DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2019 h-j-13

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.


WHOISpy

WHOISpy是一个纯Python编写的基于RFC3912的WHOIS客户端,你可以通过他轻松的获取并提取域名WHOIS关键信息

>>>from WHOISpy.WHOIS import WHOIS
>>>WHOIS("github.com")
{
    "domain": "baidu.com",
    "tld": "com",
    "top_whois_server": "whois.verisign-grs.com",
    "sec_whois_server": "whois.markmonitor.com",
    "sponsoring_registrar": "MarkMonitor, Inc.",
    ...
}
"""

import copy

from domain_extract import Domain
from WHOIS_server import WHOIS_server
from WHOIS_connect import WHOIS_srv_connect
from WHOIS_info_extract import extract_WHOIS_info, \
    FLAG_CANT_DEAL, WHOIS_RECORD, FLAG_OK, FLAG_NO_WHOIS_ADDR, FLAG_TOP_WHOIS_FAILED, FLAG_EMPTY_WHOIS_INFO

choose_whois_server = None


def WHOIS(raw_domain,
          whois_server="",
          format_time=True,
          format_domain_status=True,
          list_name_server=True,
          socket_time_out=5,
          socket_retry_time=1,
          use_sock_proxy=False,
          proxy_type="SOCKS5",
          proxy_ip="",
          proxy_port="",
          proxy_username="",
          proxy_password="",
          use_relay_WHOIS_server=False
          ):
    """
    获取域名WHOIS信息并智能解析关键字段
    :param raw_domain:                  原始url
    :param whois_server:                指定的WHOIS服务器
    :param format_time:                 标准化时间
    :param format_domain_status:        标准化域名标记
    :param list_name_server:            列表格式记录域名NS服务器标记
    :param socket_time_out:             socket 连接超时时间
    :param socket_retry_time:           socket 连接最大重试次数
    :param use_sock_proxy:              是否使用socks代理
    :param proxy_type:                  代理的类型(仅支持 SOCKS4 , SOCKS5 不支持 HTTP,HTTPS 代理)
    :param proxy_ip:                    代理ip
    :param proxy_port:                  代理端口
    :param proxy_username:              代理用户名
    :param proxy_password:              代理密码
    :param use_relay_WHOIS_server:      是否使用转发服务器查询标记
    :return: 经过关键字段解析及标准化的WHOIS信息字典
    """
    global choose_whois_server

    # 处理域名信息
    d = Domain(raw_domain)
    tld = d.tld_punycode
    if not tld:
        res = copy.deepcopy(WHOIS_RECORD)
        res["domain"] = raw_domain
        res["flag"] = FLAG_CANT_DEAL
        res["details"] = "WHOIS ERROR : DOMAIN EXTRACT FAILED " + str(raw_domain)
        res["top_whois_detail"] = res["details"]
        return res

    # 根据输入的参数,或者根据TLD自动选择WHOIS服务器
    if whois_server:
        ws = whois_server
    else:
        if not choose_whois_server:
            choose_whois_server = WHOIS_server()
        ws = choose_whois_server.get_WHOIS_server(tld)

    # 获取原始whois数据
    raw_whois_data = ""
    flag = FLAG_OK
    raw_whois_data = WHOIS_srv_connect(d.domain_punycode, ws)
    if raw_whois_data.startswith("SOCKET ERROR"):
        flag = FLAG_TOP_WHOIS_FAILED
    elif raw_whois_data.startswith("WHOIS ERROR"):
        flag = FLAG_NO_WHOIS_ADDR
    elif not raw_whois_data.strip():
        flag = FLAG_EMPTY_WHOIS_INFO

    # 解析WHOIS关键信息
    res = extract_WHOIS_info(d.domain_punycode,
                             d.tld_punycode,
                             ws,
                             raw_whois_data,
                             flag,
                             format_time=format_time,
                             format_domain_status=format_domain_status,
                             list_name_server=list_name_server,
                             socket_time_out=socket_time_out,
                             socket_retry_time=socket_retry_time,
                             use_sock_proxy=use_sock_proxy,
                             proxy_type=proxy_type,
                             proxy_ip=proxy_ip,
                             proxy_port=proxy_port,
                             proxy_username=proxy_username,
                             proxy_password=proxy_password,
                             use_relay_WHOIS_server=use_relay_WHOIS_server
                             )

    return res


if __name__ == '__main__':
    # use demo
    ws = WHOIS("google.jp")
    print ws['details']
    import json

    print(json.dumps(ws, indent=4))
