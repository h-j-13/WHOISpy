#!/usr/bin/env python
# encoding:utf-8

"""
连接WHOIS服务器,获取数据

为了支持socks代理功能,使用了PySocks库
A SOCKS proxy client and wrapper for Python.
https://github.com/Anorov/PySocks

支持socks4,socks5形式的代理

如果不使用代理的话,使用python自带的socket库即可较为简单的完成请求的过程
>>> import socket
>>>
>>> try: # socket通信 ipv4 超时10s 连结43端口
>>>    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>>    s.settimeout(10)
>>>    s.connect((hostname, 43))
>>>    # 发送查询请求
>>>    s.send(bytes(query_bytes,"utf-8") + "\r\n")
>>>    # 接收数据
>>>    # recv returns bytes
>>>    while True:
>>>        d = s.recv(4096)
>>>        response += d
>>>        if not d:
>>>            break
>>> except socket.error as socketerror:
>>>    print("Socket Error:", socketerror)

因为使用域名来访问WHOIS服务器,所以DNS过程是不可避免的,然后Liunx默认情况是没有DNS缓存的
因此在Linux环境下运行时,非常推荐打开Linux DNS缓存已获得更高的效率

$ sudo apt-get install nscd

详细使用说明:
http://blog.163.com/qiushuhui1989@126/blog/static/270110892015172723478/
https://stackoverflow.com/questions/11020027/dns-caching-in-linux
"""

import socks
from WHOIS_server import WHOIS_server

WHOIS_server_data = WHOIS_server()


def WHOIS_connect(domain_punycode,
                  whois_srv="",
                  socket_time_out=5,
                  socket_retry_time=1,
                  use_sock_proxy=False,
                  proxy_type="SOCKS5",
                  proxy_ip="",
                  proxy_port="",
                  proxy_username="",
                  proxy_password="",
                  use_relay_WHOIS_server=False):
    # type: (str, str, int, int, bool, str, str, str, str, str, bool) -> str
    """
    与 WHOIS 服务器通信,获取WHOIS数据
    :param domain_punycode:             域名(punycode格式)
    :param whois_srv:                   WHOIS 服务器地址
    :param socket_time_out:             socket 连接超时时间
    :param socket_retry_time:           socket 连接最大重试次数
    :param use_sock_proxy:              是否使用socks代理
    :param proxy_type:                  代理的类型(仅支持 SOCKS4 , SOCKS5 不支持 HTTP,HTTPS 代理)
    :param proxy_ip:                    代理ip
    :param proxy_port:                  代理端口
    :param proxy_username:              代理用户名
    :param proxy_password:              代理密码
    :param use_relay_WHOIS_server:      是否使用转发服务器查询标记
    :return:WHOIS服务器返回的原始域名WHOIS数据(如果发生异常则返回异常信息)

    - 支持超时设置和多次重试
    - 支持SOCKS4,SOCKS5代理
    - 支持使用转发 WHOIS 服务器
    """

    # 基于 RFC 3912
    # 默认使用 域名\r\n 发送给 WHOIS 服务器进行查询

    def check_WHOIS_server(query_str, whois_srv):
        """
        检查WHOIS服务器是否需要额外参数
        :return: 基于RFC3192协议及WHOIS服务器特殊的请求参数修正查询字符串格式
        """
        # whois.jprs.jp
        if whois_srv == "whois.jprs.jp":
            query_str = "{domain}/e".format(domain=domain_punycode)
        # whois.denic.de
        elif whois_srv == "whois.denic.de":
            query_str = "-T dn,ace {domain}".format(domain=domain_punycode)
        # whois.verisign-grs.com
        elif whois_srv == "whois.verisign-grs.com" or whois_srv == "whois.crsnic.net":
            query_str = "={domain}".format(domain=domain_punycode)

        # RFC 3912
        query_str = query_str + "\r\n"
        return query_str

    def set_socket_opt():
        """设置socket连接参数"""
        tcpCliSock = socks.socksocket()  # 创建socket对象
        tcpCliSock.settimeout(socket_time_out)  # 设置超时时间
        if use_sock_proxy:  # socks代理配置
            # 设置代理
            if proxy_type == "SOCKS5":
                tcpCliSock.set_proxy(proxy_type=socks.SOCKS5,  # socks类型
                                     addr=proxy_ip,  # socks代地址
                                     port=proxy_port,  # 端口
                                     username=proxy_username,  # 用户名
                                     password=proxy_password)  # 密码

            elif proxy_type == "SOCKS4":
                tcpCliSock.set_proxy(proxy_type=socks.SOCKS4,  # socks类型
                                     addr=proxy_ip,  # socks代地址
                                     port=proxy_port)  # 端口
        return tcpCliSock

    def connect(request_data, whois_srv):
        """与WHOIS服务器通信"""
        global WHOIS_server_data
        # whois服务器ip，代理ip
        if whois_srv or use_relay_WHOIS_server:
            if use_relay_WHOIS_server:  # 如果选择了使用WHOIS转发服务器,则不论输入什么,一律采用WHOIS转发服务器来进行通信
                whois_srv = WHOIS_server_data.get_random_relay_WHOIS_server()
            tcpCliSock = set_socket_opt()
            data_result = ""
            try:
                tcpCliSock.connect((whois_srv, 43))  # 连接whois服务器
                tcpCliSock.send(request_data)  # 发出请求
            except Exception as connect_err:  # Exception来自socks.py 中设置的异常
                data_result = "SOCKET ERROR : " + str(connect_err)
            # 接收数据
            while True:
                try:
                    data_rcv = tcpCliSock.recv(1024)  # 反复接收数据
                except Exception as connect_err:
                    tcpCliSock.close()
                    return "SOCKET ERROR : " + str(connect_err)
                if not len(data_rcv):
                    tcpCliSock.close()
                    return data_result  # 返回查询结果
                data_result = data_result + data_rcv  # 每次返回结果组合
        else:
            return "WHOIS ERROR : no whois server addr"

    # 通信控制和管理
    res = ""
    query_str = check_WHOIS_server(domain_punycode, whois_srv)
    for i in xrange(int(max(1, socket_retry_time))):
        res = connect(query_str, whois_srv)
        if not (res.startswith("SOCKET ERROR") or res.startswith("WHOIS ERROR")):
            return res
    return res


if __name__ == "__main__":
    # use demo
    print WHOIS_connect("baidu.com", "whois.verisign-grs.com")
    print WHOIS_connect("baidu.com", "whois.markmonitor.com")
    print WHOIS_connect("baidu.com", "")
    print WHOIS_connect("baidu.com", "", use_relay_WHOIS_server=True)
