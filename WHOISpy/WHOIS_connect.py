#!/usr/bin/env python
# encoding:utf-8

"""
连接WHOIS服务器,获取数据

为了支持socks代理功能,使用了PySocks库
A SOCKS proxy client and wrapper for Python.
https://github.com/Anorov/PySocks

支持socks4,socks5形式的代理


"""

import socks

from WHOIS_server import WHOIS_server

global WHOIS_server_data
WHOIS_server_data = WHOIS_server()


def WHOIS_connect(domain_punycode,
                  WHOIS_srv,
                  socket_time_out=10,
                  socket_retry_time=3,
                  proxy_flag=False,
                  proxy_type='SOCKS5',
                  proxy_ip='',
                  proxy_port='',
                  proxy_username='',
                  proxy_password='',
                  use_relay_WHOIS_server=False):
    """
    与 WHOIS 服务器通信,获取WHOIS数据

    三次重试
    支持SOCKS4,SOCKS5代理
    支持使用转发 WHOIS 服务器
    :param domain_punycode:     域名(punycode格式)
    :param WHOIS_srv:           WHOIS 服务器地址/ip
    :param socket_time_out:     socket 连接超时时间
    :param socket_retry_time:   socket 连接最大重试次数
    :param proxy_flag:          是否使用代理标志
    :param proxy_type:          代理的类型(仅支持 SOCKS4 , SOCKS5 不支持 HTTP,HTTPS 代理)
    :param proxy_ip:            代理ip
    :param proxy_port:          代理端口
    :param proxy_username:      代理用户名
    :param proxy_password:      代理密码
    :param use_relay_WHOIS_server:  是否使用转发服务器查询标记
    :return:WHOIS 服务器返回的原始域名 WHOIS 数据
    """

    # 基于 RFC 3912
    # 默认使用 域名\r\n 发送给 WHOIS 服务器进行查询
    query_str = domain_punycode + '\r\n'

    # TODO 完成这个函数并进行单元测试
    def check_proxy_format():
        """检查是否输入了正确格式的代理"""
        pass

    def check_WHOIS_server():
        """检查WHOIS服务器是否需要额外参数"""
        pass

    def connect():
        """与WHOIS服务器通信"""
        pass

    def connect_manager():
        """与WHOIS服务器通信过程管理与控制"""
        pass


class GetWhoisInfo:
    """whois 通信类"""

    # 处理几个特殊的whois服务器（jp，de，com二级）
    def __init__(self, domain, whois_srv):
        """处理whois服务器"""
        # 处理特殊的请求格式
        if whois_srv == "whois.jprs.jp":
            self.request_data = "%s/e" % domain  # Suppress Japanese output
        elif domain.endswith(".de") and (whois_srv == "whois.denic.de" or whois_srv == "de.whois-servers.net"):
            self.request_data = "-T dn,ace %s" % domain  # regional specific stuff
        elif whois_srv == "whois.verisign-grs.com" or whois_srv == "whois.crsnic.net":
            self.request_data = "=%s" % domain  # Avoid partial matches
        else:
            self.request_data = domain
        self.whois_srv = whois_srv

    @staticmethod
    def _is_error(data):
        """判断返回数据中是否有错误"""
        return True if (data in error_list or data is None) else False

    def get(self):
        """获取数据"""
        data = ''
        for i in range(RECONNECT):  # 最大重连数
            data = self._connect()
            if not GetWhoisInfo._is_error(data):  # 如果数据没有错误,则直接返回
                break
        # 处理异常类型
        for ban_str in ban_list:  # 查询过快
            if data.find(ban_str) != -1:
                raise WhoisConnectException(5)
        if data in error_list:  # 如果在设定的错误类型中
            print data
            raise WhoisConnectException(error_list.index(data) + 1)
        elif data is None:  # 空数据
            raise WhoisConnectException(5)
        else:  # 正常情况
            return data

    def _connect(self):
        """核心函数：与whois通信
        需要：socks.py (ver 1.5.7)"""
        # whois服务器ip，代理ip
        global _server_ip, _proxy_socks
        host = _server_ip.get_server_ip(self.whois_srv)  # 服务器地址
        host = host if host else self.whois_srv  # 如果ip地址为空则使用服务器地址
        self.tcpCliSock = socks.socksocket()  # 创建socket对象
        self.tcpCliSock.settimeout(TIMEOUT)  # 设置超时时间
        if Proxy_Flag:  # socks代理配置
            proxy_info = _proxy_socks.get_proxy_socks(self.whois_srv)  # 代理IP
            if proxy_info is not None:
                # 设置代理
                if proxy_info['mode'] == 'SOCKS5':
                    self.tcpCliSock.set_proxy(proxy_type=socks.SOCKS5,  # socks类型
                                              addr=proxy_info['ip'],  # socks代地址
                                              port=proxy_info['port'],  # 端口
                                              username=proxy_info['username'],  # 用户名
                                              password=proxy_info['password'])  # 密码

                elif proxy_info['mode'] == 'SOCKS4':
                    self.tcpCliSock.set_proxy(proxy_type=socks.SOCKS4,  # socks类型
                                              addr=proxy_info['ip'],  # socks代地址
                                              port=proxy_info['port'])  # 端口
        data_result = ""
        try:
            self.tcpCliSock.connect((host, 43))  # 连接whois服务器
            self.tcpCliSock.send(self.request_data + '\r\n')  # 发出请求
        except Exception as e:  # Exception来自socks.py 中设置的异常
            if str(e).find("timed out") != -1 or \
                    str(e).find("TTL expired") != -1:  # 连接超时
                self.tcpCliSock.close()
                return "ERROR -1"
            elif str(e).find("Temporary failure in name resolution") != -1 or \
                    str(e).find("cannot connect to identd on the client") != -1 or \
                    str(e).find("unreachable") != -1:
                self.tcpCliSock.close()
                return "ERROR -2"
            else:
                self.tcpCliSock.close()
                return "ERROR OTHER"
        # 接收数据
        while True:
            try:
                data_rcv = self.tcpCliSock.recv(1024)  # 反复接收数据
            except:
                self.tcpCliSock.close()
                return "ERROR -3"
            if not len(data_rcv):
                self.tcpCliSock.close()
                return data_result  # 返回查询结果
            data_result = data_result + data_rcv  # 每次返回结果组合


def __Demo(Domain):
    domain = Domain  # 需要获取的域名
    whois_server = 'whois.afilias-grs.info.'  # 域名对应的whois服务器
    data_result = ''
    try:
        data_result = GetWhoisInfo(domain, whois_server).get()  # 获取
    except Exception as e:
        print e
    print "data->", data_result


if __name__ == '__main__':
    # Demo
    __Demo("yh888.info")
