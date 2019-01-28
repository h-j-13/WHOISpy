#!/usr/bin/env python
# encoding:utf-8

"""
选择域名的WHOIS服务器

数据及获取、维护方法详见 https://github.com/h-j-13/WHOIS-server-list

核心数据 : WHOIS_server_list.dat
辅助数据 : relay_WHOIS_server_list.dat
"""

import os
from random import choice


class WHOIS_server(object):
    """WHOIS服务器"""

    _instance = None

    def __new__(cls, *args, **kw):
        """单例模式"""

        if not cls._instance:
            cls._instance = super(WHOIS_server, cls).__new__(cls, *args, **kw)
        return cls._instance

    def __init__(self):
        """构造函数"""
        # 读取 /data 目录下的文件,构造WHOIS与转发WHOIS服务器字典
        # 顶级域/后缀    :   WHOIS 服务器
        self.WHOIS_server_general_format = 'whois.nic.'
        self.WHOIS_server_dict = {}
        self.relay_WHOIS_server_list = []

        if not self.WHOIS_server_dict:
            server_file_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'WHOIS_server_list.dat')
            with open(server_file_path) as f:
                for data in [line.strip() for line in f.readlines() if not line.startswith('//') and line.strip()]:
                    if data.find(':') != -1:
                        k, v = data.split(':', 1)
                        self.WHOIS_server_dict[k.strip()] = v.strip()
                    else:
                        suffix = data.strip()
                        self.WHOIS_server_dict[suffix] = self.WHOIS_server_general_format + suffix

        if not self.relay_WHOIS_server_list:
            relay_server_file_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data',
                                                  'relay_WHOIS_server_list.dat')
            with open(relay_server_file_path) as f:
                self.relay_WHOIS_server_list = [line.strip() for line in f.readlines() if
                                                not line.startswith('//') and line.strip()]

    def get_WHOIS_server(self, tld):
        """
        获取该 TLD 对应的 WHOIS 服务器地址
        :param tld: 域名的 TLD 或者 suffix
        :return:与输入 tld/suffix 对应的 WHOIS 服务器
                或者None (没有找到对应的记录)
        """
        return self.WHOIS_server_dict[tld] if self.WHOIS_server_dict.has_key(tld) else None

    def get_random_relay_WHOIS_server(self):
        """
        获取一个随机的转发 WHOIS 服务器
        """
        return choice(self.relay_WHOIS_server_list)


if __name__ == '__main__':
    # Demo
    w = WHOIS_server()
    print w.get_WHOIS_server("")
    print w.get_WHOIS_server("just_for_test")
    print w.get_WHOIS_server("africa")
    print w.get_WHOIS_server("xn--czru2d")
