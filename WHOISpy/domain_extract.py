#!/usr/bin/env python
# encoding:utf-8

"""
解析url(Uniform Resource Locator)与FQDN(Fully Qualified Domain Name)转化为标准格式的域名

思路
===============================================================================
有关于域名的提取与解析约3有种思路
1.正则
通过正则表达式解析输入的FQDN而转化为域名,因为域名的格式较多所以此法需要大量的精力来维护正则规则

2.第三方库 例如 tldextract (https://pypi.python.org/pypi/tldextract)
可以通过

tldextract.extract('http://forums.news.cnn.com/')
ExtractResult(subdomain='forums.news', domain='cnn', suffix='com')

较为轻松的解析FQDN,但是在使用中发现,tldextract在运行之前需要初始化,若只是解析单个域名则较为浪费时间
此外还会在其调用的目录下生成cache文件,最后其对于部分punycode格式的域名和部分其他编码的域名支持不是很好,
有部分域名无法解析出正确结果.是最简单且最易用的方法

3.基于 public_suffix_list 进行最长匹配
https://publicsuffix.org/list/public_suffix_list.dat 此站点目前收录了所有已知的公开域名后缀.
且在github上一直较为积极的维护.
可以将输入的FQDN与public_suffix_list文件内公开的域名后缀进行比对,
通过提取最长匹配的字段来确定域名的suffix与domain.
此法较为简单,且维护起来也比较方便

相关资料
===============================================================================
1.域名&域名格式
https://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D
https://tools.ietf.org/html/rfc1035

2.国际化域名(IDNA)
https://zh.wikipedia.org/wiki/%E5%9B%BD%E9%99%85%E5%8C%96%E5%9F%9F%E5%90%8D
https://tools.ietf.org/html/rfc3490
"""

import os
import re

suffixes = None


class Domain(object):
    """域名的处理与解析"""

    domain = ''  # 默认解析为utf8编码域名
    domain_punycode = ''
    suffix = ''
    suffix_punycode = ''
    tld = ''
    tld_punycode = ''

    def __init__(self, url):
        """
        构造函数
        :param url:需要解析的url
        """
        # 载入 public_suffix_list.dat 数据
        global suffixes
        if not suffixes:
            suffix_file_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'public_suffix_list.dat')
            with open(suffix_file_path) as sf:
                suffixes = set(line for line in sf.read().splitlines() if line and not line.startswith('//'))
        # 预处理url
        # 如输入了unicode则转码为utf8
        if not isinstance(url, str):
            url = url.encode('utf-8')
        # 去除协议相关字符 http、https、ftp、sftp...
        url = re.sub('^.*://', '', url)
        # 去除 / 后面的无用数据
        url = url.split('/')[0].lower()
        self.extract_domain(url)

    def __punycode2utf8(self, punycode_str):
        """将punycode编码字符串转化为utf8字符串"""
        return str(punycode_str).decode('idna').encode('utf8')

    def __utf82punycode(self, utf8_str):
        """将utf8编码字符串转化为punycode字符串"""
        return str(utf8_str).decode('utf8').encode('idna')

    def extract_domain(self, url):
        """
        解析域名,将解析数据存入相应的静态变量中
        :param url:经过预处理的url
        """
        # punycode格式统一转为utf8
        if url.find('xn--') != -1:
            url = self.__punycode2utf8(url)
        # 最长匹配后缀为 suffix,并再取后一级一并作为域名
        d = ''
        for section in reversed(url.split('.')):
            if d:
                d = b'.' + d
            d = section + d
            if d not in suffixes:
                break
        # 解析域名
        Domain.domain = d
        Domain.suffix = Domain.domain.split('.', 1)[1]
        Domain.tld = Domain.suffix.split('.')[-1]
        Domain.domain_punycode = self.__utf82punycode(Domain.domain)
        Domain.suffix_punycode = self.__utf82punycode(Domain.suffix)
        Domain.tld_punycode = self.__utf82punycode(Domain.tld)


if __name__ == '__main__':
    print Domain('http://baidu.com.cn/p/123123').domain
    print Domain(u'中国.中国').domain
    print Domain(u'xn--fiqs8s.com').domain
    print Domain('xn--fiqs8s.com').domain
    print Domain('\xe4\xb8\xad\xe5\x9b\xbd.com').domain
    print Domain(u'www.公司.hk').domain
    print Domain('102.112.2O7.net').domain
    print Domain('1-0-1-1-1-0-1-1-1-1-1-1-1-.0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info').domain

