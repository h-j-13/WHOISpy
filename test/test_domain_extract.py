#!/usr/bin/env python
# encoding:utf-8

import unittest

from WHOISpy import domain_extract


class TestDomain(unittest.TestCase):

    def setUp(self):
        with open('test_data/extract_domain.dat') as f:
            self.test_domain_list = [l.strip() for l in f.readlines() if not l.startswith('//')]

    def test_extract_domain(self):
        for domain in self.test_domain_list:
            domain_extract.Domain(domain)

    def test_utf8_domain(self):
        self.assertEquals(domain_extract.Domain('youtube.com').domain, 'youtube.com')
        self.assertEquals(domain_extract.Domain(u'www.google.com').domain, 'google.com')
        self.assertEquals(domain_extract.Domain(u'www.公司.hk').domain, 'www.公司.hk')

    def test_punycode_domain(self):
        self.assertEquals(domain_extract.Domain('https://github.com/h-j-13').domain_punycode, 'github.com')
        self.assertEquals(domain_extract.Domain('https://github.com/h-j-13').domain_punycode,
                          domain_extract.Domain('https://github.com/h-j-13').domain)
        self.assertEquals(domain_extract.Domain(u'google.クラウド').domain_punycode, 'google.xn--gckr3f0f')
        self.assertEquals(domain_extract.Domain('google.みんな').domain_punycode, 'google.xn--q9jyb4c')
        self.assertEquals(domain_extract.Domain(u'google.இந்தியா').domain_punycode, 'google.xn--xkc2dl3a5ee0h')
        self.assertEquals(domain_extract.Domain('google.닷넷').domain_punycode, 'google.xn--t60b56a')
        self.assertEquals(domain_extract.Domain(u'google.中国').domain_punycode, 'google.xn--fiqs8s')
        self.assertEquals(domain_extract.Domain('google.السعودية').domain_punycode, 'google.xn--mgberp4a5d4ar')
        self.assertEquals(domain_extract.Domain(u'google.онлайн').domain_punycode, 'google.xn--80asehdb')

    def test_url(self):
        self.assertEquals(domain_extract.Domain('https://github.com/h-j-13').domain_punycode, 'github.com')

    def test_tld(self):
        self.assertEquals(domain_extract.Domain('google.中国').tld_punycode, 'xn--fiqs8s')

    def test_suffix(self):
        self.assertEquals(domain_extract.Domain('baidu.com.cn').suffix, 'com.cn')


if __name__ == '__main__':
    unittest.main()
