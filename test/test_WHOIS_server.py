#!/usr/bin/env python
# encoding:utf-8

import unittest

from WHOISpy import domain_extract
from WHOISpy import WHOIS_server


class TestDomain(unittest.TestCase):

    def setUp(self):
        with open('test_data/extract_domain.dat') as f:
            self.test_domain_list = [l.strip() for l in f.readlines() if not l.startswith('//')]
        with open('test_data/WHOIS_server_list.dat') as f:
            self.test_WHOIS_data_list = [l.strip() for l in f.readlines() if not l.startswith('//')]

    def test_get_relay_WHOIS_server(self):
        self.assertIsInstance(WHOIS_server.WHOIS_server().get_random_relay_WHOIS_server(), str)

    def test_WHOIS_server(self):
        for i in self.test_WHOIS_data_list:
            if i.find(':') != -1:
                t, s = i.split(':')
                t = t.strip()
                s = s.strip()
                self.assertEqual(WHOIS_server.WHOIS_server().get_WHOIS_server(t), s)
            elif i.strip():
                t = i.strip()
                if not WHOIS_server.WHOIS_server().get_WHOIS_server(t):
                    self.assertEqual(WHOIS_server.WHOIS_server().get_WHOIS_server(t), 'whois.nic.' + t)

    def test_get_WHOIS_server(self):
        tld_count = 0
        fail_count = 0
        for domain in self.test_domain_list:
            t = domain_extract.Domain(domain).tld_punycode
            s = domain_extract.Domain(domain).suffix_punycode
            if not WHOIS_server.WHOIS_server().get_WHOIS_server(s):
                if not WHOIS_server.WHOIS_server().get_WHOIS_server(t):
                    print t + "\t don't have record about WHOIS server"
                    fail_count += 1
            tld_count += 1
        if fail_count:
            print "==================================================================="
            print "(" + str(tld_count - fail_count) + " / " + str(tld_count) + ") TLD pass,",
            print " total " + str(fail_count) + " tld or suffix can't get their WHOIS server"
            print "maybe update the WHOISpy/data/WHOIS_server_list.dat can fix a few"
