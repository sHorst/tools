#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unittest import TestCase, main

import spfToIPs
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network


class _MockData:
    @staticmethod
    def get_cache():
        return {
            ('ultrachaos.de', 'A'): ['78.46.123.52'],
            ('ultrachaos.de', 'AAAA'): [b'*\x01\x04\xf8\x010\x81\xa2\x00B\x00\x00\x00\x00\x01\x05'],
            ('ultrachaos.de', 'TXT'): [
                [b'v=spf1 mx a:www.ultrachaos.de ~all'],
                [b'keybase-site-verification=faEfxs-pmZ0g8omzcRBnhUZmqvsKQ2Bd9IQhXZT_Y24'],
                [b'google-site-verification=7FsoQWOJgBaURDI409XAi5wdMtMNcI7RdRg5Jj7boNE']
            ],
            ('ultrachaos.de', 'MX'): [(10, 'mail.ultrachaos.de')],
            ('mail.ultrachaos.de', 'A'): ['78.46.123.54'],
            ('mail.ultrachaos.de', 'AAAA'): [b'*\x01\x04\xf8\x010\x81\xa2\x00B\x00\x00\x00\x00\x01\x07'],
            ('www.ultrachaos.de', 'A'): ['78.46.123.52'],
            ('www.ultrachaos.de', 'AAAA'): [b'*\x01\x04\xf8\x010\x81\xa2\x00B\x00\x00\x00\x00\x01\x05'],
        }


class TestSpfToIPs(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.query = spfToIPs.QueryNew()
        # Mock the cache
        cls.query.cache = _MockData.get_cache()

    def test_get_a_record(self):
        ips = []
        ips += map(lambda x: ip_address(x), self.query.dns_a('ultrachaos.de', 'A'))

        self.assertEqual(len(ips) == 1, True, "does have more than one element")
        self.assertListEqual(ips, [ip_address('78.46.123.52')], "returned IP is wrong")

    def test_get_aaaa_record(self):
        ips = []
        ips += map(lambda x: ip_address(x), self.query.dns_a('ultrachaos.de', 'AAAA'))

        self.assertEqual(len(ips) == 1, True, "does have more than one element")
        self.assertListEqual(ips, [ip_address('2a01:4f8:130:81a2:42::105')], "returned IP is wrong")

    def test_get_spf_record(self):
        spf = self.query.dns_spf('ultrachaos.de')

        self.assertEqual(spf, "v=spf1 mx a:www.ultrachaos.de ~all")

    def test_get_mx_a_record(self):
        self.query.A = 'A'
        ips = []
        ips += map(lambda x: ip_address(x), self.query.dns_mx('ultrachaos.de'))

        self.assertEqual(len(ips) == 1, True, "does have more than one element")
        self.assertListEqual(ips, [ip_address('78.46.123.54')], "returned IP is wrong")

    def test_get_mx_aaaa_record(self):
        self.query.A = 'AAAA'
        ips = []
        ips += map(lambda x: ip_address(x), self.query.dns_mx('ultrachaos.de'))

        self.assertEqual(len(ips) == 1, True, "does have more than one element")
        self.assertListEqual(ips, [ip_address('2a01:4f8:130:81a2:42::107')], "returned IP is wrong")

    def test_get_ip_from_spf(self):
        ips = self.query.get_ips(self.query.dns_spf('ultrachaos.de'), True)

        self.assertEqual(len(ips) == 4, True, "does have more than one element")
        self.assertListEqual(ips, [IPv4Address('78.46.123.54'), IPv6Address('2a01:4f8:130:81a2:42::107'),
                                   IPv4Address('78.46.123.52'), IPv6Address('2a01:4f8:130:81a2:42::105')],
                             "returned IP is wrong")

if __name__ == '__main__':
    main()
