import sys
import logging
import os.path
from os.path import join as pjoin
import unittest
from M2Crypto import RSA, DSA
from auth_pubtkt import *


tests_dir = os.path.dirname(os.path.abspath(__file__))

rsa_priv = RSA.load_key(pjoin(tests_dir, 'rsa_priv.pem'))
rsa_pub = RSA.load_pub_key(pjoin(tests_dir, 'rsa_pub.pem'))
dsa_priv = DSA.load_key(pjoin(tests_dir, 'dsa_priv.pem'))
dsa_pub = DSA.load_pub_key(pjoin(tests_dir, 'dsa_pub.pem'))

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


def verify_ok(pubkey, data, sig):
    return True

class ParseTicketTests(unittest.TestCase):


    def test_valid_rsa(self):

        ticket = '''uid=user1;cip=192.168.1.10;validuntil=1277190189;tokens=editor,moderator;udata=custom data;sig=W4/D/Ci2B9e60s7a1K810wPCQ3TzvlCXnAimjTVFRb6mqTFTlvdxCFmc6urC86d+8v8CtM4KsV5jsTmW/250OVkgk1PcoCz/Fvk84V5WqieWj2AVPC5DOujwy73lEeuu3/a4BfnsTagFWJZa6wGWqTEE5pULq8ZWthNXqkhXLzs='''

        fields = parse_ticket(ticket, rsa_pub)
        assert 'uid' in fields and fields['uid'] == 'user1'
        assert fields['cip'] == '192.168.1.10'
        assert fields['validuntil'] == 1277190189
        assert fields['tokens'] == ['editor', 'moderator']
        assert fields['udata'] == 'custom data'


    def test_valid_dsa(self):

        ticket = '''uid=user1;cip=192.168.1.10;validuntil=1277190189;tokens=editor,moderator;udata=custom data;sig=MCwCFAeCfK65QEWPWEfGkf/v8ZANOzqFAhRuuFs3miPbrcuLksDMiyeExgZOPQ=='''

        fields = parse_ticket(ticket, dsa_pub)


    def test_dirty_ticket(self):
        ticket = 'dfasdfasdfasdfsdf;sig=324dsfsdfsdrfrdsf'
        self.assertRaises(BadTicket, parse_ticket, ticket, rsa_pub, verify_sig=verify_ok)


    def test_uid_absent(self):
        ticket = '''cip=192.168.1.10;validuntil=1277190189;tokens=editor,moderator;udata=custom data;sig=MCwCFAeCfK65QEWPWEfGkf/v8ZANOzqFAhRuuFs3miPbrcuLksDMiyeExgZOPQ=='''
        self.assertRaises(BadTicket, parse_ticket, ticket, dsa_pub, verify_sig=verify_ok)


    def test_validuntil(self):
        ticket = '''uid=user1;cip=192.168.1.10;tokens=editor,moderator;udata=custom data;sig=MCwCFAeCfK65QEWPWEfGkf/v8ZANOzqFAhRuuFs3miPbrcuLksDMiyeExgZOPQ=='''
        self.assertRaises(BadTicket, parse_ticket, ticket, dsa_pub, verify_sig=verify_ok)
        ticket = '''uid=user1;cip=192.168.1.10;validuntil=asdasdasd;tokens=editor,moderator;udata=custom data;sig=MCwCFAeCfK65QEWPWEfGkf/v8ZANOzqFAhRuuFs3miPbrcuLksDMiyeExgZOPQ=='''
        self.assertRaises(BadTicket, parse_ticket, ticket, dsa_pub, verify_sig=verify_ok)


    def test_empty_tokens(self):
        ticket = '''uid=user1;cip=192.168.1.10;validuntil=1277190189;tokens=;udata=custom data;sig=MCwCFAeCfK65QEWPWEfGkf/v8ZANOzqFAhRuuFs3miPbrcuLksDMiyeExgZOPQ=='''
        fields = parse_ticket(ticket, dsa_pub, verify_sig=verify_ok)
        assert fields['tokens'] == []


    def test_extra_fields(self):
        ticket = '''uid=user1;cip=192.168.1.10;validuntil=1277190189;tokens=aaa;udata=custom data;name=username;email=user1@mail.ru;sig=MCwCFAeCfK65QEWPWEfGkf/v8ZANOzqFAhRuuFs3miPbrcuLksDMiyeExgZOPQ=='''
        fields = parse_ticket(ticket, dsa_pub, verify_sig=verify_ok)
        assert 'name' in fields and fields['name'] == 'username'
        assert 'email' in fields and fields['email'] == 'user1@mail.ru'
        

class CalculateDigestTests(unittest.TestCase):

    def test_rsa(self):
        data = 'uid=user1;cip=192.168.1.10;validuntil=1277190189;tokens=editor,moderator;udata=custom data'
        dgst = calculate_digest(rsa_priv, data)
        assert dgst == 'W4/D/Ci2B9e60s7a1K810wPCQ3TzvlCXnAimjTVFRb6mqTFTlvdxCFmc6urC86d+8v8CtM4KsV5jsTmW/250OVkgk1PcoCz/Fvk84V5WqieWj2AVPC5DOujwy73lEeuu3/a4BfnsTagFWJZa6wGWqTEE5pULq8ZWthNXqkhXLzs='


    def test_dsa(self):
        data = 'uid=user1;cip=192.168.1.10;validuntil=1277190189;tokens=editor,moderator;udata=custom data'
        dgst = calculate_digest(dsa_priv, data)
        parse_ticket(data+';sig='+dgst, dsa_pub)


class CreateTicketTests(unittest.TestCase):

    def test_rsa(self):
        v = create_ticket(rsa_priv,
                          uid='user1', validuntil=1277190189, ip='192.168.1.10',
                          tokens=('editor','moderator'), udata='custom data', graceperiod=3600,
                          extra_fields=(('email', 'test@test.com'),('display_name', 'John')))

        assert v == 'uid=user1;validuntil=1277190189;cip=192.168.1.10;tokens=editor,moderator;graceperiod=3600;udata=custom data;email=test@test.com;display_name=John;sig=YaMhb5yXkfqOtQ87P5gYeh4kSgQev1c6XjqT0pXT/ojXj/qpswpyqWenNv3y5rcUPT++80zZPBVNFfwPUI5Crps5nHZP55FNPtBE337KYZ6KYoMEVQD6xqnouf5i1Jm5KwB1IfQdr8fvRQs2oqBIMMTkVyfv6yRRNWVPz+7xwxw='


    def test_dsa(self):
        v = create_ticket(dsa_priv,
                          uid='user1', validuntil=1277190189, ip='192.168.1.10',
                          tokens=('editor','moderator'), udata='custom data', graceperiod=3600,
                          extra_fields=(('email', 'test@test.com'),('display_name', 'John')))
        assert v.startswith('uid=user1;validuntil=1277190189;cip=192.168.1.10;tokens=editor,moderator;graceperiod=3600;udata=custom data;email=test@test.com;display_name=John;sig=')


class DumbApp(object):

    def __call__(self, env, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return ['OK']


def dumb_start_response(status, headers):
    pass


class MiddlewareTests(unittest.TestCase):


    def test_auth_req(self):        
        app = DumbApp()
        app = AuthPubTKTMiddleware(app, rsa_pub)
        env = {}
        env['REMOTE_ADDR'] = '192.168.1.10'
        env['REQUEST_METHOD'] = 'GET'
        env['HTTP_COOKIE'] = 'auth_pubtkt="uid=user1;validuntil=1277190189;cip=192.168.1.10;tokens=editor,moderator;graceperiod=3600;udata=custom data;email=test@test.com;display_name=John;sig=YaMhb5yXkfqOtQ87P5gYeh4kSgQev1c6XjqT0pXT/ojXj/qpswpyqWenNv3y5rcUPT++80zZPBVNFfwPUI5Crps5nHZP55FNPtBE337KYZ6KYoMEVQD6xqnouf5i1Jm5KwB1IfQdr8fvRQs2oqBIMMTkVyfv6yRRNWVPz+7xwxw="'

        
        app(env, dumb_start_response)

        assert env['REMOTE_USER'] == 'user1'
        assert env['REMOTE_USER_TOKENS'] == 'editor,moderator'
        assert env['REMOTE_USER_DATA'] == 'custom data'
        assert env['REMOTE_USER_TOKENS_LIST'] == ['editor', 'moderator']


    def test_bad_sig(self):
        app = DumbApp()
        app = AuthPubTKTMiddleware(app, rsa_pub)
        env = {}
        env['REQUEST_METHOD'] = 'GET'
        env['REMOTE_ADDR'] = '192.168.1.10'
        env['HTTP_COOKIE'] = 'auth_pubtkt="uid=user1;validuntil=1277190189;cip=192.168.1.10;tokens=editor,moderator;graceperiod=3600;udata=custom data;email=test@test.com;display_name=John;sig=YaMhb5yXkfqOtQ87P5gYeh4kSgQev1c6XjqT0pXT/ojXj/qpswpyqWenNv3y5rcUPT++80zZPBVNFfwPUI5Crps5nHZP55FNPtBE337KYZ6KYoMEVQD6xqnouf5i1Jm5KwB1IfQdr8fvRQs2oqBIMMTkVyfv6yRj36VPz+7xwxw="'

        assert 'REMOTE_USER' not in env


    def test_ip_mismatch(self):
        app = DumbApp()
        app = AuthPubTKTMiddleware(app, rsa_pub)
        env = {}
        env['REMOTE_ADDR'] = '127.0.0.1'
        env['HTTP_COOKIE'] = 'auth_pubtkt="uid=user1;validuntil=1277190189;cip=192.168.1.10;tokens=editor,moderator;graceperiod=3600;udata=custom data;email=test@test.com;display_name=John;sig=YaMhb5yXkfqOtQ87P5gYeh4kSgQev1c6XjqT0pXT/ojXj/qpswpyqWenNv3y5rcUPT++80zZPBVNFfwPUI5Crps5nHZP55FNPtBE337KYZ6KYoMEVQD6xqnouf5i1Jm5KwB1IfQdr8fvRQs2oqBIMMTkVyfv6yRRNWVPz+7xwxw="'

        
        app(env, dumb_start_response)
        assert 'REMOTE_USER' not in env


    def test_cache(self):
        import time
        from beaker.cache import CacheManager
        cm = CacheManager()
        cache = cm.get_cache('auth_pubtkt_middleware', type='memory', expire=3600)
        app = DumbApp()
        app = AuthPubTKTMiddleware(app, rsa_pub, cache=cache)
        env = {}
        env['REMOTE_ADDR'] = '192.168.1.10'
        env['REQUEST_METHOD'] = 'GET'
        env['HTTP_COOKIE'] = 'auth_pubtkt="uid=user1;validuntil=1277190189;cip=192.168.1.10;tokens=editor,moderator;graceperiod=3600;udata=custom data;email=test@test.com;display_name=John;sig=YaMhb5yXkfqOtQ87P5gYeh4kSgQev1c6XjqT0pXT/ojXj/qpswpyqWenNv3y5rcUPT++80zZPBVNFfwPUI5Crps5nHZP55FNPtBE337KYZ6KYoMEVQD6xqnouf5i1Jm5KwB1IfQdr8fvRQs2oqBIMMTkVyfv6yRRNWVPz+7xwxw="'

        
        app(env, dumb_start_response)
        app(env, dumb_start_response)
        


if __name__ == '__main__':
    unittest.main()
