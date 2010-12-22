auth_pubtkt
===========

Ticket creation
---------------

Importing nessesary modules:

  >>> from M2Crypto import RSA
  >>> import auth_pubtkt
  >>> import auth_pubtkt.tests
  >>> import os.path
  >>> import time, datetime

Loading RSA private key from tests package:

  >>> privkey_path = os.path.join(os.path.dirname(auth_pubtkt.tests.__file__), 'rsa_priv.pem')
  >>> privkey = RSA.load_key(privkey_path)

Set expiration time to 2011/01/01 00:00

  >>> validuntil = int(time.mktime(datetime.datetime(2011, 1, 1).timetuple()))

Generating ticket for user 'john':

  >>> ticket = auth_pubtkt.create_ticket(privkey, 'john', validuntil, tokens=['su'])
  >>> ticket
  'uid=john;validuntil=1293814800;tokens=su;sig=YuM/RL8ub+XMb0ZTTlFYF6ehwRV8SnKx+TLj/syZmVx1ncR4QD58OMdRkmdmDCY9sdsoivcf+ACRCRX19nmEc5Ba+182FyRKC8bGL51GwPs+lMgaIaXxvhSvRbl/00sTWny+XEv1fEQDSc5tw3/ug6/YA9xt2wywUX1+hxfWQ5U='
  

Middleware
----------

  >>> import urllib
  >>> pubkey_path = os.path.join(os.path.dirname(auth_pubtkt.tests.__file__), 'rsa_pub.pem')
  >>> pubkey = RSA.load_pub_key(pubkey_path)
  >>> def test_app(environ, start_response):
  ...    for key in sorted(environ.keys()):
  ...        print '%s: %s' % (key, environ[key])
  >>> app = auth_pubtkt.AuthPubTKTMiddleware(test_app, pubkey)
  >>> env = {}
  >>> env['REMOTE_ADDR'] = '192.168.1.10'
  >>> env['REQUEST_METHOD'] = 'GET'
  >>> env['HTTP_COOKIE'] = 'auth_pubtkt="%s"' % urllib.quote(ticket)
  >>> app(env, lambda status, start: None)
  AUTH_TYPE: cookie
  HTTP_COOKIE: auth_pubtkt="uid%3Djohn%3Bvaliduntil%3D1293814800%3Btokens%3Dsu%3Bsig%3DYuM/RL8ub%2BXMb0ZTTlFYF6ehwRV8SnKx%2BTLj/syZmVx1ncR4QD58OMdRkmdmDCY9sdsoivcf%2BACRCRX19nmEc5Ba%2B182FyRKC8bGL51GwPs%2BlMgaIaXxvhSvRbl/00sTWny%2BXEv1fEQDSc5tw3/ug6/YA9xt2wywUX1%2BhxfWQ5U%3D"
  REMOTE_ADDR: 192.168.1.10
  REMOTE_USER: john
  REMOTE_USER_DATA: 
  REMOTE_USER_TOKENS: su
  REMOTE_USER_TOKENS_LIST: ['su']
  REQUEST_METHOD: GET
  auth_pubtkt.ticket_fields: {'tokens': ['su'], 'validuntil': 1293814800, 'uid': 'john'}




