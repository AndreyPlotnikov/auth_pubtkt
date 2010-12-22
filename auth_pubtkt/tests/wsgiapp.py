import os.path
from os.path import join as pjoin
from M2Crypto import RSA
from auth_pubtkt import AuthPubTKTMiddleware

tests_dir = os.path.dirname(os.path.abspath(__file__))
rsa_pub = RSA.load_pub_key(pjoin(tests_dir, 'rsa_pub.pem'))

def app(env, start_response):
    ##start_response('200 OK', [('Content-Type', 'text/plain')])
    start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
    return ['Authentication required']

if __name__ == '__main__':
    from paste import httpserver
    app = AuthPubTKTMiddleware(app, rsa_pub, 'RSA', login_url='https://passport.webra.ru')
    httpserver.serve(app, host='127.0.0.1', port='8070')

    
