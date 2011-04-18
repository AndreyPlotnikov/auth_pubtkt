"""WSGI application which acts as backend for nginx module
http_auth_request (http://mdounin.ru/hg/ngx_http_auth_request_module)
"""
import time
import urllib
import logging
from datetime import datetime
from webob import Request, Response
from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options
from M2Crypto import RSA, DSA
from auth_pubtkt import parse_ticket, TicketParseError


class AuthRequestApp(object):

    def __init__(self, pub_key, cookie_name='auth_pubtkt', cache=None,
                 hdr_prefix='X-AuthPubTKT-', log_name=None):
        self.pub_key = pub_key
        self.cookie_name = cookie_name
        self.cache = cache
        self.hdr_prefix = hdr_prefix
        if not log_name:
            log_name = __name__
        self.log = logging.getLogger(log_name)


    def __call__(self, environ, start_response):
        req = Request(environ)
        resp = Response()
        def unauth():        
            resp.status_int = 401
            return resp(environ, start_response)
            
        ticket = req.cookies.get(self.cookie_name)
        if not ticket:
            self.log.debug("Deny: there is no ticket in cookie '%s'" % self.cookie_name)
            return unauth()
        
        ticket = urllib.unquote(ticket)
        
        def get_parsed_ticket():
            self.log.debug('Parse ticket: %s' % ticket)
            return parse_ticket(ticket, self.pub_key)

        try:
            fields = self.cache.get(ticket, createfunc=get_parsed_ticket) if self.cache else get_parsed_ticket()
        except TicketParseError, err:
            self.log.info('Ticket parse error:\n' + str(err))
            return unauth()
        
        remote_addr = environ.get('REMOTE_ADDR', '')
        tokens = fields['tokens']
        tokens_str = ','.join(tokens)
        userinfo = '%s - %s - %s - %s' % (fields['uid'], remote_addr,
                                          datetime.fromtimestamp(fields['validuntil']).strftime('%b/%d %H:%M:%S'),
                                          tokens_str)
        
        if fields['validuntil'] <= time.time():
            self.log.info("Deny: expired ticket - %s" % userinfo)
            return unauth()

        if 'cip' in fields and remote_addr:
            if fields['cip'] != remote_addr:
                self.log.info("Deny: ticket's IP (%s) does not match the REMOTE_ADDR (%s) - %s" % \
                               (fields['cip'], remote_addr, userinfo))
                return unauth()

        tokens_all = req.headers.get(self._hdr_name('Tokens-All'))
        if tokens_all:
            for t in tokens_all.split(','):
                if t not in fields['tokens']:
                    self.log.info("Deny: required token '%s' is not found - %s" % (t, userinfo))
                    return unauth()
                
        tokens_any = req.headers.get(self._hdr_name('Tokens-Any'))
        if tokens_any:
            for t in tokens_any.split(','):
                if t in tokens:
                    break
            else:
                self.log.info("Deny: ticket must have one of these tokens: %s - %s" % (tokens_str, userinfo))
                return unauth()

        self.log.info("Allow: %s" % userinfo)
        resp.headers[self._hdr_name('User')] = fields['uid']
        return resp(environ, start_response)
        

    def _hdr_name(self, name):
        return self.hdr_prefix + name



def make_app(global_conf,
             pub_key,
             key_type='RSA',
             cookie_name=None,
             hdr_prefix=None,
             log_name=None,
             **app_conf):
    """Paste application factory"""
    
    pub_key = RSA.load_pub_key(pub_key) if key_type == 'RSA' else DSA.load_pub_key(pub_key)
    params = {}
    if cookie_name is not None:
        params['cookie_name'] = cookie_name
    if hdr_prefix is not None:
        params['hdr_prefix'] = hdr_prefix
    if log_name is not None:
        params['log_name'] = log_name
    cache_opts = parse_cache_config_options(app_conf)
    if cache_opts.get('enabled') == True:
        cache_mgr = CacheManager(**cache_opts)
        cache = cache_mgr.get_cache('tickets_cache')
        params['cache'] = cache

    return AuthRequestApp(pub_key, **params)
             




    

if __name__ == '__main__':
    print TokensExpr('&su,mgr,|11,22', ['su', 'mgr', '11']).eval()
    
##     import sys
##     from paste import httpserver
##     from paste.exceptions.errormiddleware import ErrorMiddleware
##     from repoze.debug.responselogger import ResponseLoggingMiddleware
##     logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
##     pub_key = RSA.load_pub_key(sys.argv[1])
##     app  = AuthRequestApp(pub_key)
##     app = ResponseLoggingMiddleware(app, max_bodylen=0,
##                                     keep=100, verbose_logger=logging.getLogger('verbose'),
##                                     trace_logger=logging.getLogger('trace'))
##     app = ErrorMiddleware(app, error_log='error.log')
##     httpserver.serve(app, '127.0.0.1', 5030)
    
