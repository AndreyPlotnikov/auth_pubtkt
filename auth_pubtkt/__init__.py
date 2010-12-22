"""
This module contains routines and WSGI middleware for working with mod_auth_pubtkt authentication.

See https://neon1.net/mod_auth_pubtkt/ for more details
"""
import urllib
import hashlib
import base64
import Cookie
import logging
from M2Crypto import RSA, DSA


class TicketParseError(Exception):
    """Base class for all ticket parsing errors"""
    
    def __init__(self, ticket, msg=''):
        self.ticket = ticket
        self.msg = msg

    def __str__(self):
        return 'Ticket parse error: %s  (%s)' % (self.msg, self.ticket)


class BadTicket(TicketParseError):
    """Exception raised when a ticket has invalid format"""

    def __init__(self, ticket, msg=''):
        if not msg:
            msg = 'Invalid ticket format'
        super(self.__class__, self).__init__(ticket, msg)
    

class BadSignature(TicketParseError):
    """Exception raised when a signature verification is failed"""

    def __init__(self, ticket):
        super(self.__class__, self).__init__(ticket, 'Bad signature')


def verify_sig(pubkey, data, sig):
    """Verify ticket signature.

    Returns False if ticket is tampered with and True if ticket is good.

    Arguments:

    ``pubkey``:
        Public key object. It must be M2Crypto.RSA.RSA_pub or M2Crypto.DSA.DSA_pub instance

    ``data``:
        Ticket string without signature part.

    ``sig``:
        Ticket's sig field value.
        
    """
    sig = base64.b64decode(sig)
    dgst = hashlib.sha1(data).digest()
    if isinstance(pubkey, RSA.RSA_pub):
        try:
            pubkey.verify(dgst, sig, 'sha1')
        except RSA.RSAError:
            return False
        return True
    elif isinstance(pubkey, DSA.DSA_pub):
        return not not pubkey.verify_asn1(dgst, sig)
    else:
        raise ValueError('Unknown key type: %s' % pubkey)


def calculate_digest(privkey, data):
    """Calculates and returns ticket's signature.

    Arguments:

    ``privkey``:
       Private key object. It must be M2Crypto.RSA.RSA or M2Crypto.DSA.DSA instance.

    ``data``:
       Ticket string without signature part.

    """
    dgst = hashlib.sha1(data).digest()
    if isinstance(privkey, RSA.RSA):
        sig = privkey.sign(dgst, 'sha1')
        sig = base64.b64encode(sig)
    elif isinstance(privkey, DSA.DSA):
        sig = privkey.sign_asn1(dgst)
        sig = base64.b64encode(sig)
    else:
        raise ValueError('Unknonw key type: %s' % privkey)

    return sig


def parse_ticket(ticket, pubkey, verify_sig=verify_sig):
    """Parse and verify auth_pubtkt ticket.

    Returns dict with ticket's fields.

    ``BadTicket`` and ``BadSignature`` exceptions can be raised
    in case of invalid ticket format or signature verification failure.

    Arguments:

    ``ticket``:
        Ticket string value.

    ``pubkey``:
        Public key object. It must be M2Crypto.RSA.RSA_pub or M2Crypto.DSA.DSA_pub instance

    ``verify_sig``:
        Function which perform signature verification. By default verify_sig function from this module is used.
        This argument is needed for testing purposes only.

    """

    i = ticket.rfind(';')
    sig = ticket[i+1:]
    if sig[:4] != 'sig=':
        raise BadTicket(ticket)
    sig = sig[4:]
    data = ticket[:i]

    if not verify_sig(pubkey, data, sig):
        raise BadSignature(ticket)

    try:
        fields = dict(f.split('=', 1) for f in data.split(';'))
    except ValueError:
        raise BadTicket(ticket)

    if 'uid' not in fields:
        raise BadTicket(ticket, 'uid field required')

    if 'validuntil' not in fields:
        raise BadTicket(ticket, 'validuntil field required')

    try:
        fields['validuntil'] = int(fields['validuntil'])
    except ValueError:
        raise BadTicket(ticket, 'Bad value for validuntil field')

    if 'tokens' in fields:
        tokens = fields['tokens'].split(',')
        if tokens == ['']:
            tokens = []
        fields['tokens'] = tokens

    if 'graceperiod' in fields:
        try:
            fields['graceperiod'] = int(fields['graceperiod'])
        except ValueError:
            raise BadTicket(ticket, 'Bad value for graceperiod field')
    
    return fields


def create_ticket(privkey, uid, validuntil, ip=None, tokens=(),
                  udata='', graceperiod=None, extra_fields = ()):
    """Returns signed mod_auth_pubtkt ticket.

    Mandatory arguments:

    ``privkey``:
       Private key object. It must be M2Crypto.RSA.RSA or M2Crypto.DSA.DSA instance.

    ``uid``:
        The user ID. String value 32 chars max.

    ``validuntil``:
        A unix timestamp that describe when this ticket will expire. Integer value.

    Optional arguments:

    ``ip``:
       The IP address of the client that the ticket has been issued for.

    ``tokens``:
       List of authorization tokens.

    ``udata``:
       Misc user data.

    ``graceperiod``:
        A unix timestamp after which GET requests will be redirected to refresh URL.

    ``extra_fields``:
        List of (field_name, field_value) pairs which contains addtional, non-standard fields.
    """

    v = 'uid=%s;validuntil=%d' % (uid, validuntil)
    if ip:
        v += ';cip=%s' % ip
    if tokens:
        v += ';tokens=%s' % ','.join(tokens)
    if graceperiod:
        v += ';graceperiod=%d' % graceperiod
    if udata:
        v += ';udata=%s' % udata
    for k,fv in extra_fields:
        v += ';%s=%s' % (k,fv)
    v += ';sig=%s' % calculate_digest(privkey, v)
    return v

    
class ConfigError(Exception):
    pass


class AuthPubTKTMiddleware(object):
    """WSGI middleware that checks requests for
    mod_auth_pubtkt <https://neon1.net/mod_auth_pubtkt/> authentication ticket
    and then parse and verify it.

    If ticket is valid the following environment variables will be set:

    ``REMOTE_USER``:
        It contains ticket's uid field.

    ``REMOTE_USER_TOKENS``:
        Comma separated list of authorization tokens.

    ``REMOTE_USER_TOKENS_LIST``:
        The same as REMOTE_USER_TOKENS but parsed to list data type.

    ``REMOTE_USER_DATA``:
        Ticket's udata field.

    ``auth_pubtkt.ticket_fields``:
        Dict which contains all ticket fields.
        
    """
    
    def __init__(self, app, pubkey, cookie_name='auth_pubtkt',
                 logname=None, login_url=None, cache=None):
        """Initializes AuthPubTKTMiddleware object.

        ``pubkey``:
            Public key object. It must be M2Crypto.RSA.RSA_pub or M2Crypto.DSA.DSA_pub instance

        ``cookie_name``:
            Cookie which holds ticket ('auth_pubtkt' by default).

        ``logname``:
            Logger's name. If None then __name__ will be used.

        ``login_url``:
            URL that users without a valid ticket will be redirected to.
            It only happens when middleware catches 401 response status
            from downstream layers.

        ``cache``:
            Instance of beaker.cache.Cache object.
            It's used for caching succesfully parsed tickets.
            
        """
        self.app = app
        self.pubkey = pubkey
        self.cookie_name = cookie_name
        if logname is None:
            logname = __name__
        self.log = logging.getLogger(logname)
        self.login_url = login_url
        self.cache = cache


    @classmethod
    def make_from_config(cls, app, config, prefix='auth.', **kw):
        """Creates instance of AuthPubTKTMiddleware
        from dictionary-like configuration.        
        """
        keytype = config.get(prefix+'key_type', 'RSA')
        if keytype not in ('RSA', 'DSA'):
            raise ConfigError('Wrong key type: %s' % keytype)
        authpubkey = config.get(prefix+'pubkey', '')
        if not authpubkey:
            raise ConfigError('%spubkey parameter is required' % prefix)
        try:
            if keytype == 'RSA':
                pubkey = RSA.load_pub_key(authpubkey)
            else:
                pubkey = DSA.load_pub_key(authpubkey)
        except Exception, err:
            raise ConfigError('Error loading public key %s: %s' % (authpubkey, str(err)))

        def asbool(v, param):
            v = v.lower()
            if v in ('true', 'yes', 'on', '1'):
                v = True
            elif v in ('false', 'no', 'off', '0'):
                v = False
            else:
                ConfigError('Bad value for param %s: %s' % (params, v))
            return v

        for p, t in (('cookie_name', 'str'),
                     ('login_url', 'str')):
            k = prefix+p
            if (p not in kw) and (k in config):
                v = config[k]
                if t == 'bool':
                    v = asbool(v, k)
                kw[p] = v

        return cls(app, pubkey, keytype, **kw)


    def __call__(self, environ, start_response):
        cookies = Cookie.SimpleCookie(environ.get('HTTP_COOKIE', ''))
        if cookies.has_key(self.cookie_name):
            cookie_value = cookies[self.cookie_name].value
        else:
            cookie_value = ''
        if cookie_value:
            cookie_value = urllib.unquote(cookie_value)
            
            def get_parsed_ticket():
                self.log.debug('Parse ticket: %s' % cookie_value)
                return parse_ticket(cookie_value, self.pubkey)
            
            try:
                if self.cache is None:
                    fields = get_parsed_ticket()
                else:
                    fields = self.cache.get(cookie_value, createfunc=get_parsed_ticket)
            except TicketParseError, err:
                self.log.debug(str(err))
                return self.app(environ, start_response)

            if 'cip' in fields:
                if fields['cip'] != environ['REMOTE_ADDR']:
                    self.log.debug("Ticket's IP (%s) does not match the REMOTE_ADDR (%s)" % \
                                   (fields['cip'], environ['REMOTE_ADDR']))
                    return self.app(environ, start_response)
                    
            environ['REMOTE_USER'] = fields['uid']
            tokens = fields.get('tokens', [])
            environ['REMOTE_USER_TOKENS'] = ','.join(tokens)
            udata = fields.get('udata' ,'')
            environ['REMOTE_USER_DATA'] = udata
            environ['auth_pubtkt.ticket_fields'] = fields
            environ['REMOTE_USER_TOKENS_LIST'] = tokens
            environ['AUTH_TYPE'] = 'cookie'


        class unauth_start_response(object):
            def __call__(self, status, headers, exc_info=None):
                self.status = status
                self.headers = headers
                self.exc_info = exc_info

        if environ['REQUEST_METHOD'] == 'GET' and self.login_url:
            r = unauth_start_response()
            ret = self.app(environ, r)
            if r.status.startswith('401'):
                start_response('302 Found', [('Location', self.login_url)])
                return []
            start_response(r.status, r.headers, r.exc_info)
            return ret
        else:
            return self.app(environ, start_response)

    
