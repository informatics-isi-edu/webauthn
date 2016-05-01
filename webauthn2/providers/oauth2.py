# 
# Copyright 2010-2012 University of Southern California
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
Webauthn2 provider implementations using OAuth2 OpenID Connect. This class inherits from DatabaseConnection2

Provider-specific parameters inherited from DatabaseConnection2 module:

`database_type`
   : The database type (e.g., postgres).

`database_dsn`
   : The database source name (e.g., "host=localhost user=ermrest password=... dbname=ermrest").

`database_schema`
   : The schema name qualifier for provider tables within the database (text or None).

`database_max_retries`
   : The number of times to retry transient errors when running independent transactions (int).

Provider-specific parameters specific to OAuth2:

`oauth2_discovery_uri`
   : OpenID Connect Discovery 1.0 endpoint

`oauth2_redirect_relative_uri`
   : The path that users are redirected to after providing consent/authorization

`oauth2_client_secret_file`
   : The file, obtained from an OAuth2 provider (e.g., google) during registration, containing shared secrets and other information.

"""

from providers import *
from webauthn2.util import *
from webauthn2.providers import database

import web

import random
import urllib
import urllib2
import uuid
import urlparse
import web
import simplejson
import psycopg2
import oauth2client.client
import jwkest
from jwkest import jwk
from jwkest import jws
from oauth2client.crypt import AppIdentityError, _urlsafe_b64decode, CLOCK_SKEW_SECS, AUTH_TOKEN_LIFETIME_SECS, MAX_TOKEN_LIFETIME_SECS, PyCryptoVerifier
import time
import base64
from Crypto import Random
from Crypto.Hash.HMAC import HMAC
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import json
from datetime import datetime, timedelta
import pytz
import webauthn2.providers
import collections

config_built_ins = web.storage(
    # Items needed for methods inherited from database provider
    database_type= 'postgres',
    database_dsn= 'dbname=',
    database_schema= 'webauthn2',
    database_max_retries= 5,
    # OAuth-specific items
    oauth2_nonce_hard_timeout=3600,
    oauth2_nonce_cookie_name='oauth2_auth_nonce',
    # File with parameters, including the shared secret, shared between the client and the OAuth provider
    oauth2_client_secret_file=None,
    oauth2_discovery_uri=None,
    oauth2_redirect_relative_uri="/authn/session",
    oauth2_request_offline_access=False,
    oauth2_scope="openid email profile",
    oauth2_provider_sets_token_nonce=False
    )

class nonce_util(database.DatabaseConnection2):
    algorithm=Crypto.Hash.SHA256
    hash_key_table='oauth2_nonce'
    referrer_table='oauth2_nonce_referrer'
    default_referrer_timeout=3600

    def __init__(self, config):
        database.DatabaseConnection2.__init__(self, config)
        referrer_timeout = config.get('oauth2_referrer_timeout')
        if referrer_timeout == None or referrer_timeout < config.oauth2_nonce_hard_timeout:
            referrer_timeout = config.oauth2_nonce_hard_timeout

        self.config_params = {'hard_timeout' : config.oauth2_nonce_hard_timeout,
                              'soft_timeout' : config.oauth2_nonce_hard_timeout / 2,
                              'hash_key_table' : config.database_schema + '.' + self.hash_key_table,
                              'referrer_table' : config.database_schema + '.' + self.referrer_table,
                              'referrer_timeout' : referrer_timeout}
        self.keys=[]

    def get_keys(self, db):
        self.update_timeout(db)
        def db_body(db):
            return db.select(self.config_params['hash_key_table'], what="timeout, key", order="timeout desc")
        
        if db:
            textkeys = db_body(db)
        else:
            textkeys = self._db_wrapper(db_body)

        self.keys=[]
        for k in textkeys:
            self.keys.append((k.get('timeout'), self.texttokey(k.get('key'))))
        return self.keys

    def update_timeout(self, db, force=False):
        if not force:
            for k in self.keys:
                if datetime.now(pytz.timezone('UTC')) + timedelta(0, self.config_params['soft_timeout']) < k[0]:
                    return
        def db_body(db):
            db.query("delete from {referrer_table} where timeout < now()".format(referrer_table=self.config_params.get('referrer_table')))
            db.query("delete from %(hash_key_table)s where timeout < now()" % self.config_params)
            db.query("""
insert into %(hash_key_table)s (key, timeout)
  select $new_key, now() + interval '%(hard_timeout)d seconds'
  where not exists
    (select 1 from %(hash_key_table)s where timeout - now() > interval '%(soft_timeout)d seconds')
""" % self.config_params,
                     vars={'new_key' : self.keytotext(self.make_key())})

        if db:
            db_body(db)
        else:
            self._db_wrapper(db_body)

    def get_current_key(self, db):
        return self.get_keys(db)[0][1]

    def log_referrer(self, nonce, referrer, db):
        def db_body(db):
            db.query("insert into {referrer_table}(nonce, referrer, timeout) select {nonce}, {referrer}, now() + interval '{referrer_timeout} seconds'"\
                     .format(referrer_table=self.config_params.get('referrer_table'),
                             nonce=sql_literal(nonce),
                             referrer=sql_literal(referrer),
                             referrer_timeout=self.config_params.get('referrer_timeout')))
        if db:
            db_body(db)
        else:
            self._db_wrapper(db_body)

    def get_referrer(self, nonce):
        def db_body(db):
            return db.query("select referrer from {referrer_table} where nonce={nonce}".format(referrer_table=self.config_params.get('referrer_table'), nonce=sql_literal(nonce)))
        
        rows=self._db_wrapper(db_body)
        if len(rows) != 1:
            raise ValueError("Found referrer {x} rows for nonce {nonce}; expected 1".format(x=str(len(rows)), nonce=nonce))
        referrer = rows[0].get('referrer')
        if referrer == None:
            web.debug("null referrer for nonce {nonce}".format(nonce=nonce))
        return referrer

    @staticmethod
    def get_cookie_ts(cookie):
        return int(cookie.split('.')[0])

    @staticmethod
    def keytotext(key):
        return base64.b64encode(key)

    @staticmethod
    def texttokey(text):
        return base64.b64decode(text)

    def make_key(self):
        return Random.get_random_bytes(self.algorithm.digest_size)

    def time_ok(self, value):
        return time.time() - value < self.config_params['hard_timeout']

    def encode(self, msg, db):
        h = HMAC(self.get_current_key(db), msg, self.algorithm)
        return h.hexdigest()

    def hash_matches(self, msg, hashed, db):
        retval = self._check_hash_match(msg, hashed, db)
        if retval == False:
            self.update_timeout(db, True)
            retval = self._check_hash_match(msg, hashed, db)
        return retval

    def _check_hash_match(self, msg, hashed, db):
        for k in self.get_keys(db):
            h = HMAC(k[1], msg, self.algorithm)
            if h.hexdigest() == hashed:
                return True
        return False

__all__ = [
    'OAuth2SessionStateProvider',
    'OAuth2ClientProvider',
    'config_built_ins'
    ]

class OAuth2 (database.DatabaseConnection2):

    # this is the storage format version, not the software version
    major = 1
    minor = 0

    def __init__(self, config):
        database.DatabaseConnection2.__init__(self, config)

class OAuth2Login (ClientLogin):

    def __init__(self, provider):
        ClientLogin.__init__(self, provider)

    def login(self, manager, context, db, **kwargs):
        """
        Return "username" in the form iss:sub.

        It is expected that the caller will store the resulting username into context.client for reuse.
        
        """
        repeatable = True
        vals = web.input()
        # Wallet isn't exposed yet, but we will probably want it at some point in the future
        context.wallet = dict()
        # Check that this request came from the same user who initiated the oauth flow
        nonce_vals = {
            'auth_url_nonce' : vals.get('state'),
            'auth_cookie_nonce' : web.cookies().get(self.provider.nonce_cookie_name)
            }


        if nonce_vals['auth_url_nonce'] == None:
            raise OAuth2ProtocolError("No authn_nonce in initial redirect")

        if (nonce_vals['auth_cookie_nonce'] == None):
            raise OAuth2ProtocolError("No authn nonce cookie")

        # Has the cookie nonce expired?
        try:
            ts = nonce_util.get_cookie_ts(nonce_vals['auth_cookie_nonce'])
        except:
            raise OAuth2ProtocolError('bad nonce cookie')

        if not self.provider.nonce_state.time_ok(ts):
            raise OAuth2LoginTimeoutError('Login timed out')

        if not self.provider.nonce_state.hash_matches(nonce_vals['auth_cookie_nonce'], nonce_vals['auth_url_nonce'], db):
            raise OAuth2ProtocolError('nonce mismatch')

        # we'll write this to the db if all goes well
        redirect_full_payload=simplejson.dumps(vals, separators=(',', ':'))

        # Get id token
        token_args = {
            'code' : vals.get('code'),
            'client_id' : self.provider.cfg.get('client_id'),
            'client_secret' : self.provider.cfg.get('client_secret'),
            'redirect_uri' : web.ctx.home + web.ctx.path,
            'nonce' : nonce_vals['auth_url_nonce'],
            'grant_type' : 'authorization_code'}
        base_timestamp = datetime.now(pytz.timezone('UTC'))
        token_request = urllib2.Request(self.provider.cfg.get('token_endpoint'), urllib.urlencode(token_args))
        self.add_extra_token_request_headers(token_request)
        u = self.open_url(token_request, "getting token", repeatable)
        repeatable = False
        # Access token has been used, so from this point on, all exceptions should be ones
        # that will not cause db_wrapper to retry (because those retries will fail and generate
        # confusing exceptions / log messages).
        self.payload=simplejson.load(u)
        u.close()
        token_payload=simplejson.dumps(self.payload, separators=(',', ':'))
        raw_id_token=self.payload.get('id_token')

        # Validate id token
        u=self.open_url(self.provider.cfg.get('jwks_uri'), "getting jwks info", repeatable)
        raw_keys = jwk.KEYS()
        raw_keys.load_jwks(u.read())
        u.close()
        keys=[]
        for k in raw_keys:
            keys.append(k.key.exportKey())

        id_result=self.verify_signed_jwt_with_keys(raw_id_token, keys, self.provider.cfg.get('client_id'))
        self.id_token=id_result.get('body')
        id_header=id_result.get('header')
        if self.id_token.get('iss') == None or self.id_token.get('iss').strip() == '':
            raise OAuth2IDTokenError('No issuer in ID token')
        if self.id_token.get('sub') == None or self.id_token.get('sub').strip() == '':
            raise OAuth2IDTokenError('No subject in ID token')
        if self.provider.provider_sets_token_nonce and self.id_token.get('nonce') != nonce_vals['auth_url_nonce']:
            raise OAuth2IDTokenError('Bad nonce in ID token')

        # Validate access token
        self.validate_access_token(id_header.get('alg'), self.id_token.get('at_hash'), self.payload.get('access_token'))

        # Get user directory data. Right now we're assuming the server will return json.
        # TODO: in theory the return value could be signed jwt
        userinfo_endpoint = self.provider.cfg.get('userinfo_endpoint')
        req = self.make_userinfo_request(self.provider.cfg.get('userinfo_endpoint'), self.payload.get('access_token'))
        f = self.open_url(req, "getting userinfo", repeatable)
        self.userinfo=simplejson.load(f)
        f.close()
        username = str(self.id_token.get('iss') + '/' + self.id_token.get('sub'))
        context.user = dict()
        self.fill_context_from_userinfo(context, username, self.userinfo)

        # Update user table
        self.create_or_update_user(manager, context, username, self.id_token, self.userinfo, base_timestamp, self.payload, db)
        context.client = KeyedDict()
        for key in ClientLogin.standard_names:
            if context.user.get(key) != None:
                context.client[key] = context.user.get(key)
        return context.client

    @staticmethod
    def add_to_wallet(context, scope, issuer, token):
        # Wallet isn't exposed yet, but we will might as well take this first step
        if context.wallet.get(issuer) == None:
            context.wallet[issuer] = dict()
        context.wallet[issuer][scope] = token


    def add_extra_token_request_headers(self, token_request):
        pass

    def make_userinfo_request(self, userinfo_endpoint, access_token):
        return urllib2.Request(userinfo_endpoint, headers={'Authorization' : 'Bearer ' + access_token})

    def fill_context_from_userinfo(self, context, username, userinfo):
        context.user[ID] = username
        # try both openid connect userinfo claims and oauth token introspection claims
        val = userinfo.get('preferred_username')
        if val == None:
            val = userinfo.get('username')
        if val != None:
            context.user[DISPLAY_NAME] = val
        
        val = userinfo.get('name')
        if val != None:
            context.user[FULL_NAME] = val

        val = userinfo.get('email')
        if val != None:
            context.user[EMAIL] = val


    def create_or_update_user(self, manager, context, username, id_token, userinfo, base_timestamp, token_payload, db):
        context.user['id_token'] = simplejson.dumps(id_token, separators=(',', ':'))
        context.user['userinfo'] = simplejson.dumps(userinfo, separators=(',', ':'))
        context.user['access_token'] = token_payload.get('access_token')
        context.user['access_token_expiration'] = base_timestamp + timedelta(seconds=int(token_payload.get('expires_in')))
        context.user['refresh_token'] = token_payload.get('refresh_token')
        if self.provider._client_exists(db, username):
            manager.clients.manage.update_noauthz(manager, context, username, db)
        else:
            manager.clients.manage.create_noauthz(manager, context, username, db)

    @staticmethod
    def open_url(req, text="opening url", repeatable=True):
        # This is called within db_wrapper, which will retry if it gets
        # a urllib2.HTTPError
        try:
            return urllib2.urlopen(req)
        except Exception, ev:
            if repeatable:
                raise ev
            else:
                raise OAuth2ProtocolError("Error {text}: {ev} ({url})".format(text=text, ev=str(ev), url=req.get_full_url()))

    def validate_userinfo(self, userinfo, id_token):
        if userinfo.get('sub') != id_token.get('sub'):
            raise Oauth2UserinfoError("Subject mismatch")
        for key in ['iss', 'aud']:
            if userinfo.get(key) != None and userinfo.get(key) != id_token.get(key):
                raise OAuth2UserinfoError("Bad value for " + key)

    @classmethod
    def validate_access_token(cls, alg, expected_hash, access_token):
        if alg == None:
            raise OAuth2ProtocolError("No hash algorithm specified")
        hash = cls.do_left_hash(access_token, alg, base64.urlsafe_b64encode)

        if hash == None:
            raise OAuth2Exception("Hash failed, alg = '" + alg + "', token is '" + access_token + "'")
        if hash != expected_hash:
            hash = cls.do_left_hash(access_token, alg, jwkest.b64e)
            if hash != expected_hash:
                raise OAuth2Exception("Bad hash value in access token, alg = '" + alg + "', hash = '" + str(hash) + "', expected = '" + str(expected_hash) + "'")

    @classmethod
    def do_left_hash(cls, input, alg, base64_func):
        hash_funcs = { 'HS256' : [16, jwk.sha256_digest],
                       'hs256' : [16, jwk.sha256_digest],
                       'RS256' : [16, jwk.sha256_digest],
                       'rs256' : [16, jwk.sha256_digest],
                       'HS384' : [24, jwk.sha384_digest],
                       'hs384' : [24, jwk.sha384_digest],
                       'RS384' : [24, jwk.sha384_digest],
                       'rs384' : [24, jwk.sha384_digest],
                       'HS512' : [32, jwk.sha512_digest],
                       'hs512' : [32, jwk.sha512_digest],
                       'RS512' : [32, jwk.sha512_digest],
                       'rs512' : [32, jwk.sha512_digest]
                       }

        hash_info = hash_funcs.get(alg)
        if hash_info == None:
            raise OAuth2ProtocolError("unknown hash algorithm: " + alg)

        hash_size, hash_func = hash_info
        return jwkest.as_unicode(base64_func(hash_func(input)[:hash_size]))



    @classmethod
    def verify_signed_jwt_with_keys(cls, jwt, keys, audience):
      """Verify a JWT against public keys.
    
      See http://self-issued.info/docs/draft-jones-json-web-token.html.
    
      Args:
        jwt: string, A JWT.
    
      Returns:
        dict, The deserialized JSON payload in the JWT.
    
      Raises:
        AppIdentityError if any checks are failed.
      """
      segments = jwt.split('.')
    
      if len(segments) != 3:
        raise AppIdentityError('Wrong number of segments in token: %s' % jwt)
      signed = '%s.%s' % (segments[0], segments[1])
    
      header = simplejson.loads(_urlsafe_b64decode(segments[0]))

      signature = _urlsafe_b64decode(segments[2])
    
      # Parse token.
      json_body = _urlsafe_b64decode(segments[1])
      try:
        parsed = json.loads(json_body)
      except:
        raise AppIdentityError('Can\'t parse token: %s' % json_body)
    
      # Check signature.
      verified = False
      for pem in keys:
        verified = cls.verify_signature(header.get('alg'), pem, signed, signature)
        if verified:
            break
      if not verified:
        raise AppIdentityError('Invalid token signature: %s' % jwt)
    
      # Check creation timestamp.
      iat = parsed.get('iat')
      if iat is None:
        raise AppIdentityError('No iat field in token: %s' % json_body)
      earliest = iat - CLOCK_SKEW_SECS
    
      # Check expiration timestamp.
      now = long(time.time())
      exp = parsed.get('exp')
      if exp is None:
        raise AppIdentityError('No exp field in token: %s' % json_body)

      latest = exp + CLOCK_SKEW_SECS
    
      if now < earliest:
        raise AppIdentityError('Token used too early, %d < %d: %s' %
                               (now, earliest, json_body))
      if now > latest:
        raise AppIdentityError('Token used too late, %d > %d: %s' %
                               (now, latest, json_body))
    
      # Check audience.
      if audience is not None:
        aud = parsed.get('aud')
        if aud is None:
          raise AppIdentityError('No aud field in token: %s' % json_body)
        if aud != audience:
          raise AppIdentityError('Wrong recipient, %s != %s: %s' %
                                 (aud, audience, json_body))
    
      return {'header' : header, 'body' : parsed}

        
    def accepts_login_get(self):
        return True

    def login_keywords(self, optional=False):
        return set()

    @staticmethod
    def verify_signature(alg_name, pem, signed, signature):
        hash_algs = {'RS256' : Crypto.Hash.SHA256,
                     'RS512' : Crypto.Hash.SHA512
                     }
        hash_alg = hash_algs.get(alg_name)
        if hash_alg == None:
            raise AppIdentityError("Unknown signature algorithm: " + alg_name)
        hash = hash_alg.new(signed)
        return PKCS1_v1_5.new(RSA.importKey(pem)).verify(hash, signature)


class OAuth2PreauthProvider (PreauthProvider):
    key = 'oauth2'

    def __init__(self, config):
        PreauthProvider.__init__(self, config)
        self.nonce_state = nonce_util(config)
        self.nonce_cookie_name = config.oauth2_nonce_cookie_name
        self.cfg=OAuth2Config(config)

        auth_url=urlparse.urlsplit(self.cfg.get('authorization_endpoint'))
        self.authentication_uri_base = [auth_url.scheme, auth_url.netloc, auth_url.path]
        self.authentication_uri_args = {
            "client_id" : self.cfg.get("client_id"),
            "response_type" : "code",
            "response_mode" : "form_post",
            "scope" : config.oauth2_scope
        }
        if config.oauth2_request_offline_access == True:
            self.authentication_uri_args["access_type"] = "offline"

    def preauth_info(self, manager, context, db):
        """
        Present any required pre-authentication information (e.g., a web form with options).
        """
        content_type = negotiated_content_type(
            ['application/json', 'text/html'],
            'application/json'
            )

        if self.cfg.get("oauth2_preauth_html_compatibility_mode") == True and content_type == 'text/html':
            self.preauth_initiate(manager, context, db, True)
        else:
            return {
                    AUTHENTICATION_TYPE : self.key,
                    COOKIE : self.nonce_cookie_name,
                    REDIRECT_URL : self.preauth_initiate(manager, context, db, False)}

    def preauth_initiate(self, manager, context, db, do_redirect):
        """
        Initiate a login (redirect to OAuth2 provider)
        """
        self.authentication_uri_args["redirect_uri"] = self.make_uri(str(self.cfg.get('oauth2_redirect_relative_uri')))
        session = self.make_session(db)
        self.nonce_state.log_referrer(session.get('auth_url_nonce'), web.input().get('referrer'), db)
        web.setcookie(self.nonce_cookie_name, session.get('auth_cookie_nonce'), secure=True)
        auth_request_args = self.make_auth_request_args(session)
        if do_redirect :
            web.debug("redirecting")
            raise web.seeother(self.make_redirect_uri(auth_request_args))
        else:
            return self.make_redirect_uri(auth_request_args)

    def preauth_referrer(self):
        """
        Get the original referring URL (stored in the auth_nonce cookie)
        """
        auth_url_nonce = web.input().get('state')
        if auth_url_nonce == None:
            raise OAuth2ProtocolError("No state argument")
        return self.nonce_state.get_referrer(auth_url_nonce)
        
    def make_uri(self, relative_uri):
        return web.ctx.home + relative_uri

    def make_auth_request_args(self, session):
        auth_request_args=dict()
        for key in self.authentication_uri_args.keys():
            auth_request_args[key] = self.authentication_uri_args.get(key)
        auth_request_args['state'] = session['auth_url_nonce']
        return auth_request_args

    def make_session(self, db):
        session=dict()
        for key in self.authentication_uri_args.keys():
            session[key] = self.authentication_uri_args.get(key)
        session['session_id'] = str(uuid.uuid4())
        session['auth_cookie_nonce'] = self.generate_nonce()
        session['auth_url_nonce'] = self.nonce_state.encode(session['auth_cookie_nonce'], db)
        return session

    @staticmethod
    def generate_nonce():
      nonce = str(int(time.time())) + '.' + base64.urlsafe_b64encode(Random.get_random_bytes(30)) + '.'
      return nonce

    def make_redirect_uriargs(self, args):
        return urllib.urlencode(args)

    def make_redirect_uri(self, args):
        components = self.authentication_uri_base + [self.make_redirect_uriargs(args), None]
        return urlparse.urlunsplit(components)


class OAuth2ClientManage(database.DatabaseClientManage):
    def __init__(self, provider):
        database.DatabaseClientManage.__init__(self, provider)

    def _create_noauthz_extras(self, manager, context, clientname, db):
        return self.__extracols(manager, context, clientname, db)

    def _get_noauthz_updatecols(self, manager, context, clientname, db):
        return self.__extracols(manager, context, clientname, db, False)

    def __extracols(self, manager, context, clientname, db, quote=True):
        """
        Generate extra (column, value) pairs for INSERT or UPDATE of user record

        """
        ec = []
        for k in context.user.keys():
            if k != ID and context.user.get(k) != None:
                if quote:
                    ec.append((k, sql_literal(context.user.get(k))))
                else:
                    ec.append((k, context.user.get(k)))
        return ec

    def create_noauthz(self, manager, context, clientname, db=None):
        def db_body(db):
            if self.provider._client_exists(db, clientname):
                return

            extras = self._create_noauthz_extras(manager, context, clientname, db)
            extracols = [ extra[0] for extra in extras ]
            extravals = [ extra[1] for extra in extras ]
            results = db.query("""
            INSERT INTO %(utable)s (%(idcol)s %(extracols)s) VALUES ( %(uname)s %(extravals)s );
"""
                               % dict(utable=self.provider._table(self.provider.client_storage_name),
                                      idcol=sql_identifier(ID),
                                      uname=sql_literal(context.user.get(ID)),
                                      extracols=','.join(extracols and [ '' ] + extracols),
                                      extravals=','.join(extravals and [ '' ] + extravals))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)



class OAuth2Passwd(ClientPasswd):
    def create_noauthz(self, manager, context, clientname, password=None, oldpasswd=None, db=None):
        raise NotImplementedError("Local passwords are not used with OAuth")

    def delete_noauthz(self, manager, context, clientname, db=None):
        raise NotImplementedError("Local passwords are not used with OAuth")
    
    def create(self, manager, context, clientname, password=None, oldpasswd=None, db=None):
        raise NotImplementedError("Local passwords are not used with OAuth")

    def delete(self, manager, context, clientname, oldpasswd=None, db=None):
        raise NotImplementedError("Local passwords are not used with OAuth")

class OAuth2SessionStateProvider(database.DatabaseSessionStateProvider):
    key="oauth2"

    def __init__(self, config):
        database.DatabaseSessionStateProvider.__init__(self, config)
        self.cfg = OAuth2Config(config)
        self.oauth_context = dict()

    def set_oauth_context_val(self, key, value):
        self.oauth_context[key] = value

    def set_oauth_context_val(self, key):
        return self.oauth_context.get(key)

class OAuth2ClientProvider (database.DatabaseClientProvider):

    key = 'oauth2'
    client_storage_name = 'user'
    extra_client_columns = [(DISPLAY_NAME, 'text'),
                            (FULL_NAME, 'text'),
                            (EMAIL, 'text'),
                            ('id_token', 'json'),
                            ('userinfo', 'json'),
                            ('access_token', 'text'),
                            ('access_token_expiration', 'timestamptz'),
                            ('refresh_token', 'text')]  # list of (columnname, typestring) pairs
    summary_storage_name = 'usersummary'
    
    # data storage format version
    major = 2
    minor = 0

    def __init__(self, config, 
                 Login=OAuth2Login,
                 Search=database.DatabaseClientSearch,
                 Manage=OAuth2ClientManage,
                 Passwd=None):
        ClientProvider.__init__(self, config)
        database.DatabaseConnection2.__init__(self, config)
        self.login = Login(self)
        self.search = Search(self)
        self.manage = Manage(self)
        if Passwd:
            self.passwd = Passwd(self)
        self.nonce_state = nonce_util(config)
        self.cfg = OAuth2Config(config)
        self.nonce_cookie_name = config.oauth2_nonce_cookie_name
        self.provider_sets_token_nonce = config.oauth2_provider_sets_token_nonce

    def deploy_views(self, db):
        if self._table_exists(db, self.summary_storage_name):
            db.query('DROP VIEW %s' % self._table(self.summary_storage_name))

        db.query("""
CREATE VIEW %(summary)s AS
  SELECT *
  FROM %(utable)s u ;
;
"""
                 % dict(utable=self._table(self.client_storage_name),
                        summary=self._table(self.summary_storage_name))
                 )


    def deploy(self, db=None):
        """
        Deploy initial provider state.

        """
        def db_body(db):
            database.DatabaseClientProvider.deploy(self)
            tables_added = False

            if not self._table_exists(db, nonce_util.hash_key_table):
                tables_added = True
                db.query("""
CREATE TABLE %(ntable)s (
  key text,
  timeout timestamptz
);
"""
                         % dict(ntable=self._table(nonce_util.hash_key_table))
                         )


            if not self._table_exists(db, nonce_util.referrer_table):
                tables_added = True
                db.query("""
CREATE TABLE %(rtable)s (
  nonce text primary key,
  referrer text,
  timeout timestamptz
);
"""
                         % dict(rtable=self._table(nonce_util.referrer_table))
                         )

            self.deploy_guard(db, '_client')

            if tables_added:
                self.deploy_views(db)

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)  


class OAuth2Config(collections.MutableMapping):
    def __init__(self, config):
        self.dictionaries = [self.load_client_secret_data(config),
                             self.load_discovery_data(config),
                             config]

    def load_client_secret_data(self, config):
        if config.oauth2_client_secret_file == None:
            raise OAuth2ConfigurationError("No oauth2_client_secret_file configured")
        f = open(config.oauth2_client_secret_file)
        csd = simplejson.load(f).get('web')
        f.close()
        return csd

    def load_discovery_data(self, config):
        if config.oauth2_discovery_uri == None:
            discovery_data = dict()
        else:
            f = urllib2.urlopen(config.oauth2_discovery_uri)
            discovery_data = simplejson.load(f)
            f.close()
        return discovery_data

    def __getitem__(self, key):
        for d in self.dictionaries:
            if d.has_key(key):
                return d.get(key)
        return None

    def __setitem__(self, key, value):
        return self.override_data.__setitem__(key, value)

    def __delitem__(self, key):
        found_one = False
        for d in self.dictionaries:
            if d.has_key(key):
                found_one = True
                d.__delitem__(key)
        if found_one == False:
            raise KeyError(key)
        return None

    def keys(self):
        klist = []
        for d in self.dictionaries:
            for k in d.keys():
                if not klist.__contains__(k):
                    klist.append(k)
        return klist

    def __iter__(self):
        raise NotImplementedError

    def __len__(self):
        return len(self.keys())



class OAuth2Exception(ValueError):
    pass

class OAuth2SessionGenerationFailed(OAuth2Exception):
    pass

class OAuth2ProtocolError(OAuth2Exception):
    pass

class OAuth2UserinfoError(OAuth2ProtocolError):
    pass

class OAuth2LoginTimeoutError(OAuth2ProtocolError):
    pass

class OAuth2ConfigurationError(OAuth2Exception):
    pass

class OAuth2IdTokenError(OAuth2ProtocolError):
    pass
