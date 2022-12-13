
# 
# Copyright 2010-2019 University of Southern California
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
   : The database source name (e.g., "host=localhost user=webauthn password=... dbname=webauthn").

`database_schema`
   : The schema name qualifier for provider tables within the database (text or None).

`database_max_retries`
   : The number of times to retry transient errors when running independent transactions (int).

Provider-specific parameters specific to OAuth2:

`oauth2_discovery_uri`
   : OpenID Connect Discovery 1.0 endpoint


`oauth2_redirect_uri`
   : The path (relative to the current host) that users are redirected to after providing consent/authorization

`oauth2_redirect_relative_uri`
   : (deprecated) The path (relative to the current service) that users are redirected to after providing consent/authorization

`oauth2_client_secret_file`
   : The file, obtained from an OAuth2 provider (e.g., google) during registration, containing shared secrets and other information.

"""

import web

import random
import urllib
import uuid
import web
import json
import psycopg2
import oauth2client.client
import jwkest
from jwkest import jwk
from jwkest import jws
from oauth2client.crypt import AppIdentityError, CLOCK_SKEW_SECS, AUTH_TOKEN_LIFETIME_SECS, MAX_TOKEN_LIFETIME_SECS, PyCryptoVerifier
import time
import base64
from Crypto import Random
from Crypto.Hash.HMAC import HMAC
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import datetime
from datetime import timedelta, timezone
import hashlib
import math

from ..util import *
from . import database, webcookie
from .providers import *

if sys.version_info[:2] >= (3, 8):
    from collections.abc import MutableMapping
else:
    from collections import MutableMapping

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
                if datetime.datetime.now(timezone.utc) + timedelta(0, self.config_params['soft_timeout']) < k[0]:
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
            # use convert iterator to list...
            return list(db.query("select referrer from {referrer_table} where nonce={nonce}".format(referrer_table=self.config_params.get('referrer_table'), nonce=sql_literal(nonce))))
        
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
        return base64.b64encode(key).decode()

    @staticmethod
    def texttokey(text):
        return base64.b64decode(text)

    def make_key(self):
        return Random.get_random_bytes(self.algorithm.digest_size)

    def time_ok(self, value):
        return time.time() - value < self.config_params['hard_timeout']

    def encode(self, msg, db):
        h = HMAC(self.get_current_key(db), msg.encode(), self.algorithm)
        return h.hexdigest()

    def hash_matches(self, msg, hashed, db):
        retval = self._check_hash_match(msg, hashed, db)
        if retval == False:
            self.update_timeout(db, True)
            retval = self._check_hash_match(msg, hashed, db)
        return retval

    def _check_hash_match(self, msg, hashed, db):
        for k in self.get_keys(db):
            h = HMAC(k[1], msg.encode(), self.algorithm)
            if h.hexdigest() == hashed:
                return True
        return False

class bearer_token_util():
    @staticmethod
    def token_from_request():
        if not 'env' in web.ctx:
            return None
        authz_header=web.ctx.env.get('HTTP_AUTHORIZATION')
        if authz_header == None:
            return None
        authz_header = authz_header.strip()
        if not authz_header.startswith('Bearer '):
            web.debug('"Authorization:" header does not start with "Bearer "')
            return None
        return authz_header[7:].lstrip()

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

        bearer_token = bearer_token_util.token_from_request()
        nonce_vals = dict()
        base_timestamp = datetime.datetime.now(timezone.utc)
        context.wallet = dict()        
        if bearer_token == None:
            self.authorization_code_flow(context, db)
        else:
            self.payload_from_bearer_token(bearer_token, context, db)

        # Get user directory data. Right now we're assuming the server will return json.
        # TODO: in theory the return value could be signed jwt
        userinfo_endpoint = self.provider.cfg.get('userinfo_endpoint')
        req = self.make_userinfo_request(self.provider.cfg.get('userinfo_endpoint'), self.payload.get('access_token'))
        f = self.open_url(req, "getting userinfo")
        self.userinfo=json.load(f)
        self.validate_userinfo()
        f.close()
        if self.userinfo.get('active') != True or self.userinfo.get('iss') == None or self.userinfo.get('sub') == None:
            web.debug("Login failed, userinfo is not active, or iss or sub is missing: {u}".format(u=str(self.userinfo)))
            raise OAuth2UserinfoError("Login failed, userinfo is not active, or iss or sub is missing: {u}".format(u=str(self.userinfo)))
        username = str(self.userinfo.get('iss') + '/' + self.userinfo.get('sub'))
        context.user = dict()
        self.fill_context_from_userinfo(context, username, self.userinfo)

        # Update user table
        self.create_or_update_user(manager, context, username, self.id_token, self.userinfo, base_timestamp, self.payload, db)
        context.client = KeyedDict()
        for key in ClientLogin.standard_names:
            if context.user.get(key) != None:
                context.client[key] = context.user.get(key)
        context.client[IDENTITIES] = [context.client.get(ID)]
        self.provider.manage.update_last_login(manager, context, context.client[ID], db);
        return context.client      

    def authorization_code_flow(self, context, db):
        vals = web.input()
        # Check that this request came from the same user who initiated the oauth flow
        nonce_vals = {
            'auth_url_nonce' : vals.get('state'),
            'auth_cookie_nonce' : web.cookies().get(self.provider.nonce_cookie_name)
            }


        if nonce_vals['auth_url_nonce'] == None:
            raise OAuth2ProtocolError("No authn_nonce in initial redirect")

        if (nonce_vals['auth_cookie_nonce'] == None):
            # Debug this -- we're getting this error even when the value is set
            error_string="No authn nonce ({ncn}) cookie found. Cookie header was: {h}".format(
                ncn=str(self.provider.nonce_cookie_name),
                h=str(web.ctx.env.get('HTTP_COOKIE')))
            raise OAuth2ProtocolError(error_string)

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
        redirect_full_payload=json.dumps(vals, separators=(',', ':'))

        # Get id token
        token_args = {
            'code' : vals.get('code'),
            'client_id' : self.provider.cfg.get('client_id'),
            'client_secret' : self.provider.cfg.get('client_secret'),
            'redirect_uri' : web.ctx.home + web.ctx.path,
            'nonce' : nonce_vals['auth_url_nonce'],
            'grant_type' : 'authorization_code'}

        token_request = urllib.request.Request(self.provider.cfg.get('token_endpoint'), urllib.parse.urlencode(token_args).encode())
        self.add_extra_token_request_headers(token_request)
        u = self.open_url(token_request, "getting token")
        if (u == None):
            raise OAuth2Exception("Error opening connection for token request")
        # Accesss code has been used, so from this point on, all exceptions should be ones
        # that will not cause db_wrapper to retry (because those retries will fail and generate
        # confusing exceptions / log messages).
        try:
            self.payload=json.load(u)
#            web.debug("openid connect flow: payload is {p}".format(p=json.dumps(self.payload)))
        except Exception as ex:
            raise OAUth2Exception('Exception decoding token payload: http code {code}'.format(code=str(u.getcode())))
        u.close()
            
        raw_id_token=self.payload.get('id_token')
        if raw_id_token is None:
            web.debug("Illegal token response: didn't include an id token. Keys were {k}. Token type was {t}, scope was {s}".format(k=str(self.payload.keys()), t=str(self.payload.get('token_type')), s=str(self.payload.get('scope'))))
            raise OAuth2Exception("Illegal token response: didn't include an id token")

#        web.debug("Good token response. Keys were {k}. Token type was {t}, scope was {s}".format(k=str(self.payload.keys()), t=str(self.payload.get('token_type')), s=str(self.payload.get('scope'))))        

        # Validate id token
        u=self.open_url(urllib.request.Request(self.provider.cfg.get('jwks_uri')), "getting jwks info")
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
        if self.provider.provider_sets_token_nonce and self.id_token.get('nonce') != nonce_vals.get('auth_url_nonce'):
            raise OAuth2IDTokenError('Bad nonce in ID token')

        # Validate access token
        self.validate_access_token(id_header.get('alg'), self.id_token.get('at_hash'), self.payload.get('access_token'))
        
    def payload_from_bearer_token(self, bearer_token, context, db):
        self.payload = {'access_token': bearer_token}
        self.id_token = None

       
    @staticmethod
    def add_to_wallet(context, issuer, token):
        # If the wallet format is ever changed, the function get_wallet_entries in deriva-py will also need to be updated.
        if context.wallet.get('oauth2') == None:
            context.wallet['oauth2'] = dict()
        my_wallet = context.wallet.get('oauth2')
        if my_wallet.get(issuer) == None:
            my_wallet[issuer] = []
        my_wallet[issuer].append(token)

    def add_extra_token_request_headers(self, token_request):
        pass

    def make_userinfo_request(self, userinfo_endpoint, access_token):
        return urllib.request.Request(userinfo_endpoint, headers={'Authorization' : 'Bearer ' + access_token})

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
        context.user['id_token'] = json.dumps(id_token, separators=(',', ':'))
        context.user['userinfo'] = json.dumps(userinfo, separators=(',', ':'))
        context.user['access_token'] = token_payload.get('access_token')
        if token_payload.get('exp') != None:
            context.user['access_token_expiration'] = datetime.datetime.fromtimestamp(token_payload.get('exp'))
        else:
            context.user['access_token_expiration'] = base_timestamp + timedelta(seconds=int(token_payload.get('expires_in')))
        context.user['refresh_token'] = token_payload.get('refresh_token')
        if self.provider._client_exists(db, username):
            manager.clients.manage.update_noauthz(manager, context, username, db)
        else:
            manager.clients.manage.create_noauthz(manager, context, username, db)

    @staticmethod
    def open_url(req, text="opening url"):
        # This is called within the login method, which is wrapped by db_wrapper.
        # The access code can only be used once, so after the first use, we can't
        # let db_wrapper retry, so we do our own retry loop here.
        max_retries=5
        for retry in range(1, max_retries):
            try:
                return urllib.request.urlopen(req)
            except Exception as ev:
                web.debug("Attempt {x} of {y} failed: Got {t} exception {ev} while {text} (url {url})".format(
                    x=str(retry), y=str(max_retries), t=str(type(ev)), ev=str(ev), text=str(text), url=str(req.get_full_url())))
                delay = random.uniform(0.75, 1.25) * math.pow(10.0, retry) * 0.00000001
                time.sleep(delay)
                
        raise OAuth2ProtocolError("Error {text}: {ev} ({url})".format(text=text, ev=str(ev), url=req.get_full_url()))

    def validate_userinfo(self):
        # Check times

        if self.userinfo.get('nbf') != None and self.userinfo.get('nbf') > time.time():
            raise OAuth2UserinfoError("Access token is not yet valid")
        if self.userinfo.get('exp') != None:
            if self.userinfo.get('exp') < time.time():
                raise OAuth2UserinfoError("Access token has expired")            
            self.payload['exp'] = self.userinfo.get('exp')

        # Check issuer and (if applicable) audiende
        accepted_scopes = self.provider.cfg.get('oauth2_accepted_scopes')
        found_scopes=[]
        if self.userinfo.get('scope') != None:
            found_scopes = self.userinfo.get('scope').split()

        # First check for normal (user-involved) authorization flow. Userinfo will include the "openid" scope, and there
        # will be an id token. Compare the issuer, audience, and subject.
        if 'openid' in found_scopes and self.id_token != None:
            if self.userinfo.get('sub') != self.id_token.get('sub'):
                web.debug("Subject mismatch id/userinfo")                
                raise OAuth2UserinfoError("Subject mismatch id/userinfo")
            for key in ['iss', 'aud']:
                uval = self.userinfo.get(key)
                ival = self.id_token.get(key)
                if not (uval == ival or (isinstance(uval, list) and ival in uval)):
                    web.debug("id/userinfo mismatch for " + key)
                    web.debug("userinfo[{key}] = {u}, id[{key}] = {i}".format(key=key, u=str(self.userinfo.get(key)), i=str(self.id_token.get(key))))
                    raise OAuth2UserinfoError("id/userinfo mismatch for " + key)
            return

        # If we got an access token without getting the authorization flow, check to see that the scope is one we're
        # configured to accept and that the issuer is who we expect
        for a in accepted_scopes:
            if a.get('scope') in found_scopes:
                if a.get("issuer") == self.userinfo.get('iss'):
                    return
        web.debug("Bad scope or issuer for OAuth2 bearer token")
        raise OAuth2UserinfoError("Bad scope or issuer for OAuth2 bearer token")
            

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

      assert jwt is not None
      segments = jwt.split('.')
    
      if len(segments) != 3:
        raise AppIdentityError('Wrong number of segments in token: %s' % jwt)
      signed = '%s.%s' % (segments[0], segments[1])
    
      header = json.loads(cls.urlsafe_b64decode(segments[0]))

      signature = cls.urlsafe_b64decode(segments[2])
    
      # Parse token.
      json_body = cls.urlsafe_b64decode(segments[1])
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
      now = int(time.time())
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

    @staticmethod
    def urlsafe_b64decode(text):
        padded = text.encode() + b'=' * (4 - len(text) % 4)
        return base64.urlsafe_b64decode(padded)
          
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
        hash = hash_alg.new(signed.encode())
        return PKCS1_v1_5.new(RSA.importKey(pem)).verify(hash, signature)

    def request_has_relevant_auth_headers(self):
        return bearer_token_util.token_from_request() is not None
    


class OAuth2PreauthProvider (PreauthProvider):
    key = 'oauth2'

    def __init__(self, config):
        PreauthProvider.__init__(self, config)
        self.nonce_state = nonce_util(config)
        self.nonce_cookie_name = config.oauth2_nonce_cookie_name
        self.cfg=OAuth2Config(config)

        auth_url=urllib.parse.urlsplit(self.cfg.get('authorization_endpoint'))
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
        self.authentication_uri_args["redirect_uri"] = self.make_uri(self.cfg.get('oauth2_redirect_uri'))
        if self.authentication_uri_args["redirect_uri"] == None:
            self.authentication_uri_args["redirect_uri"] = self.make_relative_uri(str(self.cfg.get('oauth2_redirect_relative_uri')))
        session = self.make_session(db)
        self.nonce_state.log_referrer(session.get('auth_url_nonce'), web.input().get('referrer'), db)
        web.setcookie(self.nonce_cookie_name, session.get('auth_cookie_nonce'), secure=True, path="/")
        auth_request_args = self.make_auth_request_args(session)
        if do_redirect :
            raise web.seeother(self.make_redirect_uri(auth_request_args))
        else:
            return self.make_redirect_uri(auth_request_args)

    def make_uri(self, base):
        if base == None:
            return None
        return "{prot}://{host}{path}".format(prot=web.ctx.protocol, host=web.ctx.host, path=base)

    def preauth_referrer(self):
        """
        Get the original referring URL (stored in the auth_nonce cookie)
        """
        auth_url_nonce = web.input().get('state')
        if auth_url_nonce == None:
            return None
        else:
            return self.nonce_state.get_referrer(auth_url_nonce)
        
    def make_relative_uri(self, relative_uri):
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
      nonce = str(int(time.time())) + '.' + base64.urlsafe_b64encode(Random.get_random_bytes(30)).decode() + '.'
      return nonce

    def make_redirect_uriargs(self, args):
        return urllib.parse.urlencode(args)

    def make_redirect_uri(self, args):
        components = self.authentication_uri_base + [self.make_redirect_uriargs(args), None]
        return urllib.parse.urlunsplit(components)

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
    xref_storage_name = 'session_oauth_key'

    def __init__(self, config):
        database.DatabaseSessionStateProvider.__init__(self, config)
        self.cfg = OAuth2Config(config)
        self.oauth_context = dict()
        self.nonce_cookie_name = config.oauth2_nonce_cookie_name
        self.extra_columns = [('wallet', 'json')]

    def _new_session_extras(self, manager, context, db):
        if hasattr(context, "wallet"):
            return [('wallet', json.dumps(context.wallet, separators=(',', ':')))]
        else:
            return []

    def set_oauth_context_val(self, key, value):
        self.oauth_context[key] = value

    def set_oauth_context_val(self, key):
        return self.oauth_context.get(key)

    def deploy_minor_upgrade(self, old_minor, db):
        if self.major == 2 and old_minor == 0:
            self._add_extra_columns(db)
        return True

    def terminate(self, manager, context, db=None, preferred_final_url=None):
        database.DatabaseSessionStateProvider.terminate(self, manager, context, db, preferred_final_url)
        web.setcookie(self.nonce_cookie_name, "", expires=-1)

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


class OAuth2Config(MutableMapping):
    def __init__(self, config):
        self.dictionaries = [self.load_client_secret_data(config),
                             self.load_discovery_data(config),
                             config]

    def load_client_secret_data(self, config):
        if config.oauth2_client_secret_file == None:
            raise OAuth2ConfigurationError("No oauth2_client_secret_file configured")
        f = open(config.oauth2_client_secret_file)
        csd = json.load(f).get('web')
        f.close()
        return csd

    def load_discovery_data(self, config):
        if config.oauth2_discovery_uri == None:
            discovery_data = dict()
        else:
            f = urllib.request.urlopen(config.oauth2_discovery_uri)
            discovery_data = json.load(f)
            f.close()
        return discovery_data

    def __getitem__(self, key):
        for d in self.dictionaries:
            if key in d:
                return d.get(key)
        return None

    def __setitem__(self, key, value):
        return self.override_data.__setitem__(key, value)

    def __delitem__(self, key):
        found_one = False
        for d in self.dictionaries:
            if key in d:
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


class OAuth2SessionIdProvider (webcookie.WebcookieSessionIdProvider, database.DatabaseConnection2):
    """
    OAuth2SessionIdProvider implements session IDs based on HTTP cookies or OAuth2 Authorization headers

    """
    
    key = 'oauth2'

    def __init__(self, config):
        database.DatabaseConnection2.__init__(self, config)
        webcookie.WebcookieSessionIdProvider.__init__(self, config)
        # validate oauth2 discovery scope, if specified
        discovery_scopes = config.get("oauth2_discovery_scopes")
        if discovery_scopes is not None:
            accepted_scopes = self.accepted_scopes_to_set(config)
            final_scopes = dict()
            for key in discovery_scopes.keys():
                if discovery_scopes[key] in accepted_scopes:
                    final_scopes[key] = discovery_scopes[key]
                else:
                    web.debug("'{s}' is configured as a discovery scope but not an accepted scope".format(s=discovery_scopes[key]))
            self.discovery_info = {"oauth2_scopes" : final_scopes}
        else:
            self.discovery_info = {}

    def accepted_scopes_to_set(self, config):
        scopes = set()
        acs = config.get("oauth2_accepted_scopes")
        if isinstance(acs, list):
            for s in acs:
                scope = s.get("scope")
                if scope is not None:
                    scopes.add(scope)
        return scopes

    def get_discovery_info(self):
        return(self.discovery_info)

    def get_request_sessionids(self, manager, context, db=None):
        # Use md5 because apr library (used by webauthn apache module) doesn't support sha256
        bearer_token = bearer_token_util.token_from_request()
        if bearer_token != None:
            m = hashlib.md5()
            m.update(bearer_token.encode())
            return(["oauth2-hash:{hash}".format(hash=m.hexdigest())])
            
        return webcookie.WebcookieSessionIdProvider.get_request_sessionids(self, manager, context, db)

    def create_unique_sessionids(self, manager, context, db=None):
        context.session.keys = self.get_request_sessionids(manager, context, db)
        if context.session.keys == None or len(context.session.keys) == 0:
            webcookie.WebcookieSessionIdProvider.create_unique_sessionids(self, manager, context, db)

class GroupTokenProcessor:
    def __init__(self, expected_scopes):
        self.expected_scopes = expected_scopes

    def token_recognized(self, token):
        for scope in self.expected_scopes:
            if self.token_has_scope(token, scope):
                return True
        return False

    @classmethod
    def token_has_scope(cls, token, scope):
        if token == None:
            return False
        scopes = token.get('scope')
        if scopes == None:
            return False
        return scope in scopes.split()

class OAuth2Exception(ValueError):
    pass

class OAuth2SessionGenerationFailed(OAuth2Exception):
    pass

class OAuth2ProtocolError(OAuth2Exception):
    pass

class OAuth2UserinfoError(OAuth2Exception):
    pass

class OAuth2LoginTimeoutError(OAuth2ProtocolError):
    pass

class OAuth2ConfigurationError(OAuth2Exception):
    pass

class OAuth2IdTokenError(OAuth2ProtocolError):
    pass
