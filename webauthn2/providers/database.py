
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
Webauthn2 provider implementations using private database tables.

`DatabaseSessionStateProvider`
   : Session persistence provider 'database'.

`DatabaseClientProvider`
   : Client provider 'database' supports login, search, manage, passwd APIs.

`DatabaseAttributeProvider`
   : Attribute provider 'database' supports client, search, manage, assign, nest APIs.

Provider-specific parameters for database module:

`database_type`
   : The database type (e.g., postgres).

`database_dsn`
   : The database source name (e.g., "host=localhost user=ermrest password=... dbname=ermrest").

`database_schema`
   : The schema name qualifier for provider tables within the database (text or None).

`database_max_retries`
   : The number of times to retry transient errors when running independent transactions (int).

`def_passwd_len`
   : The default password length in number of characters when generating random passwords (int).

`hash_passwd_reps`
   : The number of repetitions of salted password hashing to prevent brute-force attack (int).

"""

from providers import *
from webauthn2.util import *
from webauthn2.exc import *
import json

import web

import hmac
import random
import datetime
import pytz
import urllib
import re

config_built_ins = web.storage(
    database_type= 'postgres',
    database_dsn= 'dbname=',
    database_schema= 'webauthn2',
    database_max_retries= 5,
    def_passwd_len= 10,
    hash_passwd_reps= 1000
    )

__all__ = [
    'make_random_password',
    'hash_password',
    'DatabaseSessionStateProvider',
    'DatabaseClientProvider',
    'DatabaseAttributeProvider',
    'DatabasePreauthProvider',
    'config_built_ins'
    ]

def make_random_password(length=10, symbols=False):
    """Generate a random password of given length."""
    return generate_random_string(length, symbols=False)

def hash_password(password, salthex=None, reps=1000):
    """Compute secure (hash, salthex, reps) triplet for password.

       The password string is required.  The returned salthex and reps
       must be saved and reused to hash any comparison password in
       order for it to match the returned hash.

       The salthex string will be chosen randomly if not provided, and
       if provided must be an even-length string of hexadecimal
       digits, recommended length 16 or
       greater. E.g. salt="([0-9a-z][0-9a-z])*"

       The reps integer must be 1 or greater and should be a
       relatively large number (default 1000) to slow down brute-force
       attacks."""
    
    if not salthex:
        salthex = ''.join([ "%02x" % random.randint(0, 0xFF) 
                            for d in range(0,8) ])

    salt = []
    for p in range(0, len(salthex), 2):
        salt.append(int(salthex[p:p+2], 16))
    salt = ''.join([chr(n) for n in salt])

    if reps < 1:
        reps = 1

    msg = password
    for r in range(0,reps):
        msg = hmac.HMAC(salt, msg).hexdigest()

    return (msg, salthex, reps)


class DatabaseConnection2 (DatabaseConnection):

    # this is the storage format version, not the software version
    major = 1
    minor = 0

    def __init__(self, config):
        DatabaseConnection.__init__(self, config)

        # create a raw client early to force config errors
        self._put_pooled_connection(self._get_pooled_connection())

    def deploy_upgrade(self, db, versioninfo):
        """
        Upgrade database storage format to current version with tri-state response.

        Results:
           True:  database was upgraded
           None:  no upgrade was necessary
           False: upgrade not possible, data incompatible

        """
        if versioninfo.major != self.major or versioninfo.minor != self.minor:
            return False
        else:
            return None

    def deploy_guard(self, db, suffix=''):
        """
        Atomic test and set deployed version info with optional suffix for version storage.

        Override this method if the derived class can do something
        better than an exact version equality test, such as in-place
        upgrades.

        """
        if not self._table_exists(db, 'webauthn2_version' + suffix):
            db.query("""
CREATE VIEW %(version)s AS
  SELECT %(major)s::int AS major, %(minor)s::int AS minor;
"""
                     % dict(version=self._table('webauthn2_version' + suffix),
                            major=sql_literal(self.major),
                            minor=sql_literal(self.minor))
                     )

        else:
            results = db.query("SELECT * FROM %s" % self._table('webauthn2_version' + suffix))

            if len(results) != 1:
                raise TypeError('Unexpected version info format in %s' % self._table('webauthn2_version' + suffix))

            versioninfo = results[0]

            test_result = self.deploy_upgrade(db, versioninfo)

            if test_result == False:
                raise ValueError('Incompatible %s == %s.' % (self._table('webauthn2_version' + suffix), versioninfo))

            elif test_result == True:
                db.query("""
DROP VIEW %(version)s;
CREATE VIEW %(version)s AS
  SELECT 2 AS major, 0 AS minor;
"""
                         % dict(version=self._table('webauthn2_version' + suffix),
                                major=sql_literal(self.major),
                                minor=sql_literal(self.minor))
                         )
    
    def deploy(self, db=None):
        """
        Deploy custom schema if necessary.

        """
        def db_body(db):
            if self.database_schema and not self._schema_exists(db, self.database_schema):
                db.query("""
CREATE SCHEMA %(schema)s ;
"""
                         % dict(schema=sql_identifier(self.database_schema))
                         )

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

class DatabaseSessionStateProvider (SessionStateProvider, DatabaseConnection2):

    key = 'database'
    storage_name = 'session'
    extra_columns = []  # list of (columnname, typestring) pairs

    # data storage format version
    major = 1
    minor = 0

    def __init__(self, config):
        SessionStateProvider(config)
        DatabaseConnection2.__init__(self, config)

    def set_msg_context(self, manager, context, sessionids, db=None):
        """
        Load existing session state keyed by sessionids.

        Update context.session.keys if the canonical key is updated. The
        caller will attempt to propogate key updates to the client
        where possible, but care should be taken to provide an
        idempotent transition period where the old keys will continue
        to map to the new canonical keying.

        """
        def db_body(db):
            return self._session(db, sessionids)

        try:
            if db:
                srow = db_body(db)
            else:
                srow = self._db_wrapper(db_body)

            context.session = Session([ srow.key ], 
                                      srow.since,
                                      srow.expires)

            context.client = srow.get('client')
            context.attributes = srow.get('attributes')

            return srow

        except KeyError:
            context.session = None
            return None

    def _new_session_extras(self, manager, context, db):
        """
        Generate extra (column, value) pairs for INSERT of new session.

        """
        return []

    def new(self, manager, context, db=None):
        """
        Create a new persistent session state mirroring context.

        If there is a key conflict between context and provider
        storage, throw a KeyError exception.

        """
        def db_body(db):
            try:
                srow = self._session(db, context.session.keys)
            except KeyError:
                srow = None

            if srow:
                raise KeyError('key not unique')

            if not context.session.since:
                context.session.since = datetime.datetime.now(pytz.timezone('UTC'))
            
            if not context.session.expires:
                duration = datetime.timedelta(minutes=int(manager.config.get('session_expiration_minutes', 30)))
                context.session.expires = context.session.since + duration

            usercols=[]
            uservals=[]
            for key in ClientLogin.standard_names:
                if context.client.get(key) != None:
                    usercols.append(sql_identifier(key))
                    uservals.append(sql_literal(context.client.get(key)))
            extras = self._new_session_extras(manager, context, db)
            extracols = [ sql_identifier(extra[0]) for extra in extras ]
            extravals = [ sql_literal(extra[1]) for extra in extras ]
            db.query("""
INSERT INTO %(stable)s (key, since, keysince, expires, client, attributes, %(usercols)s %(extracols)s)
  VALUES (%(key)s, %(since)s, %(since)s, %(expires)s, %(client)s, %(attributes)s, %(uservals)s %(extravals)s) ;
"""
                     % dict(stable=self._table(self.storage_name),
                            key=sql_literal(context.session.keys[0]),
                            since=sql_literal(context.session.since),
                            expires=sql_literal(context.session.expires),
                            client=sql_literal(json.dumps(context.client)),
                            attributes='ARRAY[%s]::json[]' % ','.join([ sql_literal(json.dumps(a)) for a in context.attributes ]),
                            usercols=','.join(usercols),
                            uservals=','.join(uservals),
                            extracols=','.join(extracols and [ '' ] + extracols),
                            extravals=','.join(extravals and [ '' ] + extravals))
                     
                     )

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)
        

    def extend(self, manager, context, db=None):
        """
        Update expiration time of existing session mirroring context in persistent store.

        """
        def db_body(db):
            srow = self._session(db, context.session.keys)
            now = datetime.datetime.now(pytz.timezone('UTC'))
            duration = datetime.timedelta(minutes=int(manager.config.get('session_expiration_minutes', 30)))
            expires = now + duration
            # check timestamp ordering because python time differences wrap around
            # in ugly ways instead of producing signed results!
            if (srow.expires > expires) or (expires - srow.expires).seconds < 5:
                # don't update too often
                return
            db.query("""
UPDATE %(stable)s SET expires = %(expires)s WHERE key = %(key)s AND %(expires)s > expires ;
"""
                     % dict(stable=self._table(self.storage_name),
                            key=sql_literal(srow.key),
                            expires=sql_literal(expires))
                     )

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

    def terminate(self, manager, context, db=None):
        """
        Destroy any persistent session mirroring context.

        """
        def db_body(db):
            srow = self._session(db, context.session.keys)
            db.query("""
DELETE FROM %(stable)s WHERE key = %(key)s ;
"""
                     % dict(stable=self._table(self.storage_name),
                            key=sql_literal(srow.key))

                     )

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

    def _session(self, db, sessionids):
        # purge old sessions before searching for valid keys
        db.query("""
DELETE FROM %(stable)s WHERE expires < 'now'::timestamptz ;
"""
                 % dict(stable=self._table(self.storage_name))
                 )

        results = db.query("""
SELECT * FROM %(stable)s 
WHERE key IN ( %(keys)s ) OR key_old IN ( %(keys)s )
ORDER BY expires DESC ;
"""
                           % dict(stable=self._table(self.storage_name),
                                  keys=','.join([ sql_literal(k) for k in sessionids ]))
                           )
        if len(results) > 1:
            # TODO: warn about this
            pass
        if len(results) > 0:
            return results[0]
        else:
            raise KeyError(str('sessionids'))

    def deploy(self, db=None):
        """
        Deploy initial provider state.

        """
        def db_body(db):
            DatabaseConnection2.deploy(self)

            if not self._table_exists(db, self.storage_name):
                db.query("""
CREATE TABLE %(stable)s (
  key text UNIQUE,
  key_old text UNIQUE,
  since timestamptz,
  keysince timestamptz,
  expires timestamptz,
  client json,
  attributes json[],
  %(user_columns)s                
  %(extras)s
);
"""
                         % dict(stable=self._table(self.storage_name),
                                user_columns=','.join("%s text" % name for name in ClientLogin.standard_names),
                                extras=','.join(self.extra_columns and [ '' ] + [ '%s %s' % ec for ec in self.extra_columns ]))
                         )

            self.deploy_guard(db, '_' + self.storage_name)

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

class DatabaseClientSearch (ClientSearch):

    def __init__(self, provider):
        ClientSearch.__init__(self, provider)

    def get_all_clients_noauthz(self, manager, context, db=None):
        """
        Return set of all available client identifiers.

        """
        def db_body(db):
            return set([ row.get(ID)
                         for row in db.query("""
SELECT %(username)s FROM %(utable)s ;
"""
                                             % dict(utable=self.provider._table(self.provider.client_storage_name),
                                                    username=ID)
                                             ) ])

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

        
class DatabaseLogin (ClientLogin):

    def __init__(self, provider):
        ClientLogin.__init__(self, provider)

    def login(self, manager, context, db, **kwargs):
        """
        Return username if the user can be logged in using 'username' and 'password' keyword arguments.

        Raises TypeError if either keyword argument is absent.
        Raises KeyError if username is not found or user cannot use this application.
        Raises ValueError if password and username combination are not valid.

        It is expected that the caller will store the resulting username into context.client for reuse.
        
        """
        try:
            username = kwargs['username']
            password = kwargs['password']
        except KeyError, ve:
            # treat lack of proper kwargs as a type error
            raise TypeError(str(ve))

        def db_body(db):
            uname = self.provider._client_passwd_matches(db, username, password)
            if uname != None:
                context.client = KeyedDict()
                context.client[ID] = uname
                context.client[DISPLAY_NAME] = uname
                return context.client

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)
        
class DatabaseClientManage (ClientManage):

    def __init__(self, provider):
        ClientManage.__init__(self, provider)

    def _create_noauthz_extras(self, manager, context, clientname, db):
        """
        Generate extra (column, value) pairs for INSERT of new client.

        """
        return []

    def create_noauthz(self, manager, context, clientname, db=None):
        def db_body(db):
            if self.provider._client_exists(db, clientname):
                return

            extras = self._create_noauthz_extras(manager, context, clientname, db)
            extracols = [ extra[0] for extra in extras ]
            extravals = [ extra[1] for extra in extras ]

            results = db.query("""
INSERT INTO %(utable)s (%(id)s %(extracols)s) VALUES ( %(uname)s %(extravals)s );
"""
            % dict(utable=self.provider._table(self.provider.client_storage_name),
                   uname=sql_literal(clientname),
                   id=sql_identifier(ID),
                   extracols=','.join(extracols and [ '' ] + extracols),
                   extravals=','.join(extravals and [ '' ] + extravals))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def delete_noauthz(self, manager, context, clientname, db=None):
        def db_body(db):
            if not self.provider._client_exists(db, clientname):
                raise KeyError(clientname)

            results = db.query("""
DELETE FROM %(utable)s WHERE %(username)s = %(uname)s ;
"""
                               % dict(utable=self.provider._table(self.provider.client_storage_name),
                                      username=ID,
                                      uname=sql_literal(clientname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def update_noauthz(self, manager, context, clientname, db=None):
        def db_body(db):
            if not self.provider._client_exists(db, clientname):
                raise ValueError("User does not exist")

            rawcols = self._get_noauthz_updatecols(manager, context, clientname, db)
            cols=[]
            vals=dict()
            for c in rawcols:
                cols.append(c[0] + '= $' + c[0])
                vals[c[0]] = c[1]
            results = db.query("""
UPDATE %(utable)s SET %(colstring)s where %(username)s=%(uname)s
"""
                               % dict(utable=self.provider._table(self.provider.client_storage_name),
                                      colstring=','.join(cols),
                                      username=ID,
                                      uname=sql_literal(clientname)),
                               vars=vals)
        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)



class DatabaseClientPasswd (ClientPasswd):

    def __init__(self, provider):
        ClientPasswd.__init__(self, provider)

    def _create_noauthz_extras(self, manager, context, clientname, db):
        """
        Generate extra (column, value) pairs for INSERT of new client.

        """
        return []

    def create_noauthz(self, manager, context, clientname, password=None, oldpasswd=None, db=None):
        made_random = False
        if not password:
            made_random = True
            password = make_random_password(self.provider.def_passwd_len)

        pwhash, salthex, reps = hash_password(password, reps=self.provider.hash_passwd_reps)

        def db_body(db):
            if oldpasswd != None:
                try:
                    self.provider._client_passwd_matches(db, clientname, oldpasswd)
                except KeyError:
                    # trying to compare to non-existant current passwd?
                    raise
                except ValueError:
                    # oldpasswd doesn't match new passwd
                    raise ValueError('user %s or old password' % clientname)
            
            if self.provider._client_passwd(db, clientname) != None:
                self.delete_noauthz(manager, context, clientname, db=db)

            extras = self._create_noauthz_extras(manager, context, clientname, db)
            extracols = [ extra[0] for extra in extras ]
            extravals = [ extra[1] for extra in extras ]
            
            if not self.provider._client_exists(db, clientname):
                raise KeyError(clientname)
            
            results = db.query("""
INSERT INTO %(ptable)s (uid, pwhash, salthex, reps %(extracols)s) 
  SELECT uid, %(pwhash)s, %(salthex)s, %(reps)s %(extravals)s
  FROM %(utable)s
  WHERE %(username)s = %(uname)s
"""
                               % dict(ptable=self.provider._table(self.provider.passwd_storage_name),
                                      utable=self.provider._table(self.provider.client_storage_name),
                                      uname=sql_literal(clientname),
                                      username=ID,
                                      pwhash=sql_literal(pwhash),
                                      salthex=sql_literal(salthex),
                                      reps=sql_literal(reps),
                                      extracols=','.join(extracols and [ '' ] + extracols),
                                      extravals=','.join(extravals and [ '' ] + extravals))
                               )
            if made_random:
                return password
            else:
                return True

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def delete_noauthz(self, manager, context, clientname, oldpasswd=None, db=None):
        def db_body(db):
            prow = self.provider._client_passwd(db, clientname)
            if prow == None:
                raise KeyError(clientname)

            if oldpasswd != None:
                try:
                    self.provider._client_passwd_matches(db, clientname, oldpasswd)
                except KeyError:
                    # trying to compare to non-existant current passwd?
                    raise
                except ValueError:
                    # oldpasswd doesn't match new passwd
                    raise ValueError('user %s or old password' % clientname)
            
            results = db.query("""
DELETE FROM %(ptable)s p
USING %(utable)s u
WHERE u.%(username)s = %(uname)s
  AND u.uid = p.uid ;
"""
                               % dict(ptable=self.provider._table(self.provider.passwd_storage_name),
                                      utable=self.provider._table(self.provider.client_storage_name),
                                      username=ID,
                                      uname=sql_literal(clientname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

class DatabaseClientProvider (ClientProvider, DatabaseConnection2):

    key = 'database'
    client_storage_name = 'user'
    extra_client_columns = []  # list of (columnname, typestring) pairs
    passwd_storage_name = 'password'
    extra_passwd_columns = []  # list of (columnname, typestring) pairs
    summary_storage_name = 'usersummary'
    
    # data storage format version
    major = 1
    minor = 0

    def __init__(self, config, 
                 Login=DatabaseLogin,
                 Search=DatabaseClientSearch,
                 Manage=DatabaseClientManage,
                 Passwd=DatabaseClientPasswd):
        ClientProvider.__init__(self, config)
        DatabaseConnection2.__init__(self, config)
        self.def_passwd_len = config.def_passwd_len
        self.hash_passwd_reps = config.hash_passwd_reps
        self.login = Login(self)
        self.search = Search(self)
        self.manage = Manage(self)
        self.passwd = Passwd(self)

    def _client_exists(self, db, clientname):
        results = db.query("""
SELECT * FROM %(utable)s WHERE %(username)s = %(uname)s ;
"""
                           % dict(utable=self._table(self.client_storage_name),
                                  username=ID,
                                  uname=sql_literal(clientname))
                           )
        return len(results) > 0

    def _client_passwd(self, db, clientname):
        results = db.query("""
SELECT
  u.uid uid,
  p.uid puid,
  u.%(username)s username,
  p.pwhash pwhash,
  p.salthex salthex,
  p.reps reps
  %(extras)s
FROM %(utable)s u
JOIN %(ptable)s p USING (uid)
WHERE u.%(username)s = %(uname)s
""" 
                           % dict(ptable=self._table(self.passwd_storage_name),
                                  utable=self._table(self.client_storage_name),
                                  uname=sql_literal(clientname),
                                  username=ID,
                                  extras=','.join(self.extra_passwd_columns and
                                                  [''] + ['p.%s %s' % (ec[0], ec[0]) for ec in self.extra_passwd_columns]))
                           )
        if len(results) > 0:
            return results[0]
        else:
            return None

    def _client_passwd_matches(self, db, clientname, passwd):
        row = self._client_passwd(db, clientname)
        if row == None:
            raise KeyError(clientname)

        inhash, salthex, reps = hash_password(passwd, row.salthex, row.reps)

        if inhash == row.pwhash:
            return row.get('username')
        else:
            raise ValueError('user %s or password' % clientname)

    def deploy_views(self, db):
        if self._table_exists(db, self.summary_storage_name):
            db.query('DROP VIEW %s' % self._table(self.summary_storage_name))

        db.query("""
CREATE VIEW %(summary)s AS
  SELECT *
  FROM %(utable)s u
  LEFT OUTER JOIN %(ptable)s p USING (uid) ;
;
"""
                 % dict(utable=self._table(self.client_storage_name),
                        ptable=self._table(self.passwd_storage_name),
                        summary=self._table(self.summary_storage_name))
                 )

    def deploy_upgrade(self, db, versioninfo):
        """
        Conditionally upgrade provider state.

        """
        if versioninfo.major == self.major and versioninfo.minor == self.minor:
            # nothing to do
            return None
        elif versioninfo.major == self.major and versioninfo.minor < self.minor:
            # minor updates only change the helper view definitions but not the tables?
            self.deploy_views(db)
            return True
        else:
            return False

    def deploy(self, db=None):
        """
        Deploy initial provider state.

        """
        def db_body(db):
            DatabaseConnection2.deploy(self)
            tables_added = False

            if not self._table_exists(db, self.client_storage_name):
                tables_added = True
                db.query("""
CREATE TABLE %(utable)s (
  uid serial PRIMARY KEY,
  %(username)s text UNIQUE
  %(extras)s
);
"""
                         % dict(utable=self._table(self.client_storage_name),
                                username=ID,
                                extras=','.join(self.extra_client_columns and
                                                [''] + ['%s %s' % ec for ec in self.extra_client_columns]))
                         )

            if not self._table_exists(db, self.passwd_storage_name):
                tables_added = True
                db.query("""
CREATE TABLE %(ptable)s (
  uid int PRIMARY KEY REFERENCES %(utable)s (uid) ON DELETE CASCADE,
  pwhash text,
  salthex text,
  reps int
  %(extras)s
);
"""
                         % dict(utable=self._table(self.client_storage_name),
                                ptable=self._table(self.passwd_storage_name),
                                extras=','.join(self.extra_passwd_columns and
                                                [''] + ['%s %s' % ec for ec in self.extra_passwd_columns]))
                         )

            self.deploy_guard(db, '_client')

            if tables_added:
                self.deploy_views(db)

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

class DatabaseAttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        """
        Update context with client attributes.

        This method is for providers which can derive client attributes
        directly from context.client identifier.

        """
        def db_body(db):
            if context.client != None:
                context.attributes.add(context.client)

            # expand direct user-attributes
            for row in db.query("""
SELECT a.attribute AS attribute
FROM %(uatable)s ua 
JOIN %(atable)s a USING (aid)
WHERE ua.%(username)s = %(uname)s ;
"""
                                   % dict(uatable=self.provider._table('userattribute'),
                                          atable=self.provider._table('attribute'),
                                          username=sql_identifier(ID),
                                          uname=sql_literal(context.client.get(ID)))
                                ):
                context.attributes.add(KeyedDict({ID : row.attribute, DISPLAY_NAME : row.attribute}))

            # recursively expand nested-attributes
            while True:
                results = db.query("""
SELECT p.aid, p.attribute AS attribute
FROM %(natable)s na 
JOIN %(atable)s p ON (p.aid = na.parent)
JOIN %(atable)s c ON (c.aid = na.child)
WHERE c.attribute IN ( %(attrs)s )
  AND p.attribute NOT IN ( %(attrs)s ) ;
"""
                                   % dict(natable=self.provider._table('nestedattribute'),
                                          atable=self.provider._table('attribute'),
                                          attrs=','.join([ sql_literal(a.get(ID)) for a in context.attributes ]))
                                   )
                if len(results) == 0:
                    break
                else:
                    for row in results:
                        context.attributes.add({ID : row.aid, DISPLAY_NAME : row.attribute})

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

class DatabaseAttributeSearch (AttributeSearch):

    def __init__(self, provider):
        AttributeSearch.__init__(self, provider)

    def get_all_attributes_noauthz(self, manager, context, clientnames, db=None):
        """
        Return set of all available attributes including all clientnames.

        """
        def db_body(db):
            return set([ row.attribute
                         for row in db.query("""
SELECT attribute FROM %(atable)s ;
"""
                                             % dict(atable=self.provider._table('attribute'))
                                             ) ]).union( clientnames )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

class DatabaseAttributeManage (AttributeManage):

    def __init__(self, provider):
        AttributeManage.__init__(self, provider)

    def create_noauthz(self, manager, context, attributename, db=None):
        def db_body(db):
            if self.provider._attribute_exists(db, attributename):
                return

            results = db.query("""
INSERT INTO %(atable)s (attribute) VALUES ( %(aname)s );
"""
                               % dict(atable=self.provider._table('attribute'),
                                      aname=sql_literal(attributename))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def delete_noauthz(self, manager, context, attributename, db=None):
        def db_body(db):
            if not self.provider._attribute_exists(db, attributename):
                raise KeyError(attributename)

            results = db.query("""
DELETE FROM %(atable)s WHERE attribute = %(aname)s ;
"""
                               % dict(atable=self.provider._table('attribute'),
                                      aname=sql_literal(attributename))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

class DatabaseAttributeAssign (AttributeAssign):

    def __init__(self, provider):
        AttributeAssign.__init__(self, provider)

    def list_noauthz(self, manager, context, clientname, db=None):
        def db_body(db):
            results = db.query("""
SELECT a.attribute AS attribute
FROM %(uatable)s ua
JOIN %(atable)s a USING (aid)
WHERE ua.%(username)s = %(uname)s ;
"""
                               % dict(uatable=self.provider._table('userattribute'),
                                      atable=self.provider._table('attribute'),
                                      username=ID,
                                      uname=sql_literal(clientname))
                               )

            return [ r.attribute for r in results ]

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def create_noauthz(self, manager, context, attributename, clientname, db=None):
        def db_body(db):
            if self.provider._attribute_assigned(db, attributename, clientname):
                return

            if not self.provider._attribute_exists(db, attributename):
                raise KeyError('attribute %s' % attributename)

            results = db.query("""
INSERT INTO %(uatable)s (aid, %(username)s)
  SELECT (SELECT aid FROM %(atable)s WHERE attribute = %(aname)s), %(uname)s ;
"""
                               % dict(uatable=self.provider._table('userattribute'),
                                      atable=self.provider._table('attribute'),
                                      aname=sql_literal(attributename),
                                      username=ID,
                                      uname=sql_literal(clientname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def delete_noauthz(self, manager, context, attributename, clientname, db=None):
        def db_body(db):
            if not self.provider._attribute_exists(db, attributename):
                raise KeyError('attribute %s' % attributename)

            if not self.provider._attribute_assigned(db, attributename, clientname):
                raise KeyError('attribute %s on client %s' % (attributename, clientname))

            results = db.query("""
DELETE FROM %(uatable)s ua
USING %(atable)s a
WHERE a.attribute = %(aname)s 
  AND ua.%(username)s = %(uname)s
  AND ua.aid = a.aid ;
"""
                               % dict(uatable=self.provider._table('userattribute'),
                                      atable=self.provider._table('attribute'),
                                      aname=sql_literal(attributename),
                                      username=ID,
                                      uname=sql_literal(clientname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)


class DatabaseAttributeNest (AttributeNest):

    def __init__(self, provider):
        AttributeNest.__init__(self, provider)

    def list_noauthz(self, manager, context, childname, db=None):
        def db_body(db):
            if not self.provider._attribute_exists(db, childname):
                raise KeyError('attribute %s' % childname)

            results = db.query("""
SELECT p.attribute AS attribute
FROM %(aatable)s na
JOIN %(atable)s p ON (na.parent = p.aid)
JOIN %(atable)s c ON (na.child = c.aid)
WHERE c.attribute = %(cname)s;
"""
                               % dict(aatable=self.provider._table('nestedattribute'),
                                      atable=self.provider._table('attribute'),
                                      cname=sql_literal(childname))
                               )


            return [ r.attribute for r in results ]

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def create_noauthz(self, manager, context, parentname, childname, db=None):
        def db_body(db):
            if self.provider._attribute_nested(db, parentname, childname):
                return

            if not self.provider._attribute_exists(db, parentname):
                raise KeyError('attribute %s' % parentname)

            if not self.provider._attribute_exists(db, childname):
                raise KeyError('attribute %s' % childname)

            results = db.query("""
INSERT INTO %(aatable)s (parent, child)
  SELECT (SELECT aid FROM %(atable)s WHERE attribute = %(pname)s),
         (SELECT aid FROM %(atable)s WHERE attribute = %(cname)s) ;
"""
                               % dict(aatable=self.provider._table('nestedattribute'),
                                      atable=self.provider._table('attribute'),
                                      pname=sql_literal(parentname),
                                      cname=sql_literal(childname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

    def delete_noauthz(self, manager, context, parentname, childname, db=None):
        def db_body(db):
            if not self.provider._attribute_exists(db, parentname):
                raise KeyError('attribute %s' % parentname)

            if not self.provider._attribute_exists(db, childname):
                raise KeyError('attribute %s' % childname)

            if not self.provider._attribute_nested(db, parentname, childname):
                raise KeyError('attribute %s nested in attribute %s' % (parentname, childname))

            results = db.query("""
DELETE FROM %(aatable)s na
USING %(atable)s p, %(atable)s c
WHERE p.attribute = %(pname)s 
  AND c.attribute = %(cname)s
  AND na.parent = p.aid
  AND na.child = c.aid ;
"""
                               % dict(aatable=self.provider._table('nestedattribute'),
                                      atable=self.provider._table('attribute'),
                                      pname=sql_literal(parentname),
                                      cname=sql_literal(childname))
                               )

        if db:
            return db_body(db)
        else:
            self.provider._db_wrapper(db_body)

class DatabaseAttributeProvider (AttributeProvider, DatabaseConnection2):

    key = 'database'

    # data storage format version
    major = 1
    minor = 0

    def __init__(self, config):
        AttributeProvider.__init__(self, config)
        DatabaseConnection2.__init__(self, config)
        self.client = DatabaseAttributeClient(self)
        self.search = DatabaseAttributeSearch(self)
        self.manage = DatabaseAttributeManage(self)
        self.assign = DatabaseAttributeAssign(self)
        self.nest   = DatabaseAttributeNest(self)
    
    def _attribute_exists(self, db, attributename):
        results = db.query("""
SELECT * FROM %(atable)s WHERE attribute = %(aname)s ;
"""
                           % dict(atable=self._table('attribute'),
                                  aname=sql_literal(attributename))
                           )
        return len(results) > 0

    def _attribute_assigned(self, db, attributename, clientname):
        results = db.query("""
SELECT * 
FROM %(uatable)s ua
JOIN %(atable)s a USING (aid)
WHERE a.attribute = %(aname)s 
  AND ua.%(username)s = %(uname)s ;
"""
                           % dict(uatable=self._table('userattribute'),
                                  atable=self._table('attribute'),
                                  aname=sql_literal(attributename),
                                  username=ID,
                                  uname=sql_literal(clientname))
                           )
        return len(results) > 0

    def _attribute_nested(self, db, parentname, childname):
        results = db.query("""
SELECT * 
FROM %(natable)s na
JOIN %(atable)s c ON (na.child = c.aid)
JOIN %(atable)s p ON (na.parent = p.aid)
WHERE c.attribute = %(cname)s 
  AND p.attribute = %(pname)s ;
"""
                           % dict(natable=self._table('nestedattribute'),
                                  atable=self._table('attribute'),
                                  cname=sql_literal(childname),
                                  pname=sql_literal(parentname))
                           )
        return len(results) > 0

    def deploy_views(self, db):
        if self._table_exists(db, 'attributesummary'):
            db.query("DROP VIEW %s" % self._table('attributesummary'))

        db.query("""
CREATE VIEW %(summary)s AS
  WITH RECURSIVE taa(aid, taid) AS (
      SELECT aid, aid FROM %(atable)s
    UNION
      SELECT base.aid, recur.parent
      FROM taa AS base
      JOIN %(aatable)s AS recur ON (base.taid = recur.child)
  ), 

  tua2 AS (
    SELECT ua.%(username)s AS username, array_agg(DISTINCT a.attribute) AS attributes
    FROM %(uatable)s AS ua 
    JOIN taa ON (ua.aid = taa.aid)
    JOIN %(atable)s AS a ON (taa.taid = a.aid)
    GROUP BY ua.%(username)s
  ), 

  taa2 AS (
    SELECT taa.aid AS aid, array_agg(a.attribute) AS attributes
    FROM taa 
    JOIN %(atable)s AS a ON (taa.taid = a.aid)
    GROUP BY taa.aid
  ), 

  aa2 AS (
    SELECT aa.child AS aid, array_agg(DISTINCT a.attribute) AS attributes 
    FROM (SELECT * FROM %(aatable)s UNION SELECT aid, aid FROM %(atable)s) AS aa
    JOIN %(atable)s AS a ON (aa.parent = a.aid)
    GROUP BY aa.child
  ), 

  ua2 AS (
    SELECT ua.%(username)s, array_agg(DISTINCT a.attribute) AS attributes 
    FROM %(uatable)s AS ua
    JOIN %(atable)s AS a ON (ua.aid = a.aid)
    GROUP BY ua.%(username)s
  )

  SELECT 
    ua2.%(username)s AS name,
    'client' AS type,
    ua2.attributes AS direct_attributes,
    tua2.attributes AS all_attributes
  FROM ua2
  LEFT OUTER JOIN tua2 ON (ua2.%(username)s = tua2.username)

UNION

  SELECT 
    a.attribute AS name,
    'attribute' AS type,
    aa2.attributes AS direct_attributes,
    taa2.attributes AS all_attributes
  FROM %(atable)s a
  LEFT OUTER JOIN aa2 ON (a.aid = aa2.aid)
  LEFT OUTER JOIN taa2 ON (a.aid = taa2.aid)

;
"""
                 % dict(atable=self._table('attribute'),
                        uatable=self._table('userattribute'),
                        aatable=self._table('nestedattribute'),
                        username=ID,
                        summary=self._table('attributesummary'))
                 )

    def deploy_upgrade(self, db, versioninfo):
        """
        Conditionally upgrade provider state.

        """
        if versioninfo.major == self.major and versioninfo.minor == self.minor:
            # nothing to do
            return None
        elif versioninfo.major == self.major and versioninfo.minor < self.minor:
            # minor updates only change the helper view definitions but not the tables?
            self.deploy_views(db)
            return True
        else:
            return False

    def deploy(self, db=None):
        """
        Deploy initial provider state.

        """
        def db_body(db):
            DatabaseConnection2.deploy(self)
            tables_added = False

            if not self._table_exists(db, 'attribute'):
                tables_added = True
                db.query("""
CREATE TABLE %(atable)s (
  aid serial PRIMARY KEY,
  attribute text UNIQUE
);
"""
                         % dict(atable=self._table('attribute'))
                         )

            if not self._table_exists(db, 'userattribute'):
                tables_added = True
                db.query("""
CREATE TABLE %(uatable)s (
  %(username)s text,
  aid int REFERENCES %(atable)s (aid) ON DELETE CASCADE,
  UNIQUE (%(username)s, aid)
);
"""
                         % dict(atable=self._table('attribute'),
                                username=ID,
                                uatable=self._table('userattribute'))
                         )

            if not self._table_exists(db, 'nestedattribute'):
                tables_added = True
                db.query("""
CREATE TABLE %(aatable)s (
  child int REFERENCES %(atable)s (aid) ON DELETE CASCADE,
  parent int REFERENCES %(atable)s (aid) ON DELETE CASCADE,
  UNIQUE (child, parent)
);
"""
                         % dict(atable=self._table('attribute'),
                                aatable=self._table('nestedattribute'))
                         )

            self.deploy_guard(db, '_attribute')

            if tables_added:
                self.deploy_views(db)
            
        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

class DatabasePreauthProvider (PreauthProvider):
    key = 'database'
