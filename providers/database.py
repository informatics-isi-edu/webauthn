"""
Webauthn2 provider implementations using private database tables.

`DatabaseSessionStateProvider`
   : Session persistence provider 'database'.

`DatabaseClientProvider`
   : Client provider 'database' supports login, search, manage, passwd APIs.

`DatabaseAttributeProvider`
   : Attribute provider 'database' supports client, search, manage, assign, nest APIs.

Provider-specific parameters for database module:

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

import web

import hmac
import random
import datetime
import pytz
import urllib
import re

config_built_ins = web.storage(
    database_name= '',
    database_type= 'postgres',
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

    def __init__(self, config):
        DatabaseConnection.__init__(self, config)

        # create a raw client early to force config errors
        self._put_pooled_connection(self._get_pooled_connection())

    def _client_exists(self, db, clientname):
        results = db.query("""
SELECT * FROM %(utable)s WHERE username = %(uname)s ;
"""
                           % dict(utable=self._table('user'),
                                  uname=sql_literal(clientname))
                           )
        return len(results) > 0

    def _client_passwd(self, db, clientname):
        results = db.query("""
SELECT
  u.uid uid,
  p.uid puid,
  u.username username,
  p.pwhash pwhash,
  p.salthex salthex,
  p.reps reps
FROM %(utable)s u
JOIN %(ptable)s p USING (uid)
WHERE u.username = %(uname)s
""" 
                           % dict(ptable=self._table('password'),
                                  utable=self._table('user'),
                                  uname=sql_literal(clientname))
                           )
        if len(results) > 0:
            return results[0]
        else:
            web.debug('no password entry for %s' % clientname)
            return None

    def _session(self, db, sessionids):
        # purge old sessions before searching for valid keys
        db.query("""
DELETE FROM %(stable)s WHERE expires < 'now'::timestamptz ;
"""
                 % dict(stable=self._table('session'))
                 )

        results = db.query("""
SELECT * FROM %(stable)s 
WHERE key IN ( %(keys)s ) OR key_old IN ( %(keys)s )
ORDER BY expires DESC ;
"""
                           % dict(stable=self._table('session'),
                                  keys=','.join([ sql_literal(k) for k in sessionids ]))
                           )
        if len(results) > 1:
            # TODO: warn about this
            pass
        if len(results) > 0:
            return results[0]
        else:
            raise KeyError(str('sessionids'))

    def _client_passwd_matches(self, db, clientname, passwd):
        row = self._client_passwd(db, clientname)
        if row == None:
            raise KeyError(username)

        inhash, salthex, reps = hash_password(passwd, row.salthex, row.reps)

        if inhash == row.pwhash:
            return row.username
        else:
            raise ValueError('user %s or password' % clientname)

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
JOIN %(utable)s u USING (uid)
WHERE a.attribute = %(aname)s 
  AND u.username = %(uname)s ;
"""
                           % dict(uatable=self._table('userattribute'),
                                  atable=self._table('attribute'),
                                  utable=self._table('user'),
                                  aname=sql_literal(attributename),
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

            if srow.attributes:
                context.attributes = set( srow.attributes )
            else:
                context.attributes = set()

            if srow.client:
                context.client = srow.client
                context.attributes.add( context.client )

        except KeyError:
            context.session = None

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

            db.query("""
INSERT INTO %(stable)s (key, since, keysince, expires, client, attributes)
  VALUES (%(key)s, %(since)s, %(since)s, %(expires)s, %(client)s, %(attributes)s) ;
"""
                     % dict(stable=self._table('session'),
                            key=sql_literal(context.session.keys[0]),
                            since=sql_literal(context.session.since),
                            expires=sql_literal(context.session.expires),
                            client=sql_literal(context.client),
                            attributes='ARRAY[%s]::text[]' % ','.join([ sql_literal(a) for a in context.attributes ]))
                     
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
            if (expires - srow.expires).seconds < 5:
                # don't update too often
                return
            db.query("""
UPDATE %(stable)s SET expires = %(expires)s WHERE key = %(key)s ;
"""
                     % dict(stable=self._table('session'),
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
                     % dict(stable=self._table('session'),
                            key=sql_literal(srow.key))

                     )

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

    def deploy(self, db=None):
        """
        Deploy initial provider state.

        """
        def db_body(db):
            DatabaseConnection2.deploy(self)

            if not self._table_exists(db, 'session'):
                db.query("""
CREATE TABLE %(stable)s (
  key text UNIQUE,
  key_old text UNIQUE,
  since timestamptz,
  keysince timestamptz,
  expires timestamptz,
  client text,
  attributes text[]
);
"""
                         % dict(stable=self._table('session'))
                         )

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

class DatabaseClientSearch (ClientSearch):

    def __init__(self, provider):
        ClientSearch.__init__(self, provider)

    def get_all_clients_noauthz(self, manager, context):
        """
        Return set of all available client identifiers.

        """
        def db_body(db):
            return set([ row.username
                         for row in db.query("""
SELECT username FROM %(utable)s ;
"""
                                             % dict(utable=self.provider._table('user'))
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
            return self.provider._client_passwd_matches(db, username, password)

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)
        
class DatabaseClientSearch (ClientSearch):

    def __init__(self, provider):
        ClientSearch.__init__(self, provider)

    def get_all_clients_noauthz(self, manager, context):
        """
        Return set of all available client identifiers.

        """
        raise NotImplementedError()

class DatabaseClientManage (ClientManage):

    def __init__(self, provider):
        ClientManage.__init__(self, provider)

    def create_noauthz(self, manager, context, clientname, db=None):
        def db_body(db):
            if self.provider._client_exists(db, clientname):
                return

            results = db.query("""
INSERT INTO %(utable)s (username) VALUES ( %(uname)s );
"""
                               % dict(utable=self.provider._table('user'),
                                      uname=sql_literal(clientname))
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
DELETE FROM %(utable)s WHERE username = %(uname)s ;
"""
                               % dict(utable=self.provider._table('user'),
                                      uname=sql_literal(clientname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

class DatabaseClientPasswd (ClientPasswd):

    def __init__(self, provider):
        ClientPasswd.__init__(self, provider)

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

            results = db.query("""
INSERT INTO %(ptable)s (uid, pwhash, salthex, reps) 
  SELECT uid, %(pwhash)s, %(salthex)s, %(reps)s
  FROM %(utable)s
  WHERE username = %(uname)s
"""
                               % dict(ptable=self.provider._table('password'),
                                      utable=self.provider._table('user'),
                                      uname=sql_literal(clientname),
                                      pwhash=sql_literal(pwhash),
                                      salthex=sql_literal(salthex),
                                      reps=sql_literal(reps))
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
WHERE u.username = %(uname)s
  AND u.uid = p.uid ;
"""
                               % dict(ptable=self.provider._table('password'),
                                      utable=self.provider._table('user'),
                                      uname=sql_literal(clientname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)

class DatabaseClientProvider (ClientProvider, DatabaseConnection2):

    key = 'database'

    def __init__(self, config):
        ClientProvider.__init__(self, config)
        DatabaseConnection2.__init__(self, config)
        self.def_passwd_len = config.def_passwd_len
        self.hash_passwd_reps = config.hash_passwd_reps
        self.login = DatabaseLogin(self)
        self.search = DatabaseClientSearch(self)
        self.manage = DatabaseClientManage(self)
        self.passwd = DatabaseClientPasswd(self)

    def deploy(self, db=None):
        """
        Deploy initial provider state.

        """
        def db_body(db):
            DatabaseConnection2.deploy(self)
            
            if not self._table_exists(db, 'user'):
                db.query("""
CREATE TABLE %(utable)s (
  uid serial PRIMARY KEY,
  username text UNIQUE
);
"""
                         % dict(utable=self._table('user'))
                         )

            if not self._table_exists(db, 'password'):
                db.query("""
CREATE TABLE %(ptable)s (
  uid int PRIMARY KEY REFERENCES %(utable)s (uid),
  pwhash text,
  salthex text,
  reps int
);
"""
                         % dict(utable=self._table('user'),
                                ptable=self._table('password'))
                         )

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
JOIN %(utable)s u USING (uid)
WHERE u.username = %(uname)s ;
"""
                                   % dict(uatable=self.provider._table('userattribute'),
                                          utable=self.provider._table('user'),
                                          atable=self.provider._table('attribute'),
                                          uname=sql_literal(context.client))
                                ):
                context.attributes.add(row.attribute)

            # recursively expand nested-attributes
            while True:
                results = db.query("""
SELECT p.attribute AS attribute
FROM %(natable)s na 
JOIN %(atable)s p ON (p.aid = na.parent)
JOIN %(atable)s c ON (c.aid = na.child)
WHERE c.attribute IN ( %(attrs)s )
  AND p.attribute NOT IN ( %(attrs)s ) ;
"""
                                   % dict(natable=self.provider._table('nestedattribute'),
                                          utable=self.provider._table('user'),
                                          atable=self.provider._table('attribute'),
                                          attrs=','.join([ sql_literal(a) for a in context.attributes ]))
                                   )
                if len(results) == 0:
                    break
                else:
                    for row in results:
                        context.attributes.add(row.attribute)

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

    def create_noauthz(self, manager, context, attributename, clientname, db=None):
        def db_body(db):
            if self.provider._attribute_assigned(db, attributename, clientname):
                return

            if not self.provider._attribute_exists(db, attributename):
                raise KeyError('attribute %s' % attributename)

            if not self.provider._client_exists(db, clientname):
                raise KeyError('user %s' % clientname)

            results = db.query("""
INSERT INTO %(uatable)s (aid, uid)
  SELECT (SELECT aid FROM %(atable)s WHERE attribute = %(aname)s),
         (SELECT uid FROM %(utable)s WHERE username = %(uname)s) ;
"""
                               % dict(uatable=self.provider._table('userattribute'),
                                      atable=self.provider._table('attribute'),
                                      utable=self.provider._table('user'),
                                      aname=sql_literal(attributename),
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

            if not self.provider._client_exists(db, clientname):
                raise KeyError('user %s' % clientname)

            if not self.provider._attribute_assigned(db, attributename, clientname):
                raise KeyError(attributename)

            results = db.query("""
DELETE FROM %(uatable)s ua
USING %(atable)s a, %(utable)s u
WHERE a.attribute = %(aname)s 
  AND u.username = %(uname)s
  AND ua.aid = a.aid
  AND ua.uid = u.uid ;
"""
                               % dict(uatable=self.provider._table('userattribute'),
                                      atable=self.provider._table('attribute'),
                                      utable=self.provider._table('user'),
                                      aname=sql_literal(attributename),
                                      uname=sql_literal(clientname))
                               )

        if db:
            return db_body(db)
        else:
            return self.provider._db_wrapper(db_body)


class DatabaseAttributeNest (AttributeNest):

    def __init__(self, provider):
        AttributeNest.__init__(self, provider)

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
  AND aa.parent = p.aid
  AND aa.child = c.aid ;
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

    def __init__(self, config):
        AttributeProvider.__init__(self, config)
        DatabaseConnection2.__init__(self, config)
        self.client = DatabaseAttributeClient(self)
        self.search = DatabaseAttributeSearch(self)
        self.manage = DatabaseAttributeManage(self)
        self.assign = DatabaseAttributeAssign(self)
        self.nest   = DatabaseAttributeNest(self)
    
    def deploy(self, db=None):
        """
        Deploy initial provider state.

        """
        def db_body(db):
            DatabaseConnection2.deploy(self)

            if not self._table_exists(db, 'attribute'):
                db.query("""
CREATE TABLE %(atable)s (
  aid serial PRIMARY KEY,
  attribute text UNIQUE
);
"""
                         % dict(atable=self._table('attribute'))
                         )

            if not self._table_exists(db, 'userattribute'):
                db.query("""
CREATE TABLE %(uatable)s (
  uid int REFERENCES %(utable)s (uid),
  aid int REFERENCES %(atable)s (aid),
  UNIQUE (uid, aid)
);
"""
                         % dict(utable=self._table('user'),
                                atable=self._table('attribute'),
                                uatable=self._table('userattribute'))
                         )

            if not self._table_exists(db, 'nestedattribute'):
                db.query("""
CREATE TABLE %(aatable)s (
  child int REFERENCES %(atable)s (aid),
  parent int REFERENCES %(atable)s (aid),
  UNIQUE (child, parent)
);
"""
                         % dict(atable=self._table('attribute'),
                                aatable=self._table('nestedattribute'))
                         )

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
    SELECT ua.uid AS uid, array_agg(DISTINCT a.attribute) AS attributes
    FROM %(uatable)s AS ua 
    JOIN taa ON (ua.aid = taa.aid)
    JOIN %(atable)s AS a ON (taa.taid = a.aid)
    GROUP BY ua.uid
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
    SELECT ua.uid, array_agg(DISTINCT a.attribute) AS attributes 
    FROM %(uatable)s AS ua
    JOIN %(atable)s AS a ON (ua.aid = a.aid)
    GROUP BY ua.uid
  )

  SELECT 
    u.username AS name,
    'client' AS type,
    ua2.attributes AS direct_attributes,
    tua2.attributes AS all_attributes
  FROM %(utable)s u
  LEFT OUTER JOIN ua2 ON (u.uid = ua2.uid)
  LEFT OUTER JOIN tua2 ON (u.uid = tua2.uid)

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
                         % dict(utable=self._table('user'),
                                atable=self._table('attribute'),
                                uatable=self._table('userattribute'),
                                aatable=self._table('nestedattribute'),
                                summary=self._table('attributesummary'))
                         )

            if self._view_exists(db, 'usersummary'):
                db.query("DROP VIEW %s" % self._table('usersummary'))

            db.query("""
CREATE VIEW %(usummary)s AS
  SELECT
    u.username AS username,
    CASE WHEN p.pwhash IS NOT NULL THEN p.pwhash || ' ' || p.salthex || ' ' || CAST(p.reps AS text)
         ELSE NULL::text
    END AS passwd,
    asum.all_attributes AS all_attributes
  FROM %(utable)s AS u
  LEFT OUTER JOIN %(ptable)s AS p ON (u.uid = p.uid)
  LEFT OUTER JOIN %(asummary)s AS asum ON (u.username = asum.name AND asum.type = 'client') ;
"""
                     % dict(usummary=self._table('usersummary'),
                            asummary=self._table('attributesummary'),
                            utable=self._table('user'),
                            ptable=self._table('password')
                            )
                     )

            

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)
