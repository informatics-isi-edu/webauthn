
# 
# Copyright 2012-2023 University of Southern California
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
Webauthn2 modular provider system.

`Session`
   : Base session information container.

`SessionIdProvider`
   : Abstract base class for session identifier providers.

`SessionStateProvider`
   : Abstract base class for session persistence providers.

`ClientProvider`
   : Abstract base class for client identity providers.

`AttributeProvider`
   : Abstract base class for client attribute providers.

`PreauthProvider`
   : Abstract base interface for pre-login tasks (OAuth2 authentication redirect, selecting IdP, etc.)

These base classes have interface slots that can be optionally
populated by a derived class, and each interface also has an abstract
base class available:

`ClientLogin`
   : Abstract base interface for client authentication using a login sequence.

`ClientMsgAuthn`
   : Abstract base interface for client authentication using message-borne assertions.

`ClientSearch`
   : Abstract base interface for listing available client identities.

`ClientManage`
   : Abstract base interface for managing available client identities.

`ClientPasswd`
   : Abstract base interface for managing client passwords.

`AttributeClient`
   : Abstract base interface for expanding attributes of a given client identity.

`AttributeMsgAuthn`
   : Abstract base interface for discovering attributes using message-borne assertions.

`AttributeSearch`
   : Abstract base interface for listing available attributes.

`AttributeManage`
   : Abstract base interface for managing available attributes.

`AttributeAssign`
   : Abstract base interface for managing attribute assignments to clients.

`AttributeNest`
   : Abstract base interface for managing attribute nesting/hierarchy.


General webauthn2 provider-related parameters:

`listusers_permit`
   : The list of client attributes authorized to view available users (list of strings).

`listattributes_permit`
   : The list of client attributes authorized to view available attributes (list of strings).

`manageusers_permit`
   : The list of client attributes authorized to manage users (list of strings).

`manageattributes_permit`
   : The list of client attributes authorized to manage attributes (list of strings).

`session_expiration_minutes`
   : The number of minutes into the future an inactive session lasts (int).

"""

from ..util import *

config_built_ins = web_storage(
    listusers_permit=[],
    listattributes_permit=[],
    manageusers_permit=[],
    manageattributes_permit=[],
    session_expiration_minutes=30
    )

__all__ = [
    'Session',
    'SessionIdProvider',
    'SessionStateProvider',

    'ClientProvider',
    'ClientLogin',
    'ClientMsgAuthn',
    'ClientSearch',
    'ClientManage',
    'ClientPasswd',

    'AttributeProvider',
    'AttributeClient',
    'AttributeMsgAuthn',
    'AttributeSearch',
    'AttributeManage',
    'AttributeAssign',
    'AttributeNest',

    'PreauthProvider',

    'config_built_ins',

    'ID',
    'DISPLAY_NAME',
    'FULL_NAME',
    'EMAIL',
    'REDIRECT_URL',
    'REDIRECT_PATH',
    'REDIRECT_NAME',
    'AUTHENTICATION_TYPE',
    'COOKIE',
    'LOGIN_FORM',
    'LAST_LOGIN',
    'LAST_GROUP_UPDATE',
    'LAST_SESSION_EXTENSION',
    'KeyedDict',
    'IDENTITIES'

    ]

ID="id"
DISPLAY_NAME="display_name"
FULL_NAME="full_name"
EMAIL="email"
REDIRECT_URL="redirect_url"
REDIRECT_PATH="redirect_path"
REDIRECT_NAME="redirect_name"
AUTHENTICATION_TYPE="authentication_type"
COOKIE="cookie"
LOGIN_FORM="login_form"
LAST_LOGIN="last_login"
LAST_SESSION_EXTENSION="last_session_extension"
LAST_GROUP_UPDATE="last_group_update"
IDENTITIES="identities"


class Provider (object):

    def __init__(self, config):
        self.listusers_permit = config.listusers_permit
        self.listattributes_permit = config.listattributes_permit
        self.manageusers_permit = config.manageusers_permit
        self.manageattributes_permit = config.manageattributes_permit

    def get_http_vary(self):
        return set()

    def get_discovery_info(self):
        return {}

class ProviderInterface (object):

    def __init__(self, provider):
        self.provider = provider
    
class Session (object):

    def __init__(self, keys=[], since=None, expires=None):
        self.keys = keys
        self.since = since
        self.expires = expires

    def to_dict(self):
        r = {}
        for k, v in [
                ('since', self.since),
                ('expires', self.expires),
        ]:
            if v is not None:
                r[k] = v.isoformat(' ')
        return r
        
    def __repr__(self):
        return '<%s %s>' % (type(self), dict(keys=self.keys, 
                                             since=self.since,
                                             expires=self.expires))

class SessionIdProvider (Provider):

    def __init__(self, config):
        Provider.__init__(self, config)

    def get_request_sessionids(self, manager, context, conn=None, cur=None):
        return []

    def create_unique_sessionids(self, manager, context):
        raise NotImplementedError()

    def set_request_sessionids(self, manager, context):
        pass

    def terminate(self, manager, context, conn=None, cur=None):
        """
        Destroy any persistent session id context.
        """
        raise NotImplementedError()


class SessionStateProvider (Provider):

    def __init__(self, config):
        Provider.__init__(self, config)

    def set_msg_context(self, manager, context, sessionids, conn=None, cur=None):
        """
        Load existing session state keyed by sessionids.

        Update context.keys if the canonical key is updated. The
        caller will attempt to propogate key updates to the client
        where possible, but care should be taken to provide an
        idempotent transition period where the old keys will continue
        to map to the new canonical keying.

        Optional conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When absent, the provider manages its own
        database connection as needed.

        """
        context.session = Session(sessionids)

    def new(self, manager, context, conn=None, cur=None):
        """
        Create a new persistent session state mirroring context.

        If there is a key conflict between context and provider
        storage, throw a KeyError exception.

        Optional conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When absent, the provider manages its own
        database connection as needed.

        """
        raise NotImplementedError()

    def extend(self, manager, context, conn=None, cur=None):
        """
        Update expiration time of existing session mirroring context in persistent store.

        Optional conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When absent, the provider manages its own
        database connection as needed.

        """
        raise NotImplementedError()

    def terminate(self, manager, context, conn=None, cur=None, preferred_final_url=None):
        """
        Destroy any persistent session mirroring context.

        Optional conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When absent, the provider manages its own
        database connection as needed.

        """
        raise NotImplementedError()

class PreauthProvider(Provider):
    """
    Preauth interface for pre-login tasks (OAuth2 authentication redirect, selecting IdP, etc.)
    """
    def __init__(self, config):
        Provider.__init__(self, config)

    def preauth_info(self, manager, context, conn=None, cur=None):
        """
        Return a dict with any required pre-authentication information (e.g., a web form with options).
        """
        raise NotImplementedError()

    def preauth_referrer(self):
        """
        If there's some special way of getting the original referrer, do it here.
        """
        pass

class ClientLogin (ProviderInterface):
    """
    ClientLogin interface for establishing client identity.

    """

    # Standard names for context fields that a login client might support

    standard_names = [ID, DISPLAY_NAME, FULL_NAME, EMAIL]

    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def login_keywords(self, optional=False):
        """
        Return the set of required and optional keyword args for login() method.

        If optional==True, return set of both required and optional
        keyword arguments for this provider.

        """
        return set(['username', 'password'])
    
    def login(self, manager, context, conn, cur, **kwargs):
        """
        Return username if the user can be logged in using keyword arguments.

        Parameters conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When None, the provider manages its own
        database connection as needed.

        Use companion method login_keywords() to determine supported
        and required arguments for a given provider.

        Raises TypeError if either keyword argument is absent.
        Raises KeyError if username is not found or user cannot use this application.
        Raises ValueError if password and username combination are not valid.

        It is expected that the caller will store the resulting username into context.client for reuse.

        Some providers may support or require additional keyword arguments.
        
        """
        raise NotImplementedError()

    def accepts_login_get(self):
        """
        return True if this login mechanism is required to accept login requests via GET, False otherwise.
        """
        return False

    def request_has_relevant_auth_headers(self):
        """
        return True if this login mechanism recognizes authorization headers, and the request has headers
                    that may potentially be used to authenticate it
               False otherwise
        """
        return False
        

class ClientMsgAuthn (ProviderInterface):
    """
    ClientMsgAuthn interface for augmenting request context based on message content.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)
        
    def set_msg_context(self, manager, context, conn=None, cur=None):
        """
        Update context with client identity if appropriate for provider.

        This method is for providers which can derive client identity
        directly from request context, without requiring a separate
        login sequence. For example, a provider consuming external
        message authentication data from HTTPD.

        Optional conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When absent, the provider manages its own
        database connection as needed.

        """
        pass

class ClientSearch (ProviderInterface):
    """
    ClientSearch interface for listing available clients.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def get_all_clients_noauthz(self, manager, context, conn=None, cur=None):
        """
        Return set of all available client identifiers.

        Optional conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When absent, the provider manages its own
        database connection as needed.

        """
        raise NotImplementedError()

    def get_all_clients(self, manager, context, conn=None, cur=None):
        """
        Return set of all available client identifiers or None if not allowed.

        Optional conn+cur are psycopg2 connection+cursor, presumed to
        have an active transaction, and the provider will use them
        directly as needed. When absent, the provider manages its own
        database connection as needed.

        """
        if is_authorized(context, self.provider.listusers_permit):
            # allowed
            return self.get_all_clients_noauthz(manager, context, conn, cur)
        else:
            # not allowed
            return None

class ClientManage (ProviderInterface):
    """
    ClientManage interface for adding or removing available client names.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def create_noauthz(self, manager, context, clientname, conn=None, cur=None):
        raise NotImplementedError()

    def delete_noauthz(self, manager, context, clientname, conn=None, cur=None):
        raise NotImplementedError()

    def update_noauthz(self, manager, context, clientname, conn=None, cur=None):
        raise NotImplementedError()

    def create(self, manager, context, clientname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageusers_permit):
            return self.create_noauthz(manager, context, clientname, conn, cur)
        else:
            raise ValueError('unauthorized')

    def delete(self, manager, context, clientname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageusers_permit):
            return self.delete_noauthz(manager, context, clientname, conn, cur)
        else:
            raise ValueError('unauthorized')

    def update_last_login(self, manager, context, username, conn=None, cur=None):
        raise NotImplementedError()

    def update_last_session_extension(self, manager, context, username, conn=None, cur=None):
        raise NotImplementedError()

    def update_last_group_update(self, manager, context, username, conn=None, cur=None):
        raise NotImplementedError()

class ClientPasswd (ProviderInterface):
    """
    ClientPasswd interface for managing client passwords.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def create_noauthz(self, manager, context, clientname, password=None, oldpasswd=None, conn=None, cur=None):
        raise NotImplementedError()

    def delete_noauthz(self, manager, context, clientname, conn=None, cur=None):
        raise NotImplementedError()
    
    def create(self, manager, context, clientname, password=None, oldpasswd=None, conn=None, cur=None):
        if is_authorized(context, self.provider.manageusers_permit):
            return self.create_noauthz(manager, context, clientname, password, oldpasswd, conn, cur)
        elif context.client == clientname and oldpasswd:
            return self.create_noauthz(manager, context, clientname, password, oldpasswd, conn, cur)
        else:
            raise ValueError('unauthorized')

    def delete(self, manager, context, clientname, oldpasswd=None, conn=None, cur=None):
        if is_authorized(context, self.provider.manageusers_permit):
            return self.delete_noauthz(manager, context, clientname, oldpasswd, conn, cur)
        elif context.client == clientname:
            return self.delete_noauthz(manager, context, clientname, oldpasswd, conn, cur)
        else:
            raise ValueError('unauthorized')
    

class ClientProvider (Provider):

    def __init__(self, config):
        """
        Initialize client identity provider using config parameters.

        Providers implement a set of interfaces or leave them as None
        if they do not support the interface:

        login:    implements ClientLogin API
        msgauthn: implements ClientMsgAuthn API
        search:   implements ClientSearch API
        manage:   implements ClientManage API
        passwd:   implements ClientPasswd API

        """
        Provider.__init__(self, config)
        self.login = None
        self.msgauthn = None
        self.search = None
        self.manage = None
        self.passwd = None
    def update_last_login(self, manager, context, conn=None, cur=None):
        raise NotImplementedError()

    def update_last_session_extension(self, manager, context, conn=None, cur=None):
        raise NotImplementedError()

    def update_last_group_update(self, manager, context, conn=None, cur=None):
        raise NotImplementedError()

class AttributeClient (ProviderInterface):
    """
    AttributeClient interface for augmenting request context based on context.client ID.

    """

    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def set_msg_context(self, manager, context, conn=None, cur=None):
        """
        Update context with client attributes.

        This method is for providers which can derive client attributes
        directly from context.client identifier.

        """
        raise NotImplementedError()

class AttributeMsgAuthn (ProviderInterface):
    """
    AttributeMsgAuthn interface for augmenting request context based on message content.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def set_msg_context(self, manager, context, conn=None, cur=None):
        """
        Update context with client attributes.

        This method is for providers which can derive client
        attributes directly from request context. For example, a
        provider consuming external message authentication data from
        HTTPD.

        """
        raise NotImplementedError()

class AttributeSearch (ProviderInterface):
    """
    AttributeSearch interface for listing available attributes.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def get_all_attributes_noauthz(self, manager, context, clientnames, conn=None, cur=None):
        """
        Return set of all available attributes including all clientnames.

        """
        raise NotImplementedError()

    def get_all_attributes(self, manager, context, conn=None, cur=None, includeclients=True):
        """
        Return set of all available attributes or None if not allowed.

        """
        if is_authorized(context, self.provider.listattributes_permit):
            # allowed
            if includeclients and manager.clients.search:
                clientnames = manager.clients.get_all_clients(manager, context, conn, cur)
            else:
                clientnames = None

            if clientnames == None:
                clientnames = set()

            return self.get_all_attributes_noauthz(manager, context, clientnames, conn, cur)
        else:
            # not allowed
            raise ValueError('unauthorized')

class AttributeManage (ProviderInterface):
    """
    AttributeManage interface for adding or removing available attributes.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def create_noauthz(self, manager, context, attributename, conn=None, cur=None):
        raise NotImplementedError()

    def delete_noauthz(self, manager, context, attributename, conn=None, cur=None):
        raise NotImplementedError()

    def create(self, manager, context, attributename, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit):
            return self.create_noauthz(manager, context, attributename, conn, cur)
        else:
            raise ValueError('unauthorized')

    def delete(self, manager, context, attributename, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit):
            return self.delete_noauthz(manager, context, attributename, conn, cur)
        else:
            raise ValueError('unauthorized')

class AttributeAssign (ProviderInterface):
    """
    AttributeAssign interface for assigning or removing attributes on clients.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def list_noauthz(self, manager, context, clientname, conn=None, cur=None):
        raise NotImplementedError()

    def create_noauthz(self, manager, context, attributename, clientname, conn=None, cur=None):
        raise NotImplementedError()

    def delete_noauthz(self, manager, context, attributename, clientname, conn=None, cur=None):
        raise NotImplementedError()

    def list(self, manager, context, clientname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit) or clientname == context.client:
            return self.list_noauthz(manager, context, clientname, conn, cur)
        else:
            raise ValueError('unauthorized')

    def create(self, manager, context, attributename, clientname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit):
            return self.create_noauthz(manager, context, attributename, clientname, conn, cur)
        else:
            raise ValueError('unauthorized')

    def delete(self, manager, context, attributename, clientname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit):
            return self.delete_noauthz(manager, context, attributename, clientname, conn, cur)
        else:
            raise ValueError('unauthorized')

class AttributeNest (ProviderInterface):
    """
    AttributeNest interface for nesting or unnesting attributes.

    If a child attribute is nested in a parent attribute, then
    assignment of the child to a client implicitly assigns the parent
    as well.  However, assignment of the parent to a client does not
    imply assignment of the child.

    That is, assignment and parentage is a unidirectional, transitive
    relationship.

    """
    def __init__(self, provider):
        ProviderInterface.__init__(self, provider)

    def list_noauthz(self, manager, context, childname, conn=None, cur=None):
        raise NotImplementedError()

    def create_noauthz(self, manager, context, parentname, childname, conn=None, cur=None):
        raise NotImplementedError()

    def delete_noauthz(self, manager, context, parentname, childname, conn=None, cur=None):
        raise NotImplementedError()

    def list(self, manager, context, childname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit) or childname in context.attributes:
            return self.list_noauthz(manager, context, childname, conn, cur)
        else:
            raise ValueError('unauthorized')

    def create(self, manager, context, parentname, childname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit):
            return self.create_noauthz(manager, context, parentname, childname, conn, cur)
        else:
            raise ValueError('unauthorized')

    def delete(self, manager, context, parentname, childname, conn=None, cur=None):
        if is_authorized(context, self.provider.manageattributes_permit):
            return self.delete_noauthz(manager, context, parentname, childname, conn, cur)
        else:
            raise ValueError('unauthorized')

class AttributeProvider (Provider):

    def __init__(self, config):
        """
        Initialize client attribute provider using config parameters.

        Providers implement a set of interfaces or leave them as None
        if they do not support the interface:

        client:   implements AttributeClient API
        msgauthn: implements AttributeMsgAuthn API
        search:   implements AttributeSearch API
        manage:   implements AttributeManage API
        assign:   implements AttributeAssign API
        nest:     implements AttributeNest API

        """
        Provider.__init__(self, config)
        self.client = None
        self.msgauthn = None
        self.search = None
        self.manage = None
        self.assign = None
        self.nest = None


    
class KeyedDict(dict):
    def __hash__(self):
        return (self.get(ID)).__hash__()
