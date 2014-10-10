
# 
# Copyright 2013 University of Southern California
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
Webauthn2 provider implementations using Crowd REST API version 1 for Crowd 2.1 and later

`CrowdREST1ClientProvider`
   : Client provider 'crowdrest1' supports APIs for login and search.

`CrowdREST1AttributeProvider`
   : Attribute provider 'crowdrest1' supports APIs for client-expansion and search.

Provider-specific configuration parameters:

`crowd_listusers_scope`
   : A list of groups to expand when listing available users to limit scope (list of text).

`crowd_listgroups_scope`
   : A list of groups to expand when listing available groups to limit scope (list of text).

`crowd_max_retries`
   : Maximum number of times to retry SOAP requests on transient errors (int).

`crowd_home_uri`
   : The base URI of the Crowd REST service which may include context path, e.g. /crowd.

`crowd_app_name`
   : The name of this application when authenticating with the Crowd directory.

`crowd_app_passwd`
   : The secrete of this application when authenticating with the Crowd directory.

"""

from providers import *
from webauthn2.util import *

import web

import sys
import traceback

import json
import httplib
import re

import base64

config_built_ins = web.storage(
    crowd_listusers_scope= [],
    crowd_listgroups_scope= [],
    crowd_max_retries= 5,
    crowd_home_uri= None,
    crowd_app_name= None,
    crowd_app_passwd= None
    )

__all__ = [
    'CrowdREST1ClientProvider',
    'CrowdREST1AttributeProvider',
    'config_built_ins'
    ]

class CrowdREST1ApiClient (httplib.HTTPSConnection):

    def __init__(self, config):
        self.config = config

        self.authz = 'Basic ' + base64.standard_b64encode('%s:%s' % (config.crowd_app_name, config.crowd_app_passwd))
        self.crowd_listusers_scope = frozenset(config.crowd_listusers_scope)
        self.crowd_listgroups_scope = frozenset(config.crowd_listgroups_scope)
        self.crowd_max_retries = min(0,config.crowd_max_retries)
                        
        m = re.match(r'^(?P<scheme>https)://(?P<host>[^:]+):(?P<port>[0-9]+)(?P<context>.*)$', config.crowd_home_uri)
        if not m:
            raise IndexError('Cannot determine Crowd REST server information from config.crowd_home_uri: "%s"' % config.crowd_home_uri)
        g = m.groupdict()
        self.crowd_host = g['host']
        self.crowd_port = g['port']
        self.crowd_context = g['context'].rstrip("/")

        self.api_prefix = self.crowd_context + '/rest/usermanagement/1'

        httplib.HTTPSConnection.__init__(self, self.crowd_host, self.crowd_port)

    def request(self, method, url, body=None, headers=None):
        """Initiate authenticated HTTP request.

           Adds Basic Authorization header with Crowd App credentials.

           Serializes non-text body as JSON or passes through text
           body.

           Adds JSON content-type and accept headers as defaults if no
           such headers are set by caller.
        """
        if headers is None:
            headers = dict()

        headers['Authorization'] = self.authz
        if 'Accept' not in headers:
            headers['Accept'] = 'application/json'

        if body is not None and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        if body is not None and type(body) not in [ str, unicode ]:
            body = json.dumps(body)

        return httplib.HTTPSConnection.request(self, method, self.api_prefix + url, body, headers)

    def json_request_sync(self, method, url, body=None, headers=None):
        """Perform synchronous, authenticated REST request with JSON (de)serialization of body and response.

           Returns (status, result) pair containing HTTP status and
           deserialized JSON response body if available.

           Will retry on IOError up to self.crowd_max_retries times.
        """
        retries = self.crowd_max_retries + 1
        while retries > 0:
            try:
                self.request(method, url, body, headers)
                response = self.getresponse()
                status = response.status
                result = response.read()
                response.close()
                jsonbody = result and json.loads(result) or None
                return (status, jsonbody)
            except IOError, e:
                retries -= 1
                if retries > 0:
                    web.debug('retrying after IOError: %s' % str(e))
        

    def crowd_authenticate(self, username, password):
        status, result = self.json_request_sync(
            'POST', 
            '/authentication?username=%s' % urlquote(username),
            json.dumps(dict(value=password))
            )

        if status == 200:
            if 'name' in result:
                return result['name']
        elif status == 400:
            if result.get('reason') == 'INVALID_USER_AUTHENTICATION':
                raise ValueError(result['message'])
            elif result.get('reason') == 'USER_NOT_FOUND':
                raise KeyError(result['message'])

        raise IOError('Crowd REST user authentication returned status, result: %s, %s' % (status, result))

    def crowd_users_list(self, groupname=None, include_indirect=True):
        """List users in group or all users if no group is specified."""
        if groupname:
            url = '/group/user/%s?groupname=%s' % (include_indirect and 'nested' or 'direct', urlquote(groupname))
            api = 'group-based user listing'
        else:
            url = '/search?entity-type=user'
            api = 'user search'

        status, result = self.json_request_sync('GET', url)

        if status == 200:
            return set([ u['name'] for u in result['users'] ])
        elif status == 404:
            return set()

        raise IOError('Crowd REST %s returned status, result: %s, %s' % (api, status, result))

    def crowd_groups_list(self, username=None, parentgroupname=None, include_indirect=True):
        """List groups for user or parent group or all groups if no user or parent is specified."""
        if username:
            url = '/user/group/%s?username=%s' % (include_indirect and 'nested' or 'direct', urlquote(username))
            api = 'user-based group listing'
        elif parentgroupname:
            url = '/group/child-group/%s?groupname=%s' % (include_indirect and 'nested' or 'direct', urlquote(parentgroupname))
            api = 'parentgroup-based group listing'
        else:
            url = '/search?entity-type=group'
            api = 'group search'

        status, result = self.json_request_sync('GET', url)

        if status == 200:
            return set([ g['name'] for g in result['groups'] ])
        elif status == 404:
            return set()

        raise IOError('Crowd REST %s returned status, result: %s, %s' % (api, status, result))

class CrowdREST1Login (ClientLogin):

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
        
        return self.provider.crowd_authenticate(username, password)
            

class CrowdREST1ClientSearch (ClientSearch):

    def __init__(self, provider):
        ClientSearch.__init__(self, provider)

    def get_all_clients_noauthz(self, manager, context):
        """
        Return set of all available client identifiers drawn from Crowd user names.

        """
        if self.provider.crowd_listusers_scope:
            # scope limited to specified groups
            names = set()
            for group in self.provider.crowd_listusers_scope:
                names.update( self.provider.crowd_users_list(group) )

            return names
        else:
            # unlimited scope
            return self.provider.crowd_users_list()


class CrowdREST1ClientProvider (ClientProvider, CrowdREST1ApiClient):

    key = 'crowdrest1'

    def __init__(self, config):
        ClientProvider.__init__(self, config)
        CrowdREST1ApiClient.__init__(self, config)
        self.login = CrowdREST1Login(self)
        self.search = CrowdREST1ClientSearch(self)
    
class CrowdREST1AttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        """Update context.attributes for the contex.client"""
        if context.client != None:
            context.attributes.add( context.client )
            context.attributes.update( self.provider.crowd_groups_list(context.client) )

class CrowdREST1AttributeSearch (AttributeSearch):
    
    def __init__(self, provider):
        AttributeSearch.__init__(self, provider)
        
    def get_all_attributes_noauthz(self, manager, context, clientnames):
        """
        Return set of all available attributes drawn from Crowd groups plus clientnames.

        """
        attributes = set(clientnames)
        if self.provider.crowd_listgroups_scope:
            # scope limited to specified groups
            for group in self.provider.crowd_listgroups_scope:
                attributes.add( self.provider.crowd_groups_list(parentgroupname=group) )
                attributes.add( group )
            return attributes
        else:
            # unlimited scope
            attributes.update( self.provider.crowd_groups_list() )
            return attributes

class CrowdREST1AttributeProvider (AttributeProvider, CrowdREST1ApiClient):
    
    key = 'crowdrest1'
    
    def __init__(self, config):
        AttributeProvider.__init__(self, config)
        CrowdREST1ApiClient.__init__(self, config)
        self.client = CrowdREST1AttributeClient(self)
        self.search = CrowdREST1AttributeSearch(self)

