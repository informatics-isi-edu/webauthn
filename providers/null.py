
# 
# Copyright 2012 University of Southern California
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
Webauthn2 null provider stubs.



"""

from providers import *
import web

config_built_ins = web.storage()

__all__ = [
    'NullSessionIdProvider',
    'NullSessionStateProvider',
    'NullClientProvider',
    'NullAttributeProvider',
    'config_built_ins'
    ]

class NullSessionIdProvider (SessionIdProvider):
    
    key = 'null'
    
    def __init__(self, config):
        SessionIdProvider.__init__(self, config)

class NullSessionStateProvider (SessionStateProvider):

    key = 'null'

    def __init__(self, config):
        SessionStateProvider.__init__(self, config)

class NullClientProvider (ClientProvider):

    key = 'null'

    def __init__(self, config):
        ClientProvider.__init__(self, config)

class NullAttributeProvider (AttributeProvider):

    key = 'null'

    def __init__(self, config):
        AttributeProvider.__init__(self, config)

