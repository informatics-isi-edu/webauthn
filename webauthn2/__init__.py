
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
Webauthn2 web app security context management system.

"""

__version__ = "2.0"
__license__ = "Apache License, Version 2.0"

import exc
import rest
import manager
import providers

from rest import RestHandlerFactory

from manager import *
from util import *

import hashlib
import inspect

def source_checksum():
    """Get checksum representing the loaded module for cache management etc."""

    if manager.source_checksum is None:
        h = hashlib.md5()
        for mod in [ exc, rest, manager, util, providers,
                     providers.providers, providers.null, providers.webcookie, 
                     providers.database, providers.web ]:
            try:
                h.update( inspect.getsource( mod ) )
            except IOError:
                pass
        manager.source_checksum = h.hexdigest()

    return manager.source_checksum

__doc__ += manager.__doc__ + rest.__doc__

__all__ = [
    'RestHandlerFactory',
    'Manager',
    'Context',
    'nullmanager',
    'config_built_ins',
    'jsonReader',
    'jsonWriter',
    'jsonFileReader',
    'merge_config',
    'sql_literal',
    'sql_identifier',
    'urlquote',
    'urlunquote',
    'BadRequest',
    'PooledConnection',
    'DatabaseConnection',
    'source_checksum'
    ]

