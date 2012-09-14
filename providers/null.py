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
        SessionIdProvider(config)

class NullSessionStateProvider (SessionStateProvider):

    key = 'null'

    def __init__(self, config):
        SessionStateProvider(config)

class NullClientProvider (ClientProvider):

    key = 'null'

    def __init__(self, config):
        ClientProvider(config)

class NullAttributeProvider (AttributeProvider):

    key = 'null'

    def __init__(self, config):
        AttributeProvider(config)

