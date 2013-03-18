from providers import *
import web

__all__ = [
    'GlobusOnlineClientProvider',
    'GlobusOnlineAttributeProvider'
    ]


class GlobusOnlineClientMsgAuthn (ClientMsgAuthn):
    
    def __init__(self, provider):
        ClientMsgAuthn.__init__(self, provider)
        
    def set_msg_context(self, manager, context, db=None):
        # make remote calls to globus nexus
        # context.client = user id
        # put attributes into context as a globusonline specific attribute
        raise NotImplementedError()


class GlobusOnlineClientProvider (ClientProvider):

    key = 'globusOnline'

    def __init__(self, config):
        ClientProvider.__init__(self, config)
        self.msgauthn = GlobusOnlineClientMsgAuthn(self)


class GlobusOnlineAttributeClient (AttributeClient):

    def __init__(self, provider):
        GlobusOnlineAttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        # get globusonline specific attribute
        raise NotImplementedError()


class GlobusOnlineAttributeProvider (AttributeProvider):

    key = 'globusOnline'

    def __init__(self, config):
        AttributeProvider.__init__(self, config)
        self.client = GlobusOnlineAttributeClient(provider)
