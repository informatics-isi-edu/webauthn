"""
webauthn2 exceptions. webauthn2.rest provides handlers that map these
to rest/HTTP errors, defined in webauthn2.util.
"""

class Webauthn2Exception(Exception):
    pass


class ConfigError(Webauthn2Exception):
    """Raise in Provider classes if the provider configuration is invalid"""
    pass


class AuthnFailed(Webauthn2Exception):
    """Raise if authentication failed and none of the subclasses are appropriate"""
    pass


class UserNotFound(AuthnFailed):
    """Raise if the user was not found"""
    pass


class InvalidCredentials(AuthnFailed):
    """Raise if credentials are missing or not well formed"""
    pass


class InternalError(Webauthn2Exception):
    """Raise when an unexpected error is encountered on the server, e.g.
    unable to contact auth server."""
    pass
