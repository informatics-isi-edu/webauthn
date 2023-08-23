# webauthn

[Webauthn](http://github.com/informatics-isi-edu/webauthn) is a small,
modular authentication provider framework written to support several
Python-based, RESTful web services written by our organization. It
allows deployment-time configuration of several alternative identity
and attribute provider modules to establish client security context
for web requests by talking to a local or remote provider.

## Status

[![Build Status](https://github.com/informatics-isi-edu/webauthn/actions/workflows/main.yml/badge.svg)](https://github.com/informatics-isi-edu/webauthn/actions/workflows/main.yml)


Webauthn is research software, but its core features have proven
stable enough to use in several production science projects.

## Using Webauthn

Webauthn is a server software library meant to be integrated into a
web service written in Python and using the Flask web framework.

1. Install the webauthn software and prerequisites.
2. Create a customized local JSON configuration file.
3. Perform deployment steps to configure database schemas, enable web services, etc.
4. Establish client identities and attribute bindings in the relevant providers.
5. Use the [webauthn REST API](#rest-api)
  - Check session status
  - Establish session via login sequence
  - Extend session expiration time
  - Delete session
6. Use a web service API that consumes webauthn security context
  - Service is aware of client's context (identity and attributes)
  - Service MAY refuse access to anonymous clients who lack security context
  - Service MAY apply fine-grained authorization decisions based on resource-level policies

## Installation

As root, run these convenience `Makefile` targets for development and test:

    make preinstall_centos
    make install
	make deploy

The `preinstall_centos` target may work on several Linux distributions
including CentOS 7 and recent Fedora. It is not a frequently tested
build method as most production environments choose to manage
prerequisites more explicitly and so the webauthn `install` target
does not attempt to solve those prerequisites itself.

If you wish to modify the service configuration, edit the
`~webauthn/webauthn2_config.json` (see `samples/` folder in source
tree for examples. Then, repeat the `make deploy` step so that the
database can be fully configured.

## Help and Contact

Please direct questions and comments to the [project issue tracker](https://github.com/informatics-isi-edu/webauthn/issues) at GitHub.

## Deployment Scenarios

Currently, we support a few use case scenarios using different
combinations of webauthn provider modules. Additional legacy provider
modules exist in the codebase but are not seeing regular use nor
testing.

### Standalone Database Providers

Mostly for development and testing purposes, a complete set of local
providers can be deployed:

1. Cookie-based session identifiers
2. Local database session state provider
3. Local database user identity provider with salted and hashed password storage
  - Basic HTML FORM submission for login
4. Local attribute provider

In this mode, a local administration command-line interface utility
can be used to manage the user and attribute provider content to
create client accounts and bind their security attributes. This
scenario is used in our continuous integration test suites to perform
system tests involving authenticated web clients.

The pertinent webauthn data for the JSON configuration file would be:

```
  ...
  "sessionids_provider": "webcookie", 
  "sessionstates_provider": "database", 
  "clients_provider": "database", 
  "attributes_provider": "database", 
            
  "web_cookie_name": "webauthn", 
  "web_cookie_path": "/", 
  "web_cookie_secure": true, 

  "database_schema": "webauthn2", 
  "database_type": "postgres", 
  "database_dsn": "dbname=webauthn", 
  "database_max_retries": 5
  
```

### Globus Providers

For collaborative projects, an integration with Globus Online can be
deployed:

1. Cookie-based session identifiers
2. Oauth2 variant local database session state provider
3. Globus identity provider
  - Various OAuth workflows to establish client identity
4. Globus groups provider
  - Custom Globus workflows to establish client group memberships as attributes

#### 2016 Globus Providers

The new Globus identity establishment workflow is OpenID Connect
compliant, and a generic OpenID Connect provider is under development
to use this feature natively. Once integration has been validated,
this alternate configuration will be documented here.

Support for the new Globus Groups service will also be documented here
once available.

### Pure OpenID Connect Providers

For experimentation, an integration with OpenID Connect identity
providers such as Google can be deployed:

1. Cookie-based session identifiers
2. Oauth2 variant local database session state provider
3. Oauth2 identity provider using OpenID Connect workflow
4. No group/attribute provider.

This is somewhat limiting as a configuration as the web service must
express all access policies in terms of individual client identities
rather than using group or role-based abstractions.

The pertinent webauthn data for the JSON configuration file would be:

```
  ...
  "sessionids_provider": "webcookie", 
  "sessionstates_provider": "oauth2", 
  "clients_provider": "oauth2", 
  "preauth_provider": "oauth2", 
  "attributes_provider": null, 
            
  "web_cookie_name": "webauthn", 
  "web_cookie_path": "/", 
  "web_cookie_secure": true, 
  "setheader": false,

  "database_schema": "webauthn2_oauth2", 
  "database_type": "postgres", 
  "database_dsn": "dbname=webauthn", 
  "database_max_retries": 5, 

  "oauth2_nonce_hard_timeout" : 3600,
  "oauth2_discovery_uri": "https://accounts.google.com/.well-known/openid-configuration",
  "oauth2_redirect_relative_uri": "/authn/session",
  "oauth2_client_secret_file": "/usr/local/etc/oauth2/client_secret_google.json",
  "oauth2_scope": "openid email profile",
  "oauth2_provider_sets_token_nonce": false

```

TODO: validate whether this information is still accurate.

## REST API

Webauthn contains its own REST service endpoint, so
`http://www.example.com/authn/session` might be the URL to a webauthn
session resource if deployed on your `www.example.com` server.

The API described below is assuming cookie-based session tracking as
in the security provider scenarios previously described.

### Session Status Check

The GET operation is used to check the status of the existing session.

    GET /authn/session HTTP/1.1
    Host: www.example.com
	Accept: application/json
	Cookie: webauthn=SESSION_ID_GOES_HERE

A successful response will include a JSON representation of the
current session status:

    HTTP/1.1 200 OK
    Content-Length: 180
	Content-Type: application/json

    {"attributes": [{"id": "group1", "display_name": "group1"}, {"id": "testuser", "display_name": "testuser"}], "seconds_remaining": 1792, "since": "2016-02-02 17:23:42.260959-08:00", "expires": "2016-02-02 17:53:42.260959-08:00", "client": {"id": "testuser", "display_name": "testuser"}}

The exact content of user identity or group attribute objects depends on
the configured providers.

Typical error responses:

- `404 Not Found`: indicates that there is not a current session for this client.

### Session Extension

Normally, webauthn is integrated into a web service and the client
session is extended automatically whenever that other web service is
accessed by a client with an active session credential. Session
expiration is thus based on an expiration time being exceeded with a
lack of protocol activity. In some cases, a client may be busy with
user interaction or other client-side processes and need to extend the
session without performing other web service operations.

The PUT operation is used to simulate other web service interactions
and cause extension of the session expiration time.

    PUT /authn/session HTTP/1.1
    Host: www.example.com
	Accept: application/json
	Cookie: webauthn=SESSION_ID_GOES_HERE

A successful response will include a JSON representation of the
current session status following the adjustment of the expiration time:

    HTTP/1.1 200 OK
    Content-Length: 180
	Content-Type: application/json

    {"attributes": [{"id": "group1", "display_name": "group1"}, {"id": "testuser", "display_name": "testuser"}], "seconds_remaining": 1799, "since": "2016-02-02 17:23:42.260959-08:00", "expires": "2016-02-02 18:05:44.533946-08:00", "client": {"id": "testuser", "display_name": "testuser"}}

Typical error responses:

- `404 Not Found`: indicates that there is not a current session for this client.

### Session Termination

The DELETE operation is used to logout or terminate the webauthn session.

    DELETE /authn/session HTTP/1.1
    Host: www.example.com
	Cookie: webauthn=SESSION_ID_GOES_HERE

A successful response will be empty:

    HTTP/1.1 204 No Content

Typical error responses:

- `404 Not Found`: indicates that there is not a current session for this client.

#### Termination/Establishment Loops

In certain configurations and environments, the session termination
operation may be futile or confusing:

1. The DELETE method destroys the session state in webauthn.
2. An AJAX application or other request attempts service access without security context.
3. The AJAX application or service redirects the client to the session establishment workflow.
4. When using Globus Auth or other OpenID Connect providers, the user may automatically login without further user interaction.
  - The user is still authenticated with the external Globus or OpenID Connect identity provider, e.g. via cookies that are not controlled by webauthn.
  - The user has previously selected a choice in the identity provider to remember their decision to grant access to the webauthn-enabled web server.
5. The user is again faced with an active session after having requested logout.

In deployments where aggressive or automatic login is enabled, the
AJAX application or web UI may need to track logout decisions via
additional cookies to break this loop, or perhaps hide the logout
option or otherwise advise the user that logout may be unreliable.

### Session Establishment

The workflow for session establishment depends on the provider module configuration.

#### Standalone Database Provider Workflow

The POST method is used to submit a username and password and create a
session in a single round-trip:

    POST /authn/session HTTP/1.1
    Host: www.example.com
	Content-Type: application/x-www-urlencoded
	Content-Length:

    username=testuser&password=dummypassword

A successful response has `201 Created` status, a `Set-Cookie`
response header, and a content type and body which SHOULD otherwise be
ignored as it MAY change in future code revisions:

    HTTP/1.1 201 Created
    Content-Length:
	Set-Cookie: webauthn=NEW_SESSION_ID_GOES_HERE; Path=/; secure
	Location: /authn/session/NEW_SESSION_ID_GOES_HERE
	Content-Type: text/uri-list

	NEW_SESSION_ID_GOES_HERE
	
Typical error responses:

- `409 Conflict`: An existing session was found, e.g. by `Cookie` in the request.
- `401 Unauthorized`: The client is still unauthenticated, whether due
to invalid username or password.

Note: the response status `Unauthorized` is an unfortunate misnomer
required by the HTTP standards, meaning that the client identity is
unknown and therefore the requested operation could not be performed.

#### OpenID Connect and Similar Workflow

When using the various OAuth2 OpenID Connect workflows, there is a
more complex interaction and it is assumed that this is happening in
an interactive web user agent aka a web browser:

1. Get preauthentication instructions from the service.
2. Send the user agent to an identity provider URL specific to this login attempt.
3. Do provider-specific workflow to authenticate the user with the identity provider.
4. Do provider-specific workflow to authorize the service to use the client identity.
5. Redirect the user agent to a webauthn callback URL to complete the login.
6. Redirect the user agent to an application-specific page with active session.

##### Get preauthentication instructions

The GET operation is used to start the workflow:

    GET /authn/preauth HTTP/1.1
    Host: www.example.com

A successful response sets initial cookies and contains a JSON
representation of the instructions:

    HTTP/1.1 200 OK
    Set-Cookie: oauth2_auth_nonce=NONCE_GOES_HERE; Path=/; secure
	Content-Type: application/json
	Content-Length: 255

    {"authentication_type": "oauth2", "cookie": "oauth2_auth_nonce", "redirect_url": "https://www.globus.org/OAuth?state=STATE_VALUE_GOES_HERE&redirect_uri=https%3A%2F%2Fwww.example.com%2Fauthn%2Fsession&response_type=code&client_id=exampleclient"}

TODO: document the rest of the workflow that should follow based on these instructions.

## License

Webauthn is made available as open source under the Apache License,
Version 2.0. Please see the [LICENSE file](LICENSE) for more
information.

## About Us

Webauthn is developed in the
[Informatics group](http://www.isi.edu/research_groups/informatics/home)
at the [USC Information Sciences Institute](http://www.isi.edu).
