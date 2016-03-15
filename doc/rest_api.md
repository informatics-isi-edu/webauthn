# Webauthn's REST API

Webauthn's REST API supports six endpoints (note: the endpoint names are 
* Endpoints that are typically used during end-user sessions
  * preauth - used for handling any required pre-authentication setup. In the future, this will be standardized enough for UI developers to rely on it for all providers; it's currently only used with OAuth-based providers.
  * session - used for authenticating end-users, establishing sessions, and discovering information about logged-in users.
* Endpoints used for management (creating users, changing passwords, assigning users to groups, etc.)
  * user - implemented by some providers to manage users.
  * password - implemented by some providers to manage passwords.
  * attribute - implemented by some provides to manage attributes (groups).

In general, a typical user session will use only the /preauth and /session endpoints.

## Endpoints used in a typical end-user session
### /preauth
#### GET /preauth
**Arguments:**

| Param | Description |
| --- | --- |
| referrer (optional) | A URI pointing to a location where the user should be redirected to after a successful authentication (typically, the page that referred the user to /preauth in the first place).|

**Relevant HTTP Headers**

| Header | Effect |
| --- | --- |
| Accept | If application/json is accepted (or if text/html is not), return a JSON structure (documented below) with hints for the UI developer. Otherwise, return whatever the installed preauth provider returns. |

**JSON return structure**

This is the current state of the structure returned by /preauth. It assumes that the desired behavior is to refer the user to remote location. In future, this will be expanded to include hints for authentication mechanisms that collect information locally (e.g., the names of parameters to collect in a username/password form).

```json
{
  "authentication-type": "preauth_provider_name",
  "cookie": "oauth2_auth_nonce",
  "redirect_uri": "uri_to_redirect_to"
}
```

| Field | Meaning |
| --- | --- |
| authentication-type | The name of the preauth provider |
| cookie | The name of a cookie, if any, that has been added to request headers. That cookie, if it exists, should be sent back to the webauthn server on subsequent requests. |
| redirect_uri | The URI that the end-user should be redirected to. |

### /session
#### POST /session
Authenticates the user and creates a login session.

**Parameters**

Login parameters are different for each provider.
* Login parameters for database provider
* Login parameters for oauth2 provider
* Login parameters for goauth provider
* Login parameters for globus_auth provider

**Responses**

| Condition | HTTP Header | Value |
| Successful login following a /preauth request with a referrer parameter | 303 See Other | *referrer* value |
| Successful login, no previously-specified referrer parameter | 201 Created | New session id |
| Request was made during an existing login session | 409 Conflict | Login request conflicts with current client authentication state. |
| Authentication failed | 401 Unauthorized | session establishment with (*provider-specific text*) failed |

#### GET /Session
Gets information about the current session (or, under certain circumstances, behaves exactly like POSt /session)

**Parameters**

If the currently-configured login provider accepts GET requests for login, and parameters are specified, then the request will be treated as if it were a POST /session request with the same parameters.

Otherwise, GET /session takes no parameters.

**Responses**

| Condition | HTTP Header | Response |
| --- | --- | --- |
| Called from within a valid session | 200 OK | JSON object described below |
| Not called from within a valid session | 404 Not Found | No existing login session found. |

**JSON return structure**

```json
{
  "seconds_remaining": ​1791,
  "since": "2016-03-14 16:47:05.049485-07:00",
  "expires": "2016-03-14 17:17:05.049485-07:00",
  "client": "https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587",
  "user": {
    "username": "https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587",
    "display_username": "laura@globusid.org",
    "name": "Laura Pearlman",
    "email": "laura@isi.edu"
  },
  "attributes": [
    "attribute_id_1",
    "attribute_id_2,
      ...
  ]
}

| Field | Always present? | Meaning |
| user | yes | Structure with information about the user's identity. |
| user.username | yes | The unique identifier associated with this end-user. This value should always be used when enforcing policies. |
| user.display_username | no | A more user-friendly version of the user's login name. If available, this usually corresponds to the username the user used when logging in. This should be used for display purposes only, not for making policy decisions. |
| user.name | no | If available, this is the user's full name. |
| user.email | no | If available, this is the user's email address. |
| attributes | yes | This is a list of the user's attributes (identities and groups). It should be used for attribute-based policy enforcement. |
| client | yes | This will have the same value as user.username. It's kept for backward-compatibility. |
| seconds_remaining | yes | The number of seconds remaining (when the response was created) for the current user session. |
| since | yes | The time the session was initiated. |
| expires | yes | The time the session expires. |

#### DELETE /session
Ends a current user session, logging the user out if possible.

**Arguments**

DELETE /session doesn't take any arguments. It does the following:

1. Invalidates the current session.
2. Calls the currently-configured logout provider. In some cases, 


