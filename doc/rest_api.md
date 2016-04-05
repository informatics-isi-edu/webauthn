# Webauthn's REST API

Webauthn's REST API supports these endpoints:
* Endpoints that are typically used during end-user sessions
  * preauth - used for handling any required pre-authentication setup.
  * session - used for authenticating end-users, establishing sessions, and discovering information about logged-in users.
* Endpoints used for management (creating users, changing passwords, assigning users to groups, etc.)
  * user - implemented by some providers to manage users.
  * password - implemented by some providers to manage passwords.
  * attribute - implemented by some provides to manage attributes (groups).

**To log a user in**

1. Send a GET /preauth request, setting the "Accept: application/json" header.
2. If successful, the return value will be a JSON structure that contains either a "redirect_url" or "login_form" attribute. If "redirect_url" is present, redirect the user to that URL. If not, create a login form according to the parameters in "login_form" (as described below) and present that to the user.

**To log a user out**

1. Send a DELETE /session request
2. The request will return a JSON structure that includes a "redirect_url" parameter. Redirect the end-user to that URL.

Webauthn uses the following logic to determine what to set the HTTP status and `redirect_url` to:

* If there is a valid session, the HTTP status is 200 and:
  * If the provider sets a redirect URL, that value is used for redirect_url.
  * If not, then
     * If the "default_logout_path" configuration parameter is set to a relative URL (like "/chaise/search"), that's combined with the current protocol and hostname to create the redirect URL (e.g., "https://dev.isrd.isi.edu/chaise/search").
     * If the "default_logout_url" configuration parameter is set to an absolute URL (like "https://remote.server.org/some/path", that value is used.
  * If none of these is found, a ConfigurationError exception will be raised (and the user will see a 500 server error).
* If there isn't a valid session, the HTTP status is set to 404 and:
   * If the "logout_no_session_path" configuration parameter is set to a relative URL (like "/chaise/search"), that's combined with the current protocol and hostname to create the redirect URL (e.g., "https://dev.isrd.isi.edu/chaise/search").
   * If the "logout_no_session_url" configuration parameter is set to an absolute URL (like "https://remote.server.org/some/path", that value is used.
   * If the "default_logout_path" configuration parameter is set to a relative URL (like "/chaise/search"), that's combined with the current protocol and hostname to create the redirect URL (e.g., "https://dev.isrd.isi.edu/chaise/search").
   * If the "default_logout_url" configuration parameter is set to an absolute URL (like "https://remote.server.org/some/path", that value is used.
  * If none of these is found, a ConfigurationError exception will be raised (and the user will see a 500 server error).




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
  "redirect_url": "url_to_redirect_to",
  "login_form": {
     "method" : "GET or POST",
     "action" : "relative_url_for_session_handler",
     "input_fields" : [
       {"type": "argument_type", "name": "argument_name"},
            ...
       {"type": "argument_type", "name": "argument_name"}
     ]
   }
}
```

| Field | Meaning |
| --- | --- |
| authentication-type | The name of the preauth provider |
| cookie | The name of a cookie, if any, that has been added to request headers. That cookie, if it exists, should be sent back to the webauthn server on subsequent requests. |
| redirect_url | The URL that the end-user should be redirected to (only used with providers that require a redirect URI). Typically, GET /preauth will return either a redirect_uri or login_form, but not both. |
| login_form | For providers that require input from the user (e.g., the database provider, which requires a username and password), information that can be used to build an HTML form to present to the user). |
| login_form.method | The method (GET or POST) to use when the form is submitted. |
| login_form.action | Where the information collected by the form should be sent (e.g., /ermrest/authn/session). |
| login_form.input_fields | A list of name/type entries corresponding to the form arguments. Each has a "name" entry, which should be the name of the parameter (e.g., "username") and a type entry, which is the suggested input field type (e.g., "text" or "password"). |

##### Example: Output of GET /preauth with the database provider

```json
{
    "authentication-type": "database",
    "login_form": {
        "method" : "POST",
        "action": "/ermrest/authn/session",
        "input_fields": [
            {"type": "text", "name": "username"},
            {"type": "password", "name": "password"}
         ]
     }
 }
```

##### Example: Output of GET /preauth with a database provider with a custom HTML form

```json
{
   "authentication_type": "database",
   "redirect_url": "https://webauthn-dev.isi.edu/login_form.html"
}
```

##### Example: Output of GET /preauth with the oauth2 provider

```json
{
    "authentication_type": "oauth2",
    "cookie": "oauth2_auth_nonce",
    "redirect_url": "https://accounts.google.com/o/oauth2/v2/auth?and_a_very_long_set_of_arguments"
 }
 ```
    
    
### /session
#### POST /session
Authenticates the user and creates a login session.

**Parameters**

Login parameters are different for each provider. However, the preauth process should create a form or redirect URL that will result in the correct parameters being passed to the POST /session request.


**Responses**

| Condition | HTTP Header | Value |
| --- | --- | --- |
| Successful login following a /preauth request with a referrer parameter | 303 See Other | *referrer* value |
| Successful login, no previously-specified referrer parameter | 200 OK | Session information |
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
     "client": {
          "id": "https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587",
           "display_name": "laura@globusid.org",
           "full_name": "Laura Pearlman",
           "email": "laura@isi.edu"
     },
     "attributes": [
        {
            "display_name": "isrd-staff",
            "id" : "https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b"
        },
        {
            "display_name": "isrd-systems",
            "id" : "https://auth.globus.org/3938e0d0-ed35-11e5-8641-22000ab4b42b"
        }
      ...
  ]
}
```
| Field | Always present? | Meaning |
| --- | --- | --- |
| client | yes | Structure with information about the user's identity. |
| client.id | yes | The unique identifier associated with this end-user. This value should always be used when enforcing policies. |
| client.display_name | no | A more user-friendly version of the user's login name. If available, this usually corresponds to the username the user used when logging in. This should be used for display purposes only, not for making policy decisions. |
| client.full_name | no | If available, this is the user's full name. |
| client.email | no | If available, this is the user's email address. |
| attributes | yes | This is a list of the user's attributes (identities and groups). It should be used for attribute-based policy enforcement. Each attribute has an "id" field containing the unique identifier associated with this identity or group. The "id" field should be used for policy enforcement. An attribute may also have a "display_name" field (user-friendly version of the identity or group name) and, for identities, "full_name" and "email" fields. |
| seconds_remaining | yes | The number of seconds remaining (when the response was created) for the current user session. |
| since | yes | The time the session was initiated. |
| expires | yes | The time the session expires. |

#### DELETE /session

Ends a current user session, logging the user out and, if applicable, returning a URL that the user should be redirected to in order to complete the logout process at the third-party identity provicer.


**Arguments**

DELETE /session passes arguments to the underlying provider. Currently, these are used only by the globus_auth provider.

| Param | Description |
| --- | --- |
| redirect_path | A relative URL (e.g., "/chaise/logout") specifying the destination that the user should be redirected to (or that should be linked back to) by the remote IdP after the logout is complete. |
| redirect_uri | An absolute URL (e.g., "https://my.host.com/chaise/logout") specifying the destination that the user should be redirected to (or that should be linked back to) by the remote IdP after the logout is complete. This should only be used if the desired destination is on a remote host; otherwise, redirect_path should be used instead. |
| redirect_name | A user-friendly name for the destination that the user should be redirected to. Providers that provide links back use the redirect_name argument for the text to display with the link. Currently supported only by the globus_auth provider. |

These arguments are currently only supported by the globus_auth provider. They can also be specified as global defaults in the configuration file, with names preceded by globus_auth_logout (e.g., globus_auth_logout_redirect_path).

**Responses**

| Condition | HTTP Header | Value |
| --- | --- | --- |
| Logout is complete; no more action needs to be taken. | 204 No Content | |
| The user needs to be redirected to a third-party identity provider to complete the logout. | 200 OK | A json structure specifying the third-party IdP logout URL. The user should be redirected to this URL |
| The user is not logged in | 404 Not Found | existing session not found |

The post-logout json structure is:

```json
{ "logout_url" : "https://a/long/url/to/a/third-party/logout/page"}
```
