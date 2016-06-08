# The Webauthn Apache Module

The apache module can be used to specify authorization policies to be enforced by httpd. It can be used for static web pages, cgi scripts, wsgi services like ermrest and hatrac, or anything else served by httpd except for the webauthn tree (currently called `/ermrest/authn`, soon to be called `/authn`) itself. It works by calling the webauthn service to find the user's identity and other session info (including the user's group memberships). To avoid putting too heavy a burden on the webauthn service, the apache module maintains its own cache.

## Configuration

First you'll need to include some boilerplate configuration directives to tell httpd to use the webauthn module and to tell the webauthn module how to find the webauthn service:

These lines must be added to the resource configuration section (the main section, outside of any Directory or Location sections) to tell Apache to load the module and to tell the module where to find the webauthn service endpoints).

```
LoadModule webauthn_module    /usr/lib64/httpd/modules/mod_webauthn.so
WebauthnLoginPath /ermrest/authn/preauth
WebauthnSessionPath /ermrest/authn/session
```

In each `Directory` or `Location` section (or `.htaccess` file) in which you want to use the module, you'll need this line to tell httpd to use webauthn for authentication within that directory/location:

```
AuthType webauthn
```

To actually do anything with the module, you'll need some `Require` directives. There are two relevant kinds:

- `Require valid-user`
- `Require webauthn-group` _group_id_

These do pretty much what you'd expect, using the webauthn service to log the user in (if they're not logged in already) and then validate that they're authenticated (for `valid_user`) or in the specified group (for `webauthn-group`).

```
Require webauthn-group https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b
```

This checks that the user's session includes a group with the id `https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b`

As a convenience, you can also specify group aliases:

```
WebauthnAddGroupAlias isrd-staff https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b
Require webauthn-group isrd-staff
```

This checks that the user's session includes a group whose `id` is `https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b` __and__ whose `display_name` is `isrd-staff`. The `display_name` check is a safeguard against someone cutting and pasting the wrong group id into a configuration file; it can be disabled for an alias by adding `noverify` as a third argument to `WebauthnAddGroupAlias`.

The `WebauthnAddGroupAlias` directive can appear in the resource section or in `Directory` or `Location` sections or `.htaccess` files.

You can mix and match the webauthn `Require` directives the same way you can any others:

```
WebauthnAddGroupAlias isrd-staff https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b
WebauthnAddGroupAlias isrd-systems https://auth.globus.org/3938e0d0-ed35-11e5-8641-22000ab4b42b
WebauthnAddGroupAlias kidney-users https://auth.globus.org/ff766864-a03f-11e5-b097-22000aef184d
WebauthnAddGroupAlias my-made-up-alias https://auth.globus.org/55299de4-b47e-11e3-ad4b-12313d2d6e7f noverify

<RequireAny>
    <RequireAll>
       Require webauthn-group isrd-staff
       Require webauthn-group isrd-systems
    </RequireAll>
    Require webauthn-group kidney-users
    Require webauthn-group my-made-up-alias
</RequireAny>
```

This will only authorize users who are:
- in both `isrd-staff` and `isrd-systems`, or
- in `kidney-users`, or
- in `my-made-up-alias`

In addition, the `isrd-staff`, `isrd-systems`, and `kidney-users` statements will cause webauthn to check both the `id` and `display_name` for each group, but the `my-made-up-alias` statemetn will cause webauthn to check only the `id`.

## Environment Variables Set by the Module

After a successful authentication, these environment variables will be set:

variable | Value
-------- | -----
`REMOTE_USER` | The user `id` of the authenticated user
`USER_DISPLAY_NAME` | The `display_name` of the authenticated user
`WEBAUTHN_SESSION_BASE64` | A base64-encoded version of a JSON representation of the user's session data.

In addition, the utillity function `webauthn.util.session_from_environment()` can be used to read the user's session context from the environment and return it in dictionary form.

```python
>>> from webauthn2 import util
>>> sess=util.session_from_environment()
>>> sess
{'seconds_remaining': 1755, 'since': '2016-06-07 17:25:18.670424-07:00', 'expires': '2016-06-07 17:55:18.670424-07:00', 'client': {'display_name': 'laura@globusid.org', 'id': 'https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587', 'full_name': 'Laura Pearlman', 'email': 'laura@isi.edu'}, 'attributes': [{'display_name': 'birn-steering', 'id': 'https://auth.globus.org/00e4fbe0-881e-11e1-aeb3-1231380dcd5a'}, {'display_name': 'birn-developers', 'id': 'https://auth.globus.org/02659628-881e-11e1-aeb3-1231380dcd5a'}, {'display_name': 'birn-sec-task-force', 'id': 'https://auth.globus.org/07940620-881e-11e1-aeb3-1231380dcd5a'}, {'display_name': 'gpcr_academia_readers', 'id': 'https://auth.globus.org/6489c7d4-b5bf-11e5-b1f4-22000aef184d'}, {'display_name': 'BIRN Community', 'id': 'https://auth.globus.org/e34a302c-7f3b-11e1-aeb3-1231380dcd5a'}, {'display_name': 'isrd-test-4', 'id': 'https://auth.globus.org/62807020-fa9b-11e5-b07b-22000ab80e73'}, {'display_name': 'isrd-systems', 'id': 'https://auth.globus.org/3938e0d0-ed35-11e5-8641-22000ab4b42b'}, {'id': 'https://auth.globus.org/a4e08a76-d274-11e5-9a49-4bb61ffc9a24'}, {'display_name': 'nhprc-drafts', 'id': 'https://auth.globus.org/06e19382-881e-11e1-aeb3-1231380dcd5a'}, {'display_name': 'isrd-test-3', 'id': 'https://auth.globus.org/dd427e4e-fa9a-11e5-86bd-22000aef184d'}, {'display_name': 'BIRNCC', 'id': 'https://auth.globus.org/003a0a78-881e-11e1-aeb3-1231380dcd5a'}, {'display_name': 'confluence-users-birn', 'id': 'https://auth.globus.org/fedee52c-881d-11e1-aeb3-1231380dcd5a'}, {'display_name': 'birnpath_django_devel_base', 'id': 'https://auth.globus.org/05e271cc-881e-11e1-aeb3-1231380dcd5a'}, {'display_name': 'FaceBase Users', 'id': 'https://auth.globus.org/143f5bdc-c127-11e4-ab32-22000a1dd033'}, {'display_name': 'isrd-staff', 'id': 'https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b'}, {'display_name': 'laura@globusid.org', 'id': 'https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587', 'full_name': 'Laura Pearlman', 'email': 'laura@isi.edu'}, {'display_name': 'isrd-test-2', 'id': 'https://auth.globus.org/0e1d35e8-fa93-11e5-86bd-22000aef184d'}, {'id': 'https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587'}, {'display_name': 'cirm-usc', 'id': 'https://auth.globus.org/55299de4-b47e-11e3-ad4b-12313d2d6e7f'}, {'display_name': 'isrd-test-group', 'id': 'https://auth.globus.org/12c0b92c-f862-11e5-98ed-22000ab80e73'}, {'display_name': 'kidney-users', 'id': 'https://auth.globus.org/ff766864-a03f-11e5-b097-22000aef184d'}, {'display_name': 'nhprc-svn', 'id': 'https://auth.globus.org/086e724c-881e-11e1-aeb3-1231380dcd5a'}, {'id': 'https://auth.globus.org/1bb1f136-e665-11e5-b417-23b1699a1b15'}, {'display_name': 'confluence-administrators', 'id': 'https://auth.globus.org/2d3188bc-88b9-11e1-98d4-1231380dcd5a'}], 'vary_headers': ['cookie']}
```

## Logging

By default, httpd logs the user's `id` with each authenticated request. This is a standard `ssl_access_log` entry:

```
128.9.136.72 - https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587 [02/Jun/2016:19:40:13 -0700] "GET /static/hello.txt HTTP/1.1" 200 6
```

You can add `%{USER_DISPLAY_NAME}e` to a LogFormat directive to log the user's display_name:

```
128.9.136.72 - https://auth.globus.org/a4e03698-d274-11e5-9a48-8b6f49eb5587 [02/Jun/2016:19:40:13 -0700] "GET /static/hello.txt HTTP/1.1" 200 6 laura@globusid.org
```

Note: the format for `ssl_access_log` needs to be specified in `/etc/httpd/conf.d/ssl.conf` The log message above was produced by adding:

```
LogFormat "%h %l %u %t \"%r\" %>s %b %{USER_DISPLAY_NAME}e"
```

to `ssl.conf`.
