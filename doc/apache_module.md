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
checks that the user's session includes a group with the id `https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b`

As a convenience, you can also specify group aliases:

```
WebauthnAddGroupAlias isrd-staff https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b
Require webauthn-group isrd-staff
```
checks that the user's session includes a group whose `id` is `https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b` __and__ whose `display_name` is `isrd-staff`. The `display_name` check is a safeguard against someone cutting and pasting the wrong group id into a configuration file; it can be disabled for an alias by adding `noverify` as a third argument to `WebauthnAddGroupAlias`.

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
