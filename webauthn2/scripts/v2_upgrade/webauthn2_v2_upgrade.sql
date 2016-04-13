set search_path = :myschema;

begin;

create or replace function :myschema.upgrade_goauth() returns text as $$
declare
  major_version integer;
  pw_constraint_name text;
  myschema text;
begin
  select current_schema() into myschema;
  select major into major_version from webauthn2_version_client;
  if major_version >= 2 then
     return 'user table is already at or past version 2, skipping';
  end if;

  alter table "user" rename to pre_upgrade_user;

  create table "user" (
     uid serial primary key,
     id text unique not null,
     last_login timestamp,
     last_session_extension timestamp,
     last_group_update timestamp,
     display_name text,
     full_name text,
     email text,
     id_token json,
     userinfo json,
     access_token text,
     access_token_expiration timestamp,
     refresh_token text
  );
  
  insert into "user" (
     uid,
     id,
     userinfo,
     access_token,
     access_token_expiration,
     refresh_token
  ) select
    uid,
    username,
    userinfo,
    access_token,
    access_token_expiration,
    refresh_token
  from pre_upgrade_user;
  
  with a as (
    select uid, min(x->>'username') display_name, min(x->>'full_name') full_name, min(x->>'email') email
    from (select uid, json_array_elements(userinfo) x from "user") y
    group by y.uid
  )
  update "user" u
  set
    display_name = a.display_name,
    full_name = a.full_name,
    email = a.email
  from a where a.uid = u.uid;
  
  perform setval('user_uid_seq', (select max(uid) from "user"));

  alter table session rename to pre_upgrade_session;

  create table session (
     key text,
     key_old text,
     since timestamp,
     keysince timestamp,
     expires timestamp,
     client json,
     attributes json[],
     id text,
     display_name text,
     full_name text,
     email text
  );
  
  select constraint_name into pw_constraint_name
  from information_schema.constraint_column_usage
  where table_schema = myschema and table_name = 'password' and column_name = 'uid';
  
  if pw_constraint_name is not null then
     alter table password drop constraint pw_constraint_name;
     alter table password add foreign key (uid) references "user"(uid);
  end if;

  create table oauth2_nonce_referrer (
    nonce text primary key,
    referrer text,
    timeout timestamp
  );

  create or replace view webauthn2_version_client as select 2 major, 0 minor;
  create or replace view webauthn2_version_session as select 2 major, 0 minor;
  create or replace view webauthn2_version_preauth as select 2 major, 0 minor;
  return 'upgrade successful';
end;
$$ LANGUAGE plpgsql;

select upgrade_goauth();
commit;
