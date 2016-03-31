set search_path = :new;
insert into :new.user (
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
from :old.user;

with a as (
  select uid, min(x->>'username') display_name, min(x->>'full_name') full_name, min(x->>'email') email
  from (select uid, json_array_elements(userinfo) x from :old.user) y
  group by y.uid
)
update :new.user u
set
  display_name = a.display_name,
  full_name = a.full_name,
  email = a.email
from a where a.uid = u.uid;


select setval('user_uid_seq', (select max(uid) from :new."user"));

insert into :new.attribute(aid, attribute)
  select aid, attribute from :old.attribute;

select setval('attribute_aid_seq', (select max(aid) from :new."attribute"));

insert into :new.nestedattribute (child, parent)
  select child, parent from :old.nestedattribute;

insert into :new.userattribute(id, aid)
  select id, aid from :old.userattribute;


