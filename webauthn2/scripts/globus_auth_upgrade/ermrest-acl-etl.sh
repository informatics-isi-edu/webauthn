#!/bin/sh

# help convert an existing ermrest deployment to globus_auth provider

# set ADD_ISRD_STAFF=true to augment catalog ACLs w/ staff data read/write access
ADD_ISRD_STAFF=${ADD_ISRD_STAFF:-false}
# set ADD_ISRD_SYS=false to suppress augmenting catalog ACLs w/ systems ownership
ADD_ISRD_SYS=${ADD_ISRD_SYS:-true}


# for each registered catalog...
su -c "psql -q -t -A -c \"select (descriptor::json)->>'dbname' from simple_registry\" ermrest" - ermrest \
    | while read dbname
do
    # rewrite old `g:....` GUIDs as new `https://auth.globus.org/....` GUIDs
    su -c "psql -q -t -A -c \"insert into _ermrest.meta (select key, 'https://auth.globus.org/' || substring(value from 3) from _ermrest.meta where value ~ 'g:[-a-f0-9]+' except select key, value from _ermrest.meta) returning *\" \"${dbname}\"" - ermrest

    if [[ "${ADD_ISRD_STAFF}" = "true" ]]
    then
	staff='https://auth.globus.org/176baec4-ed26-11e5-8e88-22000ab4b42b'
	su -c "psql -q -t -A -c \"insert into _ermrest.meta (key, value) (values ('content_write_user', '$staff'), ('read_user', '$staff'), ('content_read_user', '$staff') except select key, value from _ermrest.meta) returning * \" $dbname" - ermrest
    fi

    if [[ "${ADD_ISRD_SYS}" = "true" ]]
    then
	systems='https://auth.globus.org/3938e0d0-ed35-11e5-8641-22000ab4b42b'
	su -c "psql -q -t -A -c \"insert into _ermrest.meta (key, value) (values ('owner', '$systems') except select key, value from _ermrest.meta) returning * \" $dbname" - ermrest
    fi

done

