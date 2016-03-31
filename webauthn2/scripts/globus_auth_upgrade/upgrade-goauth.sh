usage="Usage: $0 old_goauth_schema new_goauth_schema [db]"

db=

if [ $# -lt 2 ]; then
   echo $usage
   exit 1
fi

old=$1; shift
new=$1; shift
if [ $# -gt 0 ]; then
   db=$1; shift
fi

psql -v old="$old" -v new="$new" -f upgrade_goauth.sql $db
