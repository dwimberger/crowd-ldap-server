#!/bin/bash
USER_UID=$1
GROUP_ID=$2
ldapsearch -v -x -D 'uid='${USER_UID}',ou=users,dc=crowd' -W -H ldap://localhost:10389 -b ou=users,dc=crowd uid=${USER_UID}
ldapsearch -WxD "uid=${USER_UID},ou=users,dc=crowd" -H ldap://localhost:10389 -b "dn=${GROUP_ID},ou=groups,dc=crowd"
