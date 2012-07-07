#!/bin/bash
USER_UID=<Crowd user>
ldapsearch -v -x -D 'uid='${USER_UID}',ou=users,dc=crowd' -W -H ldaps://localhost:10389 -b ou=users,dc=crowd uid=${USER_UID}
