#!/bin/sh
JAR=target/crowd-ldap-server-1.0.4-SNAPSHOT.jar

# Apache DS Settings
FIXADS="-Duser.language=en -Duser.country=US"

# SSL Debugging
#DEBUG_SSL="-Djavax.net.debug=ssl"
DEBUG_SSL=

# Run Server
java $FIXADS $DEBUG_SSL -cp etc -jar $JAR $*

