#!/bin/sh
JAR=crowd-ldap-server-*.jar

# Apache DS Settings
FIXADS="-Duser.language=en -Duser.country=US"

# SSL Debugging
#DEBUG_SSL="-Djavax.net.debug=ssl"
DEBUG_SSL=

# Override etc/crowd.properties, e.g. from Docker
if [ -n "${CROWD_APP_NAME+1}" ]; then
  CROWD="-Dapplication.name=$CROWD_APP_NAME $CROWD"
fi
if [ -n "${CROWD_APP_PW+1}" ]; then
  CROWD="-Dapplication.password=$CROWD_APP_PW $CROWD"
fi
if [ -n "${CROWD_APP_URL+1}" ]; then
  CROWD="-Dapplication.login.url=$CROWD_APP_URL $CROWD"
fi
if [ -n "${CROWD_URL+1}" ]; then
  CROWD="-Dcrowd.server.url=$CROWD_URL $CROWD"
fi


# Run Server
exec java $CROWD $FIXADS $DEBUG_SSL -cp etc -jar $JAR $*
