@echo off
set JAR=lib\crowd-ldap-server-1.0.1-SNAPSHOT.jar
set CLASSPATH=etc
rem Apache DS Settings
set FIXADS="-Duser.language=en -Duser.country=US"

rem SSL Debugging
rem set DEBUG_SSL="-Djavax.net.debug=ssl"
set DEBUG_SSL=

rem Run Server
java.exe %FIXADS% %DEBUG_SSL% -Djava.awt.headless=true -cp %classpath% -jar %JAR% %*

