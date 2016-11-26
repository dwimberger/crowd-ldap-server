#!/bin/sh
JAR=target/crowd-ldap-server-1.0.2-SNAPSHOT.jar
rm -rf work
jar -xvf  $JAR work/schema
