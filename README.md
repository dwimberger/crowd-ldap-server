# Crowd LDAP Server

Implementation of an LDAP server that delegates authentication to an 
[Atlassian Crowd](https://www.atlassian.com/software/crowd/overview) installation
using the Crowd REST API. 

This service allows your favourite SSO authentication source to be used from many legacy devices, appliances and systems.

The LDAP implementation is based on the [Apache Directory Server](https://directory.apache.org/) v1.5.7,  
which is distributed under the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## License

This application is licenced under the [Apache License v2.0](LICENSE.txt).


## Building

To build this source code, you will need [Apache Maven 3](https://maven.apache.org/download.html) and 
[Java JDK 7](http://www.oracle.com/technetwork/java/javase/downloads/) or newer.

Then run:

    mvn clean install



## Configuration

You will need to edit `etc/crowd.properties` to specify the connection details of the 
Crowd server after 
[adding an application to Crowd](https://confluence.atlassian.com/display/CROWD/Adding+an+Application)

If you are running `run.sh` you can alternatively set the configuration using these shell variables:

    CROWD_APP_NAME 
    CROWD_APP_PW 
    CROWD_APP_URL 
    CROWD_URL 

You can configure the LDAP port (default: 10389) and enable SSL in `etc/crowd-ldap-server.properties`


## Running

You can run this service by executing:

    ./run.sh

or on Windows:

    run.bat

## Docker image

This application is also available as an [Docker](https://www.docker.com/) image.

To build the Docker image:

    docker build -t crowd-ldap-server .

To run the image you will need to expose the port `10389` and specify the environment variables:
    
    docker run -p 10389:10389 -e CROWD_URL=http://crowd.example.com:8095/crowd -e CROWD_APP_PW s3cret crowd-ldap-server 

The default variables are:

    CROWD_APP_NAME crowd-ldap-server
    CROWD_APP_PW crowd-ldap-server
    CROWD_APP_URL http://crowd:8095/
    CROWD_URL http://crowd:8095/crowd

This can thus be combined with the 
[atlassian-crowd](https://registry.hub.docker.com/u/durdn/atlassian-crowd/) docker image:

    docker run -p 8095:8095 --name crowd griff/crowd

After setting up http://localhost:8095/crowd with a valid license, you can 
[add an application to Crowd](https://confluence.atlassian.com/display/CROWD/Adding+an+Application) for
`crowd-ldap-server` as a _Generic Application_. 

For the _URL_ field either use `http://example.com/` (as the LDAP server has not got a web interface) or 
the URL of the service that ultimately will be using the LDAP server.

For the _Remote Address_ field you should set the IP address as a range `172.17.0.0/16` 
as Docker will allocate virtual IP addresses dynamically. Note that the
actual range will vary per host.
    
To determine the IP address range, try

    $ docker run busybox head -n1 /etc/hosts
    172.17.0.21 1489e30925d0

Finally start the `crowd-ldap-server` container:

    docker run --link crowd:crowd -p 10389:10389 -e CROWD_APP_PW s3cret crowd-ldap-server

