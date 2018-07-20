FROM java:8-jre
EXPOSE 10389
ADD crowd-ldap-server-2.0.0.jar /crowd-ldap-server-2.0.0.jar
ADD start.sh /start.sh
ADD etc /etc/

ENV CROWD_APP_NAME ldap
ENV CROWD_APP_PW ldap@password
ENV CROWD_APP_URL https://id.simpleway.global/crowd
ENV CROWD_URL https://id.simpleway.global/crowd/services

CMD ["/start.sh"]
