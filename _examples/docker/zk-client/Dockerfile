FROM zookeeper:latest

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -qq update
RUN apt-get -qq install krb5-user
RUN apt-get -qq clean

ADD ./krb-client-setup.sh /

ENTRYPOINT [ "/krb-client-setup.sh" ]