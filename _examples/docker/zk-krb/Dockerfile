FROM zookeeper:latest

EXPOSE 2181

ADD	./zk-krb-setup.sh /

ENTRYPOINT ["/zk-krb-setup.sh"]
CMD ["zkServer.sh", "start-foreground"]