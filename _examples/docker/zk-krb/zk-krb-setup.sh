#!/bin/bash
set -ex


readonly REALM="EXAMPLE.COM"
readonly KRB_PATH="/krb"

readonly KRB_SRV_HOSTNAME=${KRB_SRV_HOSTNAME:-krb-srv-host}

# server(s) 
# TODO: maybe this value deserves a env var shared in docker compose.
# This principal name must match the -Dzookeeper.server.principal=zookeeper/localhost 
# JVM option in this setup. 
readonly ZK_SERVER_PRINICPAL="zookeeper/localhost" 
readonly ZK_SERVER_KEYTAB="${KRB_PATH}/zookeeper.keytab"

tee /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM

[realms]
	$REALM = {
		kdc = ${KRB_SRV_HOSTNAME}
        admin_server = ${KRB_SRV_HOSTNAME}
	}
EOF

tee /conf/jaas.conf <<EOF
Server {
       com.sun.security.auth.module.Krb5LoginModule required
       useKeyTab=true
       keyTab="${ZK_SERVER_KEYTAB}"
       storeKey=true
       useTicketCache=false
       debug=true
       principal="${ZK_SERVER_PRINICPAL}";
};
EOF

# zookeeper user is made form base zk docker image
chown zookeeper.zookeeper ${ZK_SERVER_KEYTAB}

# upstream zookeeper entrypoint.
exec /docker-entrypoint.sh "$@"
