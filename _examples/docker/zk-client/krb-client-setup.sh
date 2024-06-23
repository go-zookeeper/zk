#!/bin/bash
set -ex

readonly REALM="EXAMPLE.COM"
readonly KRB_PATH="/krb"

readonly KRB_SRV_HOSTNAME=${KRB_SRV_HOSTNAME:-krb-srv-host}

# client(s)
readonly ZK_CLIENT_PRINICPAL="myzkclient"
readonly ZK_CLIENT_KEYTAB="${KRB_PATH}/myzkclient.keytab"

tee /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM

[realms]
	$REALM = {
		kdc = ${KRB_SRV_HOSTNAME}
        admin_server = ${KRB_SRV_HOSTNAME}
	}
EOF

# Used for the zkCli.sh toolchain. Demonstrate the working standard tooling. 
tee /conf/jaas.conf <<EOF
Client {
       com.sun.security.auth.module.Krb5LoginModule required
       useKeyTab=true
       keyTab="${ZK_CLIENT_KEYTAB}"
       storeKey=true
       useTicketCache=false
       debug=true
       principal="${ZK_CLIENT_PRINICPAL}";
};
EOF

# zookeeper user is made form base zk docker image
chown zookeeper.zookeeper ${ZK_CLIENT_KEYTAB}

# upstream zookeeper entrypoint.
exec /docker-entrypoint.sh "$@"
