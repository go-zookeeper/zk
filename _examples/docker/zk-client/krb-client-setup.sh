#!/bin/bash
set -x

readonly REALM="EXAMPLE.COM"

readonly KRB_PATH="/krb"
readonly ZK_CLIENT_PRINICPAL="myzkclient"
readonly ZK_CLIENT_KEYTAB="${KRB_PATH}/${ZK_CLIENT_PRINICPAL}.keytab"

tee /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    rdns = false

[realms]
	$REALM = {
		kdc = zoo1
        admin_server = zoo1
	}

[domain_realm]
 .zoo1 = EXAMPLE.COM
 zoo1 = EXAMPLE.COM
EOF

tee /conf/jaas.conf <<EOF
Client {
       com.sun.security.auth.module.Krb5LoginModule required
       useKeyTab=true
       keyTab="${ZK_CLIENT_KEYTAB}"
       storeKey=true
       useTicketCache=false
       debug=true
       serviceName="zookeeper"
       principal="$ZK_CLIENT_PRINICPAL";
};
EOF

# upstream zookeeper entrypoint.
exec /docker-entrypoint.sh "$@"
