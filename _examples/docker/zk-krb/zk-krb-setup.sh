#!/bin/bash

readonly REALM="EXAMPLE.COM"

readonly KRB_PATH="/krb"
readonly ZK_SERVER_PRINICPAL="zookeeper/localhost"
readonly ZK_SERVER_KEYTAB="${KRB_PATH}/zookeeper.keytab"

KADMIN_PRINCIPAL_FULL=$KADMIN_PRINCIPAL@$REALM

echo "REALM: $REALM"
echo "KADMIN_PRINCIPAL_FULL: $KADMIN_PRINCIPAL_FULL"
echo "KADMIN_PASSWORD: $KADMIN_PASSWORD"
echo ""


tee /etc/krb5.conf <<EOF
[libdefaults]
	default_realm = $REALM
	ticket_lifetime = 24h
	renew_lifetime = 7d
	forwardable = true

[realms]
	$REALM = {
		kdc_ports = 88,750
		kadmind_port = 749
		kdc = zoo1
		admin_server = zoo1
	}

[domain_realm]
 .zoo1 = EXAMPLE.COM
 zoo1 = EXAMPLE.COM
EOF

tee /etc/krb5kdc/kdc.conf <<EOF
[realms]
	$REALM = {
		acl_file = /etc/krb5kdc/kadm5.acl
		max_renewable_life = 7d 0h 0m 0s
		default_principal_flags = +preauth
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
       principal="${ZK_SERVER_PRINICPAL}@EXAMPLE.COM";
};
EOF

tee /etc/krb5kdc/kadm5.acl <<EOF
$KADMIN_PRINCIPAL_FULL *
noPermissions@$REALM X
EOF

MASTER_PASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
# This command also starts the krb5-kdc and krb5-admin-server services
krb5_newrealm <<EOF
$MASTER_PASSWORD
$MASTER_PASSWORD
EOF
echo ""

rm -rf "${KRB_PATH}/"
mkdir -p "${KRB_PATH}"

echo "Adding $KADMIN_PRINCIPAL principal"
kadmin.local -q "delete_principal -force $KADMIN_PRINCIPAL_FULL"
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD $KADMIN_PRINCIPAL_FULL"

echo "Adding noPermissions principal"
kadmin.local -q "delete_principal -force noPermissions@$REALM"
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD noPermissions@$REALM"
echo ""

echo "Add Zookeeper Host principal"
kadmin.local -q "addprinc -randkey zookeeper/localhost@$REALM"
kadmin.local -q "ktadd -k ${KRB_PATH}/myzkclient.keytab zookeeper/localhost"
kadmin.local -q "ktadd -k ${ZK_SERVER_KEYTAB} zookeeper/localhost"
echo ""

kadmin.local -q "addprinc -randkey zookeeper/null@$REALM"
kadmin.local -q "ktadd -k ${KRB_PATH}/myzkclient.keytab zookeeper/null@$REALM"
kadmin.local -q "ktadd -k ${ZK_SERVER_KEYTAB} zookeeper/null@$REALM"

echo "Add a Zookeeper client principal"
kadmin.local -q "addprinc -randkey myzkclient"
kadmin.local -q "ktadd -k ${KRB_PATH}/myzkclient.keytab myzkclient"
echo ""

# zookeeper user is made form base zk docker image
chown -R  zookeeper.zookeeper ${KRB_PATH}

echo "Debug listing pricipals" 
kadmin.local -q "listprincs"

krb5kdc 
kadmind

# upstream zookeeper entrypoint.
exec /docker-entrypoint.sh "$@"
