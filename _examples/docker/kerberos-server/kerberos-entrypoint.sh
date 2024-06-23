#!/bin/bash
set -xe

readonly REALM="EXAMPLE.COM"
readonly KRB_PATH="/krb"

# server(s) 
readonly ZK_SERVER_PRINICPAL="zookeeper/localhost"
readonly ZK_SERVER_KEYTAB="${KRB_PATH}/zookeeper.keytab"

# client(s)
readonly ZK_CLIENT_PRINICPAL="myzkclient"
readonly ZK_CLIENT_KEYTAB="${KRB_PATH}/myzkclient.keytab"


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
		kdc = localhost
		admin_server = localhost
	}
EOF

tee /etc/krb5kdc/kdc.conf <<EOF
[realms]
	$REALM = {
		acl_file = /etc/krb5kdc/kadm5.acl
		max_renewable_life = 7d 0h 0m 0s
		default_principal_flags = +preauth
	}
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

# clean from any previous run(s). with docker you never really know. 
rm -rf "${ZK_CLIENT_KEYTAB}"
rm -rf "${ZK_SERVER_KEYTAB}"

mkdir -p "${KRB_PATH}"

echo "Adding $KADMIN_PRINCIPAL principal"
kadmin.local -q "delete_principal -force $KADMIN_PRINCIPAL_FULL"
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD $KADMIN_PRINCIPAL_FULL"

echo "Adding noPermissions principal"
kadmin.local -q "delete_principal -force noPermissions@$REALM"
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD noPermissions@$REALM"
echo ""

echo "Add Zookeeper Host principal : this one must match -Dzookeeper.server.principal the client uses."
kadmin.local -q "addprinc -randkey ${ZK_SERVER_PRINICPAL}@$REALM"
kadmin.local -q "ktadd -k ${ZK_SERVER_KEYTAB} ${ZK_SERVER_PRINICPAL}"
echo ""

echo "Add a Zookeeper client principal"
kadmin.local -q "addprinc -randkey ${ZK_CLIENT_PRINICPAL}"
kadmin.local -q "ktadd -k ${ZK_CLIENT_KEYTAB} ${ZK_CLIENT_PRINICPAL}"
echo ""

echo "Debug listing pricipals" 
kadmin.local -q "listprincs"

krb5kdc 
kadmind -nofork