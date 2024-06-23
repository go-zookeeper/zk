# Zookeeper with Kerberos

## Summary
Zookeeper supports Authentication with Simple Authentication Security Layer (SASL). Both Server-Server mutal authentication as well as Client-Server authentication. 

This example and README are here to provide an example of how the Go zookeeler library can and supports this setup. 

## Client-Server authentication


## debugging


### 

### javax.security.auth.login.LoginException: No password provided
This means the file is found, but is not readable from the server user. normally this is fixed with chowning the file to the zookeeper user. 

or the keytab file does not exist, either one honestly. 


### Error in authenticating with a Zookeeper Quorum member: the quorum member's saslToken is null
This was from a mismatch of what pricipals were being attempted from the server.

I resolved with two changes to the setup, added this to both client and server java options:

    -Dzookeeper.server.principal=zookeeper/localhost@EXAMPLE.COM

As well as in the kerberos database adding a new principal 

    kadmin.local -q "addprinc -randkey zookeeper/localhost@$REALM"
    kadmin.local -q "ktadd -k ${KRB_PATH}/myzkclient.keytab zookeeper/localhost"
    kadmin.local -q "ktadd -k ${ZK_SERVER_KEYTAB} zookeeper/localhost"
