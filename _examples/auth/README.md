# Zookeeper with Kerberos

## Summary
Zookeeper supports Authentication with Simple Authentication Security Layer (SASL). Both Server-Server mutual  authentication as well as Client-Server authentication. 

This example and README are here to provide an example of how the Go Zookeeper library can and supports this setup. 

## Client-Server authentication
The `docker-compose.yaml` at this point in time sets up a working example of a Client-Server Kerberos SASL configuration. This setup has the Kerberos server as a separate running container to illustrate the situation where the Zookeeper server and any client is remotely communicating to a central Kerberos server. 

    docker compose up

The current result allows the `zkCli.sh` to connect.  

    docker compose run --rm zoo-client zkCli.sh -server zoo-host

The result of this should be something like this: 

    4-06-23 21:13:29,835 [myid:] - INFO  [main:o.a.z.ZooKeeper@637] - Initiating client connection, connectString=zoo-host sessionTimeout=30000 watcher=org.apache.zookeeper.ZooKeeperMain$MyWatcher@77f99a05
    2024-06-23 21:13:29,840 [myid:] - INFO  [main:o.a.z.c.X509Util@88] - Setting -D jdk.tls.rejectClientInitiatedRenegotiation=true to disable client-initiated TLS renegotiation
    2024-06-23 21:13:30,004 [myid:] - INFO  [main:o.a.z.c.X509Util@110] - Default TLS protocol is TLSv1.3, supported TLS protocols are [TLSv1.3, TLSv1.2, TLSv1.1, TLSv1, SSLv3, SSLv2Hello]
    2024-06-23 21:13:30,012 [myid:] - INFO  [main:o.a.z.ClientCnxnSocket@233] - jute.maxbuffer value is 1048575 Bytes
    2024-06-23 21:13:30,017 [myid:] - INFO  [main:o.a.z.ClientCnxn@1726] - zookeeper.request.timeout value is 0. feature enabled=false
    Welcome to ZooKeeper!
    JLine support is enabled
    Debug is  true storeKey true useTicketCache false useKeyTab true doNotPrompt false ticketCache is null isInitiator true KeyTab is /krb/myzkclient.keytab refreshKrb5Config is false principal is myzkclient tryFirstPass is false useFirstPass is false storePass is false clearPass is false
    [zk: zoo-host(CONNECTING) 0] principal is myzkclient@EXAMPLE.COM
    Will use keytab
    Commit Succeeded

    2024-06-23 21:13:30,114 [myid:zoo-host:2181] - INFO  [main-SendThread(zoo-host:2181):o.a.z.Login@320] - Client successfully logged in.
    2024-06-23 21:13:30,116 [myid:] - INFO  [Thread-1:o.a.z.Login$1@133] - TGT refresh thread started.
    2024-06-23 21:13:30,119 [myid:zoo-host:2181] - INFO  [main-SendThread(zoo-host:2181):o.a.z.u.SecurityUtils$1@119] - Client will use GSSAPI as SASL mechanism.
    2024-06-23 21:13:30,125 [myid:] - INFO  [Thread-1:o.a.z.Login@342] - TGT valid starting at:        Sun Jun 23 21:13:30 UTC 2024
    2024-06-23 21:13:30,125 [myid:] - INFO  [Thread-1:o.a.z.Login@343] - TGT expires:                  Mon Jun 24 21:13:30 UTC 2024
    2024-06-23 21:13:30,125 [myid:] - INFO  [Thread-1:o.a.z.Login$1@199] - TGT refresh sleeping until: Mon Jun 24 17:35:08 UTC 2024
    2024-06-23 21:13:30,137 [myid:zoo-host:2181] - INFO  [main-SendThread(zoo-host:2181):o.a.z.ClientCnxn$SendThread@1162] - Opening socket connection to server zoo-host/192.168.208.3:2181.
    2024-06-23 21:13:30,137 [myid:zoo-host:2181] - INFO  [main-SendThread(zoo-host:2181):o.a.z.ClientCnxn$SendThread@1164] - SASL config status: Will attempt to SASL-authenticate using Login Context section 'Client'
    2024-06-23 21:13:30,139 [myid:zoo-host:2181] - INFO  [main-SendThread(zoo-host:2181):o.a.z.ClientCnxn$SendThread@998] - Socket connection established, initiating session, client: /192.168.208.4:55510, server: zoo-host/192.168.208.3:2181
    2024-06-23 21:13:30,147 [myid:zoo-host:2181] - INFO  [main-SendThread(zoo-host:2181):o.a.z.ClientCnxn$SendThread@1432] - Session establishment complete on server zoo-host/192.168.208.3:2181, session id = 0x10000ddf5080001, negotiated timeout = 30000

    WATCHER::

    WatchedEvent state:SyncConnected type:None path:null zxid: -1

    WATCHER::

    WatchedEvent state:SaslAuthenticated type:None path:null zxid: -1

    [zk: zoo-host(CONNECTED) 0]

### testing with cli
From here we can create znodes using Kerberos:

    [zk: zoo-host(CONNECTED) 0] create /test content sasl:myzkclient@EXAMPLE.COM:cdwra
    Created /test

And check the ACLs

    [zk: zoo-host(CONNECTED) 1] getAcl /test
    'sasl,'myzkclient@EXAMPLE.COM
    : cdrwa

### todo
In the future this will be to have a Go program demonstrating using the go-zookeeper/zk library to perform the same operations. 


## debugging

### handy `-Dsun.security.krb5.debug=true`
This option for both the server and Java client may help in debugging the principles being used. This setting gets added to the env var `JVMFLAGS`

### No valid credentials provided (Mechanism level: Server not found in Kerberos database (7) - LOOKING_UP_SERVER)
This for me ended up being that the client was assuming a server principal using a hostname in it. This example setup does not want to and is not configured with host principles, we want the same server principal for all the zookeeper server hosts. 

To find this out, I used the `-Dsun.security.krb5.debug=true` from above. 

    >>>KRBError:
         sTime is Sun Jun 23 20:19:36 UTC 2024 1719173976000
         suSec is 667799
         error code is 7
         error Message is Server not found in Kerberos database
         crealm is EXAMPLE.COM
         cname is myzkclient@EXAMPLE.COM
         sname is zookeeper/zoo-kerberos-app-zoo1-1.zoo-kerberos-app_default@EXAMPLE.COM
         msgType is 30

Notice here the `sname` including `zoo-kerberos-app-zoo1-1.zoo-kerberos-app_default`. 

To fix this I add `-Dzookeeper.server.principal=zookeeper/localhost@EXAMPLE.COM` to essentially hard code this into the client connection code what we want the server principal to be verbatim. 

    zookeeper.server.principal : Specifies the server principal to be used by the client for authentication, while connecting to the zookeeper server, when Kerberos authentication is enabled. If this configuration is provided, then the ZooKeeper client will NOT USE any of the following parameters to determine the server principal: zookeeper.sasl.client.username, zookeeper.sasl.client.canonicalize.hostname, zookeeper.server.realm Note: this config parameter is working only for ZooKeeper 3.5.7+, 3.6.0+

ref: https://zookeeper.apache.org/doc/current/zookeeperProgrammers.html

### ZooKeeper server to authenticate itself properly: javax.security.auth.login.LoginException: krb-srv-host: Name or service not known
This means the krb5 config is pointing to the kerberos-server container. In my case, the kadmind service not starting was causing the container to crash, Docker compose does not have the dns record of the stopped container. TIL. 

make sure the kerberos-server is up and running healthy. 

### javax.security.auth.login.LoginException: No password provided
This means the file is found, but is not readable from the server user. normally this is fixed with chown'ing the file to the `zookeeper` user. This user is assumed from the base Zookeeper docker container. 

or the keytab file does not exist, either one honestly. 

### Error in authenticating with a Zookeeper Quorum member: the quorum member's saslToken is null
This was from a mismatch of what principles were being attempted from the server.

I resolved with two changes to the setup, added this to both client and server java options:

    -Dzookeeper.server.principal=zookeeper/localhost@EXAMPLE.COM

As well as in the kerberos database adding a new principal 

    kadmin.local -q "addprinc -randkey zookeeper/localhost@EXAMPLE.COM"
    kadmin.local -q "ktadd -k /krb/zookeeper.keytab zookeeper/localhost"

### SASL configuration failed. Will continue connection to Zookeeper server without SASL authentication, if Zookeeper server allows it.
Debug mode again, `-Dsun.security.krb5.debug=true`

    >>> KDCCommunication: kdc=localhost UDP:88, timeout=30000,Attempt =1, #bytes=140
    [zk: zoo-host(CONNECTING) 0] >>> KrbKdcReq send: error trying localhost
    java.net.PortUnreachableException

This was an attempt at having the client krb5.conf file use localhost as if the container had host networking. Since we are not doing everything on the same instance (on purpose for this example) we need to specify the hostname for the kdc server (krb-srv-host).

<table>
<thead><tr><th>Bad</th><th>Good</th></tr></thead>
<tbody>
<tr><td>

```conf
...
[realms]
    EXAMPLE.COM = {
        kdc = localhost
        admin_server = localhost
    }
```

</td><td>

```conf
...
[realms]
    EXAMPLE.COM = {
        kdc = krb-srv-host
        admin_server = krb-srv-host
    }
```

</td></tr>
<tr><td>
localhost is not where the server is running. 
</td><td>
Ensure the client krb5.conf has the hostname where the server resides

</td></tr>

</tbody></table>

## Credits
This was possible by using others guides that ill post below
1. https://cwiki.apache.org/confluence/display/ZOOKEEPER/ZooKeeper+and+SASL
2. https://github.com/ekoontz/zookeeper/wiki
3. https://github.com/ist-dsi/docker-kerberos/tree/master
4. https://zookeeper.apache.org/doc/current/zookeeperAdmin


