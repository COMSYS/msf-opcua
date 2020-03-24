## Description
The opcua_server_config module is used to obtain security related information for OPC UA server instances which can already be accessed. The module will report available endpoints, request information about other servers this server knows about and iterate all nodes looking for writable nodes.

## Vulnerable Instances
* Any OPC UA Server instances for which authentication is already possible.

## Testing Instance
You may test this implementation against any pre-configured example OPC UA server instance, like these ones for [python-opcua](https://github.com/FreeOpcUa/python-opcua/tree/master/examples) or [open62541](https://github.com/open62541/open62541/tree/master/examples), or one of the publicly available [servers](https://github.com/node-opcua/node-opcua/wiki/publicly-available-OPC-UA-Servers-and-Clients).

In order to use certificates for authentication with your own or somebody else's set-up you may create a private key and self-signed certificates using openssl like so:
```
openssl req -x509 -newkey rsa:2048 -keyout private_key.pem  -addext "subjectAltName = URI:<Client Application URI>" -out certificate.pem -days 30 -nodes
openssl x509 -outform der -in certificate.pem -out certificate.der
```
It may be required for some server instances and OPC UA implementations that the `subjectAltName` of the certificate and the Application URI of the OPC UA client match.

## Verification Steps
0. Start msfconsole
1. Do: `use auxiliary/scanner/opcua/opcua_server_config`
2. Do: `set rhosts <IP>`
3. Do: `set rport <port>`
4. Set up the authentication method via one of the following:
   * Anonymous (default): `set authentication Anonymous` and `set username ""` and `set password ""`
   * Username and Password: `set autehtication Username` and `set username <username>` and `set password <password>`
   * Certificates: `set authentication Certificate` and `set certificate <file>` and `set privatekey <file>` and `set policy <policy>`
5. Set up the security mode and security policy of the endpoint you want to connect to:
   * None (default): `set mode None`
   * Sign: `set mode Sign` and `set policy <policy>` where policy is one of the following `Basic128Rsa15`, `Basic256`, `Basic256Sha256` and `set certificate <file>` and `set privatekey <file>`
   * SignAndEncrypt: `set mode SignAndEncrypt` and `set policy <policy>` where policy is one of the following `Basic128Rsa15`, `Basic256`, `Basic256Sha256` and `set certificate <file>` and `set privatekey <file>`
6. Do: `run`

## Options
#### applicationuri
Sets the applicationUri of the OPC UA client which is used to connect to the server. May be necessary to match the subjectAltName of the certificate. Typical format `urn:<name>` .

#### servers
If set to `true`,this server will queried for servers it knows about. Relevant in the case of connecting to an OPC UA Discovery Server.

#### nodes
If set to `true`, the entire server namespace will be iterated, showing only nodes which the current user can modify (this also includes historical write access).

#### nodesverbose
If set to `true`, the entire server namespace will be iterated, showing all nodes and the permissions of the current user.

## Scenario 
### OPC UA Server With Anonymous Authentication and Node Enumeration Enabled
```
msf5 auxiliary(scanner/opcua/opcua_server_config) > use auxiliary/scanner/opcua/opcua_server_config 
msf5 auxiliary(scanner/opcua/opcua_server_config) > set rhosts opcua.rocks
rhosts => opcua.rocks
msf5 auxiliary(scanner/opcua/opcua_server_config) > set rport 4840
rport => 4840
msf5 auxiliary(scanner/opcua/opcua_server_config) > set nodesverbose true
nodesverbose => true
msf5 auxiliary(scanner/opcua/opcua_server_config) > set servers
set servers  
msf5 auxiliary(scanner/opcua/opcua_server_config) > set servers true
servers => true
msf5 auxiliary(scanner/opcua/opcua_server_config) > run

[*] Running for 195.254.227.245...
[*] 195.254.227.245:4840 - Found Servers:
[*] 195.254.227.245:4840 - ----------------------------------------
[*] 195.254.227.245:4840 - Server: opcua.rocks Sample Server
[*] 195.254.227.245:4840 - Discovery url: opc.tcp://opcua.rocks:4840/
[*] 195.254.227.245:4840 - Available Endpoints:
[*] 195.254.227.245:4840 - ----------------------------------------
[*] 195.254.227.245:4840 - Endpoint: opc.tcp://195.254.227.245:4840
[*] 195.254.227.245:4840 - ServerName: opcua.rocks Sample Server
[*] 195.254.227.245:4840 - ApplicationUri: urn:opcua.rocks.sample-server
[*] 195.254.227.245:4840 - ProductUri: http://open62541.org
[*] 195.254.227.245:4840 - SecurityLevel: 1
[*] 195.254.227.245:4840 - MessageSecurityMode: MessageSecurityMode.None_
[*] 195.254.227.245:4840 - PolicyUri: http://opcfoundation.org/UA/SecurityPolicy#None
[*] 195.254.227.245:4840 - Token: 1
[*] 195.254.227.245:4840 - TokenType: UserTokenType.Anonymous
[*] 195.254.227.245:4840 - Token: 2
[*] 195.254.227.245:4840 - TokenType: UserTokenType.UserName
[*] 195.254.227.245:4840 - ----------------------------------------
[*] 195.254.227.245:4840 - Endpoint: opc.tcp://195.254.227.245:4840
[*] 195.254.227.245:4840 - ServerName: opcua.rocks Sample Server
[*] 195.254.227.245:4840 - ApplicationUri: urn:opcua.rocks.sample-server
[*] 195.254.227.245:4840 - ProductUri: http://open62541.org
[*] 195.254.227.245:4840 - SecurityLevel: 2
[*] 195.254.227.245:4840 - MessageSecurityMode: MessageSecurityMode.Sign
[*] 195.254.227.245:4840 - PolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15
[*] 195.254.227.245:4840 - Token: 1
[*] 195.254.227.245:4840 - TokenType: UserTokenType.Anonymous
[*] 195.254.227.245:4840 - Token: 2
[*] 195.254.227.245:4840 - TokenType: UserTokenType.UserName
...
[*] 195.254.227.245:4840 - Writable Nodes:
[*] 195.254.227.245:4840 - Name: 0:LocalTime - Id: i=17634
[*] 195.254.227.245:4840 - ['CurrentRead']
[*] 195.254.227.245:4840 - Name: 0:Auditing - Id: i=2994
[*] 195.254.227.245:4840 - ['CurrentRead']
[*] 195.254.227.245:4840 - Name: 0:NamespaceArray - Id: i=2255
[*] 195.254.227.245:4840 - ['CurrentRead']
[*] 195.254.227.245:4840 - Name: 0:ServerArray - Id: i=2254
[*] 195.254.227.245:4840 - ['CurrentRead']
[*] 195.254.227.245:4840 - Name: 0:ServiceLevel - Id: i=2267
[*] 195.254.227.245:4840 - ['CurrentRead']
...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


### OPC UA Server With Username and Password Authentication and Security Mode SignAndEncrypt
```
msf5 > use auxiliary/scanner/opcua/opcua_server_config 
msf5 auxiliary(scanner/opcua/opcua_server_config) > set rhosts localhost
rhosts => localhost
msf5 auxiliary(scanner/opcua/opcua_server_config) > set rport 4840
rport => 4840
msf5 auxiliary(scanner/opcua/opcua_login) > set certificate /home/client_cert.der
certificate => /home/client_cert.der
msf5 auxiliary(scanner/opcua/opcua_login) > set privatekey /home/client_key.der
privatekey => /home/linus/client_key.der
msf5 auxiliary(scanner/opcua/opcua_login) > set mode SignAndEncrypt
mode => SignAndEncrypt
msf5 auxiliary(scanner/opcua/opcua_server_config) > set policy Basic256Sha256
policy => Basic256Sha256
msf5 auxiliary(scanner/opcua/opcua_server_config) > set username user1
username => user1
msf5 auxiliary(scanner/opcua/opcua_server_config) > set password password
password => password

msf5 auxiliary(scanner/opcua/opcua_server_config) > run

[*] Running for 127.0.0.1...
[*] 127.0.0.1:4840 - Available Endpoints:
[*] 127.0.0.1:4840 - ----------------------------------------
[*] 127.0.0.1:4840 - Endpoint: opc.tcp://127.0.0.1:4840
[*] 127.0.0.1:4840 - ServerName: open62541-based OPC UA Application
[*] 127.0.0.1:4840 - ApplicationUri: urn:open62541.server.application
[*] 127.0.0.1:4840 - ProductUri: http://open62541.org
[*] 127.0.0.1:4840 - SecurityLevel: 2
[*] 127.0.0.1:4840 - MessageSecurityMode: MessageSecurityMode.Sign
[*] 127.0.0.1:4840 - PolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
[*] 127.0.0.1:4840 - Token: 1
[*] 127.0.0.1:4840 - TokenType: UserTokenType.Anonymous
[*] 127.0.0.1:4840 - Token: 2
[*] 127.0.0.1:4840 - TokenType: UserTokenType.UserName
[*] 127.0.0.1:4840 - ----------------------------------------
[*] 127.0.0.1:4840 - Endpoint: opc.tcp://127.0.0.1:4840
[*] 127.0.0.1:4840 - ServerName: open62541-based OPC UA Application
[*] 127.0.0.1:4840 - ApplicationUri: urn:open62541.server.application
[*] 127.0.0.1:4840 - ProductUri: http://open62541.org
[*] 127.0.0.1:4840 - SecurityLevel: 3
[*] 127.0.0.1:4840 - MessageSecurityMode: MessageSecurityMode.SignAndEncrypt
[*] 127.0.0.1:4840 - PolicyUri: http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
[*] 127.0.0.1:4840 - Token: 1
[*] 127.0.0.1:4840 - TokenType: UserTokenType.Anonymous
[*] 127.0.0.1:4840 - Token: 2
[*] 127.0.0.1:4840 - TokenType: UserTokenType.UserName
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
