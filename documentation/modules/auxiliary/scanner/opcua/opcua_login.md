## Description
The opcua_login module is used to brute-force credentials for OPC UA server instances allowing anonymous or username/password connections.

## Vulnerable Instances
* Any OPC UA Server instances which are not using certificates for authentication.

## Testing Instance
* You may test this implementation against any pre-configured example OPC UA server instance, like these ones for [python-opcua](https://github.com/FreeOpcUa/python-opcua/tree/master/examples) or [open62541](https://github.com/open62541/open62541/tree/master/examples), or use one of the publicly available [servers](https://github.com/node-opcua/node-opcua/wiki/publicly-available-OPC-UA-Servers-and-Clients).

In order to use certificates for authentication with your own or somebody else's set-up you may create a private key and self-signed certificates using openssl like so:
```
openssl req -x509 -newkey rsa:2048 -keyout private_key.pem  -addext "subjectAltName = URI:<Client Application URI>" -out certificate.pem -days 30 -nodes
openssl x509 -outform der -in certificate.pem -out certificate.der
```
It may be required for some server instances and OPC UA implementations that the `subjectAltName` of the certificate and the Application URI of the OPC UA client match.

## Verification Steps
0. Start msfconsole
1. Optional: Verify that the port on your target server is indeed open and receiving tcp connections
   - In Metasploit you may use `nmap -sS localhost -p 4840`
2. Do: `use auxiliary/scanner/opcua/opcua_login`
3. Do: `set rhosts localhost`
4. Do: `set rport 4840`
5. Do: `set userpass <username> <password>` or `set userpass file:<file>`
6. Set up the security mode and security policy of the endpoint you want to connect to:
   * None (default): `set mode None`
   * Sign: `set mode Sign` and `set policy <policy>` where policy is one of the following `Basic128Rsa15`, `Basic256`, `Basic256Sha256` and `set certificate <file>` and `set privatekey <file>`
   * SignAndEncrypt: `set mode SignAndEncrypt` and `set policy <policy>` where policy is one of the following `Basic128Rsa15`, `Basic256`, `Basic256Sha256` and `set certificate <file>` and `set privatekey <file>`
7. Do: `run`

An example userpass file:
```text

admin 1234567
admin admin
Admin Admin
```
Username and password combinations are separated by a space and one pair per line. A line only containing a whitespace character (line 1 in example) means no credentials are used i.e. anonymous authentication.

## Options
#### applicationuri
Sets the applicationUri of the OPC UA client which is used to connect to the server. May be necessary to match the subjectAltName of the certificate. Typical format `urn:<name>` .

## Scenario 
### OPC UA Server With Anonymous Authentication
```
msf5 > nmap -sS localhost -p 4840
[*] exec: nmap -sS localhost -p 4840

Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-21 21:23 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000059s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
4840/tcp open  opcua-tcp

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
msf5 > use auxiliary/scanner/opcua/opcua_login 
msf5 auxiliary(scanner/opcua/opcua_login) > set rhosts localhost
rhosts => localhost
msf5 auxiliary(scanner/opcua/opcua_login) > set rport 4840
rport => 4840
msf5 auxiliary(scanner/opcua/opcua_login) > set userpass file:/home/pass.txt
userpass => file:/home/pass.txt
msf5 auxiliary(scanner/opcua/opcua_login) > run

[*] Running for 127.0.0.1...
[*] 127.0.0.1:4840 - Valid OPC UA response, continue scanning
[+] 127.0.0.1:4840 - [1/4] - :  - Success
[*] 127.0.0.1:4840 - [2/4] - admin:1234567 - Failure
[*] 127.0.0.1:4840 - [3/4] - admin:admin - Failure
[*] 127.0.0.1:4840 - [4/4] - Admin:Admin - Failure
[*] Auxiliary module execution completed
```

### OPC UA Server With Username and Password Authentication and Security Mode SignAndEncrypt
```
msf5 > nmap -sS localhost -p 4840
[*] exec: nmap -sS localhost -p 4840

Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-21 21:23 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000059s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
4840/tcp open  opcua-tcp

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
msf5 > use auxiliary/scanner/opcua/opcua_login 
msf5 auxiliary(scanner/opcua/opcua_login) > set rhosts localhost
rhosts => localhost
msf5 auxiliary(scanner/opcua/opcua_login) > set rport 4840
rport => 4840
msf5 auxiliary(scanner/opcua/opcua_login) > set userpass user password1
userpass => user password1
msf5 auxiliary(scanner/opcua/opcua_login) > set mode SignAndEncrypt
mode => SignAndEncrypt
msf5 auxiliary(scanner/opcua/opcua_login) > set policy Basic256Sha256
policy => Basic256Sha256
msf5 auxiliary(scanner/opcua/opcua_login) > set certificate /home/client_cert.der
certificate => /home/client_cert.der
msf5 auxiliary(scanner/opcua/opcua_login) > set privatekey /home/client_key.der
privatekey => /home/linus/client_key.der
msf5 auxiliary(scanner/opcua/opcua_login) > set applicationuri urn:client.application
applicationuri => urn:client.application
[*] Running for 127.0.0.1...
[*] 127.0.0.1:4840 - Valid OPC UA response, continue scanning
[+] 127.0.0.1:4840 - [1/1] - user1:password - Success
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
