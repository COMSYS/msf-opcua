## Description
The opcua_hello module is used to locate OPC UA instances by trying to perform and HEL/ACK message exchange.

## Vulnerable Instances
* Any OPC UA Server.

## Testing Instance
* You may test this implementation against any pre-configured example OPC UA server instance, like these ones for [python-opcua](https://github.com/FreeOpcUa/python-opcua/tree/master/examples) or [open62541](https://github.com/open62541/open62541/tree/master/examples), or use one of the publicly available [servers](https://github.com/node-opcua/node-opcua/wiki/publicly-available-OPC-UA-Servers-and-Clients).

## Verification Steps
0. Start msfconsole
1. Optional: Verify that the port on your target server is indeed open and receiving tcp connections
   - In Metasploit you may use `nmap -sS localhost -p 4840`
2. Do: `use auxiliary/scanner/opcua/opcua_hello`
3. Do: `set rhosts localhost`
4. Do: `set rport 4840`
5. Do: `run`

## Scenario 
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
msf5 > use auxiliary/scanner/opcua/opcua_hello 
msf5 auxiliary(scanner/opcua/opcua_hello) > set rhosts localhost
rhosts => localhost
msf5 auxiliary(scanner/opcua/opcua_hello) > set rport 4840
rport => 4840
msf5 auxiliary(scanner/opcua/opcua_hello) > run

[*] Running for 127.0.0.1...
[*] 127.0.0.1:4840 - Success
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
