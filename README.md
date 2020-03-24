# Metasploit Modules for OPC UA 

## Description
This repository contains OPC UA scanner modules as well as their respective documentation. Furthermore, a list of OPC UA specific default credentials can be found in this repository. In order to use these modules, Metasploit needs to be installed on your system. For further information on the rationale behind these scanner modules, please refer to our research paper [Assessing the Security of OPC UA Deployments](https://www.comsys.rwth-aachen.de/fileadmin/papers/2020/2020-roepert-opcua-security.pdf) presented at the [1st ITG Workshop on IT Security](https://uni-tuebingen.de/en/faculties/faculty-of-science/departments/computer-science/lehrstuehle/communication-networks/itg-itsec/2020/).

If you use any portion of our modules in your research work, please cite the following paper:

Linus Roepert, Markus Dahlmanns, Ina Berenice Fink, Jan Pennekamp and Martin Henze\
[Assessing the Security of OPC UA Deployments](https://www.comsys.rwth-aachen.de/fileadmin/papers/2020/2020-roepert-opcua-security.pdf)\
Proceedings of the 1st ITG Workshop on IT Security (ITSec), Tübingen, Germany\
April 2020.

BibTeX:
```
@inproceedings{roepert_opcua_2020,
author = {Roepert, Linus and Dahlmanns, Markus and Fink, Ina Berenice and Pennekamp, Jan and Henze, Martin},
title = {{Assessing the Security of OPC UA Deployments}},
booktitle = {Proceedings of the 1st ITG Workshop on IT Security (ITSec)},
year = {2020},
}
```

## Instructions
1. Install Metasploit using the instructions found [here](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment). You may also use Kali Linux with a pre-installed version of Metasploit.
2. If not already installed, install `python3`.
3. Install the opcua Module for python3, e.g., via pip: `pip3 install opcua`.
4. If you installed Metasploit yourself, merge the `modules` directory found in this repository with the `modules` directory in the cloned Metasploit repository. If Metasploit is pre-installed, the `modules` directory of this repository can be merged with `~/.msf4/modules`.
5. To use the supplied modules follow the respective module documentation or see the typical workflow below.

## Typical Workflow

A typical workflow could look as follows:

1. Use nmap to discover potential OPC UA servers in a (local) network.
   - `nmap -sS <IP_RANGE> -p <PORT>`
2. Use `opcua_hello` to verify that an OPC UA server runs on an open port
  - `use auxiliary/scanner/opcua/opcua_hello`
  - `set rhosts <IP>`
  - `set rport <PORT>`
  - `run`
3. Use `opcua_server_config` to get a list of endpoints on an OPC UA server.
  - `use auxiliary/scanner/opcua/opcua_server_config`
  - `set rhosts <IP>`
  - `set rport <PORT>`
  - `run`
4. Optional: Use `opcua_login` to brute-force credentials for OPC UA server instances.
  - `use auxiliary/scanner/opcua/opcua_login`
  - `set rhosts <IP>`
  - `set rport <PORT>`
  - `set userpass <username> <password>` or `set userpass file:<FILE>`
  - Optional: Set up the security mode and security policy of the endpoint you want to connect to (see `documentation/modules/auxiliary/scanner/opcua/opcua_login.md`)
  - `run`
5. Use `opcua_server_config` to obtain security related information for a specific OPC UA server.
  - `use auxiliary/scanner/opcua/opcua_server_config`
  - `set rhosts <IP>`
  - `set rport <PORT>`
  - Set up the authentication method (see `documentation/modules/auxiliary/scanner/opcua/opcua_server_config.md`)
  - Set up the security mode and security policy of the endpoint you want to connect to (see `documentation/modules/auxiliary/scanner/opcua/opcua_server_config.md`)
  - Set up information you want to retrieve from the server (`servers`, `nodes`, `nodesverbose`; see `documentation/modules/auxiliary/scanner/opcua/opcua_server_config.md`)
  - `run` 

## License

Copyright 2020 RWTH Aachen University & Fraunhofer FKIE

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

If you are planning to integrate our modules into a commercial product and do not want to disclose your source code, please contact us for other licensing options via email at martin (dot) henze (at) fkie (dot) fraunhofer (dot) de

## Acknowledgements

These modules have been developed within a cooperation between the [Chair of Communication and Distributed Systems](https://www.comsys.rwth-aachen.de/) at [RWTH Aachen University](https://www.rwth-aachen.de/) and the [Fraunhofer Institute for Communication, Information Processing and Ergonomics FKIE](https://www.fkie.fraunhofer.de/). This work has partly been funded by the Deutsche Forschungsgemeinschaft (DFG, German Research Foundation) under Germany's Excellence Strategy – EXC-2023 Internet of Production – 390621612.


