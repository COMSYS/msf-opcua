#!/usr/bin/env python3
# -*- coding: utf-8 -
# Note, works with Python 3 only

import logging
import os.path

# extra modules
dependencies_missing = False
try:
    import opcua
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    "name": "OPC UA server configuration scanner",
    "description": """
    This module connects and authenticates to an OPC UA server
    (anonymously, via password and username or via private key
    and certificate) and gathers all security relevant information
    """,
    "authors": ["Linus Roepert <roepert@comsys.rwth-aachen.de>",],
    "date": "2020-01-15",
    "references": [
        {
            "type": "url",
            "ref": "https://www.comsys.rwth-aachen.de/fileadmin/papers/2020/2020-roepert-opcua-security.pdf"
        },
        {"type": "url", "ref": "https://freeopcua.github.io/"},
        {
            "type": "url",
            "ref": "https://opcfoundation.org/developer-tools/specifications-unified-architecture",
        },
    ],
    "license": "MSF_LICENSE",
    "type": "single_scanner",
    "options": {
        "rhost": {
            "type": "address",
            "description": "The target address",
            "required": True,
            "default": None,
        },
        "rport": {
            "type": "port",
            "description": "The target port",
            "required": True,
            "default": 4840,  # Standardized OPC UA port
        },
        "authentication": {
            "type": "string",
            "description": "The authentication method to be used (Anonymous, Username, Certificate)",
            "required": True,
            "default": "Anonymous",
        },
        "username": {
            "type": "string",
            "description": "The username for the login",
            "required": True,
            "default": "",
        },
        "password": {
            "type": "string",
            "description": "The password for the login",
            "required": True,
            "default": "",
        },
        "certificate": {
            "type": "string",
            "description": "The certificate for the login and/or encryption",
            "required": True,
            "default": "",
        },
        "privatekey": {
            "type": "string",
            "description": "The private key used for the login and/or encryption",
            "required": True,
            "default": "",
        },
        "mode": {
            "type": "string",
            "description": "The security mode of the endpoint to which to connect (None, Sign, SignAndEncrypt)",
            "required": True,
            "default": "None",
        },
        "policy": {
            "type": "string",
            "description": "The security policy of the endpoint to which to connect (Basic128Rsa15, Basic256, Basic256Sha256)",
            "required": True,
            "default": "",
        },
        "applicationuri": {
            "type": "string",
            "description": "The Application URI which will be set in the client. Should match the subjectAltName in the certificate if used",
            "required": True,
            "default": "",
        },
        "servers": {
            "type": "bool",
            "description": "Try to find other servers this server knows about",
            "required": True,
            "default": False,
        },
        "nodes": {
            "type": "bool",
            "description": "Iterate all nodes and check for write permission",
            "required": True,
            "default": False,
        },
        "nodesverbose": {
            "type": "bool",
            "description": "Iterate all nodes and show all permissions",
            "required": True,
            "default": False,
        },
    },
}


def run(args):
    # Disable unnecessary opcua module logging
    logging.getLogger("opcua").addHandler(logging.NullHandler())
    logging.getLogger("opcua").propagate = False

    if dependencies_missing:
        module.log(
            "Module dependency (opcua) is missing, cannot continue", level="error"
        )
        return

    module.LogHandler.setup(msg_prefix="{}:{} - ".format(args["rhost"], args["rport"]))

    host = args["rhost"]
    port = args["rport"]
    auth = args["authentication"]
    user = args["username"]
    password = args["password"]
    certpath = args["certificate"]
    keypath = args["privatekey"]
    mode = args["mode"]
    policy = args["policy"]
    app_uri = args["applicationuri"]

    valid_auth = ["Anonymous", "Username", "Certificate"]
    valid_modes = ["None", "Sign", "SignAndEncrypt"]
    valid_policies = ["Basic128Rsa15", "Basic256", "Basic256Sha256"]

    connection_str = "opc.tcp://{}:{}".format(host, port)

    if precheckConnection(connection_str):
        logging.info("Valid OPC UA response, starting analysis")
    else:
        logging.info("No OPC UA response, stop module")
        return

    client = opcua.Client(connection_str)

    if auth not in valid_auth:
        logging.error(
            "Authentication method needs to be one of the following: {}".format(
                valid_auth
            )
        )
        return

    if auth == "Username":
        client.set_user(user)
        client.set_password(password)

    if auth == "Certificate":
        if not os.path.isfile(certpath):
            logging.error("Certificate not found")
            return

        if not os.path.isfile(keypath):
            logging.error("Key not found")
            return
        client.load_client_certificate(certpath)
        client.load_private_key(keypath)

    # Check Mode
    if mode not in valid_modes:
        logging.error(
            "Security mode needs to be one of the following: {}".format(valid_modes)
        )
        return

    # Check policy if mode not None
    if mode != "None" and policy not in valid_policies:
        logging.error(
            "Security mode other than 'None' is used thus security policy needs to be one of the following: {}".format(
                valid_policies
            )
        )
        return

    # Block for Mode setup
    security_policy = None
    security_mode = opcua.ua.MessageSecurityMode.None_
    if mode != "None":
        if not os.path.isfile(certpath):
            logging.error("Certificate not found")
            return

        if not os.path.isfile(keypath):
            logging.error("Key not found")
            return

        if policy == valid_policies[0]:
            security_policy = opcua.crypto.security_policies.SecurityPolicyBasic128Rsa15
        elif policy == valid_policies[1]:
            security_policy = opcua.crypto.security_policies.SecurityPolicyBasic256
        elif policy == valid_policies[2]:
            security_policy = (
                opcua.crypto.security_policies.SecurityPolicyBasic256Sha256
            )

        if mode == valid_modes[1]:
            security_mode = opcua.ua.MessageSecurityMode.Sign
        elif mode == valid_modes[2]:
            security_mode = opcua.ua.MessageSecurityMode.SignAndEncrypt

        # May be necessary to set
        if app_uri is not "":
            client.application_uri = app_uri

        try:
            client.set_security(security_policy, certpath, keypath, None, security_mode)
        except Exception as e:
            logging.error("Failed to set security mode and policy: {}".format(e))
            return

    endpoints = None
    servers = None
    try:
        client.connect()

        if args["servers"] == "true":
            # Ask for all known servers
            servers = client.find_servers()
            logging.info("Found Servers:")
            iterateServers(servers)

        endpoints = client.get_endpoints()
        logging.info("Available Endpoints:")
        iterateEndpoints(endpoints)

        if args["nodes"] == "true" or args["nodesverbose"] == "true":
            # Iterate over all nodes and check permissions
            if args["nodesverbose"] == "true":
                logging.info("Writable Nodes:")
                traverseTree(client.get_root_node(), True)
            else:
                logging.info("Nodes:")
                traverseTree(client.get_root_node(), False)

        client.disconnect()

    except Exception as e:
        if str(e) == "":
            logging.error("Could not obtain information")
        else:
            logging.error("Could not obtain information: {}".format(e))
        try:
            client.disconnect()
        except:
            pass
        return


def precheckConnection(connection_str):
    client = opcua.Client(connection_str)
    try:
        client.connect_socket()
        client.send_hello()
        client.disconnect_socket()
    except Exception:
        try:
            client.disconnect_socket()
        except:
            pass
        return False

    return True


def iterateServers(servers):
    """Iterates all servers and logs relevant information"""
    for server in servers:
        logging.info("-" * 40)
        logging.info("Server: {}".format(server.ApplicationName.Text))

        for url in server.DiscoveryUrls:
            logging.info("Discovery url: {}".format(url))


def iterateEndpoints(endpoints):
    """Iterates all endpoints and logs relevant information"""
    for e in endpoints:
        logging.info("-" * 40)
        logging.info("Endpoint: {}".format(e.EndpointUrl))
        server = e.Server
        logging.info("ServerName: {}".format(server.ApplicationName.Text))
        logging.info("ApplicationUri: {}".format(server.ApplicationUri))
        logging.info("ProductUri: {}".format(server.ProductUri))
        logging.info("SecurityLevel: {}".format(e.SecurityLevel))
        logging.info("MessageSecurityMode: {}".format(str(e.SecurityMode)))
        logging.info("PolicyUri: {}".format(e.SecurityPolicyUri))

        for i, token in enumerate(e.UserIdentityTokens):
            logging.info("Token: {}".format(i + 1))
            logging.info("TokenType: {}".format(str(token.TokenType)))


def traverseTree(root, verbose):
    """Recursively iterates all nodes in subtree from given root
    and logs relevant permissions"""
    children = root.get_children()
    for child in children:
        try:
            access = child.get_user_access_level()
            relevant = False
            for ac in access:
                # CurrentWrite
                if ac == opcua.ua.AccessLevel(3):
                    relevant = True
                    break

                # HistoryWrite
                if ac == opcua.ua.AccessLevel(1):
                    relevant = True
                    break

            if relevant == True or verbose == True:
                cbn = child.get_browse_name()
                cid = child.nodeid

                logging.info(
                    "Name: {} - Id: {}".format(cbn.to_string(), cid.to_string())
                )
                logging.info("{}".format([x.name for x in access]))

        except Exception as e:
            # Possibly catch BadAttributeIdInvalid
            pass
        traverseTree(child, verbose)


if __name__ == "__main__":
    module.run(metadata, run)
