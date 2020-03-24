#!/usr/bin/env python3
# -*- coding: utf-8 -
# Note, works with Python 3 only

import logging
import os
from functools import partial

# extra modules
dependencies_missing = False
try:
    import opcua
except ImportError:
    dependencies_missing = True

from metasploit import module, login_scanner

metadata = {
    "name": "OPC UA authentication scanner",
    "description": """
    This module tries to connect and authenticate to an OPC UA server,
    using the provided user credentials.
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
        "userpass": {
            "type": "string",
            "description": "The list, or file with syntax 'file:<path>', of username/password combinations to try",
            "required": True,
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
        "sleep_interval": {
            "type": "float",
            "description": "Time in seconds to wait between login attempts",
            "required": False,
        },
    },
}


def valid_login(
    host,
    port,
    user,
    password,
    security_mode,
    security_policy,
    certpath,
    keypath,
    app_uri,
):
    connection_str = "opc.tcp://{}:{}".format(host, port)
    client = opcua.Client(connection_str)
    client.set_user(user)
    client.set_password(password)

    if (
        certpath != None
        and keypath != None
        and security_policy != None
        and security_mode != None
    ):
        client.set_security(security_policy, certpath, keypath, None, security_mode)

        if app_uri is not "":
            client.application_uri = app_uri

    try:
        # Possibly increase efficiency by setting up socket etc. once
        client.connect()
        client.disconnect()

    except Exception as e:
        try:
            # Make sure session is terminated
            client.disconnect()
        except:
            pass
        return False
    else:
        return True


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
    certpath = args["certificate"]
    keypath = args["privatekey"]
    mode = args["mode"]
    policy = args["policy"]
    app_uri = args["applicationuri"]

    valid_auth = ["Anonymous", "Username", "Certificate"]
    valid_modes = ["None", "Sign", "SignAndEncrypt"]
    valid_policies = ["Basic128Rsa15", "Basic256", "Basic256Sha256"]

    # Precheck for opcua by sending HAL
    connection_str = "opc.tcp://{}:{}".format(host, port)

    if precheckConnection(connection_str):
        logging.info("Valid OPC UA response, starting analysis")
    else:
        logging.info("No OPC UA response, stop module")
        return

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
    app_uri = args["applicationuri"]
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

        security_mode = opcua.ua.MessageSecurityMode.None_
        if mode == valid_modes[1]:
            security_mode = opcua.ua.MessageSecurityMode.Sign
        elif mode == valid_modes[2]:
            security_mode = opcua.ua.MessageSecurityMode.SignAndEncrypt

    # Run the metasploit login scanner
    valid_login_with_policy = partial(
        valid_login,
        security_mode=security_mode,
        security_policy=security_policy,
        certpath=certpath,
        keypath=keypath,
        app_uri=app_uri,
    )

    scanner = login_scanner.make_scanner(
        lambda host, port, username, password: valid_login_with_policy(
            host, port, username, password
        )
    )
    scanner(args)


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


if __name__ == "__main__":
    module.run(metadata, run)
