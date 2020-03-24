#!/usr/bin/env python3
# -*- coding: utf-8 -
# Note, works with Python 3 only

import logging

# extra modules
dependencies_missing = False
try:
    import opcua
except ImportError:
    dependencies_missing = True

from metasploit import module, login_scanner

metadata = {
    "name": "OPC UA hello scanner",
    "description": """
    This module tries to perform an OPC UA HEL/ACK message exchange with a suspected OPC UA instances.
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
        "sleep_interval": {
            "type": "float",
            "description": "Time in seconds to wait between login attempts",
            "required": False,
        },
    },
}


def hel(host, port):
    connection_str = "opc.tcp://{}:{}".format(host, port)
    client = opcua.Client(connection_str)
    try:
        client.connect_socket()
        client.send_hello()
        client.disconnect_socket()
    except:
        try:
            client.disconnect_socket()
        except:
            # Error not yet caught in python opcua implementation
            pass
        return False
    else:
        return True


def run(args):
    # Disable unnecessary opcua module logging
    logging.getLogger("opcua").addHandler(logging.NullHandler())
    logging.getLogger("opcua").propagate = False

    if dependencies_missing == True:
        module.log(
            "Module dependency (opcua) is missing, cannot continue", level="error"
        )
        return

    host = args["rhost"]
    port = args["rport"]
    msg_prefix = "{}:{} - ".format(host, port)

    if hel(host, port):
        module.log(msg_prefix + "Success", level="good")
        return True
    module.log(msg_prefix + "Failure", level="error")
    return False


if __name__ == "__main__":
    module.run(metadata, run)
