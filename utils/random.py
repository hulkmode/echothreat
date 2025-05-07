#!/usr/bin/env python3
'''
 _____     _            _______ _                    _   
|  ___|   | |          / /_   _| |                  | |
| |__  ___| |__   ___ / /  | | | |__  _ __ ___  __ _| |_
|  __|/ __| '_ \ / _ < <   | | | '_ \| '__/ _ \/ _` | __|
| |__| (__| | | | (_) \ \  | | | | | | | |  __/ (_| | |_
\____/\___|_| |_|\___/ \_\ \_/ |_| |_|_|  \___|\__,_|\__|

Author: Hal Denton and AI
Description: Echo<Threat is a modular synthetic log generation tool designed for detection engineering and simulation-based verification workflows.
Date: 2025-05-07
Version: 1.0  

'''

import random
import string

HOST_SUFFIXES = ["NYC", "SEA", "CHI", "LDN", "DE1", "JP1"]
USERS = ["alice", "bob", "charlie", "diana", "admin", "svc_account"]

def rand(type_, arg=None):
    """
    Generate random data for templates.

    type_ = 'host', 'user', 'ip', 'alpha', 'digit'
    arg = extra parameter like IP subnet base or length
    """
    if type_ == "host":
        prefix = random.choice(["WIN", "DESKTOP", "PC", "LAPTOP"])
        suffix = random.choice(HOST_SUFFIXES)
        number = random.randint(1, 99)
        return f"{prefix}-{suffix}-{number:02d}"

    elif type_ == "user":
        return random.choice(USERS)

    elif type_ == "ip":
        base = arg if arg else "192.168"
        return f"{base}.{random.randint(0, 254)}.{random.randint(1, 254)}"

    elif type_ == "alpha":
        length = int(arg) if arg else 4
        return ''.join(random.choices(string.ascii_uppercase, k=length))

    elif type_ == "digit":
        length = int(arg) if arg else 4
        return ''.join(random.choices(string.digits, k=length))

    else:
        return f"rand-unknown-{type_}"
