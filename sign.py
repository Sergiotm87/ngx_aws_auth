#!/usr/bin/env python
from __future__ import print_function

import argparse
import base64
import hashlib
import hmac
import sys
from datetime import datetime

def sign(key, val):
    return hmac.new(key, val.encode('utf-8'), hashlib.sha256).digest()


signature = sign('1234', '12345')

print(base64.b64encode(signature))

# decoded = base64.b64encode(signature).decode('utf-8')
#
# print(decoded)
