#!/usr/bin/python

import sys
from ecdsa import VerifyingKey, NIST256p

base_url = 'https://confess.anthony.ai'

verifying_key_file = sys.argv[1]
message_file = sys.argv[2]
signature_file = sys.argv[3]

verifying_key = VerifyingKey.from_pem(open(verifying_key_file).read())
message = open(message_file, 'rb').read()
signature = open(signature_file, 'rb').read()

assert verifying_key.verify(signature, message)
