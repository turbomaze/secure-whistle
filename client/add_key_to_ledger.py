#!/usr/bin/python3

import os
import sys
sys.path.insert(0, os.path.abspath(__file__ + '/../../ecc_linkable_ring_signatures'))
import requests
import base64
from ecdsa import SigningKey

base_url = 'https://confess.anthony.ai'

if len(sys.argv) <= 2:
    print('usage: ./add_key_to_ledger.py PUBLIC_KEY_FILE SIGNING_KEY_FILE')
    sys.exit(0)

public_key_file = sys.argv[1]
signing_key_file = sys.argv[2]
if not os.path.isfile(public_key_file):
    print('could not find file at: %s' % public_key_file)
    sys.exit(0)
elif not os.path.isfile(signing_key_file):
    print('could not find file at: %s' % signing_key_file)
    sys.exit(0)

public_key = open(public_key_file, 'r').read()
signing_key = SigningKey.from_pem(open(signing_key_file).read())
signature = signing_key.sign(public_key)

print(export_signature_)

resp = requests.post(base_url + '/ledger/add', data={
    'pub_key': public_key,
    'sig': base64.b64encode(signature)
})
print(resp.json())
