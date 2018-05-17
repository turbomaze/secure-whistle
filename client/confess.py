#!/usr/bin/python3

import os
import sys
sys.path.insert(0, os.path.abspath(__file__ + '/../../ecc_linkable_ring_signatures'))
import requests
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.ellipticcurve import Point
from linkable_ring_signature import ring_signature, verify_ring_signature
from linkable_ring_signature import export_signature_to_string
from linkable_ring_signature import import_signature_from_string

base_url = 'https://confess.anthony.ai'

def decode_public_key(public_key):
    parts = public_key[1:-1].split(',')
    x = int(parts[0])
    y = int(parts[1])
    return Point(curve_secp256k1, x, y)

if len(sys.argv) <= 3:
    print('usage: ./add_key_to_ledger.py PUBLIC_KEY_FILE PRIVATE_KEY_FILE MESSAGE')
    sys.exit(0)

public_key_file = sys.argv[1]
private_key_file = sys.argv[2]
message = sys.argv[3]
if not os.path.isfile(private_key_file):
    print('could not find file at: %s' % private_key_file)
    sys.exit(0)

my_public_key_raw = open(public_key_file, 'rb').read()
my_private_key_raw = open(private_key_file, 'rb').read()
my_private_key = int(my_private_key_raw)
ledger = requests.get(base_url + '/ledger')
if ledger.status_code == 200:
    # get all the public keys
    public_keys_raw = list(map(lambda x: x['public_key'], ledger.json()))
    public_keys = list(map(
        lambda public_key_raw: decode_public_key(public_key_raw),
        public_keys_raw
    ))

    # figure out which key in the list is ours
    i = public_keys_raw.index(my_public_key_raw.decode())

    # compute the ring sig
    ring_sig = ring_signature(my_private_key, i, message, public_keys)
    exported = export_signature_to_string(public_keys, message, ring_sig)
    y, m, s = import_signature_from_string(exported)
    assert(verify_ring_signature(m, y, *s))

    resp = requests.post(base_url + '/confess', data={'signature': exported})
    print(resp.json())
else:
    print('bad ledger GET request')
