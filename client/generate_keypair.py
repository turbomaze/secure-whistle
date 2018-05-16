#!/usr/bin/python3

import os
import sys
sys.path.insert(0, os.path.abspath(__file__ + '/../../ecc_linkable_ring_signatures'))
from ecdsa import SigningKey, SECP256k1

if len(sys.argv) <= 1:
    sys.exit(0)

file_name_prefix = sys.argv[1]

sk = SigningKey.generate(curve=SECP256k1)
vk = sk.get_verifying_key()

open(file_name_prefix + '_private.pem', 'wb').write(sk.to_pem())
open(file_name_prefix + '_public.pem', 'wb').write(vk.to_pem())
