#!/usr/bin/python

import sys
sys.path.insert(0, './ecc_linkable_ring_signatures/')
from ecdsa import SigningKey, NIST256p

if len(sys.argv) <= 1:
    sys.exit(0)

file_name_prefix = sys.argv[1]

sk = SigningKey.generate(curve=NIST256p)
vk = sk.get_verifying_key()

open(file_name_prefix + '_private.pem', 'w').write(sk.to_pem())
open(file_name_prefix + '_public.pem', 'w').write(vk.to_pem())
