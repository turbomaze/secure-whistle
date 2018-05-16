#!/usr/bin/python3

import os
import sys
sys.path.insert(0, os.path.abspath(__file__ + '/../../ecc_linkable_ring_signatures'))
from ecdsa import SECP256k1
from ecdsa.util import randrange

if len(sys.argv) <= 1:
    sys.exit(0)

file_name_prefix = sys.argv[1]

sk = randrange(SECP256k1.order)
pk = SECP256k1.generator * sk

open(file_name_prefix + '_private.int', 'wb').write(str(sk).encode())
open(file_name_prefix + '_public.int', 'wb').write(str(pk).encode())
