#!/usr/bin/python

import os
import sys
import requests
import webbrowser

base_url = 'https://confess.anthony.ai'

if len(sys.argv) <= 1:
    print('usage: ./get_signing_key.py PUBLIC_KEY_FILE')
    sys.exit(0)

public_key_file = sys.argv[1]
if not os.path.isfile(public_key_file):
    print('could not find file at: %s' % public_key_file)
    sys.exit(0)

try:
    num_buckets = requests.get(base_url + '/bucket/count').json()
    public_key = open(public_key_file, 'r').read()
    bucket_id = 0
    for char in public_key:
        bucket_id ^= ord(char)
    bucket_id = bucket_id % num_buckets
    webbrowser.open(base_url + '/bucket/' + str(bucket_id), 2)
except:
    print('failed to get the signing key')
