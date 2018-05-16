import os
import os.path
import sys
sys.path.insert(0, os.path.abspath(__file__ + '/../../ecc_linkable_ring_signatures'))
import time
import random
import requests
import base64
from ecdsa import VerifyingKey, SigningKey, SECP256k1
from linkable_ring_signature import import_signature_from_string, verify_ring_signature
from tinydb import TinyDB, Query
from struct import pack
from hashlib import sha256 as H
from flask import Flask, render_template, redirect, request, send_from_directory, jsonify

auth_endpoint = 'https://oidc.mit.edu/authorize'
token_endpoint = 'https://oidc.mit.edu/token'
user_endpoint = 'https://oidc.mit.edu/userinfo'
num_buckets = 45

root_dir = os.path.abspath(__file__ + '/../')
db = TinyDB('./db.json')
users, User = db.table('user', cache_size=0), Query()
ledger, Ledger = db.table('ledger', cache_size=0), Query()
confessions, Confession = db.table('confession', cache_size=0), Query()
app = Flask(__name__)
valid_states = {}

def get_sha256(seed):
    h = H()
    h.update(seed)
    return h.hexdigest()

def get_random_nonce():
    seed = b''.join([pack('>Q', random.getrandbits(64))])
    return get_sha256(seed)[:64]

def get_bucket_for_key(public_key):
    bucket_id = 0
    for char in public_key:
        bucket_id ^= ord(char)
    return bucket_id % num_buckets

# routes
# ==
# home
@app.route('/')
def main():
    return render_template('main.html', login_url='/bucket/1')

@app.route('/confessions')
def view_confessions():
    return jsonify(confessions.all())

# wipe the user database
@app.route('/wipeusers')
def wipe_users():
    db.purge_table('user')
    return jsonify({'status': 'ok'})

# wipe the ledger
@app.route('/wipeledger')
def wipe_ledger():
    db.purge_table('ledger')
    return jsonify({'status': 'ok'})

# return the number of buckets
@app.route('/bucket/count')
def bucket_count():
    return jsonify(num_buckets)

# add pub key and signature to the ledger
@app.route('/ledger/add', methods=['POST'])
def add_to_ledger():
    if 'pub_key' not in request.form or 'sig' not in request.form:
        return jsonify({'error': 'need public key and its signature'})
    else:
        pub_key = request.form['pub_key']
        b64_sig = request.form['sig']
        sig = base64.b64decode(b64_sig)

        bucket_id = get_bucket_for_key(pub_key)
        key_file_name = 'bucket%d' % bucket_id
        full_key_path = root_dir + '/bucket_keys/%s' % key_file_name
        if not os.path.isfile(full_key_path + '_public.pem'):
            return jsonify({'error': 'howd u get this key wtf'})

        vk = VerifyingKey.from_pem(open(full_key_path + '_public.pem').read())
        try:
            vk.verify(sig, pub_key)
            old_key = ledger.get(Ledger.public_key == pub_key)
            if old_key != None:
                ledger.remove(doc_ids=[old_key.doc_id])
            ledger.insert({
                'public_key': pub_key,
                'b64_signature': b64_sig,
                'timestamp': time.time()
            })
            return jsonify({'status': 'ok'})
        except:
            return jsonify({'error': 'bad signature'})

# add pub key and signature to the ledger
@app.route('/ledger')
def view_ledger():
    return jsonify(ledger.all())

# confess something!
@app.route('/confess', methods=['POST'])
def add_confession():
    if 'signature' not in request.form:
        return jsonify({'error': 'need serialized signature'})
    else:
        try:
            y, m, s = import_signature_from_string(request.form['signature'])
            if verify_ring_signature(m, y, *s):
                # now make sure all the public keys are in the ledger
                keys = set(map(lambda l: l['public_key'], ledger.all()))
                all_in_ledger = all(str(p) in keys for p in y)
                if not all_in_ledger:
                    return jsonify({'error': 'all public keys must be in ledger'})
                else:
                    confessions.insert({
                        'message': m,
                        'signature': request.form['signature'],
                        'timestamp': time.time()
                    })
                    return jsonify({'status': 'ok'})
            else:
                return jsonify({'error': 'bad signature'})
        except Exception as e:
            print(str(e))
            return jsonify({'error': 'invalid signature serialization'})

# get a public key
@app.route('/public/<int:bucket_id>')
def get_public_bucket_key(bucket_id):
    if bucket_id >= num_buckets:
        return jsonify({'error': 'there are only %d bucket keys' % num_buckets})
    else:
        # create the key file if it's not there
        key_file_name = 'bucket%d' % bucket_id
        full_key_path = root_dir + '/bucket_keys/%s' % key_file_name
        if not os.path.isfile(full_key_path + '_public.pem'):
            sk = SigningKey.generate(SECP256k1)
            vk = sk.get_verifying_key()
            open(full_key_path + '_private.pem', 'wb').write(sk.to_pem())
            open(full_key_path + '_public.pem', 'wb').write(vk.to_pem())

        # give them the bucket key
        return send_from_directory(
             './bucket_keys',
             key_file_name + '_public.pem',
             mimetype='text/plain'
        )

# initiate private bucket key acquisition flow
@app.route('/bucket/<int:bucket_id>')
def get_private_bucket_key(bucket_id):
    if bucket_id >= num_buckets:
        return jsonify({'error': 'there are only %d bucket keys' % num_buckets})
    else:
        state = get_random_nonce()
        nonce = get_random_nonce()
        url = auth_endpoint + '?'
        url += 'client_id=' + os.environ['CLIENT_ID']
        url += '&response_type=code'
        url += '&scope=openid,email'
        url += '&redirect_uri=https://confess.anthony.ai/private'
        url += '&state=' + state
        url += '&nonce=' + nonce
        valid_states[state] = bucket_id
        return redirect(url)

# finish private bucket key acquisition
@app.route('/private')
def get_private_key():
    code = request.args.get('code')
    state = request.args.get('state')
    if state in valid_states:
        bucket_id = valid_states[state]
        del valid_states[state]

        # get the token
        resp = requests.post(
            token_endpoint,
            auth=(os.environ['CLIENT_ID'], os.environ['CLIENT_SECRET']),
            data={
              'grant_type': 'authorization_code',
              'code': code,
              'redirect_uri': 'https://confess.anthony.ai/private'
            }
        )

        if resp.status_code == 200 and 'access_token' in resp.json():
            # get their kerb
            access_token = resp.json()['access_token']
            info = requests.get(
                user_endpoint,
                headers={
                  'Authorization': 'Bearer ' + access_token,
                }
            )

            if info.status_code == 200 and 'email' in info.json():
                email = info.json()['email']

                u = users.search(User.email == email)
                if len(u) == 0 or u[0]['bucket_id'] == bucket_id:
                    # create the key file if it's not there
                    key_file_name = 'bucket%d' % bucket_id
                    full_key_path = root_dir + '/bucket_keys/%s' % key_file_name
                    if not os.path.isfile(full_key_path + '_private.pem'):
                        sk = SigningKey.generate(SECP256k1)
                        vk = sk.get_verifying_key()
                        open(full_key_path + '_private.pem', 'wb').write(sk.to_pem())
                        open(full_key_path + '_public.pem', 'wb').write(vk.to_pem())

                    # record them as having received this bucket
                    if len(u) == 0:
                        users.insert({'email': email, 'bucket_id': bucket_id})

                    # give them the bucket key
                    return send_from_directory(
                         './bucket_keys',
                         key_file_name + '_private.pem',
                         mimetype='text/plain'
                    )
                else:
                    return jsonify({'error': 'you already have key %d' % u[0]['bucket_id']})

    # not valid, reject user
    return jsonify({'error': 'unsuccessful authentication'})

if __name__ == '__main__':
    print('starting server')
    app.run(host='0.0.0.0', debug=True)
