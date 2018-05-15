import os
import os.path
import random
import requests
from tinydb import TinyDB, Query
from subprocess import call
from struct import pack
from hashlib import sha256 as H
from flask import Flask, render_template, redirect, request, send_from_directory, jsonify

auth_endpoint = 'https://oidc.mit.edu/authorize'
token_endpoint = 'https://oidc.mit.edu/token'
user_endpoint = 'https://oidc.mit.edu/userinfo'
num_buckets = 45

db = TinyDB('./db.json')
users = db.table('user', cache_size=0)
User = Query()
app = Flask(__name__)
valid_states = {}

def get_sha256(seed):
    h = H()
    h.update(seed)
    return h.digest().encode('hex')

def get_random_nonce():
    seed = ''.join([pack('>Q', random.getrandbits(64))])
    return get_sha256(seed)[:64]

# routes
# ==
# home
@app.route('/')
def main():
    return render_template('main.html', login_url='/bucket/1')

# wipe the database
@app.route('/wipedb')
def wipe():
    db.purge_table('user')
    return jsonify({'status': 'ok'})

# return the number of buckets
@app.route('/bucket/count')
def bucket_count():
    return jsonify(num_buckets)

# get a public key
@app.route('/public/<int:bucket_id>')
def get_public_bucket_key(bucket_id):
    if bucket_id >= num_buckets:
        return jsonify({'error': 'there are only %d bucket keys' % num_buckets})
    else:
        # create the key file if it's not there
        key_file_name = 'key%d' % bucket_id
        full_key_path = './bucket_keys/%s' % key_file_name
        if not os.path.isfile(full_key_path):
            call([
                'ssh-keygen', '-t', 'ecdsa',
                '-b', '256', '-N', '', '-f', full_key_path
            ])

        # give them the bucket key
        return send_from_directory(
             './bucket_keys',
             key_file_name + '.pub',
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
                print u
                if len(u) == 0 or u[0]['bucket_id'] == bucket_id:
                    # create the key file if it's not there
                    key_file_name = 'key%d' % bucket_id
                    full_key_path = './bucket_keys/%s' % key_file_name
                    if not os.path.isfile(full_key_path):
                        call([
                            'ssh-keygen', '-t', 'ecdsa',
                            '-b', '256', '-N', '', '-f', full_key_path
                        ])

                    # record them as having received this bucket
                    if len(u) == 0:
                        users.insert({'email': email, 'bucket_id': bucket_id})

                    # give them the bucket key
                    return send_from_directory(
                         './bucket_keys',
                         key_file_name,
                         mimetype='text/plain'
                    )
                else:
                    return jsonify({'error': 'you already have key %d' % u[0]['bucket_id']})

    # not valid, reject user
    return jsonify({'error': 'unsuccessful authentication'})

if __name__ == '__main__':
    print 'starting server'
    app.run(host='0.0.0.0', debug=True)
