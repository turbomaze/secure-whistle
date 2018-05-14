import os
import random
import requests
from struct import pack
from hashlib import sha256 as H
from flask import Flask, render_template, redirect, request, send_from_directory

app = Flask(__name__)
auth_endpoint = 'https://oidc.mit.edu/authorize'
token_endpoint = 'https://oidc.mit.edu/token'
user_endpoint = 'https://oidc.mit.edu/userinfo'
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
    return render_template('main.html', login_url='/bucket/37')

@app.route('/bucket/<int:bucket_id>')
def get_bucket_key(bucket_id):
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

                # TODO validate their email can get this bucket key
                # TODO actually send private keys
            
                # give them the bucket key
                return send_from_directory(
                     './bucket_keys',
                     'key%d' % bucket_id,
                     mimetype='text/plain'
                )
    else:
        # not valid, reject user
        return redirect('/')

if __name__ == '__main__':
    print 'starting server'
    app.run(host='0.0.0.0', debug=True)
