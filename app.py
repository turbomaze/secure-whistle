import os
import random
import requests
from struct import pack
from hashlib import sha256 as H
from flask import Flask, render_template, redirect, request

app = Flask(__name__)
token_endpoint = 'https://oidc.mit.edu/authorize'
state_bucket_chars = 4
valid_states = {}

def get_random_nonce(payload=''):
    h = H()
    h.update(''.join([pack('>Q', random.getrandbits(64))]))
    raw = h.digest().encode('hex')[:64]
    left_padding = state_bucket_chars - len(payload)
    return raw[:-state_bucket_chars] + ('0' * left_padding) + payload

# routes
# ==
# home
@app.route('/')
def main():
    return render_template('main.html', login_url='/private/37')

@app.route('/private/<bucket_id>')
def get_private(bucket_id):
    state = get_random_nonce()
    nonce = get_random_nonce()
    url = 'https://oidc.mit.edu/authorize?'
    url += 'client_id=' + os.environ['CLIENT_ID']
    url += '&response_type=code'
    url += '&scope=openid'
    url += '&redirect_uri=https://confess.anthony.ai/bucket'
    url += '&state=' + state
    url += '&nonce=' + nonce
    valid_states[state] = bucket_id
    return redirect(url)

@app.route('/bucket')
def get_bucket():
    code = request.args.get('code')
    state = request.args.get('state')
    if state in valid_states:
        # get the token
        foo = requests.post(
            token_endpoint,
            auth=(os.environ['CLIENT_ID'], os.environ['CLIENT_SECRET']),
            data={
              'grant_type': 'authorization_code',
              'code': code,
              'redirect_uri': 'https://confess.anthony.ai/login'
            }
        )

        if True:
            # give them the bucket key
            bucket_id = valid_states[state]
            print 'sending key %d' % bucket_id

        del valid_states[state]

        return render_template('login.html')
    else:
        # not valid, reject user
        return redirect('/')

if __name__ == '__main__':
    print 'starting server'
    app.run(host='0.0.0.0', debug=True)
