import os
import random
import requests
from struct import pack
from hashlib import sha256 as H
from flask import Flask, render_template, redirect, request

app = Flask(__name__)
token_endpoint='https://oidc.mit.edu/authorize'
valid_states = set()

def get_random_nonce():
    h = H()
    h.update(''.join([pack('>Q', random.getrandbits(64))]))
    return h.digest().encode('hex')[:64]

# routes
# ==
# home
@app.route('/')
def main():
    return render_template('main.html', login_url='/authorize')

@app.route('/authorize')
def authorize():
    state = get_random_nonce()
    nonce = get_random_nonce()
    url = 'https://oidc.mit.edu/authorize?'
    url += 'client_id=' + os.environ['CLIENT_ID']
    url += '&response_type=code'
    url += '&scope=openid'
    url += '&redirect_uri=https://confess.anthony.ai/login'
    url += '&state=' + state
    url += '&nonce=' + nonce
    valid_states.add(state)
    return redirect(url)

@app.route('/login')
def login():
    code = request.args.get('code')
    state = request.args.get('state')
    if state in valid_states:
        # valid, continue authorizing
        valid_states.remove(state)

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
        print foo
        return render_template('login.html')
    else:
        # not valid, reject user
        return redirect('/')

if __name__ == '__main__':
    print 'starting server'
    app.run(host='0.0.0.0', debug=True)
