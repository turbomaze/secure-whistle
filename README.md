Secure Whistle
==

Anonymously share messages with the public while providing group-membership and anonymization guarantees. Made for the specific use case of securing MIT Confessions for MIT's Computer and Network Security class, 6.857.

## Usage

All of these commands assume you're in the `./client` directory.

1. Do `./generate_keypair.py KEY_PREFIX` to generate personal public/private keys.
2. Run `./get_signing_key.py PUBLIC_KEY`, which will open a browser window and walk you through OIDC auth. Download the resulting private key.
3. Use the retrieved signing key to add your key to the public ledger with `./add_key_to_ledger.py YOUR_PUB_KEY DOWNLOADED_PRIV_KEY`.
4. Now that your key has been added, confess a message with `./confess.py YOUR_PUB_KEY YOUR_PRIV_KEY MESSAGE`.

## Scheme

First, each user of this system generates a public and private key according to [this paper on ring signatures](https://eprint.iacr.org/2004/027.pdf). Next, we need to distribute everyone's public keys, but we only want to share those that belong to members of a specific group. In our case, that group is MIT, and we determine that by querying MIT's OIDC endpoints. Herein lies the main challenge: how can you use a group membership black-box to authenticate a public key without associating that public key to a specific user's identity?

If we were to just use ring signatures over ~4000 members of the MIT community, it wouldn't actually matter if an adversarial authentication server knew who owned which public key. However, computing ring signatures with 4000 participants is slow. Thus, we developed a more complex scheme to achieve the same level of anonymity with ring signatures over just ~40 keys.

The central idea is that of a "bucket key": an ecdsa keypair responsible for signing a specific subset of users' public keys. The number of buckets is a parameter depending on the use case; we use 45 buckets and consequently map users' public keys to a number from 0 to 44. Users query the authentication server to request the specific bucket key they need to sign their key. Upon authenticatin via OIDC, they run a command to sign their ring signature public key and add it to a public ledger hosted by the server.

The contents of that ledger are the public keys of users that can authenticate to MIT's OIDC servers. Importantly, the authentication server has no idea which public key is whose. It only knows which bucket each MIT user's key belongs to. Thus, users can compute a ring signature over 45 randomly selected keys from the ledger, one per bucket, and achieve full anonymity.

In our paper, we describe this scheme in more detail and present an anomaly detection system (not implemented) to identify when secret keys are leaked to members outside of the authenticated group.

## Development

This project uses Python3 and Flask. Ensure you have flask/requests/tinydb/pysha3 installed and then run the following commands.

1. First time only: `cp run.sh.example run.sh` and update the secrets.
2. Make an empty `db.json` file if it doesn't exist for TinyDB.
3. `./run.sh`

## License

MIT License: https://igliu.mit-license.org/
