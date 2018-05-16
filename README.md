Secure Whistle
==

Anonymously share messages with the public while providing group-membership and anonymization guarantees. Made for the specific use case of securing MIT Confessions.

## Usage

All of these commands assume you're in the `./client` directory.

1. Do `./generate_keypair.py KEY_PREFIX` to generate personal public/private keys.
2. Run `./get_signing_key.py PUBLIC_KEY`, which will open a browser window and walk you through OIDC auth. Download the resulting private key.
3. Use the retrieved signing key to add your key to the public ledger with `./add_key_to_ledger.py YOUR_PUB_KEY DOWNLOADED_PRIV_KEY`.
4. [TODO] Consult the public ledger to ring-sign a message and confess it.

## Development

This project uses Python and Flask. Ensure you have flask/requests/tinydb/ecdsa installed and then run the following commands.

1. First time only: `cp run.sh.example run.sh` and update the secrets.
2. Make an empty `db.json` file if it doesn't exist for TinyDB.
3. `./run.sh`

## License

MIT License: https://igliu.mit-license.org/
