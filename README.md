# DOZORRO Database admin keytool

## Requirements

- python 3.4+
- python3-venv
- python3-dev


## Installation

	$ git clone https://github.com/dozorro/dozorro-keytool.git
	$ cd dozorro-keytool

	$ python3 -m venv venv
	# -- OR --
	$ virtualenv --python=`which python3` venv

	$ . venv/bin/activate
	$ pip install -r requirements.txt


## Troubleshooting

If you have problems with virtualenv or build modules
just use pure python2 implementation `nodep-keytool.py`


## Create keys

	$ python3 admin-keytool.py generate
	Private signing key saved to keypair.dat

	$ python3 admin-keytool.py export owner.name
	Public verifying key saved to pubkey.json

	$ python3 admin-keytool.py verify
	Verify public key data from pubkey.json
	Result OK


## Sign and verify files

	$ python3 admin-keytool.py sign data.json

	$ python3 admin-keytool.py verify data.json

Note: keypair.dat and pubkey.json must be in current directory
for signing files (or links to them)


## Ed25519 Software

- [Home page](http://ed25519.cr.yp.to/software.html)
- [NaCl library](https://nacl.cr.yp.to/)
- [wolfSSL](https://www.wolfssl.com/wolfSSL/Products-wolfssl.html)
- [Sodium crypto library](https://libsodium.org/)
- [Bindings for other languages](https://download.libsodium.org/doc/bindings_for_other_languages/)


## License

Apache License, [Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)


## Copyright

&copy; 2016-2017 Volodymyr Flonts <vflonts@gmail.com>
