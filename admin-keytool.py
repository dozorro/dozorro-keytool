#!/usr/bin/env python
import os
import sys
import hashlib
import datetime
try:
    import pytz
    import ed25519
except ImportError as e:
    print("ImportError: {}".format(e))
    print("Did you forget to activate a virtual environment?")
    sys.exit(1)
try:
    import rapidjson as json
except ImportError:
    import json


TZ = pytz.timezone(os.environ.get('TZ', 'Europe/Kiev'))


def hash_id(datab):
    h1 = hashlib.sha256(datab).digest()
    h2 = hashlib.sha256(h1).hexdigest()
    return h2[:32]


def dump_binstr(data, kwargs={}):
    # For compact encoding use separators w/o spaces
    # not necessary for rapidjson module
    if json.__name__ == 'json':
        kwargs['separators'] = (',', ':')
    out = json.dumps(data,
        skipkeys=False,
        ensure_ascii=False,
        sort_keys=True,
        **kwargs)
    return out.encode('utf-8')


def data_sign(data, sk):
    data_bin = dump_binstr(data['envelope'])
    data['id'] = hash_id(data_bin)
    data['sign'] = sk.sign(data_bin, encoding='base64').decode()


def data_verify(data, vk):
    sign = data['sign']
    data_bin = dump_binstr(data['envelope'])
    data_hid = hash_id(data_bin)
    assert data_hid == data['id'], 'Bad hash ID'
    vk.verify(sign, data_bin, encoding='base64')


def dump_pretty(data):
    out = json.dumps(data,
        indent=2,
        ensure_ascii=False,
        sort_keys=True)
    return out.encode('utf-8')


def save_private(sk, seckey):
    if os.path.exists(seckey):
        print('Error: file already exists', seckey)
        return 1
    sk_s = sk.to_bytes()
    with open(seckey, 'wb') as fp:
        fp.write(sk_s)
    os.chmod(seckey, 0o600)
    print('Private signing key saved to', seckey)


def generate(seckey='keypair.dat'):
    sk, vk = ed25519.create_keypair()
    save_private(sk, seckey)


def fromseed(seckey='keypair.dat', seedfile='keyseed.dat'):
    if len(sys.argv) > 2:
        seedfile = sys.argv[2]
    print('Load key seed data from', seedfile)
    seed = open(seedfile, 'rb').read(32)
    sk = ed25519.SigningKey(seed)
    save_private(sk, seckey)


def export_pubkey(seckey='keypair.dat', pubkey='pubkey.json', owner_name='root'):
    keydata = open(seckey, 'rb').read()
    sk = ed25519.SigningKey(keydata)
    vk = sk.get_verifying_key()
    vk_s = vk.to_ascii(encoding='hex')
    dt_now = datetime.datetime.now()
    dt_now = TZ.localize(dt_now)
    dt_exp = dt_now + datetime.timedelta(days=365)
    data = {
        'envelope': {
            'date': dt_now.isoformat(),
            'model': 'admin',
            'owner': owner_name,
            'payload': {
                'algorithm': 'Ed25519',
                'owner': owner_name,
                'publicKey': vk_s.decode(),
                'validSince': dt_now.isoformat(),
                'validTill': dt_exp.isoformat()
            },
            'schema': 'pubkey'
        }
    }
    data_sign(data, sk)
    data_s = dump_pretty(data)
    with open(pubkey, 'wb') as fp:
        fp.write(data_s)
    print('Public verifying key saved to', pubkey)


def verify_file(pubkey='pubkey.json', datafile=None):
    if len(sys.argv) > 2:
        datafile = sys.argv[2]

    if datafile and datafile != pubkey:
        print('Load public key data from', pubkey)
        print('Verify any data json from', datafile)
    else:
        print('Verify public key data from', pubkey)

    with open(pubkey, 'r', encoding='utf-8') as fp:
        data = json.loads(fp.read())

    vkey_hex = data['envelope']['payload']['publicKey']
    vk = ed25519.VerifyingKey(vkey_hex, encoding="hex")

    if datafile and datafile != pubkey:
        with open(datafile, 'r', encoding='utf-8') as fp:
            data = json.loads(fp.read())

    try:
        data_verify(data, vk)
        print("Result OK")
    except Exception as e:
        print("Can't verify:", e)
        return 1

    return 0


def sign_file(seckey='keypair.dat', pubkey='pubkey.json', datafile='data.json'):
    keydata = open(seckey, 'rb').read()
    sk = ed25519.SigningKey(keydata)
    vk = sk.get_verifying_key()
    vk_s = vk.to_ascii(encoding='hex')

    with open(pubkey, 'r', encoding='utf-8') as fp:
        pubkey_data = json.loads(fp.read())
    pubkey_payload = pubkey_data['envelope']['payload']
    vkey_hex = pubkey_payload['publicKey'].encode('ascii')
    assert vk_s == vkey_hex, 'Keys mismatch'

    print('Load data json from', datafile)
    with open(datafile, 'r', encoding='utf-8') as fp:
        data = json.loads(fp.read())

    if '--set-date' in sys.argv:
        dt_now = datetime.datetime.now(TZ)
        data['envelope']['date'] = dt_now.isoformat()

    data['envelope']['owner'] = pubkey_payload['owner']
    data_sign(data, sk)

    if '--compact' in sys.argv:
        data_s = dump_binstr(data)
    else:
        data_s = dump_pretty(data)

    print('Save signed json to', datafile)
    with open(datafile, 'wb') as fp:
        fp.write(data_s)


def usage():
    print('Usage: admin-keytool.py command [args]\n')
    print(' admin-keytool.py generate\n')
    print(' admin-keytool.py export owner-name\n')
    print(' admin-keytool.py verify [pubkey.json]\n')
    print(' admin-keytool.py sign anydata.json\n')
    return 2


def main():
    if len(sys.argv) < 2:
        return usage()

    command = sys.argv[1]

    if command == 'generate':
        return generate()

    if command == 'fromseed':
        return fromseed()

    elif command == 'export' and len(sys.argv) > 2:
        return export_pubkey(owner_name=sys.argv[2])

    elif command == 'verify':
        return verify_file()

    elif command == 'sign' and len(sys.argv) > 2:
        return sign_file(datafile=sys.argv[2])

    else:
        return usage()


if __name__ == '__main__':
    sys.exit(main())
