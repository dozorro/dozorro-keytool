#!/usr/bin/python
# pure python keytool
import os
import sys
import json
import base64
import hashlib
import datetime

assert sys.version_info < (3,0), "Python 2.7 required"

TZ = '+02:00'

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

def H(m):
    return hashlib.sha512(m).digest()

def expmod(b,e,m):
    if e == 0: return 1
    t = expmod(b,e/2,m)**2 % m
    if e & 1: t = (t*b) % m
    return t

def inv(x):
    return expmod(x,q-2,q)

d = -121665 * inv(121666)
I = expmod(2,(q-1)/4,q)

def xrecover(y):
    xx = (y*y-1) * inv(d*y*y+1)
    x = expmod(xx,(q+3)/8,q)
    if (x*x - xx) % q != 0: x = (x*I) % q
    if x % 2 != 0: x = q-x
    return x

By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q,By % q]

def edwards(P,Q):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
    y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
    return [x3 % q,y3 % q]

def scalarmult(P,e):
    if e == 0: return [0,1]
    Q = scalarmult(P,e/2)
    Q = edwards(Q,Q)
    if e & 1: Q = edwards(Q,P)
    return Q

def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

def encodepoint(P):
    x = P[0]
    y = P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

def bit(h,i):
    return (ord(h[i/8]) >> (i%8)) & 1

def publickey(sk):
    h = H(sk)
    a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
    A = scalarmult(B,a)
    return encodepoint(A)

def Hint(m):
    h = H(m)
    return sum(2**i * bit(h,i) for i in range(2*b))

def signature(m,sk,pk):
    h = H(sk)
    a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
    r = Hint(''.join([h[i] for i in range(b/8,b/4)]) + m)
    R = scalarmult(B,r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)

def isoncurve(P):
    x = P[0]
    y = P[1]
    return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0

def decodeint(s):
    return sum(2**i * bit(s,i) for i in range(0,b))

def decodepoint(s):
    y = sum(2**i * bit(s,i) for i in range(0,b-1))
    x = xrecover(y)
    if x & 1 != bit(s,b-1): x = q-x
    P = [x,y]
    if not isoncurve(P):
        raise Exception("decoding point that is not on curve")
    return P

def checkvalid(s,m,pk):
    if len(s) != b/4:
        raise Exception("signature length is wrong")
    if len(pk) != b/8:
        raise Exception("public-key length is wrong")
    R = decodepoint(s[0:b/8])
    A = decodepoint(pk)
    S = decodeint(s[b/8:b/4])
    h = Hint(encodepoint(R) + pk + m)
    if scalarmult(B,S) != edwards(R,scalarmult(A,h)):
        raise Exception("signature does not pass verification")

def generate(seckey='keyseed.dat', entropy=os.urandom):
    if os.path.exists(seckey):
        print('Error: file already exists {}'.format(seckey))
        return 1
    sk = entropy(32)
    with open(seckey, 'wb') as fp:
        fp.write(sk)
    os.chmod(seckey, 0o600)
    print('Private signing key saved to {}'.format(seckey))

def hash_id(datas):
    h1 = hashlib.sha256(datas).digest()
    h2 = hashlib.sha256(h1).hexdigest()
    return h2[:32]

def dump_binstr(data):
    datas = json.dumps(data,
        skipkeys=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',',':'))
    return datas.encode('utf-8')

def data_sign(data, sk, pk):
    datas = dump_binstr(data['envelope'])
    data['id'] = hash_id(datas)
    sign = signature(datas, sk, pk)
    data['sign'] = base64.b64encode(sign).rstrip('=')

def data_verify(data, vk):
    sign = base64.b64decode(data['sign'])
    data_bin = dump_binstr(data['envelope'])
    data_hid = hash_id(data_bin)
    assert data_hid == data['id'], 'Bad hash ID'
    checkvalid(sign, data_bin, vk)

def dump_pretty(data):
    datas = json.dumps(data,
        indent=2,
        ensure_ascii=False,
        sort_keys=True)
    return datas.encode('utf-8')

def export_pubkey(seckey='keyseed.dat', pubkey='pubkey.json', owner_name='root'):
    sk = open(seckey, 'rb').read()
    vk = publickey(sk)
    vk_s = vk.encode('hex')
    dt_now = datetime.datetime.now()
    dt_exp = dt_now + datetime.timedelta(days=365)
    data = {
        'envelope': {
            'date': dt_now.isoformat()+TZ,
            'model': 'admin',
            'owner': owner_name,
            'payload': {
                'algorithm': 'Ed25519',
                'owner': owner_name,
                'publicKey': vk_s,
                'validSince': dt_now.isoformat()+TZ,
                'validTill': dt_exp.isoformat()+TZ
            },
            'schema': 'pubkey'
        }
    }
    data_sign(data, sk, vk)
    datas = dump_pretty(data)
    with open(pubkey, 'wb') as fp:
        fp.write(datas.encode('utf-8'))
    print('Public verifying key saved to {}'.format(pubkey))

def verify_file(pubkey='pubkey.json', datafile=None):
    if len(sys.argv) > 2:
        datafile = sys.argv[2]

    if datafile and datafile != pubkey:
        print('Load public key data from {}'.format(pubkey))
        print('Verify any data json from {}'.format(datafile))
    else:
        print('Verify public key data from {}'.format(pubkey))

    with open(pubkey) as fp:
        data = json.loads(fp.read())

    vkey_hex = data['envelope']['payload']['publicKey']
    vk = vkey_hex.decode('hex')

    if datafile and datafile != pubkey:
        with open(datafile) as fp:
            data = json.loads(fp.read())

    try:
        data_verify(data, vk)
        print("Result OK")
    except Exception as e:
        print("Can't verify: {}".format(e))
        return 1

    return 0

def sign_file(seckey='keyseed.dat', pubkey='pubkey.json', datafile='data.json'):
    sk = open(seckey, 'rb').read()
    vk = publickey(sk)
    vk_s = vk.encode('hex')

    with open(pubkey) as fp:
        pubkey_data = json.loads(fp.read())

    pubkey_payload = pubkey_data['envelope']['payload']
    vkey_hex = pubkey_payload['publicKey'].encode()
    assert vk_s == vkey_hex, 'Keys mismatch'

    print('Load data json from {}'.format(datafile))
    with open(datafile) as fp:
        data = json.loads(fp.read())

    if '--set-date' in sys.argv:
        dt_now = datetime.datetime.now()
        data['envelope']['date'] = dt_now.isoformat()+TZ

    data['envelope']['owner'] = pubkey_payload['owner']
    data_sign(data, sk, vk)

    if '--compact' in sys.argv:
        datas = dump_binstr(data)
    else:
        datas = dump_pretty(data)

    print('Save signed json to {}'.format(datafile))
    with open(datafile, 'w') as fp:
        fp.write(datas)

def usage():
    print('Usage: admin-keytool.py command [args]\n')
    print(' admin-keytool.py generate\n')
    print(' admin-keytool.py export owner_name\n')
    print(' admin-keytool.py verify [pubkey.json]\n')
    print(' admin-keytool.py sign anydata.json\n')
    return 2

def main():
    if len(sys.argv) < 2:
        return usage()

    cmd = sys.argv[1]

    if cmd == 'generate':
        return generate()

    elif cmd == 'export' and len(sys.argv) > 2:
        return export_pubkey(owner_name=sys.argv[2])

    elif cmd == 'verify':
        return verify_file()

    elif cmd == 'sign' and len(sys.argv) > 2:
        return sign_file(datafile=sys.argv[2])

    else:
        return usage()

if __name__ == '__main__':
    sys.exit(main())
