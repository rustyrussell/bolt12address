#! /usr/bin/env python3
import argparse
import generated
import bolt12
import time
import sys
from typing import Tuple, Sequence, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa

class AddressProof(bolt12.Bolt12):
    """Class for an address proof"""
    def __init__(self, proof: Optional[bytes]):
        super().__init__("lnap", generated.tlv_addressproof, proof)

    @classmethod
    def create(cls, vendor: str,
               node_ids: Sequence[bytes],
               privkey_pem: bytes,
               cert_pem: bytes = None,
               chain_pem: bytes = None,
               description: Optional[str] = None,
               features: bytes = None,
               absolute_expiry: Optional[int] = None,
               chain: bytes = None):
        self = cls(None)
        self.values = {'vendor': vendor,
                       'node_ids': node_ids}
        if features is not None:
            self.values['features'] = features
        if description is not None:
            self.values['description'] = description
        if absolute_expiry is not None:
            self.values['absolute_expiry'] = absolute_expiry
        if cert_pem is not None:
            self.values['cert'] = cert_pem
        if chain_pem is not None:
            self.values['certchain'] = chain_pem
        if chain is not None:
            self.values['chains'] = [chain]

        key = load_pem_private_key(privkey_pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("privkey_pem was not RSA: {}".format(type(key)))

        sig = key.sign(self.merkle(),
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                   salt_length=padding.PSS.MAX_LENGTH),
                       utils.Prehashed(hashes.SHA256()))
        self.values['certsignature'] = sig
        return self

    @classmethod
    def from_string(cls, proofstr: str):
        dec = bolt12.Decoder()
        if not dec.add(proof):
            raise ValueError("Incomplete string")
        # FIXME: expose this is Decoder!
        hrp, bytestr = simple_bech32_decode(re.sub(r'([A-Z0-9a-z])\+\s*([A-Z0-9a-z])', r'\1\2',
                                                   dec.so_far))
        if hrp != "lnap":
            raise ValueError("This is a {} not lnap".format(hrp))
        return cls(bytestr)

    def check(self, needcert=True) -> Tuple[bool, str]:
        """Check it's OK: returns (True, '') or (False, reason)"""
        for fname in ('vendor', 'node_ids', 'certsignature'):
            if fname not in self.values:
                return False, 'Missing {}'.format(fname)

        whybad = self.check_features(self.values.get('features', bytes()))
        if whybad:
            return False, whybad

        if 'absolute_expiry' in self.values:
            if time.time() > self.values['absolute_expiry']:
                return False, "Expired {} seconds ago".format(self.values['absolute_expiry'] - int(time.time()))

        if needcert:
            for fname in ('cert', 'certchain'):
                if fname not in self.values:
                    return False, 'Missing {}'.format(fname)

        if 'cert' in self.values:
            try:
                cert = x509.load_pem_x509_certificate(bytes(self.values['cert']))
            except ValueError:
                return False, 'Unparsable PEM x509 certificate'

            key = cert.public_key()
            try:
                key.verify(bytes(self.values['certsignature']), self.merkle(),
                           padding.PSS(
                               mgf=padding.MGF1(hashes.SHA256()),
                               salt_length=padding.PSS.MAX_LENGTH),
                           utils.Prehashed(hashes.SHA256()))
            except InvalidSignature:
                return False, 'Invalid certsignature'

            # FIXME: check cert chain!

        return True, ''


class AddressProofDecoder(bolt12.Decoder):
    def result(self) -> Tuple[Optional[AddressProof], str]:
        """One string is complete(), try decoding"""
        try:
            hrp, bytestr = self.raw_decode()
        except ValueError as e:
            return None, ' '.join(e.args)

        if hrp != 'lnap':
            return None, 'Is not an AddressProof'

        return AddressProof(bytestr), ''


def create(args):
    if args.nodeid == [] and not args.no_nodeid:
        print("No nodeid specified (if you really want this, use --no-nodeids)",
              file=sys.stderr)
        sys.exit(1)

    if args.expiry and args.rel_expiry:
        print("Cannot specify both --expiry and --rel-expiry",
              file=sys.stderr)
        sys.exit(1)

    if args.rel_expiry:
        args.expiry = int(time.time()) + args.rel_expiry

    with open(args.privkeyfile, "rb") as f:
        privkey_pem = f.read()
    with open(args.certfile, "rb") as f:
        cert_pem = f.read()
    with open(args.chainfile, "rb") as f:
        chain_pem = f.read()

    # Feature fields are big-endian.  Really.
    if args.feature:
        flen = (max(args.feature) + 7) / 8
        features = sum([(1 << f) for f in args.feature]).to_bytes(flen, 'big')
    else:
        features = None

    if args.chain:
        if args.chain == 'bitcoin':
            chainhash = bytes.fromhex('6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000')
        elif args.chain == 'testnet':
            chainhash = bytes.fromhex('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000')
        elif args.chain == 'regtest':
            chainhash = bytes.fromhex('06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f')
        elif args.chain == 'signet':
            chainhash = bytes.fromhex('f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000')
        else:
            # Should not happen: choices[] should restrict it.
            raise ValueError("Unknown type {}".format(args.chain))
    else:
        # The default, bitcoin mainnet.
        chainhash = None

    ap = AddressProof.create(args.vendor,
                             [bytes.fromhex(n) for n in args.nodeid],
                             privkey_pem,
                             cert_pem,
                             chain_pem,
                             args.description,
                             features,
                             args.expiry,
                             chainhash)
    assert ap.check() == (True, '')

    if args.raw:
        sys.stdout.buffer.write(bolt12.helper_towire_tlv(ap.tlv_table, ap.values, ap.unknowns))
    else:
        print(ap.encode())


def check(args):
    if args.raw_stdin:
        ap = AddressProof(sys.stdin.buffer.read())
    else:
        dec = AddressProofDecoder()
        for a in args.ap:
            dec.add(a)
        if not dec.complete():
            print("Incomplete bolt12 string", file=sys.stderr)
            sys.exit(1)

        ap = dec.result()
        ok, whybad = ap.check()
        if not ok:
            print("Bad lnap: {}".format(whybad), file=sys.stderr)
            sys.exit(1)

    # FIXME: Get pretty!
    for k, v in ap.values.items():
        if isinstance(v, bytes):
            val = v.hex()
        elif isinstance(v, list):
            if len(v) == 0:
                val = v
            elif isinstance(v[0], int):
                val = bytes(v).hex()
            elif isinstance(v[0], bytes):
                val = [b.hex() for b in v]
            else:
                val = v
        else:
            val = v
        print("{}: {}".format(k, val))

    if 'description' in ap.values:
        for n in ap.values['node_ids']:
            offer = bolt12.Offer.create(description=ap.values['description'],
                                        node_id=n)
            print('offer_id: {}'.format(offer.merkle().hex()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tool to create/validate bolt12 address proofs')
    subparsers = parser.add_subparsers()

    createparser = subparsers.add_parser('create')
    createparser.add_argument('vendor',
                              help='Name, either DOMAIN or USER@DOMAIN')
    createparser.add_argument('privkeyfile', help='privkey.pem file for DOMAIN')
    createparser.add_argument('certfile', help='cert.pem file for DOMAIN')
    createparser.add_argument('chainfile', help='chain.pem file for DOMAIN')
    createparser.add_argument('--description',
                              help='description for others to send funds (you must create an offer with this description, too!)')
    createparser.add_argument('--feature', action='append',
                              help='Feature to set in feature field')
    createparser.add_argument('--chain', help='The name of the chain',
                              choices=['bitcoin', 'regtest', 'testnet', 'signet'])
    createparser.add_argument('--expiry',
                              help='The absolute time for the address proof to expire, in seconds since 1970', type=int)
    createparser.add_argument('--rel-expiry',
                              help='The number of seconds from now for the addressproof to expire')
    # FIXME: Add blinded paths!
    createparser.add_argument('nodeid', nargs='*',
                              help='Lightning node id for this vendor (can be multiple)')
    createparser.add_argument('--no-nodeids',
                              help='Allows no nodeids to be specified')
    createparser.add_argument('--raw', action='store_true',
                              help="Don't encode as lnap1, just output raw binary")
    createparser.set_defaults(func=create)

    checkparser = subparsers.add_parser('check')
    checkparser.add_argument('--raw-stdin', action='store_true',
                              help='Read raw bytes from stdin instead of using cm1dline lnap1 format')
    checkparser.add_argument('ap', nargs='*', help='lnap1 string to check')
    checkparser.set_defaults(func=check)

    args = parser.parse_args()
    args.func(args)
