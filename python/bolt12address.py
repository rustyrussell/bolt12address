#! /usr/bin/env python3
import argparse
import generated
import bolt12
import time
from typing import Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

class AddressProof(bolt12.Bolt12):
    """Class for an address proof"""
    def __init__(self, proof: bytes):
        super().__init__("lnap", generated.tlv_addressproof, proof)

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
