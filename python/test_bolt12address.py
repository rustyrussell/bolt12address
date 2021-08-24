from bolt12address import AddressProof, AddressProofDecoder


def test_encode():
    with open("../certs/privkey.pem", "rb") as f:
        privkey_pem = f.read()
    with open("../certs/cert.pem", "rb") as f:
        cert_pem = f.read()
    with open("../certs/chain.pem", "rb") as f:
        chain_pem = f.read()
    ap = AddressProof.create(vendor="bootstrap.bolt12.org",
                             node_ids=[bytes.fromhex("4b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605")],
                             privkey_pem=privkey_pem,
                             cert_pem = cert_pem,
                             chain_pem = chain_pem)

    ok, whybad = ap.check()
    assert ok

    dec = AddressProofDecoder()
    dec.add(ap.encode())

    ap2, _ = dec.result()
    ok, whybad = ap2.check()
    assert ok


def test_decode():
    with open("example.tlv", "rb") as f:
        tlvbytes = f.read()

    ap = AddressProof(tlvbytes)
    print(ap.values)
    print(ap.merkle().hex())

    assert ap.check() == (True, '')
