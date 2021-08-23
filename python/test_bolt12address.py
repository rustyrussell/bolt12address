from bolt12address import AddressProof

def test_decode():
    with open("example.tlv", "rb") as f:
        tlvbytes = f.read()

    ap = AddressProof(tlvbytes)
    print(ap.values)
    print(ap.merkle().hex())

    ok, whybad = ap.check()
    assert ok
