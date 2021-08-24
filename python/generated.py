from bolt12 import (towire_u64, towire_u32, towire_u16,
                    towire_byte, towire_tu64, towire_tu32,
                    fromwire_u64, fromwire_u32, fromwire_u16,
                    fromwire_byte, fromwire_tu64, fromwire_tu32,
                    towire_chain_hash, fromwire_chain_hash,
                    towire_sha256, fromwire_sha256,
                    towire_point32, fromwire_point32,
                    towire_point, fromwire_point,
                    towire_bip340sig, fromwire_bip340sig,
                    towire_array_utf8, fromwire_array_utf8,
                    towire_short_channel_id,
                    fromwire_short_channel_id, towire_bigsize,
                    fromwire_bigsize,
                    towire_tu16, fromwire_tu16,
                    towire_channel_id, fromwire_channel_id,
                    towire_signature, fromwire_signature)



def towire_addressproof_chains(value):
    _n = 0
    buf = bytes()
    value = {"chains": value}
    for v in value["chains"]:
        buf += towire_chain_hash(v)
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_chains(buffer):
    value = {}
    v = []
    i = 0
    while len(buffer) != 0:
        val, buffer = fromwire_chain_hash(buffer)
        v.append(val)
        i += 1
    value["chains"] = v

    return value["chains"], buffer


def towire_addressproof_description(value):
    _n = 0
    buf = bytes()
    value = {"description": value}
    buf += towire_array_utf8(value["description"])
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_description(buffer):
    value = {}
    value["description"], buffer = fromwire_array_utf8(buffer, len(buffer))

    return value["description"], buffer


def towire_addressproof_features(value):
    _n = 0
    buf = bytes()
    value = {"features": value}
    for v in value["features"]:
        buf += towire_byte(v)
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_features(buffer):
    value = {}
    v = []
    i = 0
    while len(buffer) != 0:
        val, buffer = fromwire_byte(buffer)
        v.append(val)
        i += 1
    value["features"] = v

    return value["features"], buffer


def towire_addressproof_absolute_expiry(value):
    _n = 0
    buf = bytes()
    value = {"seconds_from_epoch": value}
    buf += towire_tu64(value["seconds_from_epoch"])
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_absolute_expiry(buffer):
    value = {}
    val, buffer = fromwire_tu64(buffer)
    value["seconds_from_epoch"] = val

    return value["seconds_from_epoch"], buffer


def towire_addressproof_paths(value):
    _n = 0
    buf = bytes()
    value = {"paths": value}
    for v in value["paths"]:
        buf += towire_blinded_path(v)
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_paths(buffer):
    value = {}
    v = []
    i = 0
    while len(buffer) != 0:
        val, buffer = fromwire_blinded_path(buffer)
        v.append(val)
        i += 1
    value["paths"] = v

    return value["paths"], buffer


def towire_addressproof_vendor(value):
    _n = 0
    buf = bytes()
    value = {"vendor": value}
    buf += towire_array_utf8(value["vendor"])
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_vendor(buffer):
    value = {}
    value["vendor"], buffer = fromwire_array_utf8(buffer, len(buffer))

    return value["vendor"], buffer


def towire_addressproof_node_ids(value):
    _n = 0
    buf = bytes()
    value = {"node_ids": value}
    for v in value["node_ids"]:
        buf += towire_point32(v)
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_node_ids(buffer):
    value = {}
    v = []
    i = 0
    while len(buffer) != 0:
        val, buffer = fromwire_point32(buffer)
        v.append(val)
        i += 1
    value["node_ids"] = v

    return value["node_ids"], buffer


def towire_addressproof_certsignature(value):
    _n = 0
    buf = bytes()
    value = {"sig": value}
    for v in value["sig"]:
        buf += towire_byte(v)
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_certsignature(buffer):
    value = {}
    v = []
    i = 0
    while len(buffer) != 0:
        val, buffer = fromwire_byte(buffer)
        v.append(val)
        i += 1
    value["sig"] = v

    return value["sig"], buffer


def towire_addressproof_cert(value):
    _n = 0
    buf = bytes()
    value = {"cert": value}
    for v in value["cert"]:
        buf += towire_byte(v)
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_cert(buffer):
    value = {}
    v = []
    i = 0
    while len(buffer) != 0:
        val, buffer = fromwire_byte(buffer)
        v.append(val)
        i += 1
    value["cert"] = v

    return value["cert"], buffer


def towire_addressproof_certchain(value):
    _n = 0
    buf = bytes()
    value = {"chain": value}
    for v in value["chain"]:
        buf += towire_byte(v)
    _n += 1
    # Ensures there are no extra keys!
    assert len(value) == _n
    return buf


def fromwire_addressproof_certchain(buffer):
    value = {}
    v = []
    i = 0
    while len(buffer) != 0:
        val, buffer = fromwire_byte(buffer)
        v.append(val)
        i += 1
    value["chain"] = v

    return value["chain"], buffer


tlv_addressproof = {
    2: ("chains", towire_addressproof_chains, fromwire_addressproof_chains),
    10: ("description", towire_addressproof_description, fromwire_addressproof_description),
    12: ("features", towire_addressproof_features, fromwire_addressproof_features),
    14: ("absolute_expiry", towire_addressproof_absolute_expiry, fromwire_addressproof_absolute_expiry),
    16: ("paths", towire_addressproof_paths, fromwire_addressproof_paths),
    20: ("vendor", towire_addressproof_vendor, fromwire_addressproof_vendor),
    60: ("node_ids", towire_addressproof_node_ids, fromwire_addressproof_node_ids),
    500: ("certsignature", towire_addressproof_certsignature, fromwire_addressproof_certsignature),
    501: ("cert", towire_addressproof_cert, fromwire_addressproof_cert),
    503: ("certchain", towire_addressproof_certchain, fromwire_addressproof_certchain),
}
