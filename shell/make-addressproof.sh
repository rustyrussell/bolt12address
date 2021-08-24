#! /bin/sh
# Making an address proof, with shell.
set -e

hex_to_bytes() {
    echo "$@" | tr -d '[:space:]' | xxd -r -p
}

tlv_hexint() {
    if [ $1 -gt 4294967295 ]; then
	printf %02x 255
	printf %016x $1
    elif [ $1 -gt 65535 ]; then
	printf %02x 254
	printf %08x $1
    elif [ $1 -gt 253 ]; then
	printf %02x 253
	printf %04x $1
    else
	printf %02x $1
    fi
}

# Create a TLV value, hexencoded, given type (int) and contents (hex).
tlv_hex() {
    TYPE="$1"
    shift
    CONTENTS="$(echo -n $* | tr -d '[:space:]')"
    tlv_hexint "$TYPE"
    LEN=$(( $(echo "$CONTENTS" | wc -c) / 2))
    tlv_hexint "$LEN"
    echo "$CONTENTS"
}

# BOLT #12:
# The Merkle tree's leaves are, in TLV-ascending order for each tlv:
# 1. The H(`LnLeaf`,tlv).
lnleaf_hash() {
    TAGH=`echo -n "LnLeaf" | sha256sum | cut -c1-64`
    hex_to_bytes $TAGH $TAGH $1 | sha256sum | cut -c1-64
}

# BOLT #12:
# 2. The H(`LnAll`|all-tlvs,tlv)
lnall_hash() {
    TAGH=`(echo -n "LnAll"; hex_to_bytes $1) | sha256sum | cut -c1-64`
    hex_to_bytes $TAGH $TAGH $2 | sha256sum | cut -c1-64
}

merkle_pair()
{
    TAGH=`echo -n "LnBranch" | sha256sum | cut -c1-64`
    if [ "$( (echo $1; echo $2) | sort | head -n1)" = $1 ]; then
	hex_to_bytes $TAGH $TAGH $1 $2 | sha256sum | cut -c1-64
    else
	hex_to_bytes $TAGH $TAGH $2 $1 | sha256sum | cut -c1-64
    fi
}
    
# See Bolt12 for details
merkle() {
    ALL="$1"
    shift
    if [ $# = 1 ]; then
	LNLEAF=`lnleaf_hash $1`
	LNALL=`lnall_hash "$ALL" $1`
	merkle_pair $LNLEAF $LNALL
	return
    fi
    ORDER=1
    while [ $(($ORDER * 2)) -lt $# ]; do
	ORDER=$(($ORDER * 2))
    done
    LEFTARGS=""
    i=1
    while [ $i -le $ORDER ]; do
	LEFTARGS="$LEFTARGS $1"
	shift
	i=$(($i + 1))
    done

    LEFT=$(merkle "$ALL" $LEFTARGS)
    RIGHT=$(merkle "$ALL" $@)

    merkle_pair $LEFT $RIGHT
}

for arg; do
    case "$arg" in
	--expiry=*)
	    EXPVAL=$(date +%s -d "${arg#--expiry=}")
	    # Tu64
	    EXPIRY=$(printf %16x $EXPVAL | sed 's/^\(00\)*//')
	    ;;
	--vendor=*)
	    VENDOR=$(echo -n "${arg#--vendor=}" | od -tx1 -Anone)
	    ;;
	--nodeid=*)
	    NODEIDS="$NODEIDS ${arg#--nodeid=}"
	    ;;
	--description=*)
	    DESC=$(echo -n "${arg#--description=}" | od -tx1 -Anone)
	    ;;
 	--privkeyfile=*)
	    PRIVKEYFILE="${arg#--privkeyfile=}"
	    ;;
 	--certfile=*)
	    CERTFILE="${arg#--certfile=}"
	    ;;
 	--chainfile=*)
	    CHAINFILE="${arg#--chainfile=}"
	    ;;
	--chain=*)
	    case "${arg#--chain=}" in
		bitcoin)
		    CHAIN=6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000
		    ;;
		testnet)
		    CHAIN=43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000
		    ;;
		regtest)
		    CHAIN=06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f
		    ;;
		signet)
		    CHAIN=f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
		    ;;
		*)
		    echo Unknown chain "${arg#--chain=}" >&2
		    exit 1
	    esac
	    ;;
	--help|-h)
	    echo "Usage: $0 --privkeyfile=privkey.pem --vendor=bootstrap.bolt12.org --nodeid=32-byte-nodeid [--nodeid=...] [--expiry=date] [--certfile=cert.pem] [--chainfile=chain.pem] [--chain=bitcoin|testnet|regtest|signet] [--description=\"Please send money\"]" >&2
	    exit 1
	    ;;
	*)
	    echo Unknown argument "$arg" >&2
	    exit 1
    esac
done

[ -n "$PRIVKEYFILE" ] || (echo Missing --privkeyfile >&2; exit 1)
[ -n "$VENDOR" ] || (echo Missing --vendor >&2; exit 1)
[ -n "$NODEIDS" ] || (echo Need at least one --nodeid >&2; exit 1)

TLVHEX=""
if [ -n "$CHAIN" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 2 $CHAIN)"
fi
if [ -n "$DESC" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 10 $DESC)"
fi
if [ -n "$EXPIRY" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 14 $EXPIRY)"
fi
TLVHEX="$TLVHEX $(tlv_hex 20 $VENDOR)"
TLVHEX="$TLVHEX $(tlv_hex 60 $NODEIDS)"

echo TLVHEX=$TLVHEX >&2
MERKLE=$(merkle "$TLVHEX" $TLVHEX)
echo MERKLE=$MERKLE >&2

# Fields 250 - 1000 inclusive don't get included in merkle.
HEXSIG=$(hex_to_bytes $MERKLE | openssl pkeyutl -sign -inkey "$PRIVKEYFILE" -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:max | od -tx1 -Anone)
TLVHEX="$TLVHEX $(tlv_hex 500 $HEXSIG)"

if [ -n "$CERTFILE" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 501 $(od -tx1 -Anone < $CERTFILE) )"
fi
if [ -n "$CHAINFILE" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 503 $(od -tx1 -Anone < $CHAINFILE) )"
fi

hex_to_bytes $TLVHEX
