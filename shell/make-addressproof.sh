#! /bin/sh
# Making an address proof, with shell.
set -e

hex_to_bytes() {
    HEX=$(echo "$@" | tr -d '[:space:]')
    while true; do
	HEAD=$(echo $HEX | cut -c1,2)
	[ x"$HEAD" != x ] || break
	# dash builtin printf doesn't understand \x!
	/usr/bin/printf \\x$HEAD
	HEX=$(echo $HEX | cut -c3-)
    done
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

# Only handles types < 253, length < 65535.
tlv_hex() {
    TYPE="$1"
    shift
    CONTENTS="$*"
    tlv_hexint "$TYPE"
    LEN=$(($(echo -n "$CONTENTS" | tr -d '[:space:]' | wc -c) / 2))
    tlv_hexint "$LEN"
    echo "$CONTENTS"
}

# See Bolt12 for details
merkle() {
    if [ $# = 1 ]; then
	echo "$1"
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

    LEFT=$(merkle $LEFTARGS)
    RIGHT=$(merkle $@)

    if [ "$( (echo $LEFT; echo $RIGHT) | sort | head -n1)" = $LEFT ]; then
	hex_to_bytes $LEFT $RIGHT | sha256sum | cut -c1-64
    else
	hex_to_bytes $RIGHT $LEFT | sha256sum | cut -c1-64
    fi
}
       
for arg; do
    case "$arg" in
	--expiry=*)
	    EXPVAL=$(date +%s -d "${arg#--expiry=}")
	    # Tu64
	    EXPIRY=$(printf %16x $EXPVAL | sed 's/^\(00\)*//')
	    ;;
	--vendor=*)
	    VENDOR=$(echo "${arg#--vendor=}" | od -tx1 -Anone)
	    ;;
	--nodeid=*)
	    NODEIDS="$NODEIDS ${arg#--nodeid=}"
	    ;;
	--description=*)
	    DESC=$(echo "${arg#--description=}" | od -tx1 -Anone)
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
	--help|-h)
	    echo "Usage: $0 --privkeyfile=privkey.pem --vendor=bootstrap.bolt12.org --nodeid=32-byte-nodeid [--nodeid=...] [--expiry=date] [--certfile=cert.pem] [--chainfile=chain.pem] [--description=please-send-money]" >&2
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
if [ -n "$DESC" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 10 $DESC)"
fi
if [ -n "$EXPIRY" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 14 $EXPIRY)"
fi
TLVHEX="$TLVHEX $(tlv_hex 20 $VENDOR)"
TLVHEX="$TLVHEX $(tlv_hex 60 $NODEIDS)"

echo TLVHEX=$TLVHEX >&2
MERKLE=$(merkle $TLVHEX)
echo MERKLE=$MERKLE >&2

# Fields 250 - 1000 inclusive don't get included in merkle.
HEXSIG=$(hex_to_bytes $MERKLE | openssl pkeyutl -sign -inkey "$PRIVKEYFILE" | od -tx1 -Anone)
TLVHEX="$TLVHEX $(tlv_hex 500 $HEXSIG)"

if [ -n "$CERTFILE" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 501 $(od -tx1 -Anone < $CERTFILE) )"
fi
if [ -n "$CHAINFILE" ]; then
    TLVHEX="$TLVHEX $(tlv_hex 503 $(od -tx1 -Anone < $CHAINFILE) )"
fi

hex_to_bytes $TLVHEX
