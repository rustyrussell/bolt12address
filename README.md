# BOLT12 Address Support (DRAFT!)

Inspired by the awesome [lightingaddress.com](https://lightingaddress.com),
except for BOLT12:

1. Supports BOLT12
2. Allows BOLT12 vendor string authentication
3. Doesn't require your wallet to query the server directly
4. Required only to establish the initial node linkage

## How Does it Work?

Like lightningaddress.com, you turn username@domain.com into a web request:

	https://domain.com/.well-known/bolt12/username@domain.com

But you can also authenticate the entire domain:

	https://domain.com/.well-known/bolt12/domain.com

## The Format

The format is a bolt12 TLV binary (Content-type:
application/x-lightning-bolt12), containing the following fields:

1. `tlv_stream`: `addressproof`
2. types:
    * type: 10 (`description`)
    * data:
        * [`...*utf8`:`description`]
    * type: 12 (`features`)
    * data:
        * [`...*byte`:`features`]
    * type: 14 (`absolute_expiry`)
    * data:
        * [`tu64`:`seconds_from_epoch`]
    * type: 16 (`paths`)
    * data:
        * [`...*blinded_path`:`paths`]
    * type: 20 (`vendor`)
    * data:
        * [`...*utf8`:`vendor`]
    * type: 60 (`node_ids`)
    * data:
        * [`...*point32`:`node_ids`]
    * type: 500 (`certsignature`)
    * data:
        * [`...*byte`:`sig`]
    * type: 501 (`cert`)
    * data:
        * [`...*byte`:`cert`]
    * type: 503 (`certchain`)
    * data:
        * [`...*byte`:`chain`]

Only the `vendor`, `node_ids` and `certsignature` fields are required,
the others are optional.

### Requirements

The writer:

- MUST set `vendor` to filename being served:
  - either username@domain or simply domain.
- MUST set `node_ids` to zero or more node_ids which will be used to sign offers for this vendor.
- MAY set `features`, `absolute_expiry`, `description` and `paths` (see BOLT 12).
- MUST set `certsignature` to the signature of the BOLT-12 merkle root
  as per [BOLT12 Signature Calculation](https://bolt12.org/bolt12.html#signature-calculation) using the key in the certificate for the domain in `vendor`.
- MUST NOT set `description` unless it has an offer which is constructed using the other fields, and the offer's `node_id` set to the first of the `node_ids`.
- If it is serving the `addressproof` over HTTPS:
  - MAY set `cert` and `certchain`
- Otherwise:
  - MUST set both `cert` and `certchain`
- If it sets `cert`:
  - MUST set it to the PEM-encoded certificate corresponding to the domain
- If it sets `certchain`:
  - MUST set it to the PEM-encoded chain of certificates leading from
    `cert` to the root CA


The reader:
- MUST NOT accept the address proof if `vendor`, `node_ids` or
  `certsignature` is not present.
- MUST NOT accept the address proof if an even unknown bit is set in `features`.
- If it has NOT retrieved the `addressproof` over HTTPS:
  - MUST NOT accept the address proof if:
    - `cert` is not present, or not valid for the domain in `vendor`.
    - `certchain` is not present, or does not link `cert` to a root certificate authority.
	- `certsignature` field is not a valid signature for BOLT-12 merkle root using the key in `cert`.
- otherwise:
  - MAY retrieve `cert` and `certchain` from the HTTPS connection.
  - MAY NOT accept the address proof as it would in the non-HTTPS case above.
- If if has a previous, valid `addressproof` for this vendor:
  - MUST ONLY replace it with this address proof if:
    - `absolute_expiry` is set, AND
	- it is greater than the previous `absolute_expiry` OR the previous had
	  no `absolute_expiry` field.
- MUST consider the `addressproof` no longer valid if
  `absolute_expiry` is set and the current number of seconds since
  1970 is greater than that value.
- if `description` is present:
  - MAY use the fields of this `addressproof` as an unsigned offer.

- When it encounters a `vendor` field in a BOLT12 offer or invoice:
  - if the vendor begins with a valid domain, up to a space character:
    - SHOULD WARN the user if it cannot find a current valid address proof.
	- SHOULD reject the offer or invoice if the node_id is not one of the
	  `node_ids` in the offer.

### Text Encoding

The human-readable prefix for addressproof is `lnap`, if you want it
encoded as a string.

## What Does All This Do?

This allows domain validation for bolt 12 offers, which already have a
vendor field for this purpose.  e.g if the vendor in an offer is
"blockstream.com Get your blocks here!" then your wallet can reach out
to blockstream.com to see if it the node_id the offer really is under
their control.

It also allows node_id proofs for individual addresses.

But you don't need to reach out to blockstream.com: anyone (including
your wallet vendor, or the node claiming to be blockstream.com) can
collect all the `addressproof`s and certificates for you, as they
contain a signature using the existing web certificate infrastructure.
Bundling these protects your privacy more than having to request to a
vendor's website before making your first payment.

This format is a subset of the BOLT12 offer format, so if it has a
`description` it is actually a valid (amountless) offer, allowing
immediate tipping using it.  

You can also include zero node_ids, as a way of indicating that you do
*not* have any lightning nodes.

## TODO

There are numerous different certificate formats on the web.  I
prototyped using my bolt12.org [Let's
Encrypt](https://letsencrypt.org/) certificate, and the simple openssl
pkeyutl command to produce a signature.
