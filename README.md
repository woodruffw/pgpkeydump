# pgpkeydump

A tool for dumping PGP keys as JSON.

## Installation

From crates:

```bash
cargo install pgpkeydump
```

If the build fails, then you might need `nettle`. For macOS:

```bash
brew install nettle
```

## Usage

```bash
pgpkeydump somekey.asc
```

Both ASCII-armored and binary inputs should work. If the filename input
is omitted, standard input is read instead. Output always goes to standard
output.

## Example

```bash
curl https://keys.openpgp.org/vks/v1/by-fingerprint/46C39716A8F07E98384E28F785AE00C504833B3C \
  > key.asc

pgpkeydump key.asc
```

Produces:

```json
{
  "armor_headers": [
    "46C3 9716 A8F0 7E98 384E  28F7 85AE 00C5 0483 3B3C",
    "William Woodruff (yossarian.net) <william@yossarian.net"
  ],
  "fingerprint": "46C39716A8F07E98384E28F785AE00C504833B3C",
  "keyid": "85AE00C504833B3C",
  "userids": [
    "William Woodruff (yossarian.net) <william@yossarian.net>"
  ],
  "primary_key": {
    "algorithm": "RSA",
    "parameters": {
      "algorithm": "RSA",
      "e": {
        "bitness": 17,
        "value": "010001"
      },
      "n": {
        "bitness": 4096,
        "value": "long-value-here"
      }
    },
    "fingerprint": "46C39716A8F07E98384E28F785AE00C504833B3C",
    "keyid": "85AE00C504833B3C"
  },
  "subkeys": [
    {
      "algorithm": "RSA",
      "parameters": {
        "algorithm": "RSA",
        "e": {
          "bitness": 17,
          "value": "010001"
        },
        "n": {
          "bitness": 4096,
          "value": "long-value-here"
        }
      },
      "fingerprint": "B1D7372F51A23F640BB1F74F88FCC623BDF47C83",
      "keyid": "88FCC623BDF47C83"
    },
    {
      "algorithm": "RSA",
      "parameters": {
        "algorithm": "RSA",
        "e": {
          "bitness": 17,
          "value": "010001"
        },
        "n": {
          "bitness": 4096,
          "value": "long-value-here"
        }
      },
      "fingerprint": "90E81A884A66CDCB505B0894600D68320BE45ACC",
      "keyid": "600D68320BE45ACC"
    }
  ],
  "revocation_keys": []
}
```

## Why?

PGP is a
[miserable ecosystem](https://latacora.micro.blog/2019/07/16/the-pgp-problem.html),
and there is no good way to get a machine-readable representation of
a PGP message without mucking through either an unstable textual CLI
output or parsing individual PGP packets.

This tool exists *solely* to take a key-shaped PGP message and dump
(some of) its contents. It doesn't support anything else, **will never support
anything else**, and will never attempt to actually verify the authenticity
or integrity of its inputs. It is not suitable for use for anything except
exploration of a PGP key message's internals.

## Alternatives

If this tool doesn't do what you want, then the closest alternatives are:

* [`pgpdump`](https://github.com/kazu-yamamoto/pgpdump), which is
  semi-maintained but only provides a textual output (and crashes for me on all
  kinds of reasonable inputs);
* [`sq packet dump`](https://docs.sequoia-pgp.org/sq/), which is maintained
  but only provides a textual output.

## License

This code is intentionally not licensed, to prevent upstreaming or reuse in
other projects.
