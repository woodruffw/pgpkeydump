# pgpkeydump

A tool for dumping PGP keys as JSON.

## Installation

From crates:

```bash
cargo install pgpkeydump
```

If the build fails, then you might need `nettle`. For macOS:

```
brew install nettle
```

## Usage

```
pgpkeydump somekey.asc
```

Both ASCII-armored and binary inputs should work. If the filename input
is omitted, standard input is read instead. Output always goes to standard
output.

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
