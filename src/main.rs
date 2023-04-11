use std::{
    fs::File,
    io::{self},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::Parser;
use sequoia_openpgp::{
    cert::prelude::{PrimaryKeyAmalgamation, SubordinateKeyAmalgamation},
    crypto::mpi::{PublicKey, MPI},
    packet::key::PublicParts,
    parse::Parse,
    policy::StandardPolicy,
    types::RevocationKey,
    Cert,
};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(
        value_name = "FILE",
        help = "Dump the key at this path (or stdin, if not given)"
    )]
    input: Option<PathBuf>,
}

#[derive(Serialize)]
struct DumpableMPI {
    bitness: usize,
    #[serde(serialize_with = "hex::serde::serialize")]
    value: Vec<u8>,
}

impl From<&MPI> for DumpableMPI {
    fn from(mpi: &MPI) -> Self {
        Self {
            bitness: mpi.bits(),
            value: mpi.value().into(),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "algorithm")]
enum DumpableKeyParams {
    RSA {
        e: DumpableMPI,
        n: DumpableMPI,
    },
    DSA {
        p: DumpableMPI,
        q: DumpableMPI,
        g: DumpableMPI,
        y: DumpableMPI,
    },
    ElGamal {
        p: DumpableMPI,
        g: DumpableMPI,
        y: DumpableMPI,
    },
    EdDSA {
        curve: String,
        q: DumpableMPI,
    },
    ECDSA {
        curve: String,
        q: DumpableMPI,
    },
    ECDH {
        curve: String,
        q: DumpableMPI,
        hash: String,
        sym: String,
    },
    Unknown,
}

impl From<&PublicKey> for DumpableKeyParams {
    fn from(pk: &PublicKey) -> Self {
        match pk {
            PublicKey::RSA { e, n } => Self::RSA {
                e: e.into(),
                n: n.into(),
            },
            PublicKey::DSA { p, q, g, y } => Self::DSA {
                p: p.into(),
                q: q.into(),
                g: g.into(),
                y: y.into(),
            },
            PublicKey::ElGamal { p, g, y } => Self::ElGamal {
                p: p.into(),
                g: g.into(),
                y: y.into(),
            },
            PublicKey::EdDSA { curve, q } => Self::EdDSA {
                curve: curve.to_string(),
                q: q.into(),
            },
            PublicKey::ECDSA { curve, q } => Self::ECDSA {
                curve: curve.to_string(),
                q: q.into(),
            },
            PublicKey::ECDH {
                curve,
                q,
                hash,
                sym,
            } => Self::ECDH {
                curve: curve.to_string(),
                q: q.into(),
                hash: hash.to_string(),
                sym: sym.to_string(),
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Serialize)]
struct DumpableKey {
    algorithm: String,
    parameters: DumpableKeyParams,
    fingerprint: String,
    keyid: String,
}

impl From<PrimaryKeyAmalgamation<'_, PublicParts>> for DumpableKey {
    fn from(key: PrimaryKeyAmalgamation<'_, PublicParts>) -> Self {
        let key = key.key();

        Self {
            algorithm: key.pk_algo().to_string(),
            parameters: key.mpis().into(),
            fingerprint: key.fingerprint().to_hex(),
            keyid: key.keyid().to_hex(),
        }
    }
}

impl From<SubordinateKeyAmalgamation<'_, PublicParts>> for DumpableKey {
    fn from(key: SubordinateKeyAmalgamation<'_, PublicParts>) -> Self {
        let key = key.key();

        Self {
            algorithm: key.pk_algo().to_string(),
            parameters: key.mpis().into(),
            fingerprint: key.fingerprint().to_hex(),
            keyid: key.keyid().to_hex(),
        }
    }
}

#[derive(Serialize)]
struct DumpableRevocationKey {
    algorithm: String,
    fingerprint: String,
}

impl From<&RevocationKey> for DumpableRevocationKey {
    fn from(key: &RevocationKey) -> Self {
        Self {
            algorithm: key.revoker().0.to_string(),
            fingerprint: key.revoker().1.to_hex(),
        }
    }
}

#[derive(Serialize)]
struct DumpableCert {
    armor_headers: Vec<String>,
    fingerprint: String,
    keyid: String,
    userids: Vec<String>,
    primary_key: DumpableKey,
    subkeys: Vec<DumpableKey>,
    revocation_keys: Vec<DumpableRevocationKey>,
}

impl From<Cert> for DumpableCert {
    fn from(cert: Cert) -> Self {
        Self {
            armor_headers: cert.armor_headers(),
            fingerprint: cert.fingerprint().to_hex(),
            keyid: cert.keyid().to_hex(),
            userids: cert
                .userids()
                .map(|uid| String::from_utf8_lossy(uid.value()).into_owned())
                .collect(),
            primary_key: cert.primary_key().into(),
            subkeys: cert.keys().subkeys().map(DumpableKey::from).collect(),
            revocation_keys: cert
                .revocation_keys(&StandardPolicy::new())
                .map(DumpableRevocationKey::from)
                .collect(),
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let cert = match args.input {
        Some(input) => Cert::from_reader(File::open(input)?),
        None => Cert::from_reader(io::stdin()),
    }
    .with_context(|| "failed to load PGP key from input; not a key message?")?;

    let cert = DumpableCert::from(cert);

    println!("{}", serde_json::to_string_pretty(&cert)?);

    Ok(())
}
