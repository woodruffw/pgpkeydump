#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fs::File, io, path::PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use sequoia_openpgp::{
    cert::prelude::KeyAmalgamation,
    crypto::mpi::{PublicKey, Signature as SignatureParams, MPI},
    packet::{
        key::{PrimaryRole, PublicParts, SubordinateRole},
        Signature,
    },
    parse::Parse,
    types::KeyFlags,
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

#[allow(clippy::upper_case_acronyms)]
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
struct DumpableKeyFlags {
    authentication: bool,
    certification: bool,
    signing: bool,
    storage_encryption: bool,
    transport_encryption: bool,
}

impl From<KeyFlags> for DumpableKeyFlags {
    fn from(flags: KeyFlags) -> Self {
        Self {
            authentication: flags.for_authentication(),
            certification: flags.for_certification(),
            signing: flags.for_signing(),
            storage_encryption: flags.for_storage_encryption(),
            transport_encryption: flags.for_transport_encryption(),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize)]
#[serde(tag = "algorithm")]
enum DumpableSignatureParams {
    RSA { s: DumpableMPI },
    DSA { r: DumpableMPI, s: DumpableMPI },
    ElGamal { r: DumpableMPI, s: DumpableMPI },
    EdDSA { r: DumpableMPI, s: DumpableMPI },
    ECDSA { r: DumpableMPI, s: DumpableMPI },
    Unknown,
}

impl From<&SignatureParams> for DumpableSignatureParams {
    fn from(params: &SignatureParams) -> Self {
        match params {
            SignatureParams::RSA { s } => Self::RSA { s: s.into() },
            SignatureParams::DSA { r, s } => Self::DSA {
                r: r.into(),
                s: s.into(),
            },
            SignatureParams::ElGamal { r, s } => Self::ElGamal {
                r: r.into(),
                s: s.into(),
            },
            SignatureParams::EdDSA { r, s } => Self::EdDSA {
                r: r.into(),
                s: s.into(),
            },
            SignatureParams::ECDSA { r, s } => Self::ECDSA {
                r: r.into(),
                s: s.into(),
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Serialize)]
struct DumpableSignature {
    version: u8,
    algorithm: String,
    hash_algorithm: String,
    signature_params: DumpableSignatureParams,
    digest_prefix: String,
    level: usize,
    exportable: bool,
    #[serde(rename = "type")]
    typ: String,
    creation: Option<String>,
    expiration: Option<String>,
    key_validity_period: Option<f64>,
    key_flags: Option<DumpableKeyFlags>,
    issuer_key_ids: Vec<String>,
    issuer_fingerprints: Vec<String>,
    embedded_signatures: Vec<DumpableSignature>,
    intended_recipients: Vec<String>,
}

impl From<&Signature> for DumpableSignature {
    fn from(sig: &Signature) -> Self {
        Self {
            version: sig.version(),
            algorithm: sig.pk_algo().to_string(),
            hash_algorithm: sig.hash_algo().to_string(),
            signature_params: sig.mpis().into(),
            digest_prefix: hex::encode(sig.digest_prefix()),
            level: sig.level(),
            exportable: sig.exportable().is_ok(),
            typ: sig.typ().to_string(),
            creation: sig
                .signature_creation_time()
                .map(|t| DateTime::<Utc>::from(t).to_rfc3339()),
            expiration: sig
                .signature_expiration_time()
                .map(|t| DateTime::<Utc>::from(t).to_rfc3339()),
            key_validity_period: sig.key_validity_period().map(|d| d.as_secs_f64()),
            key_flags: sig.key_flags().map(Into::into),
            issuer_key_ids: sig.issuers().map(|kid| kid.to_hex()).collect(),
            issuer_fingerprints: sig.issuer_fingerprints().map(|fp| fp.to_hex()).collect(),
            embedded_signatures: sig.embedded_signatures().map(Into::into).collect(),
            intended_recipients: sig.intended_recipients().map(|ir| ir.to_hex()).collect(),
        }
    }
}

#[derive(Serialize)]
struct DumpableKey {
    algorithm: String,
    parameters: DumpableKeyParams,
    fingerprint: String,
    keyid: String,
    creation: String,
    self_signatures: Vec<DumpableSignature>,
    attestations: Vec<DumpableSignature>,
    certifications: Vec<DumpableSignature>,
    self_revocations: Vec<DumpableSignature>,
    other_revocations: Vec<DumpableSignature>,
}

impl From<KeyAmalgamation<'_, PublicParts, PrimaryRole, ()>> for DumpableKey {
    fn from(key: KeyAmalgamation<'_, PublicParts, PrimaryRole, ()>) -> Self {
        Self {
            algorithm: key.pk_algo().to_string(),
            parameters: key.mpis().into(),
            fingerprint: key.fingerprint().to_hex(),
            keyid: key.keyid().to_hex(),
            creation: DateTime::<Utc>::from(key.creation_time()).to_rfc3339(),
            self_signatures: key.self_signatures().map(Into::into).collect(),
            attestations: key.attestations().map(Into::into).collect(),
            certifications: key.certifications().map(Into::into).collect(),
            self_revocations: key.self_revocations().map(Into::into).collect(),
            other_revocations: key.other_revocations().map(Into::into).collect(),
        }
    }
}

impl From<KeyAmalgamation<'_, PublicParts, SubordinateRole, ()>> for DumpableKey {
    fn from(key: KeyAmalgamation<'_, PublicParts, SubordinateRole, ()>) -> Self {
        Self {
            algorithm: key.pk_algo().to_string(),
            parameters: key.mpis().into(),
            fingerprint: key.fingerprint().to_hex(),
            keyid: key.keyid().to_hex(),
            creation: DateTime::<Utc>::from(key.creation_time()).to_rfc3339(),
            self_signatures: key.self_signatures().map(Into::into).collect(),
            attestations: key.attestations().map(Into::into).collect(),
            certifications: key.certifications().map(Into::into).collect(),
            self_revocations: key.self_revocations().map(Into::into).collect(),
            other_revocations: key.other_revocations().map(Into::into).collect(),
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
