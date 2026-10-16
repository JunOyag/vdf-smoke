use chiavdf::{create_discriminant, prove, verify_n_wesolowski};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Instant;

const BITS: usize = 1024;

macro_rules! step {
    ($($a:tt)*) => {{ println!($($a)*); std::io::stdout().flush().unwrap(); }};
}

fn default_el() -> [u8; 100] {
    let mut e = [0u8; 100];
    e[0] = 0x08; // forme génératrice (2, 1, c), sérialisation BQFC
    e
}

fn challenge_of(pub_key: &[u8]) -> [u8; 32] {
    Sha256::digest(pub_key).into()
}

fn disc_of(ch: &[u8]) -> [u8; BITS / 8] {
    let mut d = [0u8; BITS / 8];
    assert!(create_discriminant(ch, &mut d), "create_discriminant failed");
    d
}

// Cas officiels de la crate (valident l'environnement)
fn official() {
    let seed = hex::decode("6c3b9aa767f785b537c0").unwrap();
    let mut d = [0u8; 64];
    assert!(create_discriminant(&seed, &mut d));
    let exp = "9a8eaf9c52d9a5f1db648cdf7bcd04b35cb1ac4f421c978fa61fe1344b97d4199dbff700d24e7cfc0b785e4b8b8023dc49f0e90227f74f54234032ac3381879f";
    assert_eq!(hex::encode(d), exp, "discriminant != vecteur officiel");
    step!("official: discriminant 512 bits OK");

    let g = hex::decode("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb").unwrap();
    let disc = disc_of(&g);
    let proof = prove(&g, &default_el(), BITS, 231).expect("prove failed");
    assert!(verify_n_wesolowski(&disc, &default_el(), &proof, 231, 0));
    step!("official: prove/verify T=231 OK, proof_len={}", proof.len());
}

// Notre cas : challenge = SHA-256(pub_key), chemin positif
fn positive() {
    for t in [1_000u64, 20_000] {
        for pk in [&b"pub-key-A"[..], &b"pub-key-B"[..]] {
            let ch = challenge_of(pk);
            let disc = disc_of(&ch);
            let t0 = Instant::now();
            let proof = prove(&ch, &default_el(), BITS, t).expect("prove failed");
            let dt = t0.elapsed();
            assert!(verify_n_wesolowski(&disc, &default_el(), &proof, t, 0), "valid proof rejected");
            step!("positive: T={t} proof_len={} prove={dt:?} OK", proof.len());
        }
    }
}

// Entrées invalides : doivent retourner false, SANS boucler (borne de temps via la CI)
fn negative() {
    let t = 20_000u64;
    let ch = challenge_of(b"pub-key-A");
    let disc = disc_of(&ch);
    let proof = prove(&ch, &default_el(), BITS, t).expect("prove failed");

    for i in [0, proof.len() / 2, proof.len() - 1] {
        let mut bad = proof.clone();
        bad[i] ^= 0x01;
        let t0 = Instant::now();
        let r = verify_n_wesolowski(&disc, &default_el(), &bad, t, 0);
        step!("negative: octet {i} altere -> {r} en {:?}", t0.elapsed());
        assert!(!r, "preuve alteree acceptee");
    }
    let r = verify_n_wesolowski(&disc, &default_el(), &proof, t + 1, 0);
    step!("negative: mauvais T -> {r}");
    assert!(!r);

    let other = disc_of(&challenge_of(b"autre-pub-key"));
    let r = verify_n_wesolowski(&other, &default_el(), &proof, t, 0);
    step!("negative: autre identite -> {r}");
    assert!(!r, "preuve reutilisable entre identites");
}

// Débit pour calibrer T (blocage #3)
fn bench() {
    let t = 1_000_000u64;
    let ch = challenge_of(b"bench-pub-key");
    let t0 = Instant::now();
    let proof = prove(&ch, &default_el(), BITS, t).expect("prove failed");
    let dt = t0.elapsed().as_secs_f64();
    let ips = t as f64 / dt;
    step!("bench: T={t} prove={dt:.2}s -> {ips:.0} it/s ; T pour 60 s = {:.0}", ips * 60.0);
    let disc = disc_of(&ch);
    let t0 = Instant::now();
    assert!(verify_n_wesolowski(&disc, &default_el(), &proof, t, 0));
    step!("bench: verify={:?} (Delta recalcule inclus hors mesure)", t0.elapsed());
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("official") => official(),
        Some("positive") => positive(),
        Some("negative") => negative(),
        Some("bench") => bench(),
        _ => eprintln!("usage: vdf-smoke official|positive|negative|bench"),
    }
}