//! GMP-backed (rug) prover/verifier for qedra's Sigma OR-proof over Pedersen commitments + the
//! bit-decomposition range proof, in the 2048-bit MODP QR subgroup. Byte-identical protocol to
//! `zkcore` (num-bigint) and the Python `qedra.zk_core` -- same constants, decimal-string serialization,
//! same Fiat-Shamir hash -- so proofs remain cross-verifiable. The only change is the bignum backend:
//! GMP's assembly modmul instead of num-bigint / CPython `pow`.
//!
//! Subcommands: selftest | range-selftest | prove <verdict> <m> <ms> <tag> | range-prove <limit> <amount>
//! <nbits> | bench <reps> <ms> <tag> | cert-bench <reps> <nbits>

use rand::RngCore;
use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};

const P_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

fn nmod(a: Integer, q: &Integer) -> Integer {
    let mut r = a % q;
    if r < 0 {
        r += q;
    }
    r
}

fn rand_below(q: &Integer) -> Integer {
    let nbytes = (q.significant_bits() as usize / 8) + 8;
    let mut buf = vec![0u8; nbytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    nmod(Integer::from_digits(&buf, Order::MsfBe), q)
}

struct Group {
    p: Integer,
    q: Integer,
    g: Integer,
    h: Integer,
}

impl Group {
    fn modp() -> Self {
        let p = Integer::from_str_radix(P_HEX, 16).unwrap();
        let q = Integer::from(&p - 1) / 2;
        let g = Integer::from(2).pow_mod(&Integer::from(2), &p).unwrap(); // 4
        let seed = nmod(Integer::from_digits(&Sha256::digest(b"acp/zk/v1/pedersen-h"), Order::MsfBe), &p);
        let h = seed.pow_mod(&Integer::from(2), &p).unwrap();
        Group { p, q, g, h }
    }
    fn op(&self, a: &Integer, b: &Integer) -> Integer {
        nmod(Integer::from(a * b), &self.p)
    }
    fn mul(&self, base: &Integer, k: &Integer) -> Integer {
        let e = nmod(Integer::from(k), &self.q);
        base.clone().pow_mod(&e, &self.p).unwrap()
    }
    fn ser(a: &Integer) -> String {
        a.to_string_radix(10)
    }
    fn pedersen(&self, m: &Integer, r: &Integer) -> Integer {
        self.op(&self.mul(&self.g, m), &self.mul(&self.h, r))
    }
    fn y(&self, c: &Integer, mi: &Integer) -> Integer {
        let neg = nmod(Integer::from(&self.q - &nmod(Integer::from(mi), &self.q)), &self.q);
        self.op(c, &self.mul(&self.g, &neg))
    }
    fn challenge(&self, tag: &str, verdict: &str, c: &Integer, ms: &[Integer], tser: &[String]) -> Integer {
        let mut hh = Sha256::new();
        hh.update(b"acp/zk-core/v1|");
        for part in [
            tag.to_string(),
            verdict.to_string(),
            Self::ser(&self.g),
            Self::ser(&self.h),
            Self::ser(&self.q),
            Self::ser(c),
        ] {
            hh.update(part.as_bytes());
            hh.update(b"|");
        }
        for mi in ms {
            hh.update(Self::ser(mi).as_bytes());
            hh.update(b"|");
        }
        for t in tser {
            hh.update(t.as_bytes());
            hh.update(b"|");
        }
        nmod(Integer::from_digits(&hh.finalize(), Order::MsfBe), &self.q)
    }
}

struct Proof {
    verdict: String,
    c: Integer,
    t: Vec<Integer>,
    e: Vec<Integer>,
    z: Vec<Integer>,
}

fn prove(grp: &Group, ms: &[Integer], m: &Integer, r: &Integer, verdict: &str, tag: &str) -> Proof {
    let n = ms.len();
    let j = ms.iter().position(|x| x == m).expect("m not in ms");
    let c = grp.pedersen(m, r);
    let mut t: Vec<Integer> = (0..n).map(|_| Integer::new()).collect();
    let mut e: Vec<Integer> = (0..n).map(|_| Integer::new()).collect();
    let mut z: Vec<Integer> = (0..n).map(|_| Integer::new()).collect();
    for i in 0..n {
        if i == j {
            continue;
        }
        e[i] = rand_below(&grp.q);
        z[i] = rand_below(&grp.q);
        let yi = grp.y(&c, &ms[i]);
        let neg_e = nmod(Integer::from(&grp.q - &e[i]), &grp.q);
        t[i] = grp.op(&grp.mul(&grp.h, &z[i]), &grp.mul(&yi, &neg_e));
    }
    let k = rand_below(&grp.q);
    t[j] = grp.mul(&grp.h, &k);
    let tser: Vec<String> = t.iter().map(Group::ser).collect();
    let e_total = grp.challenge(tag, verdict, &c, ms, &tser);
    let mut sum_others = Integer::new();
    for (i, ei) in e.iter().enumerate() {
        if i != j {
            sum_others += ei;
        }
    }
    e[j] = nmod(Integer::from(&e_total - &sum_others), &grp.q);
    let rq = nmod(Integer::from(r), &grp.q);
    z[j] = nmod(Integer::from(&k + Integer::from(&e[j] * &rq)), &grp.q);
    Proof { verdict: verdict.to_string(), c, t, e, z }
}

fn verify(grp: &Group, ms: &[Integer], pf: &Proof, tag: &str) -> bool {
    let n = ms.len();
    if pf.t.len() != n || pf.e.len() != n || pf.z.len() != n || n == 0 {
        return false;
    }
    for x in pf.e.iter().chain(pf.z.iter()) {
        if x.is_negative() || x.cmp(&grp.q) != std::cmp::Ordering::Less {
            return false;
        }
    }
    let tser: Vec<String> = pf.t.iter().map(Group::ser).collect();
    let mut esum = Integer::new();
    for ei in &pf.e {
        esum += ei;
    }
    if grp.challenge(tag, &pf.verdict, &pf.c, ms, &tser) != nmod(esum, &grp.q) {
        return false;
    }
    for i in 0..n {
        let yi = grp.y(&pf.c, &ms[i]);
        let lhs = grp.mul(&grp.h, &pf.z[i]);
        let rhs = grp.op(&pf.t[i], &grp.mul(&yi, &pf.e[i]));
        if lhs != rhs {
            return false;
        }
    }
    true
}

fn range_prove(grp: &Group, amount: &Integer, r_a: &Integer, limit: &Integer, nbits: usize) -> (Integer, Vec<Proof>) {
    let c_amount = grp.pedersen(amount, r_a);
    let d = Integer::from(limit - amount);
    let mut r: Vec<Integer> = (0..nbits).map(|_| rand_below(&grp.q)).collect();
    let target = nmod(Integer::from(&grp.q - &nmod(Integer::from(r_a), &grp.q)), &grp.q);
    let mut partial = Integer::new();
    for i in 0..nbits - 1 {
        let w = Integer::from(1) << (i as u32);
        partial += Integer::from(&r[i] * &w);
    }
    partial = nmod(partial, &grp.q);
    let weight_top = nmod(Integer::from(1) << ((nbits - 1) as u32), &grp.q);
    let inv_top = weight_top.pow_mod(&Integer::from(&grp.q - 2), &grp.q).unwrap();
    r[nbits - 1] = nmod(Integer::from(&nmod(Integer::from(&target - &partial), &grp.q) * &inv_top), &grp.q);
    let ms = vec![Integer::from(0), Integer::from(1)];
    let mut proofs = Vec::with_capacity(nbits);
    for i in 0..nbits {
        let bit = Integer::from(d.get_bit(i as u32) as u32);
        proofs.push(prove(grp, &ms, &bit, &r[i], "bit", &format!("range/bit/{}", i)));
    }
    (c_amount, proofs)
}

fn range_verify(grp: &Group, c_amount: &Integer, limit: &Integer, proofs: &[Proof]) -> bool {
    let ms = vec![Integer::from(0), Integer::from(1)];
    for (i, pf) in proofs.iter().enumerate() {
        if !verify(grp, &ms, pf, &format!("range/bit/{}", i)) {
            return false;
        }
    }
    let mut acc: Option<Integer> = None;
    for (i, pf) in proofs.iter().enumerate() {
        let w = nmod(Integer::from(1) << (i as u32), &grp.q);
        let term = grp.mul(&pf.c, &w);
        acc = Some(match acc {
            None => term,
            Some(a) => grp.op(&a, &term),
        });
    }
    let inv = grp.mul(c_amount, &Integer::from(&grp.q - 1));
    let c_d = grp.op(&grp.mul(&grp.g, &nmod(Integer::from(limit), &grp.q)), &inv);
    acc.map_or(false, |a| a == c_d)
}

fn arr(v: &[Integer]) -> String {
    v.iter().map(|x| format!("\"{}\"", x.to_string_radix(10))).collect::<Vec<_>>().join(",")
}

fn to_json(pf: &Proof) -> String {
    format!(
        "{{\"C\":\"{}\",\"verdict\":\"{}\",\"t\":[{}],\"e\":[{}],\"z\":[{}]}}",
        pf.c.to_string_radix(10),
        pf.verdict,
        arr(&pf.t),
        arr(&pf.e),
        arr(&pf.z)
    )
}

fn range_to_json(c_amount: &Integer, proofs: &[Proof]) -> String {
    let cbits = proofs.iter().map(|p| format!("\"{}\"", p.c.to_string_radix(10))).collect::<Vec<_>>().join(",");
    let bps = proofs
        .iter()
        .map(|p| format!("{{\"verdict\":\"{}\",\"t\":[{}],\"e\":[{}],\"z\":[{}]}}", p.verdict, arr(&p.t), arr(&p.e), arr(&p.z)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"C_amount\":\"{}\",\"range\":{{\"nbits\":{},\"C_bits\":[{}],\"bit_proofs\":[{}]}}}}", c_amount.to_string_radix(10), proofs.len(), cbits, bps)
}

fn ms_from_arg(a: &str) -> Vec<Integer> {
    a.split(',').map(|x| Integer::from_str_radix(x.trim(), 10).unwrap()).collect()
}

fn main() {
    let grp = Group::modp();
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("selftest");
    match cmd {
        "selftest" => {
            let ms = ms_from_arg("1,2,3");
            let pf = prove(&grp, &ms, &Integer::from(2), &rand_below(&grp.q), "allow", "cert/counterparty");
            let ok = verify(&grp, &ms, &pf, "cert/counterparty");
            let bad = verify(&grp, &ms_from_arg("4,5,6"), &pf, "cert/counterparty");
            println!("selftest(gmp): honest={} wrong_set={}", ok, !bad);
            std::process::exit(if ok && !bad { 0 } else { 1 });
        }
        "range-selftest" => {
            let (amount, limit, nbits) = (Integer::from(500), Integer::from(1000), 16usize);
            let (ca, proofs) = range_prove(&grp, &amount, &rand_below(&grp.q), &limit, nbits);
            let honest = range_verify(&grp, &ca, &limit, &proofs);
            let c_over = grp.pedersen(&Integer::from(9999), &rand_below(&grp.q));
            let forged = range_verify(&grp, &c_over, &limit, &proofs);
            println!("range-selftest(gmp): honest={} forged_rejected={}", honest, !forged);
            std::process::exit(if honest && !forged { 0 } else { 1 });
        }
        "prove" => {
            let verdict = &args[2];
            let m = Integer::from_str_radix(&args[3], 10).unwrap();
            let ms = ms_from_arg(&args[4]);
            let tag = &args[5];
            let pf = prove(&grp, &ms, &m, &rand_below(&grp.q), verdict, tag);
            println!("{}", to_json(&pf));
        }
        "range-prove" => {
            let limit = Integer::from_str_radix(&args[2], 10).unwrap();
            let amount = Integer::from_str_radix(&args[3], 10).unwrap();
            let nbits: usize = args[4].parse().unwrap();
            let (ca, proofs) = range_prove(&grp, &amount, &rand_below(&grp.q), &limit, nbits);
            println!("{}", range_to_json(&ca, &proofs));
        }
        "bench" => {
            let reps: u32 = args[2].parse().unwrap();
            let ms = ms_from_arg(&args[3]);
            let tag = &args[4];
            let m = Integer::from(2);
            let t0 = std::time::Instant::now();
            let mut pf = prove(&grp, &ms, &m, &rand_below(&grp.q), "allow", tag);
            for _ in 1..reps {
                pf = prove(&grp, &ms, &m, &rand_below(&grp.q), "allow", tag);
            }
            let prove_ms = t0.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            let t1 = std::time::Instant::now();
            for _ in 0..reps {
                assert!(verify(&grp, &ms, &pf, tag));
            }
            let verify_ms = t1.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            println!("zkcore-gmp(rug) MODP-2048 OR-proof(|ms|={}): prove {:.3} ms | verify {:.3} ms (reps={})", ms.len(), prove_ms, verify_ms, reps);
        }
        "cert-bench" => {
            let reps: u32 = args[2].parse().unwrap();
            let nbits: usize = args[3].parse().unwrap();
            let (amount, limit) = (Integer::from(750), Integer::from(1000));
            let ms = ms_from_arg("1,2,3");
            let m = Integer::from(2);
            let t0 = std::time::Instant::now();
            let mut last = None;
            for _ in 0..reps {
                let (ca, rp) = range_prove(&grp, &amount, &rand_below(&grp.q), &limit, nbits);
                let mp = prove(&grp, &ms, &m, &rand_below(&grp.q), "allow", "cert/cp");
                last = Some((ca, rp, mp));
            }
            let prove_ms = t0.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            let (ca, rp, mp) = last.unwrap();
            let t1 = std::time::Instant::now();
            for _ in 0..reps {
                assert!(range_verify(&grp, &ca, &limit, &rp));
                assert!(verify(&grp, &ms, &mp, "cert/cp"));
            }
            let verify_ms = t1.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            println!("zkcore-gmp(rug) full payment cert (range n={} + membership): prove {:.2} ms | verify {:.2} ms (reps={})", nbits, prove_ms, verify_ms, reps);
        }
        other => {
            eprintln!("unknown command: {}", other);
            std::process::exit(2);
        }
    }
}
