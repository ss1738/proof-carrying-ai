//! Native (Rust) prover/verifier for qedra's Cramer-Damgard-Schoenmakers Sigma OR-proof over Pedersen
//! commitments, in the 2048-bit MODP QR subgroup. WIRE-COMPATIBLE with the Python `qedra.zk_core`:
//! identical group constants, identical serialization (decimal strings), identical Fiat-Shamir hash. So a
//! proof produced here verifies in Python and vice versa -- same protocol, native speed.
//!
//! Subcommands:
//!   zkcore selftest                       prove+verify internally
//!   zkcore prove   <verdict> <m> <ms> <tag>   -> proof JSON on stdout ({C,verdict,t,e,z}, ms = "1,2,3")
//!   zkcore verify  <ms> <tag>             reads proof JSON on stdin -> exit 0 = OK, 1 = FAIL
//!   zkcore bench   <reps> <ms> <tag>      time prove+verify, print ms/op

use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use sha2::{Digest, Sha256};
use std::io::Read;

const P_HEX: &[u8] = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

struct Group {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    h: BigUint,
}

impl Group {
    fn modp() -> Self {
        let p = BigUint::parse_bytes(P_HEX, 16).unwrap();
        let q = (&p - 1u32) / 2u32; // order of the QR subgroup
        let g = BigUint::from(2u32).modpow(&BigUint::from(2u32), &p); // 4
        // h = (sha256("acp/zk/v1/pedersen-h") mod p)^2 mod p
        let seed = BigUint::from_bytes_be(&Sha256::digest(b"acp/zk/v1/pedersen-h")) % &p;
        let h = seed.modpow(&BigUint::from(2u32), &p);
        Group { p, q, g, h }
    }
    fn op(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }
    fn mul(&self, base: &BigUint, k: &BigUint) -> BigUint {
        base.modpow(&(k % &self.q), &self.p)
    }
    fn ser(a: &BigUint) -> String {
        a.to_str_radix(10)
    }
    fn pedersen(&self, m: &BigUint, r: &BigUint) -> BigUint {
        self.op(&self.mul(&self.g, m), &self.mul(&self.h, r))
    }
    // Y_i = C * g^{-mi} = C * g^{(q - mi mod q)}
    fn y(&self, c: &BigUint, mi: &BigUint) -> BigUint {
        let neg = (&self.q - (mi % &self.q)) % &self.q;
        self.op(c, &self.mul(&self.g, &neg))
    }
    // Fiat-Shamir challenge, byte-identical to Python qedra.zk_core.challenge
    fn challenge(&self, tag: &str, verdict: &str, c: &BigUint, ms: &[BigUint], tser: &[String]) -> BigUint {
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
        BigUint::from_bytes_be(&hh.finalize()) % &self.q
    }
}

struct Proof {
    verdict: String,
    c: BigUint,
    t: Vec<BigUint>,
    e: Vec<BigUint>,
    z: Vec<BigUint>,
}

fn prove(grp: &Group, ms: &[BigUint], m: &BigUint, r: &BigUint, verdict: &str, tag: &str) -> Proof {
    let n = ms.len();
    let j = ms.iter().position(|x| x == m).expect("m not in ms");
    let c = grp.pedersen(m, r);
    let mut rng = rand::thread_rng();
    let mut t = vec![BigUint::zero(); n];
    let mut e = vec![BigUint::zero(); n];
    let mut z = vec![BigUint::zero(); n];
    for i in 0..n {
        if i == j {
            continue;
        }
        e[i] = rng.gen_biguint_below(&grp.q);
        z[i] = rng.gen_biguint_below(&grp.q);
        let yi = grp.y(&c, &ms[i]);
        let neg_e = (&grp.q - &e[i]) % &grp.q;
        t[i] = grp.op(&grp.mul(&grp.h, &z[i]), &grp.mul(&yi, &neg_e));
    }
    let k = rng.gen_biguint_below(&grp.q);
    t[j] = grp.mul(&grp.h, &k);
    let tser: Vec<String> = t.iter().map(Group::ser).collect();
    let e_total = grp.challenge(tag, verdict, &c, ms, &tser);
    let mut sum_others = BigUint::zero();
    for (i, ei) in e.iter().enumerate() {
        if i != j {
            sum_others += ei;
        }
    }
    sum_others %= &grp.q;
    e[j] = (&e_total + &grp.q - &sum_others) % &grp.q;
    z[j] = (&k + &e[j] * (r % &grp.q)) % &grp.q;
    Proof { verdict: verdict.to_string(), c, t, e, z }
}

fn verify(grp: &Group, ms: &[BigUint], pf: &Proof, tag: &str) -> bool {
    let n = ms.len();
    if pf.t.len() != n || pf.e.len() != n || pf.z.len() != n || n == 0 {
        return false;
    }
    for x in pf.e.iter().chain(pf.z.iter()) {
        if x >= &grp.q {
            return false;
        }
    }
    let tser: Vec<String> = pf.t.iter().map(Group::ser).collect();
    let mut esum = BigUint::zero();
    for ei in &pf.e {
        esum += ei;
    }
    if grp.challenge(tag, &pf.verdict, &pf.c, ms, &tser) != esum % &grp.q {
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

// ---- minimal JSON (decimal-string fields only; matches Python ZKProof.to_dict + a "C" field) ----
fn to_json(pf: &Proof) -> String {
    let arr = |v: &[BigUint]| {
        v.iter()
            .map(|x| format!("\"{}\"", x.to_str_radix(10)))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "{{\"C\":\"{}\",\"verdict\":\"{}\",\"t\":[{}],\"e\":[{}],\"z\":[{}]}}",
        pf.c.to_str_radix(10),
        pf.verdict,
        arr(&pf.t),
        arr(&pf.e),
        arr(&pf.z)
    )
}

fn json_field<'a>(s: &'a str, key: &str) -> &'a str {
    // find "key": then the value (string or array), returned as a raw slice
    let pat = format!("\"{}\"", key);
    let i = s.find(&pat).expect("key") + pat.len();
    let rest = &s[i..];
    let colon = rest.find(':').unwrap() + 1;
    rest[colon..].trim_start()
}

fn parse_biguints(list: &str) -> Vec<BigUint> {
    // list like ["123","456"]  -> Vec<BigUint>
    list.trim_start_matches('[')
        .split(']')
        .next()
        .unwrap()
        .split(',')
        .filter_map(|tok| {
            let t = tok.trim().trim_matches('"');
            if t.is_empty() {
                None
            } else {
                Some(BigUint::parse_bytes(t.as_bytes(), 10).unwrap())
            }
        })
        .collect()
}

fn parse_proof(s: &str) -> Proof {
    let c = BigUint::parse_bytes(
        json_field(s, "C").trim().trim_matches('"').split('"').next().unwrap().as_bytes(),
        10,
    )
    .unwrap();
    let verdict = json_field(s, "verdict")
        .trim()
        .trim_start_matches('"')
        .split('"')
        .next()
        .unwrap()
        .to_string();
    Proof {
        verdict,
        c,
        t: parse_biguints(json_field(s, "t")),
        e: parse_biguints(json_field(s, "e")),
        z: parse_biguints(json_field(s, "z")),
    }
}

fn ms_from_arg(a: &str) -> Vec<BigUint> {
    a.split(',')
        .map(|x| BigUint::parse_bytes(x.trim().as_bytes(), 10).unwrap())
        .collect()
}

fn main() {
    let grp = Group::modp();
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("selftest");
    let mut rng = rand::thread_rng();
    match cmd {
        "selftest" => {
            let ms = ms_from_arg("1,2,3");
            let m = BigUint::from(2u32);
            let r = rng.gen_biguint_below(&grp.q);
            let pf = prove(&grp, &ms, &m, &r, "allow", "cert/counterparty");
            let ok = verify(&grp, &ms, &pf, "cert/counterparty");
            // negative: verifying against the wrong set must fail
            let bad = verify(&grp, &ms_from_arg("4,5,6"), &pf, "cert/counterparty");
            println!("selftest: honest={} wrong_set={}", ok, !bad);
            std::process::exit(if ok && !bad { 0 } else { 1 });
        }
        "prove" => {
            let verdict = &args[2];
            let m = BigUint::parse_bytes(args[3].as_bytes(), 10).unwrap();
            let ms = ms_from_arg(&args[4]);
            let tag = &args[5];
            let r = rng.gen_biguint_below(&grp.q);
            let pf = prove(&grp, &ms, &m, &r, verdict, tag);
            println!("{}", to_json(&pf));
        }
        "verify" => {
            let ms = ms_from_arg(&args[2]);
            let tag = &args[3];
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).unwrap();
            let pf = parse_proof(&s);
            let ok = verify(&grp, &ms, &pf, tag);
            println!("{}", if ok { "OK" } else { "FAIL" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        "bench" => {
            let reps: u32 = args[2].parse().unwrap();
            let ms = ms_from_arg(&args[3]);
            let tag = &args[4];
            let m = BigUint::from(2u32);
            let t0 = std::time::Instant::now();
            let mut pf = prove(&grp, &ms, &m, &rng.gen_biguint_below(&grp.q), "allow", tag);
            for _ in 1..reps {
                pf = prove(&grp, &ms, &m, &rng.gen_biguint_below(&grp.q), "allow", tag);
            }
            let prove_ms = t0.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            let t1 = std::time::Instant::now();
            for _ in 0..reps {
                assert!(verify(&grp, &ms, &pf, tag));
            }
            let verify_ms = t1.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            println!(
                "zkcore(rust) MODP-2048 OR-proof(|ms|={}): prove {:.3} ms | verify {:.3} ms  (reps={})",
                ms.len(),
                prove_ms,
                verify_ms,
                reps
            );
        }
        other => {
            eprintln!("unknown command: {}", other);
            std::process::exit(2);
        }
    }
}
