//! Native (Rust) Bulletproofs range prover over secp256k1, WIRE-COMPATIBLE with the Python bulletproof.py:
//! identical generators (nothing-up-my-sleeve hash-to-curve), identical compressed serialization, identical
//! SHA256 Fiat-Shamir byte layout. A range proof produced here verifies in Python's range_verify -- same
//! protocol, native speed. Python BP prove is ~6-13 s (pure-Python EC); this is the fast prover.
//!
//! Subcommands: gens (debug: print g[0],u ser) | selftest | range-prove <v> <nbits> | bench <reps> <nbits>

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

// secp256k1
fn p() -> BigUint {
    BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap()
}
fn order() -> BigUint {
    BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}
fn gx() -> BigUint {
    BigUint::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap()
}
fn gy() -> BigUint {
    BigUint::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap()
}

type Pt = Option<(BigUint, BigUint)>; // None = identity

fn inv_p(x: &BigUint, pp: &BigUint) -> BigUint {
    x.modpow(&(pp - 2u32), pp)
}

fn padd(a: &Pt, b: &Pt, pp: &BigUint) -> Pt {
    // affine wrapper over the Jacobian adder (defined below); one inversion at the boundary.
    to_affine(&jac_add(&jac_from(a), &jac_from(b), pp), pp)
}

// ---- Jacobian coordinates (X,Y,Z), affine (x,y)=(X/Z^2, Y/Z^3); Z=0 is identity. secp256k1 a=0. ----
// One field inversion per scalar-mul (at to_affine) instead of one per point-add -- the measured bottleneck.
type Jac = (BigUint, BigUint, BigUint);

fn jac_id() -> Jac {
    (BigUint::one(), BigUint::one(), BigUint::zero())
}
fn jac_from(pt: &Pt) -> Jac {
    match pt {
        None => jac_id(),
        Some((x, y)) => (x.clone(), y.clone(), BigUint::one()),
    }
}
fn msub(a: &BigUint, b: &BigUint, pp: &BigUint) -> BigUint {
    ((a % pp) + pp - (b % pp)) % pp
}
fn jac_double(pt: &Jac, pp: &BigUint) -> Jac {
    let (x, y, z) = pt;
    if z.is_zero() {
        return jac_id();
    }
    let aa = (x * x) % pp;
    let bb = (y * y) % pp;
    let cc = (&bb * &bb) % pp;
    let xb = (x + &bb) % pp;
    let d = (2u32 * msub(&msub(&(&xb * &xb % pp), &aa, pp), &cc, pp)) % pp;
    let e = (3u32 * &aa) % pp;
    let f = (&e * &e) % pp;
    let x3 = msub(&f, &((2u32 * &d) % pp), pp);
    let y3 = msub(&(&e * msub(&d, &x3, pp) % pp), &((8u32 * &cc) % pp), pp);
    let z3 = (2u32 * y * z) % pp;
    (x3, y3, z3)
}
fn jac_add(p1: &Jac, p2: &Jac, pp: &BigUint) -> Jac {
    if p1.2.is_zero() {
        return p2.clone();
    }
    if p2.2.is_zero() {
        return p1.clone();
    }
    let (x1, y1, z1) = p1;
    let (x2, y2, z2) = p2;
    let z1z1 = (z1 * z1) % pp;
    let z2z2 = (z2 * z2) % pp;
    let u1 = (x1 * &z2z2) % pp;
    let u2 = (x2 * &z1z1) % pp;
    let s1 = (y1 * z2 % pp * &z2z2) % pp;
    let s2 = (y2 * z1 % pp * &z1z1) % pp;
    if u1 == u2 {
        if s1 == s2 {
            return jac_double(p1, pp);
        }
        return jac_id();
    }
    let h = msub(&u2, &u1, pp);
    let hh = (&h * &h) % pp;
    let hhh = (&h * &hh) % pp;
    let rr = msub(&s2, &s1, pp);
    let v = (&u1 * &hh) % pp;
    let x3 = msub(&msub(&(&rr * &rr % pp), &hhh, pp), &((2u32 * &v) % pp), pp);
    let y3 = msub(&(&rr * msub(&v, &x3, pp) % pp), &(&s1 * &hhh % pp), pp);
    let z3 = (&h * z1 % pp * z2) % pp;
    (x3, y3, z3)
}
fn to_affine(j: &Jac, pp: &BigUint) -> Pt {
    if j.2.is_zero() {
        return None;
    }
    let zi = inv_p(&j.2, pp);
    let zi2 = (&zi * &zi) % pp;
    let zi3 = (&zi2 * &zi) % pp;
    Some(((&j.0 * &zi2) % pp, (&j.1 * &zi3) % pp))
}

fn jac_mul(k: &BigUint, base: &Pt, pp: &BigUint) -> Jac {
    let n = order();
    let mut k = k % &n;
    let mut acc = jac_id();
    let mut cur = jac_from(base);
    while !k.is_zero() {
        if (&k & BigUint::one()) == BigUint::one() {
            acc = jac_add(&acc, &cur, pp);
        }
        cur = jac_double(&cur, pp);
        k >>= 1;
    }
    acc
}

fn pmul(k: &BigUint, base: &Pt, pp: &BigUint) -> Pt {
    to_affine(&jac_mul(k, base, pp), pp)
}

fn ser(pt: &Pt) -> String {
    match pt {
        None => "00".to_string(),
        Some((x, y)) => {
            let prefix = if (y & BigUint::one()) == BigUint::one() { "03" } else { "02" };
            format!("{}{:0>64}", prefix, x.to_str_radix(16))
        }
    }
}

fn hash_to_point(label: &[u8], pp: &BigUint) -> Pt {
    let exp = (pp + 1u32) / 4u32; // p == 3 mod 4
    let mut ctr: u32 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(label);
        hasher.update(ctr.to_be_bytes());
        let x = BigUint::from_bytes_be(&hasher.finalize()) % pp;
        let rhs = (&x * &x % pp * &x + 7u32) % pp;
        let y = rhs.modpow(&exp, pp);
        if (&y * &y) % pp == rhs {
            let y = if (&y & BigUint::one()) == BigUint::one() { pp - &y } else { y };
            return Some((x, y));
        }
        ctr += 1;
    }
}

// ---- Fiat-Shamir, byte-identical to Python bulletproof._fs ----
enum FS<'a> {
    P(&'a Pt),
    S(&'a BigUint),
    L(&'a str),
}

fn fs(parts: &[FS], pp: &BigUint) -> BigUint {
    let mut h = Sha256::new();
    h.update(b"bp/fiat-shamir/v1|");
    for part in parts {
        match part {
            FS::P(pt) => h.update(ser(pt).as_bytes()),
            FS::S(s) => h.update(s.to_str_radix(10).as_bytes()),
            FS::L(s) => h.update(s.as_bytes()),
        }
        h.update(b"|");
    }
    let n = order();
    let r = BigUint::from_bytes_be(&h.finalize()) % &n;
    if r.is_zero() {
        BigUint::one()
    } else {
        r
    }
}

fn gens(n: usize, pp: &BigUint) -> (Vec<Pt>, Vec<Pt>, Pt, Pt) {
    let g = (0..n).map(|i| hash_to_point(format!("bp/g/{}", i).as_bytes(), pp)).collect();
    let h = (0..n).map(|i| hash_to_point(format!("bp/h/{}", i).as_bytes(), pp)).collect();
    let u = hash_to_point(b"bp/u", pp);
    let hb = hash_to_point(b"bp/hblind", pp);
    (g, h, u, hb)
}

fn multiexp(scalars: &[BigUint], points: &[Pt], pp: &BigUint) -> Pt {
    let n = order();
    let mut acc = jac_id();
    for (s, pt) in scalars.iter().zip(points.iter()) {
        acc = jac_add(&acc, &jac_mul(&(s % &n), pt, pp), pp);
    }
    to_affine(&acc, pp)
}

fn vec_ip(a: &[BigUint], b: &[BigUint], n: &BigUint) -> BigUint {
    let mut s = BigUint::zero();
    for (x, y) in a.iter().zip(b.iter()) {
        s = (s + x * y) % n;
    }
    s
}

fn inv_n(x: &BigUint, n: &BigUint) -> BigUint {
    x.modpow(&(n - 2u32), n)
}

// ---- inner-product argument ----
fn ipa_prove(g: &[Pt], h: &[Pt], u: &Pt, a: &[BigUint], b: &[BigUint], seed: &BigUint, pp: &BigUint)
    -> (Vec<Pt>, Vec<Pt>, BigUint, BigUint) {
    let n = order();
    let (mut g, mut h, mut a, mut b) = (g.to_vec(), h.to_vec(), a.to_vec(), b.to_vec());
    let mut ls = Vec::new();
    let mut rs = Vec::new();
    let mut e = seed.clone();
    while a.len() > 1 {
        let m = a.len() / 2;
        let cl = vec_ip(&a[..m], &b[m..], &n);
        let cr = vec_ip(&a[m..], &b[..m], &n);
        let big_l = padd(&padd(&multiexp(&a[..m], &g[m..], pp), &multiexp(&b[m..], &h[..m], pp), pp), &pmul(&cl, u, pp), pp);
        let big_r = padd(&padd(&multiexp(&a[m..], &g[..m], pp), &multiexp(&b[..m], &h[m..], pp), pp), &pmul(&cr, u, pp), pp);
        ls.push(big_l.clone());
        rs.push(big_r.clone());
        e = fs(&[FS::S(&e), FS::P(&big_l), FS::P(&big_r)], pp);
        let x = e.clone();
        let xi = inv_n(&x, &n);
        let mut na = Vec::with_capacity(m);
        let mut nb = Vec::with_capacity(m);
        let mut ng = Vec::with_capacity(m);
        let mut nh = Vec::with_capacity(m);
        for i in 0..m {
            na.push((&a[i] * &x + &a[m + i] * &xi) % &n);
            nb.push((&b[i] * &xi + &b[m + i] * &x) % &n);
            ng.push(padd(&pmul(&xi, &g[i], pp), &pmul(&x, &g[m + i], pp), pp));
            nh.push(padd(&pmul(&x, &h[i], pp), &pmul(&xi, &h[m + i], pp), pp));
        }
        a = na;
        b = nb;
        g = ng;
        h = nh;
    }
    (ls, rs, a[0].clone(), b[0].clone())
}

fn rand_scalar() -> BigUint {
    use num_bigint::RandBigInt;
    let n = order();
    rand::thread_rng().gen_biguint_below(&n)
}

struct RangeProof {
    v: Pt,
    a: Pt,
    s: Pt,
    t1: Pt,
    t2: Pt,
    tau_x: BigUint,
    mu: BigUint,
    t_hat: BigUint,
    ls: Vec<Pt>,
    rs: Vec<Pt>,
    ipa_a: BigUint,
    ipa_b: BigUint,
    n: usize,
}

fn range_prove(v: u128, gamma: &BigUint, nbits: usize, pp: &BigUint) -> RangeProof {
    let n = order();
    let (g, h, u, hb) = gens(nbits, pp);
    let gpt = Some((gx(), gy()));
    let vbig = BigUint::from(v);
    let big_v = padd(&pmul(&vbig, &gpt, pp), &pmul(gamma, &hb, pp), pp);
    let a_l: Vec<BigUint> = (0..nbits).map(|i| BigUint::from(((v >> i) & 1) as u32)).collect();
    let a_r: Vec<BigUint> = a_l.iter().map(|b| (b + &n - 1u32) % &n).collect();
    let alpha = rand_scalar();
    let big_a = padd(&padd(&pmul(&alpha, &hb, pp), &multiexp(&a_l, &g, pp), pp), &multiexp(&a_r, &h, pp), pp);
    let s_l: Vec<BigUint> = (0..nbits).map(|_| rand_scalar()).collect();
    let s_r: Vec<BigUint> = (0..nbits).map(|_| rand_scalar()).collect();
    let rho = rand_scalar();
    let big_s = padd(&padd(&pmul(&rho, &hb, pp), &multiexp(&s_l, &g, pp), pp), &multiexp(&s_r, &h, pp), pp);
    let y = fs(&[FS::L("y"), FS::P(&big_a), FS::P(&big_s)], pp);
    let z = fs(&[FS::L("z"), FS::P(&big_a), FS::P(&big_s), FS::S(&y)], pp);
    let yn: Vec<BigUint> = (0..nbits).map(|i| y.modpow(&BigUint::from(i as u32), &n)).collect();
    let twos: Vec<BigUint> = (0..nbits).map(|i| (BigUint::one() << i) % &n).collect();
    let z2 = (&z * &z) % &n;
    let l0: Vec<BigUint> = a_l.iter().map(|a| (a + &n - &z) % &n).collect();
    let l1 = s_l.clone();
    let r0: Vec<BigUint> = (0..nbits).map(|i| (&yn[i] * ((&a_r[i] + &z) % &n) + &z2 * &twos[i]) % &n).collect();
    let r1: Vec<BigUint> = (0..nbits).map(|i| (&yn[i] * &s_r[i]) % &n).collect();
    let t1 = (vec_ip(&l0, &r1, &n) + vec_ip(&l1, &r0, &n)) % &n;
    let t2 = vec_ip(&l1, &r1, &n);
    let tau1 = rand_scalar();
    let tau2 = rand_scalar();
    let big_t1 = padd(&pmul(&t1, &gpt, pp), &pmul(&tau1, &hb, pp), pp);
    let big_t2 = padd(&pmul(&t2, &gpt, pp), &pmul(&tau2, &hb, pp), pp);
    let x = fs(&[FS::L("x"), FS::P(&big_t1), FS::P(&big_t2)], pp);
    let l: Vec<BigUint> = (0..nbits).map(|i| (&l0[i] + &l1[i] * &x) % &n).collect();
    let r: Vec<BigUint> = (0..nbits).map(|i| (&r0[i] + &r1[i] * &x) % &n).collect();
    let t_hat = vec_ip(&l, &r, &n);
    let tau_x = ((&tau2 * &x % &n) * &x + &tau1 * &x + &z2 * gamma) % &n;
    let mu = (&alpha + &rho * &x) % &n;
    let yinv = inv_n(&y, &n);
    let hp: Vec<Pt> = (0..nbits).map(|i| pmul(&yinv.modpow(&BigUint::from(i as u32), &n), &h[i], pp)).collect();
    let seed = fs(&[FS::L("bp-range-ipa"), FS::P(&big_a), FS::P(&big_s), FS::P(&big_t1), FS::P(&big_t2), FS::S(&x), FS::S(&t_hat), FS::S(&mu), FS::S(&tau_x)], pp);
    let (ls, rs, ia, ib) = ipa_prove(&g, &hp, &u, &l, &r, &seed, pp);
    RangeProof { v: big_v, a: big_a, s: big_s, t1: big_t1, t2: big_t2, tau_x, mu, t_hat, ls, rs, ipa_a: ia, ipa_b: ib, n: nbits }
}

fn range_json(rp: &RangeProof) -> String {
    let arr = |v: &[Pt]| v.iter().map(|p| format!("\"{}\"", ser(p))).collect::<Vec<_>>().join(",");
    format!(
        "{{\"V\":\"{}\",\"proof\":{{\"n\":{},\"A\":\"{}\",\"S\":\"{}\",\"T1\":\"{}\",\"T2\":\"{}\",\"tau_x\":\"{}\",\"mu\":\"{}\",\"t_hat\":\"{}\",\"L\":[{}],\"R\":[{}],\"a\":\"{}\",\"b\":\"{}\"}}}}",
        ser(&rp.v), rp.n, ser(&rp.a), ser(&rp.s), ser(&rp.t1), ser(&rp.t2),
        rp.tau_x.to_str_radix(10), rp.mu.to_str_radix(10), rp.t_hat.to_str_radix(10),
        arr(&rp.ls), arr(&rp.rs), rp.ipa_a.to_str_radix(10), rp.ipa_b.to_str_radix(10)
    )
}

fn main() {
    let pp = p();
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("selftest");
    match cmd {
        "gens" => {
            let (g, _h, u, _hb) = gens(2, &pp);
            println!("g[0] {}", ser(&g[0]));
            println!("u    {}", ser(&u));
        }
        "range-prove" => {
            let v: u128 = args[2].parse().unwrap();
            let nbits: usize = args[3].parse().unwrap();
            let rp = range_prove(v, &rand_scalar(), nbits, &pp);
            println!("{}", range_json(&rp));
        }
        "bench" => {
            let reps: u32 = args[2].parse().unwrap();
            let nbits: usize = args[3].parse().unwrap();
            let v: u128 = 1u128 << (nbits.min(120) - 2);
            let t0 = std::time::Instant::now();
            for _ in 0..reps {
                let _ = range_prove(v, &rand_scalar(), nbits, &pp);
            }
            let ms = t0.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            println!("bulletproof-rs range prove (n={}): {:.2} ms (reps={})", nbits, ms, reps);
        }
        "selftest" => {
            // Rust-only sanity: prove and print JSON length; full soundness checked cross-language in Python.
            let rp = range_prove(750, &rand_scalar(), 16, &pp);
            let js = range_json(&rp);
            println!("selftest: produced n=16 range proof, {} rounds, {} bytes JSON", rp.ls.len(), js.len());
        }
        other => {
            eprintln!("unknown command: {}", other);
            std::process::exit(2);
        }
    }
}
