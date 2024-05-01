use std::time::{Duration, SystemTime};

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use ed25519_dalek::{ed25519::signature::Signer, Keypair, Signature};
use rand_core::{CryptoRng, OsRng, RngCore};

fn main() {
    let rng = &mut OsRng;
    benchmark_random_signatures(rng, 1_000);
    benchmark_mul(rng, 1_000);
    benchmark_array_equality(rng, 100_000_000);
}

pub fn benchmark_mul<R: Rng>(random: &mut R, num_iter: usize) {
    // generate scalars
    let mut s1_bytes: [u8; 32] = [0; 32];
    let mut s2_bytes: [u8; 32] = [0; 32];
    random.fill_bytes(&mut s1_bytes);
    random.fill_bytes(&mut s2_bytes);
    let scalar1 = Scalar::from_bytes_mod_order(s1_bytes);
    let scalar2 = Scalar::from_bytes_mod_order(s2_bytes);

    // generate curve point
    let ce_bytes = Keypair::generate(random).public.to_bytes();
    let compressed = CompressedEdwardsY::from_slice(&ce_bytes);

    // recursively multiply
    let mut edwards = compressed.decompress().unwrap();
    let mut timer = Timer::start();
    for _ in 0..num_iter {
        edwards = EdwardsPoint::vartime_double_scalar_mul_basepoint(&scalar1, &edwards, &scalar2);
    }
    print!("muls: {} ms\n", timer.lap().as_millis());
}

pub fn benchmark_array_equality<R: Rng>(random: &mut R, num_bytes: usize) {
    let mut one = Vec::<u8>::with_capacity(num_bytes);
    let mut two = Vec::<u8>::with_capacity(num_bytes);
    for _ in 0..num_bytes {
        one.push(0);
        two.push(0);
    }

    let mut timer = Timer::start();
    random.fill_bytes(&mut one);
    random.fill_bytes(&mut two);
    print!("generate arrays: {} ms\n", timer.lap().as_millis());

    let mut c: usize = 0;
    for i in 0..num_bytes {
        if one[i] == two[i] {
            c += 1;
        }
    }
    print!(
        "compare arrays: {} ms ({})\n",
        timer.lap().as_millis(),
        num_bytes / c
    );
}

pub fn benchmark_random_signatures<R: Rng>(random: &mut R, num_keys: usize) {
    let mut data_to_sign: [u8; 1200] = [0; 1200];
    random.fill_bytes(&mut data_to_sign);

    let mut keys = Vec::<Keypair>::with_capacity(num_keys);
    let mut timer = Timer::start();
    for _ in 0..num_keys {
        keys.push(Keypair::generate(random));
    }
    print!("generate keys: {} ms\n", timer.lap().as_millis());

    let mut signatures = Vec::<Signature>::with_capacity(num_keys);
    timer.lap();
    for key in keys.iter() {
        signatures.push(key.sign(&data_to_sign));
    }
    print!("sign: {} ms\n", timer.lap().as_millis());

    timer.lap();
    for i in 0..num_keys {
        let signature = &signatures[i];
        let keypair = &keys[i];
        keypair.verify(&data_to_sign, signature).unwrap();
    }
    print!("verify: {} ms\n", timer.lap().as_millis());
}

// fn generate_and_write_keypairs() {
//     let mut file = File::create("rust.keypairs").unwrap();
//     let mut rng = OsRng;
//     for i in 0..1_000_000 {
//         let keypair = Keypair::generate(&mut rng);
//         file.write_all(keypair.secret.as_bytes()).unwrap();
//         if i % 10000 == 0 {
//             println!("{}", i / 10000);
//         }
//     }
// }

struct Timer {
    last: SystemTime,
}

impl Timer {
    fn start() -> Self {
        let now = SystemTime::now();
        Self { last: now }
    }

    fn lap(&mut self) -> Duration {
        let last = self.last;
        self.last = SystemTime::now();
        return self.last.duration_since(last).unwrap();
    }
}

pub trait Rng: CryptoRng + RngCore {}
impl<T: CryptoRng + RngCore> Rng for T {}
