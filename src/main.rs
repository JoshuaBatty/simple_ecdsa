// Ported from https://habr.com/en/articles/692072/

use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq)]
struct Point {
    x: BigUint,
    y: BigUint,
    curve_config: CurveConfig,
}

#[derive(Clone, Debug, PartialEq)]
struct CurveConfig {
    a: BigUint,
    b: BigUint,
    p: BigUint,
}

impl Point {
    fn new(x: BigUint, y: BigUint, curve_config: CurveConfig) -> Self {
        let rhs = (&x * &x * &x + &curve_config.a * &x + &curve_config.b) % &curve_config.p;
        let lhs = (&y * &y) % &curve_config.p;
        if lhs != rhs {
            panic!("The point is not on the curve");
        }
        Point { x, y, curve_config }
    }

    fn add(&self, other: &Point) -> Point {
        let p = &self.curve_config.p;
        // Case when adding point to itself.
        if self.x == other.x && (self.y != other.y || self.y.is_zero()) {
            // Return the point at infinity represented as (0, 0) in this context.
            return Point::new(BigUint::zero(), BigUint::zero(), self.curve_config.clone());
        }
        let slope = if self.x == other.x {
            // Doubling a point.
            let numerator = 3u32 * &self.x * &self.x + &self.curve_config.a;
            let denominator = 2u32 * &self.y;
            (numerator * mod_inverse(&denominator, p)) % p
        } else {
            // Adding two distinct points.
            let numerator = if &other.y < &self.y {
                &other.y + p - &self.y
            } else {
                &other.y - &self.y
            };
            let denominator = if &other.x < &self.x {
                &other.x + p - &self.x
            } else {
                &other.x - &self.x
            };
            (numerator * mod_inverse(&denominator, p)) % p
        };
        let x3 = (&slope * &slope + p - &self.x - &other.x) % p;
        let y3 = (slope * (&self.x + p - &x3) - &self.y + p) % p;
        Point::new(x3, y3, self.curve_config.clone())
    }

    fn multiply(&self, times: &BigUint) -> Point {
        let mut current_point = self.clone();
        let mut current_coefficient = BigUint::one();
        let mut previous_points: Vec<(BigUint, Point)> = Vec::new();
        while &current_coefficient < times {
            previous_points.push((current_coefficient.clone(), current_point.clone()));
            if &(&current_coefficient * 2u32) <= times {
                current_point = current_point.add(&current_point);
                current_coefficient *= 2u32;
            } else {
                let mut next_point = self.clone();
                let mut next_coefficient = BigUint::one();
                for (previous_coefficient, previous_point) in previous_points.iter().rev() {
                    if previous_coefficient + &current_coefficient <= *times {
                        next_coefficient = previous_coefficient.clone();
                        next_point = previous_point.clone();
                        break; // Found the largest usable previous point
                    }
                }
                current_point = current_point.add(&next_point);
                current_coefficient += next_coefficient;
            }
        }
        current_point
    }
}

fn mod_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    value.modpow(&(modulus - &BigUint::from(2u32)), modulus)
}

fn sign_message(message: &BigUint, private_key: &BigUint, g_point: &Point) -> (BigUint, BigUint) {
    let n = BigUint::from_str("115792089237316195423570985008687907852837564279074904382605163141518161494337").unwrap();
    let mut rng = thread_rng();
    // Generate a random k within the range [1, n-1]
    let k = rng.gen_biguint_range(&BigUint::one(), &n);

    let r_point = g_point.multiply(&k);
    let r = &r_point.x % &n;
    if r == BigUint::zero() {
        return sign_message(message, private_key, g_point);
    }
    let k_inverse = mod_inverse(&k, &n);
    let s = (&k_inverse * (message + &r * private_key)) % &n;
    (r, s)
}

fn verify_signature(signature: &(BigUint, BigUint), message: &BigUint, public_key: &Point, g_point: &Point) -> bool {
    let n = BigUint::from_str("115792089237316195423570985008687907852837564279074904382605163141518161494337").unwrap();
    let (r, s) = signature;
    let s_inverse = mod_inverse(s, &n);
    let u = message * &s_inverse % &n;
    let v = r * &s_inverse % &n;
    let c_point = g_point.multiply(&u).add(&public_key.multiply(&v));
    c_point.x == *r
}

fn main() {
    let curve_config = CurveConfig {
        a: BigUint::zero(),
        b: BigUint::from(7u32),
        p: BigUint::parse_bytes(b"115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap(),
    };
    let g_x = BigUint::parse_bytes(b"55066263022277343669578718895168534326250603453777594175500187360389116729240", 10).unwrap();
    let g_y = BigUint::parse_bytes(b"32670510020758816978083085130507043184471273380659243275938904335757337482424", 10).unwrap();
    let g_point = Point::new(g_x, g_y, curve_config.clone());

    // Example usage
    let private_key = BigUint::from(123456789012345u64);
    let public_key = g_point.multiply(&private_key);
    assert_eq!(public_key.x, BigUint::parse_bytes(b"10781230418046409857141107048746558306281905541083370272873392624066644885158", 10).unwrap());
    assert_eq!(public_key.y, BigUint::parse_bytes(b"75292686749126855329828683795073286467340682311713336473567943831090200965133", 10).unwrap());
    
    let message = BigUint::from(12345u64);
    let signature = sign_message(&message, &private_key, &g_point);
    let is_valid = verify_signature(&signature, &message, &public_key, &g_point);
    assert!(is_valid);

    println!("Public key: {:#?}", public_key);
    println!("message: {:?}", message);
    println!("Signature: {:#?}", signature);
    println!("Is valid: {}", is_valid);
}
