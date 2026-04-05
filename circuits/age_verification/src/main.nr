// Tessaliq - Age Verification ZK Circuit v2
//
// Proves that a person is at least `min_age` years old
// WITHOUT revealing their date of birth.
//
// Field truncation: all Field inputs (credential_hash_preimage, nonce)
// are truncated to 248 bits (62 hex chars) before entering the circuit.
// This ensures values fit within the BN254 scalar field (p ~ 2^254)
// without rejection sampling. See sd-jwt.ts for full security analysis.

use std::hash::pedersen_hash;

fn main(
    // Private inputs
    birth_year: u32,
    birth_month: u32,
    birth_day: u32,
    credential_hash_preimage: Field,

    // Public inputs
    current_year: pub u32,
    current_month: pub u32,
    current_day: pub u32,
    min_age: pub u32,
    nonce: pub Field,
) -> pub Field {
    // 1. Validate date ranges
    assert(birth_month >= 1);
    assert(birth_month <= 12);
    assert(birth_day >= 1);
    assert(birth_day <= 31);
    assert(birth_year >= 1900);
    assert(birth_year <= current_year);

    // 2. Compute age
    let mut age = current_year - birth_year;

    let birthday_passed = if current_month > birth_month {
        true
    } else if current_month == birth_month {
        current_day >= birth_day
    } else {
        false
    };

    if !birthday_passed {
        age = age - 1;
    }

    // 3. Assert age >= min_age
    assert(age >= min_age, "Age is below the minimum required");

    // 4. Compute and return credential+nonce binding hash
    // This cryptographically binds the proof to BOTH the credential AND the session nonce,
    // preventing proof reuse across sessions
    let binding_hash = pedersen_hash([credential_hash_preimage, nonce]);

    binding_hash
}

#[test]
fn test_valid_age_over_18() {
    let preimage: Field = 12345;
    let nonce: Field = 99999;
    let hash = main(
        2000, 6, 15,
        preimage,
        2026, 3, 30,
        18,
        nonce,
    );
    assert(hash == pedersen_hash([preimage, nonce]));
}

#[test]
fn test_just_turned_18() {
    let preimage: Field = 42;
    let nonce: Field = 11111;
    let hash = main(
        2008, 3, 30,
        preimage,
        2026, 3, 30,
        18,
        nonce,
    );
    assert(hash == pedersen_hash([preimage, nonce]));
}

#[test(should_fail_with = "Age is below the minimum required")]
fn test_underage() {
    let preimage: Field = 777;
    let _ = main(
        2010, 1, 1,
        preimage,
        2026, 3, 30,
        18,
        55555,
    );
}

#[test(should_fail_with = "Age is below the minimum required")]
fn test_birthday_not_yet_this_year() {
    let preimage: Field = 888;
    let _ = main(
        2008, 12, 25,
        preimage,
        2026, 3, 30,
        18,
        77777,
    );
}

#[test]
fn test_age_over_21() {
    // Can verify any min_age, not just 18
    let preimage: Field = 555;
    let _ = main(
        1990, 1, 1,
        preimage,
        2026, 3, 30,
        21,
        44444,
    );
}

#[test(should_fail_with = "Age is below the minimum required")]
fn test_age_over_21_fails() {
    let preimage: Field = 666;
    let _ = main(
        2006, 1, 1,
        preimage,
        2026, 3, 30,
        21,
        33333,
    );
}
