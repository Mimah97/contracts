#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke},
    Address, Bytes, BytesN, Env, IntoVal, String,
};

/// ------------------------------------------------
/// PATIENT TESTS
/// ------------------------------------------------

#[test]
fn test_register_and_get_patient() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let patient_wallet = Address::generate(&env);
    let name = String::from_str(&env, "John Doe");
    let dob = 631152000;
    let metadata = String::from_str(&env, "ipfs://some-medical-history");

    env.mock_all_auths();

    client.register_patient(&patient_wallet, &name, &dob, &metadata);

    let patient_data = client.get_patient(&patient_wallet);
    assert_eq!(patient_data.name, name);
    assert_eq!(patient_data.dob, dob);
    assert_eq!(patient_data.metadata, metadata);
}

#[test]
fn test_update_patient() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let patient_wallet = Address::generate(&env);
    let name = String::from_str(&env, "John Doe");
    let dob = 631152000;
    let initial_metadata = String::from_str(&env, "ipfs://initial");

    env.mock_all_auths();

    client.register_patient(&patient_wallet, &name, &dob, &initial_metadata);

    let new_metadata = String::from_str(&env, "ipfs://updated-history");
    client.update_patient(&patient_wallet, &new_metadata);

    let patient_data = client.get_patient(&patient_wallet);
    assert_eq!(patient_data.metadata, new_metadata);
}

#[test]
fn test_is_patient_registered() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let patient_wallet = Address::generate(&env);
    let unregistered_wallet = Address::generate(&env);

    env.mock_all_auths();

    assert!(!client.is_patient_registered(&patient_wallet));
    assert!(!client.is_patient_registered(&unregistered_wallet));

    client.register_patient(
        &patient_wallet,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://data"),
    );

    assert!(client.is_patient_registered(&patient_wallet));
    assert!(!client.is_patient_registered(&unregistered_wallet));
}

/// ------------------------------------------------
/// DOCTOR + INSTITUTION TESTS
/// ------------------------------------------------

#[test]
fn test_register_and_get_doctor() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let doctor_wallet = Address::generate(&env);
    let name = String::from_str(&env, "Dr. Alice");
    let specialization = String::from_str(&env, "Cardiology");
    let cert_hash = Bytes::from_array(&env, &[1, 2, 3, 4]);

    env.mock_all_auths();

    client.register_doctor(&doctor_wallet, &name, &specialization, &cert_hash);

    let doctor = client.get_doctor(&doctor_wallet);
    assert_eq!(doctor.name, name);
    assert_eq!(doctor.specialization, specialization);
    assert_eq!(doctor.certificate_hash, cert_hash);
    assert!(!doctor.verified);
}

#[test]
fn test_register_institution_and_verify_doctor() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let doctor_wallet = Address::generate(&env);
    let institution_wallet = Address::generate(&env);

    let name = String::from_str(&env, "Dr. Bob");
    let specialization = String::from_str(&env, "Neurology");
    let cert_hash = Bytes::from_array(&env, &[9, 9, 9]);

    env.mock_all_auths();

    // Register doctor
    client.register_doctor(&doctor_wallet, &name, &specialization, &cert_hash);

    // Register institution
    client.register_institution(&institution_wallet);

    // Verify doctor
    client.verify_doctor(&doctor_wallet, &institution_wallet);

    let doctor = client.get_doctor(&doctor_wallet);
    assert!(doctor.verified);
}

#[test]
#[should_panic(expected = "Unauthorized institution")]
fn test_verify_doctor_by_unregistered_institution_should_fail() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let doctor_wallet = Address::generate(&env);
    let fake_institution = Address::generate(&env);

    let name = String::from_str(&env, "Dr. Eve");
    let specialization = String::from_str(&env, "Oncology");
    let cert_hash = Bytes::from_array(&env, &[7, 7, 7]);

    env.mock_all_auths();

    client.register_doctor(&doctor_wallet, &name, &specialization, &cert_hash);

    // This should panic
    client.verify_doctor(&doctor_wallet, &fake_institution);
}

#[test]
fn test_grant_access_and_add_medical_record() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);

    let hash = Bytes::from_array(&env, &[1, 2, 3]);
    let desc = String::from_str(&env, "Blood test results");

    env.mock_all_auths();

    client.grant_access(&patient, &doctor);
    client.add_medical_record(&patient, &doctor, &hash, &desc);

    let records = client.get_medical_records(&patient);
    assert_eq!(records.len(), 1);

    let record = records.get(0).unwrap();
    assert_eq!(record.record_hash, hash);
    assert_eq!(record.description, desc);
}

#[test]
#[should_panic(expected = "Doctor not authorized")]
fn test_unauthorized_doctor_cannot_add_record() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);

    let hash = Bytes::from_array(&env, &[9, 9, 9]);
    let desc = String::from_str(&env, "X-ray scan");

    env.mock_all_auths();

    client.add_medical_record(&patient, &doctor, &hash, &desc);
}

#[test]
fn test_revoke_access() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);

    env.mock_all_auths();

    client.grant_access(&patient, &doctor);
    client.revoke_access(&patient, &doctor);

    let doctors = client.get_authorized_doctors(&patient);
    assert_eq!(doctors.len(), 0);
}

// ------------------------------------------------
// REGULATORY HOLD TESTS
// ------------------------------------------------

#[test]
fn test_admin_can_place_hold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[7u8; 32]);

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://patient"),
    );

    env.ledger().set_timestamp(100);
    client.place_hold(&patient, &reason_hash, &250);

    let hold = client.get_hold(&patient).unwrap();
    assert_eq!(hold.reason_hash, reason_hash);
    assert_eq!(hold.expires_at, 250);
    assert_eq!(hold.placed_at, 100);
    assert!(client.is_hold_active(&patient));
}

#[test]
fn test_non_admin_cannot_place_hold() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let other = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[5u8; 32]);
    let name = String::from_str(&env, "Jane Doe");
    let metadata = String::from_str(&env, "ipfs://patient");
    let dob = 631152000u64;

    client
        .mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (&admin,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .initialize(&admin);

    client
        .mock_auths(&[MockAuth {
            address: &patient,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "register_patient",
                args: (&patient, &name, &dob, &metadata).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .register_patient(&patient, &name, &dob, &metadata);

    let result = client
        .mock_auths(&[MockAuth {
            address: &other,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "place_hold",
                args: (&patient, &reason_hash, &250u64).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_place_hold(&patient, &reason_hash, &250u64);

    assert!(result.is_err());
}

#[test]
fn test_admin_can_lift_hold() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[8u8; 32]);

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://patient"),
    );

    env.ledger().set_timestamp(100);
    client.place_hold(&patient, &reason_hash, &250);
    env.ledger().set_timestamp(120);
    client.lift_hold(&patient);

    assert_eq!(client.get_hold(&patient), None);
    assert!(!client.is_hold_active(&patient));
}

#[test]
fn test_non_admin_cannot_lift_hold() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let other = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[6u8; 32]);
    let name = String::from_str(&env, "Jane Doe");
    let metadata = String::from_str(&env, "ipfs://patient");
    let dob = 631152000u64;

    client
        .mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (&admin,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .initialize(&admin);

    client
        .mock_auths(&[MockAuth {
            address: &patient,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "register_patient",
                args: (&patient, &name, &dob, &metadata).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .register_patient(&patient, &name, &dob, &metadata);

    client
        .mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "place_hold",
                args: (&patient, &reason_hash, &250u64).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .place_hold(&patient, &reason_hash, &250u64);

    let result = client
        .mock_auths(&[MockAuth {
            address: &other,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "lift_hold",
                args: (&patient,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_lift_hold(&patient);

    assert!(result.is_err());
}

#[test]
fn test_hold_blocks_patient_update() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[9u8; 32]);

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://initial"),
    );
    client.place_hold(&patient, &reason_hash, &250);

    let result = client.try_update_patient(&patient, &String::from_str(&env, "ipfs://blocked"));
    assert!(result.is_err());
}

#[test]
fn test_hold_blocks_grant_and_revoke_access() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[10u8; 32]);

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://initial"),
    );

    client.grant_access(&patient, &doctor);
    client.place_hold(&patient, &reason_hash, &250);

    let grant_result = client.try_grant_access(&patient, &Address::generate(&env));
    assert!(grant_result.is_err());

    let revoke_result = client.try_revoke_access(&patient, &doctor);
    assert!(revoke_result.is_err());
}

#[test]
fn test_write_succeeds_after_hold_expiry() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[11u8; 32]);
    let updated_metadata = String::from_str(&env, "ipfs://updated");

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://initial"),
    );

    env.ledger().set_timestamp(100);
    client.place_hold(&patient, &reason_hash, &150);
    assert!(client.is_hold_active(&patient));

    env.ledger().set_timestamp(151);
    assert!(!client.is_hold_active(&patient));

    client.update_patient(&patient, &updated_metadata);
    let patient_data = client.get_patient(&patient);
    assert_eq!(patient_data.metadata, updated_metadata);
}

#[test]
fn test_hold_exposes_only_reason_hash_in_state() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[12u8; 32]);

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://patient"),
    );

    env.ledger().set_timestamp(100);
    client.place_hold(&patient, &reason_hash, &250);

    let hold = client.get_hold(&patient).unwrap();
    assert_eq!(hold.reason_hash, reason_hash);
    assert_eq!(hold.expires_at, 250);
    assert_eq!(hold.placed_at, 100);
}

#[test]
fn test_lifting_hold_restores_normal_write_ability() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[13u8; 32]);
    let updated_metadata = String::from_str(&env, "ipfs://restored");

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://initial"),
    );

    client.place_hold(&patient, &reason_hash, &300);
    client.lift_hold(&patient);
    client.update_patient(&patient, &updated_metadata);

    let patient_data = client.get_patient(&patient);
    assert_eq!(patient_data.metadata, updated_metadata);
}

#[test]
fn test_invalid_hold_expiry_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[14u8; 32]);

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://patient"),
    );

    env.ledger().set_timestamp(100);
    let result = client.try_place_hold(&patient, &reason_hash, &100u64);
    assert!(result.is_err());
}

#[test]
fn test_duplicate_active_hold_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let reason_hash = BytesN::from_array(&env, &[15u8; 32]);
    let second_reason_hash = BytesN::from_array(&env, &[16u8; 32]);

    client.initialize(&admin);
    client.register_patient(
        &patient,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://patient"),
    );

    env.ledger().set_timestamp(100);
    client.place_hold(&patient, &reason_hash, &250);

    let result = client.try_place_hold(&patient, &second_reason_hash, &300u64);
    assert!(result.is_err());
}
