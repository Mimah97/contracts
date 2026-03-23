#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Bytes, BytesN, Env, String};

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
    client.update_patient(&patient_wallet, &patient_wallet, &new_metadata);

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

    assert_eq!(client.is_patient_registered(&patient_wallet), false);
    assert_eq!(client.is_patient_registered(&unregistered_wallet), false);

    client.register_patient(
        &patient_wallet,
        &String::from_str(&env, "Jane Doe"),
        &631152000,
        &String::from_str(&env, "ipfs://data"),
    );

    assert_eq!(client.is_patient_registered(&patient_wallet), true);
    assert_eq!(client.is_patient_registered(&unregistered_wallet), false);
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
    assert_eq!(doctor.verified, false);
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
    assert_eq!(doctor.verified, true);
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

    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);

    let hash = Bytes::from_array(&env, &[1, 2, 3]);
    let desc = String::from_str(&env, "Blood test results");
    let v1 = BytesN::from_array(&env, &[1u8; 32]);

    env.mock_all_auths();

    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);
    client.acknowledge_consent(&patient, &patient, &v1);
    client.grant_access(&patient, &patient, &doctor);
    client.add_medical_record(&patient, &doctor, &hash, &desc);

    let records = client.get_medical_records(&patient);
    assert_eq!(records.len(), 1);

    let record = records.get(0).unwrap();
    assert_eq!(record.record_hash, hash);
    assert_eq!(record.description, desc);
}

#[test]
#[should_panic(expected = "Patient has not acknowledged current consent version")]
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

    client.grant_access(&patient, &patient, &doctor);
    client.revoke_access(&patient, &patient, &doctor);

    let doctors = client.get_authorized_doctors(&patient);
    assert_eq!(doctors.len(), 0);
}

/// ------------------------------------------------
/// CONSENT TESTS
/// ------------------------------------------------

fn make_version(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

#[test]
fn test_consent_status_never_signed() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let patient = Address::generate(&env);

    env.mock_all_auths();
    client.initialize(&Address::generate(&env), &Address::generate(&env), &Address::generate(&env));

    assert_eq!(client.get_consent_status(&patient), ConsentStatus::NeverSigned);
}

#[test]
fn test_consent_status_never_signed_no_ack() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&make_version(&env, 1));

    // Version published but patient never acknowledged
    assert_eq!(client.get_consent_status(&patient), ConsentStatus::NeverSigned);
}

#[test]
fn test_consent_status_acknowledged() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let v1 = make_version(&env, 1);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);
    client.acknowledge_consent(&patient, &patient, &v1);

    assert_eq!(client.get_consent_status(&patient), ConsentStatus::Acknowledged);
}

#[test]
fn test_consent_status_pending_after_new_version() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let v1 = make_version(&env, 1);
    let v2 = make_version(&env, 2);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);
    client.acknowledge_consent(&patient, &patient, &v1);

    // Admin publishes new version — patient is now Pending
    client.publish_consent_version(&v2);
    assert_eq!(client.get_consent_status(&patient), ConsentStatus::Pending);
}

#[test]
fn test_consent_re_acknowledge_restores_acknowledged() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let v1 = make_version(&env, 1);
    let v2 = make_version(&env, 2);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);
    client.acknowledge_consent(&patient, &patient, &v1);
    client.publish_consent_version(&v2);
    client.acknowledge_consent(&patient, &patient, &v2);

    assert_eq!(client.get_consent_status(&patient), ConsentStatus::Acknowledged);
}

#[test]
#[should_panic(expected = "Version mismatch")]
fn test_acknowledge_wrong_version_panics() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&make_version(&env, 1));
    client.acknowledge_consent(&patient, &patient, &make_version(&env, 99));
}

#[test]
#[should_panic(expected = "Patient has not acknowledged current consent version")]
fn test_add_record_blocked_without_consent() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&make_version(&env, 1));
    // Patient never acknowledges
    client.grant_access(&patient, &patient, &doctor);
    client.add_medical_record(
        &patient,
        &doctor,
        &Bytes::from_array(&env, &[1, 2, 3]),
        &String::from_str(&env, "test"),
    );
}

#[test]
fn test_add_record_allowed_after_consent() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);
    let v1 = make_version(&env, 1);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);
    client.acknowledge_consent(&patient, &patient, &v1);
    client.grant_access(&patient, &patient, &doctor);
    client.add_medical_record(
        &patient,
        &doctor,
        &Bytes::from_array(&env, &[1, 2, 3]),
        &String::from_str(&env, "Blood test"),
    );

    assert_eq!(client.get_medical_records(&patient).len(), 1);
}

#[test]
#[should_panic(expected = "Patient has not acknowledged current consent version")]
fn test_add_record_blocked_after_new_version() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let patient = Address::generate(&env);
    let doctor = Address::generate(&env);
    let v1 = make_version(&env, 1);
    let v2 = make_version(&env, 2);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);
    client.acknowledge_consent(&patient, &patient, &v1);
    client.grant_access(&patient, &patient, &doctor);

    // Admin bumps version — patient must re-acknowledge
    client.publish_consent_version(&v2);
    client.add_medical_record(
        &patient,
        &doctor,
        &Bytes::from_array(&env, &[1, 2, 3]),
        &String::from_str(&env, "Post-update record"),
    );
}

/// ------------------------------------------------
/// GUARDIAN TESTS
/// ------------------------------------------------

fn setup_with_consent(env: &Env) -> (MedicalRegistryClient, Address) {
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(env, &contract_id);
    let admin = Address::generate(env);
    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&make_version(env, 1));
    (client, admin)
}

#[test]
fn test_assign_and_get_guardian() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let patient = Address::generate(&env);
    let guardian = Address::generate(&env);

    client.assign_guardian(&patient, &guardian);
    assert_eq!(client.get_guardian(&patient), Some(guardian));
}

#[test]
fn test_revoke_guardian() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let patient = Address::generate(&env);
    let guardian = Address::generate(&env);

    client.assign_guardian(&patient, &guardian);
    client.revoke_guardian(&patient);
    assert_eq!(client.get_guardian(&patient), None);
}

#[test]
fn test_guardian_can_acknowledge_consent() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let v1 = make_version(&env, 1);
    let patient = Address::generate(&env);
    let guardian = Address::generate(&env);

    client.assign_guardian(&patient, &guardian);
    client.acknowledge_consent(&patient, &guardian, &v1);

    assert_eq!(client.get_consent_status(&patient), ConsentStatus::Acknowledged);
}

#[test]
fn test_guardian_can_grant_and_revoke_access() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let v1 = make_version(&env, 1);
    let patient = Address::generate(&env);
    let guardian = Address::generate(&env);
    let doctor = Address::generate(&env);

    client.assign_guardian(&patient, &guardian);
    client.acknowledge_consent(&patient, &guardian, &v1);
    client.grant_access(&patient, &guardian, &doctor);

    assert_eq!(client.get_authorized_doctors(&patient).len(), 1);

    client.revoke_access(&patient, &guardian, &doctor);
    assert_eq!(client.get_authorized_doctors(&patient).len(), 0);
}

#[test]
fn test_guardian_can_update_patient() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let patient = Address::generate(&env);
    let guardian = Address::generate(&env);

    client.register_patient(
        &patient,
        &String::from_str(&env, "Minor Patient"),
        &631152000,
        &String::from_str(&env, "ipfs://original"),
    );
    client.assign_guardian(&patient, &guardian);
    client.update_patient(&patient, &guardian, &String::from_str(&env, "ipfs://updated"));

    assert_eq!(
        client.get_patient(&patient).metadata,
        String::from_str(&env, "ipfs://updated")
    );
}

#[test]
fn test_guardian_enables_record_write() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let v1 = make_version(&env, 1);
    let patient = Address::generate(&env);
    let guardian = Address::generate(&env);
    let doctor = Address::generate(&env);

    client.assign_guardian(&patient, &guardian);
    client.acknowledge_consent(&patient, &guardian, &v1);
    client.grant_access(&patient, &guardian, &doctor);
    client.add_medical_record(
        &patient,
        &doctor,
        &Bytes::from_array(&env, &[5, 6, 7]),
        &String::from_str(&env, "Guardian-approved record"),
    );

    assert_eq!(client.get_medical_records(&patient).len(), 1);
}

#[test]
#[should_panic(expected = "Caller is not patient or assigned guardian")]
fn test_unauthorized_caller_rejected() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let v1 = make_version(&env, 1);
    let patient = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.acknowledge_consent(&patient, &stranger, &v1);
}

#[test]
#[should_panic(expected = "Caller is not patient or assigned guardian")]
fn test_revoked_guardian_rejected() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let v1 = make_version(&env, 1);
    let patient = Address::generate(&env);
    let guardian = Address::generate(&env);

    client.assign_guardian(&patient, &guardian);
    client.revoke_guardian(&patient);
    // Guardian no longer valid
    client.acknowledge_consent(&patient, &guardian, &v1);
}

#[test]
#[should_panic(expected = "Caller is not patient or assigned guardian")]
fn test_guardian_cannot_act_for_different_patient() {
    let env = Env::default();
    let (client, _admin) = setup_with_consent(&env);
    let v1 = make_version(&env, 1);
    let patient_a = Address::generate(&env);
    let patient_b = Address::generate(&env);
    let guardian = Address::generate(&env);

    // Guardian assigned only to patient_a
    client.assign_guardian(&patient_a, &guardian);
    // Attempt to act on behalf of patient_b
    client.acknowledge_consent(&patient_b, &guardian, &v1);
}

/// ------------------------------------------------
/// SNAPSHOT TESTS
/// ------------------------------------------------

fn register_patient_with_consent(
    client: &MedicalRegistryClient,
    env: &Env,
    v1: &BytesN<32>,
    wallet: &Address,
) {
    client.register_patient(
        wallet,
        &String::from_str(env, "Test Patient"),
        &631152000,
        &String::from_str(env, "ipfs://data"),
    );
    client.acknowledge_consent(wallet, wallet, v1);
}

#[test]
fn test_first_snapshot_always_allowed() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let v1 = make_version(&env, 1);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);

    // No prior snapshot — should succeed at any ledger
    client.emit_state_snapshot();
    assert_eq!(client.get_last_snapshot_ledger(), Some(env.ledger().sequence()));
}

#[test]
fn test_snapshot_records_ledger_sequence() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);

    let seq_before = env.ledger().sequence();
    client.emit_state_snapshot();
    assert_eq!(client.get_last_snapshot_ledger(), Some(seq_before));
}

#[test]
fn test_get_last_snapshot_ledger_default_zero() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);

    assert_eq!(client.get_last_snapshot_ledger(), None);
}

#[test]
#[should_panic(expected = "Snapshot rate limit: must wait 100,000 ledgers between snapshots")]
fn test_snapshot_rate_limit_enforced() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.emit_state_snapshot();

    // Advance ledger by less than 100,000
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        sequence_number: env.ledger().sequence() + 99_999,
        timestamp: env.ledger().timestamp() + 99_999,
        protocol_version: 23,
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 1,
        min_persistent_entry_ttl: 1,
        max_entry_ttl: 10_000_000,
    });

    client.emit_state_snapshot();
}

#[test]
fn test_snapshot_allowed_after_interval() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.emit_state_snapshot();

    let new_seq = env.ledger().sequence() + 100_000;
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        sequence_number: new_seq,
        timestamp: env.ledger().timestamp() + 100_000,
        protocol_version: 23,
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 1,
        min_persistent_entry_ttl: 1,
        max_entry_ttl: 10_000_000,
    });

    client.emit_state_snapshot();
    assert_eq!(client.get_last_snapshot_ledger(), Some(new_seq));
}

#[test]
fn test_snapshot_includes_registered_patients_and_doctors() {
    let env = Env::default();
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let v1 = make_version(&env, 1);

    env.mock_all_auths();
    let treasury = Address::generate(&env);
    let fee_token = Address::generate(&env);
    client.initialize(&admin, &treasury, &fee_token);
    client.publish_consent_version(&v1);

    let p1 = Address::generate(&env);
    let p2 = Address::generate(&env);
    register_patient_with_consent(&client, &env, &v1, &p1);
    register_patient_with_consent(&client, &env, &v1, &p2);

    let doctor = Address::generate(&env);
    client.register_doctor(
        &doctor,
        &String::from_str(&env, "Dr. Snap"),
        &String::from_str(&env, "Radiology"),
        &Bytes::from_array(&env, &[1, 2, 3]),
    );

    // Snapshot should succeed — lists are populated
    client.emit_state_snapshot();
    assert_eq!(client.get_last_snapshot_ledger(), Some(env.ledger().sequence()));
}

/// ------------------------------------------------
/// FEE TESTS
/// ------------------------------------------------

fn setup_with_fee(
    env: &Env,
) -> (MedicalRegistryClient, Address, Address, Address, Address, Address, BytesN<32>) {
    let contract_id = env.register(MedicalRegistry, ());
    let client = MedicalRegistryClient::new(env, &contract_id);

    // Deploy a real SAC token for cross-contract call testing
    let token_admin = Address::generate(env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_id = token_contract.address();
    let token_client = soroban_sdk::token::StellarAssetClient::new(env, &token_id);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let doctor = Address::generate(env);
    let patient = Address::generate(env);
    let v1 = make_version(env, 1);

    env.mock_all_auths();

    client.initialize(&admin, &treasury, &token_id);
    client.publish_consent_version(&v1);
    client.acknowledge_consent(&patient, &patient, &v1);
    client.grant_access(&patient, &patient, &doctor);

    // Mint tokens to doctor so they can pay fees
    token_client.mint(&doctor, &10_000);

    (client, admin, treasury, token_id, doctor, patient, v1)
}

#[test]
fn test_get_record_fee_default_zero() {
    let env = Env::default();
    let (client, _admin, _treasury, _token_id, _doctor, _patient, _v1) =
        setup_with_fee(&env);
    assert_eq!(client.get_record_fee(), 0);
}

#[test]
fn test_set_and_get_record_fee() {
    let env = Env::default();
    let (client, _admin, _treasury, _token_id, _doctor, _patient, _v1) =
        setup_with_fee(&env);
    client.set_record_fee(&500);
    assert_eq!(client.get_record_fee(), 500);
}

#[test]
fn test_add_record_zero_fee_no_transfer() {
    let env = Env::default();
    let (client, _admin, treasury, token_id, doctor, patient, _v1) =
        setup_with_fee(&env);

    // Fee is 0 — no transfer should occur
    client.add_medical_record(
        &patient,
        &doctor,
        &Bytes::from_array(&env, &[1, 2, 3]),
        &String::from_str(&env, "Zero fee record"),
    );

    let token = soroban_sdk::token::TokenClient::new(&env, &token_id);
    assert_eq!(token.balance(&treasury), 0);
    assert_eq!(token.balance(&doctor), 10_000);
}

#[test]
fn test_add_record_transfers_fee_to_treasury() {
    let env = Env::default();
    let (client, _admin, treasury, token_id, doctor, patient, _v1) =
        setup_with_fee(&env);

    client.set_record_fee(&200);
    client.add_medical_record(
        &patient,
        &doctor,
        &Bytes::from_array(&env, &[4, 5, 6]),
        &String::from_str(&env, "Paid record"),
    );

    let token = soroban_sdk::token::TokenClient::new(&env, &token_id);
    assert_eq!(token.balance(&treasury), 200);
    assert_eq!(token.balance(&doctor), 9_800);
}

#[test]
fn test_fee_deducted_per_record() {
    let env = Env::default();
    let (client, _admin, treasury, token_id, doctor, patient, _v1) =
        setup_with_fee(&env);

    client.set_record_fee(&100);

    for i in 0u8..3 {
        client.add_medical_record(
            &patient,
            &doctor,
            &Bytes::from_array(&env, &[i, i, i]),
            &String::from_str(&env, "Record"),
        );
    }

    let token = soroban_sdk::token::TokenClient::new(&env, &token_id);
    assert_eq!(token.balance(&treasury), 300);
    assert_eq!(token.balance(&doctor), 9_700);
}

#[test]
#[should_panic(expected = "Fee cannot be negative")]
fn test_set_negative_fee_panics() {
    let env = Env::default();
    let (client, _admin, _treasury, _token_id, _doctor, _patient, _v1) =
        setup_with_fee(&env);
    client.set_record_fee(&-1);
}

#[test]
fn test_fee_can_be_reset_to_zero() {
    let env = Env::default();
    let (client, _admin, treasury, token_id, doctor, patient, _v1) =
        setup_with_fee(&env);

    client.set_record_fee(&300);
    client.set_record_fee(&0);

    client.add_medical_record(
        &patient,
        &doctor,
        &Bytes::from_array(&env, &[7, 8, 9]),
        &String::from_str(&env, "Free after reset"),
    );

    let token = soroban_sdk::token::TokenClient::new(&env, &token_id);
    assert_eq!(token.balance(&treasury), 0);
}
