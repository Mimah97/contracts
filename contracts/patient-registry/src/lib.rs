#![no_std]
#![allow(deprecated)]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env, Map, String,
    Vec,
};

/// --------------------
/// Patient Structures
/// --------------------
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatientData {
    pub name: String,
    pub dob: u64,
    pub metadata: String, // IPFS / encrypted medical refs
}

/// --------------------
/// Doctor Structures
/// --------------------
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorData {
    pub name: String,
    pub specialization: String,
    pub certificate_hash: Bytes,
    pub verified: bool,
}

/// --------------------
/// Storage Keys
/// --------------------
#[contracttype]
pub enum DataKey {
    Admin,
    Patient(Address),
    Doctor(Address),
    Institution(Address),
    MedicalRecords(Address),
    AuthorizedDoctors(Address),
    RegulatoryHold(Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MedicalRecord {
    pub doctor: Address,
    pub record_hash: Bytes,
    pub description: String,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegulatoryHold {
    pub reason_hash: BytesN<32>,
    pub expires_at: u64,
    pub placed_at: u64,
}

#[contract]
pub struct MedicalRegistry;

#[contractimpl]
impl MedicalRegistry {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Contract already initialized");
        }

        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);

        env.events()
            .publish((symbol_short!("init"), admin), symbol_short!("success"));
    }

    // =====================================================
    //                    PATIENT LOGIC
    // =====================================================

    pub fn register_patient(env: Env, wallet: Address, name: String, dob: u64, metadata: String) {
        wallet.require_auth();

        let key = DataKey::Patient(wallet.clone());
        if env.storage().persistent().has(&key) {
            panic!("Patient already registered");
        }

        let patient = PatientData {
            name,
            dob,
            metadata,
        };
        env.storage().persistent().set(&key, &patient);

        env.events()
            .publish((symbol_short!("reg_pat"), wallet), symbol_short!("success"));
    }

    pub fn update_patient(env: Env, wallet: Address, metadata: String) {
        wallet.require_auth();
        Self::require_not_on_hold(&env, &wallet);

        let key = DataKey::Patient(wallet.clone());
        let mut patient: PatientData = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Patient not found");

        patient.metadata = metadata;
        env.storage().persistent().set(&key, &patient);

        env.events()
            .publish((symbol_short!("upd_pat"), wallet), symbol_short!("success"));
    }

    pub fn get_patient(env: Env, wallet: Address) -> PatientData {
        let key = DataKey::Patient(wallet);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Patient not found")
    }

    pub fn is_patient_registered(env: Env, wallet: Address) -> bool {
        let key = DataKey::Patient(wallet);
        env.storage().persistent().has(&key)
    }

    pub fn place_hold(env: Env, patient: Address, reason_hash: BytesN<32>, expires_at: u64) {
        Self::require_admin(&env);
        Self::require_patient_exists(&env, &patient);

        let now = env.ledger().timestamp();
        if expires_at <= now {
            panic!("Hold expiry must be in the future");
        }
        if Self::active_hold(&env, &patient).is_some() {
            panic!("Regulatory hold already active");
        }

        let hold = RegulatoryHold {
            reason_hash: reason_hash.clone(),
            expires_at,
            placed_at: now,
        };

        env.storage()
            .persistent()
            .set(&DataKey::RegulatoryHold(patient.clone()), &hold);

        env.events().publish(
            (symbol_short!("hold_set"), patient),
            (reason_hash, expires_at, now),
        );
    }

    pub fn lift_hold(env: Env, patient: Address) {
        Self::require_admin(&env);

        let hold = Self::active_hold(&env, &patient).expect("No active regulatory hold");
        let lifted_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .remove(&DataKey::RegulatoryHold(patient.clone()));

        env.events().publish(
            (symbol_short!("hold_lift"), patient),
            (hold.reason_hash, hold.expires_at, hold.placed_at, lifted_at),
        );
    }

    pub fn is_hold_active(env: Env, patient: Address) -> bool {
        Self::active_hold(&env, &patient).is_some()
    }

    pub fn get_hold(env: Env, patient: Address) -> Option<RegulatoryHold> {
        Self::active_hold(&env, &patient)
    }

    // =====================================================
    //                    DOCTOR LOGIC
    // =====================================================

    pub fn register_doctor(
        env: Env,
        wallet: Address,
        name: String,
        specialization: String,
        certificate_hash: Bytes,
    ) {
        wallet.require_auth();

        let key = DataKey::Doctor(wallet.clone());
        if env.storage().persistent().has(&key) {
            panic!("Doctor already registered");
        }

        let doctor = DoctorData {
            name,
            specialization,
            certificate_hash,
            verified: false,
        };

        env.storage().persistent().set(&key, &doctor);

        env.events()
            .publish((symbol_short!("reg_doc"), wallet), symbol_short!("success"));
    }

    pub fn verify_doctor(env: Env, wallet: Address, institution_wallet: Address) {
        institution_wallet.require_auth();

        let inst_key = DataKey::Institution(institution_wallet);
        if !env.storage().persistent().has(&inst_key) {
            panic!("Unauthorized institution");
        }

        let doc_key = DataKey::Doctor(wallet.clone());
        let mut doctor: DoctorData = env
            .storage()
            .persistent()
            .get(&doc_key)
            .expect("Doctor not found");

        doctor.verified = true;
        env.storage().persistent().set(&doc_key, &doctor);

        env.events().publish(
            (symbol_short!("ver_doc"), wallet),
            symbol_short!("verified"),
        );
    }

    pub fn get_doctor(env: Env, wallet: Address) -> DoctorData {
        let key = DataKey::Doctor(wallet);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Doctor not found")
    }

    // =====================================================
    //              INSTITUTION MANAGEMENT
    // =====================================================

    pub fn register_institution(env: Env, institution_wallet: Address) {
        institution_wallet.require_auth();
        let key = DataKey::Institution(institution_wallet);
        env.storage().persistent().set(&key, &true);
    }

    // =====================================================
    //            MEDICAL RECORD ACCESS CONTROL
    // =====================================================

    pub fn grant_access(env: Env, patient: Address, doctor: Address) {
        patient.require_auth();
        Self::require_not_on_hold(&env, &patient);

        let key = DataKey::AuthorizedDoctors(patient.clone());
        let mut map: Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Map::new(&env));

        map.set(doctor, true);
        env.storage().persistent().set(&key, &map);
    }

    pub fn revoke_access(env: Env, patient: Address, doctor: Address) {
        patient.require_auth();
        Self::require_not_on_hold(&env, &patient);

        let key = DataKey::AuthorizedDoctors(patient.clone());
        let mut map: Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Map::new(&env));

        map.remove(doctor);
        env.storage().persistent().set(&key, &map);
    }

    pub fn get_authorized_doctors(env: Env, patient: Address) -> Vec<Address> {
        let key = DataKey::AuthorizedDoctors(patient);
        let map: Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Map::new(&env));

        map.keys()
    }

    pub fn add_medical_record(
        env: Env,
        patient: Address,
        doctor: Address,
        record_hash: Bytes,
        description: String,
    ) {
        doctor.require_auth();

        // Check access
        let access_key = DataKey::AuthorizedDoctors(patient.clone());
        let access_map: Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&access_key)
            .unwrap_or(Map::new(&env));

        if !access_map.contains_key(doctor.clone()) {
            panic!("Doctor not authorized");
        }

        let record = MedicalRecord {
            doctor,
            record_hash,
            description,
            timestamp: env.ledger().timestamp(),
        };

        let records_key = DataKey::MedicalRecords(patient.clone());
        let mut records: Vec<MedicalRecord> = env
            .storage()
            .persistent()
            .get(&records_key)
            .unwrap_or(Vec::new(&env));

        records.push_back(record);
        env.storage().persistent().set(&records_key, &records);
    }

    pub fn get_medical_records(env: Env, patient: Address) -> Vec<MedicalRecord> {
        let key = DataKey::MedicalRecords(patient);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env))
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Contract not initialized");
        admin.require_auth();
    }

    fn require_patient_exists(env: &Env, patient: &Address) {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Patient(patient.clone()))
        {
            panic!("Patient not found");
        }
    }

    fn require_not_on_hold(env: &Env, patient: &Address) {
        if Self::active_hold(env, patient).is_some() {
            panic!("Patient data is on regulatory hold");
        }
    }

    fn active_hold(env: &Env, patient: &Address) -> Option<RegulatoryHold> {
        let key = DataKey::RegulatoryHold(patient.clone());
        let hold: Option<RegulatoryHold> = env.storage().persistent().get(&key);

        match hold {
            Some(existing) if existing.expires_at > env.ledger().timestamp() => Some(existing),
            Some(_) => {
                env.storage().persistent().remove(&key);
                None
            }
            None => None,
        }
    }
}
#[cfg(test)]
mod test;
