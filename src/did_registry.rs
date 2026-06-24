use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Vec,
};

use crate::{DIDDocument, Service, VerificationMethod};

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DidKey {
    Doc(Bytes),
    Controller(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DIDRegistryError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidFormat = 4,
    Deactivated = 5,
    InvalidSignature = 6,
}

#[contract]
pub struct DIDRegistry;

#[contractimpl]
impl DIDRegistry {
    const MAX_DID_LENGTH: u32 = 256;
    const MAX_VM_ID_LENGTH: u32 = 128;
    const MAX_SERVICE_ID_LENGTH: u32 = 128;
    const MAX_SERVICE_ENDPOINT_LENGTH: u32 = 512;

    pub fn create_did(
        env: Env,
        controller: Address,
        did_id: Bytes,
        verification_methods: Vec<VerificationMethod>,
        services: Vec<Service>,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        if !Self::check_did_prefix(&env, &did_id) {
            return Err(DIDRegistryError::InvalidFormat);
        }
        if did_id.len() > Self::MAX_DID_LENGTH {
            return Err(DIDRegistryError::InvalidFormat);
        }
        for vm in verification_methods.iter() {
            if vm.id.len() > Self::MAX_VM_ID_LENGTH {
                return Err(DIDRegistryError::InvalidFormat);
            }
        }
        for svc in services.iter() {
            if svc.id.len() > Self::MAX_SERVICE_ID_LENGTH
                || svc.endpoint.len() > Self::MAX_SERVICE_ENDPOINT_LENGTH
            {
                return Err(DIDRegistryError::InvalidFormat);
            }
        }

        if env
            .storage()
            .persistent()
            .has(&DidKey::Doc(did_id.clone()))
        {
            return Err(DIDRegistryError::AlreadyExists);
        }

        let now = env.ledger().timestamp();
        let doc = DIDDocument {
            id: did_id.clone(),
            controller: controller.clone(),
            verification_method: verification_methods,
            authentication: Vec::new(&env),
            service: services,
            created: now,
            updated: now,
            deactivated: false,
        };

        env.storage()
            .persistent()
            .set(&DidKey::Doc(did_id.clone()), &doc);
        env.storage()
            .persistent()
            .set(&DidKey::Controller(controller), &did_id);

        Ok(())
    }

    pub fn resolve_did(env: Env, did: Bytes) -> Result<DIDDocument, DIDRegistryError> {
        env.storage()
            .persistent()
            .get(&DidKey::Doc(did))
            .ok_or(DIDRegistryError::NotFound)
    }

    pub fn update_did(
        env: Env,
        controller: Address,
        verification_methods: Option<Vec<VerificationMethod>>,
        services: Option<Vec<Service>>,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        if let Some(methods) = verification_methods {
            doc.verification_method = methods;
        }
        if let Some(svcs) = services {
            doc.service = svcs;
        }

        doc.updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did), &doc);

        Ok(())
    }

    pub fn deactivate_did(env: Env, controller: Address) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        doc.deactivated = true;
        doc.updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did), &doc);

        Ok(())
    }

    pub fn add_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        doc.authentication.push_back(authentication_method);
        doc.updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did), &doc);

        Ok(())
    }

    pub fn remove_authentication(
        env: Env,
        controller: Address,
        authentication_method: Bytes,
    ) -> Result<(), DIDRegistryError> {
        controller.require_auth();

        let did: Bytes = env
            .storage()
            .persistent()
            .get(&DidKey::Controller(controller.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        let mut doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did.clone()))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let mut found = false;
        let mut new_auth: Vec<Bytes> = Vec::new(&env);
        for auth in doc.authentication.iter() {
            if auth != authentication_method {
                new_auth.push_back(auth);
            } else {
                found = true;
            }
        }

        if !found {
            return Err(DIDRegistryError::NotFound);
        }

        doc.authentication = new_auth;
        doc.updated = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DidKey::Doc(did), &doc);

        Ok(())
    }

    pub fn verify_signature(
        env: Env,
        did: Bytes,
        message: Bytes,
        signature: BytesN<64>,
    ) -> Result<bool, DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(0)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto()
            .ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

    pub fn verify_signature_with_method(
        env: Env,
        did: Bytes,
        message: Bytes,
        signature: BytesN<64>,
        method_index: u32,
    ) -> Result<bool, DIDRegistryError> {
        let doc: DIDDocument = env
            .storage()
            .persistent()
            .get(&DidKey::Doc(did))
            .ok_or(DIDRegistryError::NotFound)?;

        if doc.deactivated {
            return Err(DIDRegistryError::Deactivated);
        }

        let vm = doc
            .verification_method
            .get(method_index)
            .ok_or(DIDRegistryError::NotFound)?;

        env.crypto()
            .ed25519_verify(&vm.public_key, &message, &signature);

        Ok(true)
    }

    pub fn did_exists(env: Env, did: Bytes) -> bool {
        env.storage()
            .persistent()
            .has(&DidKey::Doc(did))
    }

    pub fn get_controller_did(env: Env, controller: Address) -> Option<Bytes> {
        env.storage()
            .persistent()
            .get(&DidKey::Controller(controller))
    }

    fn check_did_prefix(env: &Env, did: &Bytes) -> bool {
        let prefix = Bytes::from_slice(env, b"did:stellar:");
        let prefix_len = prefix.len();

        if did.len() < prefix_len {
            return false;
        }

        for i in 0..prefix_len {
            if did.get(i) != prefix.get(i) {
                return false;
            }
        }

        true
    }
}
