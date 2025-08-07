use ic_cdk::api::caller;
use ic_cdk_macros::*;
use std::collections::HashMap;

type VaultId = String;
type UserId = String;
type SecretName = String;

#[derive(Clone, Debug, candid::CandidType, serde::Serialize, serde::Deserialize)]
pub struct EncryptedSecret {
    pub ciphertext: String,
    pub metadata: String, 
}

type VaultData = HashMap<SecretName, EncryptedSecret>;

// Key: (user_id + "::" + vault_id)
type VaultKey = String;

thread_local! {
    static VAULTS: std::cell::RefCell<HashMap<VaultKey, VaultData>> = std::cell::RefCell::new(HashMap::new());
}

fn make_key(user_id: &str, vault_id: &str) -> VaultKey {
    format!("{}::{}", user_id, vault_id)
}

#[update]
fn store_secret(user_id: String, vault_id: String, secret_name: String, secret: EncryptedSecret) {
    let key = make_key(&user_id, &vault_id);
    VAULTS.with(|vaults| {
        let mut map = vaults.borrow_mut();
        let vault = map.entry(key).or_insert_with(HashMap::new);
        vault.insert(secret_name, secret);
    });
}

#[query]
fn get_secret(user_id: String, vault_id: String, secret_name: String) -> Option<EncryptedSecret> {
    let key = make_key(&user_id, &vault_id);
    VAULTS.with(|vaults| {
        vaults.borrow().get(&key).and_then(|vault| vault.get(&secret_name).cloned())
    })
}

#[query]
fn list_secret_names(user_id: String, vault_id: String) -> Vec<String> {
    let key = make_key(&user_id, &vault_id);
    VAULTS.with(|vaults| {
        vaults.borrow().get(&key)
            .map(|vault| vault.keys().cloned().collect())
            .unwrap_or_default()
    })
}

ic_cdk::export_candid!();