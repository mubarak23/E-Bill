use super::identity::Identity;
use super::BitcreditBill;
use crate::constants::{CONTACT_MAP_FILE_PATH, USEDNET};
use crate::dht::Client;
use bitcoin::secp256k1::Scalar;
use borsh::{to_vec, BorshDeserialize};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use rocket::serde::{Deserialize, Serialize};
use rocket::FromForm;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Contact {
    name: String,
    peer_id: String,
}

#[derive(
    BorshSerialize, BorshDeserialize, FromForm, Debug, Serialize, Deserialize, Clone, Eq, PartialEq,
)]
#[serde(crate = "rocket::serde")]
pub struct IdentityPublicData {
    pub peer_id: String,
    pub name: String,
    pub company: String,
    pub bitcoin_public_key: String,
    pub postal_address: String,
    pub email: String,
    pub rsa_public_key_pem: String,
}

impl IdentityPublicData {
    pub fn new(identity: Identity, peer_id: String) -> Self {
        Self {
            peer_id,
            name: identity.name,
            company: identity.company,
            bitcoin_public_key: identity.bitcoin_public_key,
            postal_address: identity.postal_address,
            email: identity.email,
            rsa_public_key_pem: identity.public_key_pem,
        }
    }

    pub fn new_empty() -> Self {
        Self {
            peer_id: "".to_string(),
            name: "".to_string(),
            company: "".to_string(),
            bitcoin_public_key: "".to_string(),
            postal_address: "".to_string(),
            email: "".to_string(),
            rsa_public_key_pem: "".to_string(),
        }
    }

    pub fn new_only_peer_id(peer_id: String) -> Self {
        Self {
            peer_id,
            name: "".to_string(),
            company: "".to_string(),
            bitcoin_public_key: "".to_string(),
            postal_address: "".to_string(),
            email: "".to_string(),
            rsa_public_key_pem: "".to_string(),
        }
    }
}

pub fn get_contacts_vec() -> Vec<Contact> {
    if !Path::new(CONTACT_MAP_FILE_PATH).exists() {
        create_contacts_map();
    }
    let data: Vec<u8> = fs::read(CONTACT_MAP_FILE_PATH).expect("Unable to read contacts.");
    let contacts: HashMap<String, IdentityPublicData> = HashMap::try_from_slice(&data).unwrap();
    let mut contacts_vec: Vec<Contact> = Vec::new();
    for (name, public_data) in contacts {
        contacts_vec.push(Contact {
            name,
            peer_id: public_data.peer_id,
        });
    }
    contacts_vec
}

fn read_contacts_map() -> HashMap<String, IdentityPublicData> {
    if !Path::new(CONTACT_MAP_FILE_PATH).exists() {
        create_contacts_map();
    }
    let data: Vec<u8> = fs::read(CONTACT_MAP_FILE_PATH).expect("Unable to read contacts.");
    let contacts: HashMap<String, IdentityPublicData> = HashMap::try_from_slice(&data).unwrap();
    contacts
}

pub fn delete_from_contacts_map(name: String) {
    if Path::new(CONTACT_MAP_FILE_PATH).exists() {
        let mut contacts: HashMap<String, IdentityPublicData> = read_contacts_map();
        contacts.remove(&name);
        write_contacts_map(contacts);
    }
}

pub async fn add_in_contacts_map(name: String, peer_id: String, mut client: Client) {
    if !Path::new(CONTACT_MAP_FILE_PATH).exists() {
        create_contacts_map();
    }

    let mut identity_public_data = IdentityPublicData::new_only_peer_id(peer_id.clone());

    let identity_public_data_from_dht = client.get_identity_public_data_from_dht(peer_id).await;

    if !identity_public_data.name.is_empty() {
        identity_public_data = identity_public_data_from_dht;
    }

    let mut contacts: HashMap<String, IdentityPublicData> = read_contacts_map();

    contacts.insert(name, identity_public_data);
    write_contacts_map(contacts);
}

pub fn get_current_payee_private_key(identity: Identity, bill: BitcreditBill) -> String {
    let private_key_bill = bitcoin::PrivateKey::from_str(&bill.private_key).unwrap();

    let private_key_bill_holder =
        bitcoin::PrivateKey::from_str(&identity.bitcoin_private_key).unwrap();

    let privat_key_bill = private_key_bill
        .inner
        .add_tweak(&Scalar::from(private_key_bill_holder.inner))
        .unwrap();

    bitcoin::PrivateKey::new(privat_key_bill, USEDNET).to_string()
}

pub async fn get_identity_public_data(
    identity_real_name: String,
    mut client: Client,
) -> IdentityPublicData {
    let mut identity = get_contact_from_map(&identity_real_name);

    let identity_public_data = client
        .get_identity_public_data_from_dht(identity.peer_id.clone())
        .await;

    if !identity_public_data.name.is_empty() {
        change_contact_data_from_dht(
            identity_real_name,
            identity_public_data.clone(),
            identity.clone(),
        );
        identity = identity_public_data;
    }

    identity
}

pub fn change_contact_data_from_dht(
    name: String,
    dht_data: IdentityPublicData,
    local_data: IdentityPublicData,
) {
    if !dht_data.eq(&local_data) {
        let mut contacts: HashMap<String, IdentityPublicData> = read_contacts_map();
        contacts.remove(&name);
        contacts.insert(name, dht_data);
        write_contacts_map(contacts);
    }
}

pub fn change_contact_name_from_contacts_map(old_entry_key: String, new_name: String) {
    let mut contacts: HashMap<String, IdentityPublicData> = read_contacts_map();
    let peer_info = contacts.get(&old_entry_key).unwrap().clone();
    contacts.remove(&old_entry_key);
    contacts.insert(new_name, peer_info);
    write_contacts_map(contacts);
}

fn create_contacts_map() {
    let contacts: HashMap<String, IdentityPublicData> = HashMap::new();
    write_contacts_map(contacts);
}

fn write_contacts_map(map: HashMap<String, IdentityPublicData>) {
    let contacts_byte = to_vec(&map).unwrap();
    fs::write(CONTACT_MAP_FILE_PATH, contacts_byte).expect("Unable to write peer id in file.");
}

fn get_contact_from_map(name: &String) -> IdentityPublicData {
    let contacts = read_contacts_map();
    if contacts.contains_key(name) {
        let data = contacts.get(name).unwrap().clone();
        data
    } else {
        IdentityPublicData::new_empty()
    }
}
