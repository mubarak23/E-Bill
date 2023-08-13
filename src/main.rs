extern crate core;
#[macro_use]
extern crate rocket;

use bitcoin::PublicKey;
use std::collections::HashMap;
use std::fs::DirEntry;
use std::path::Path;
use std::{env, fs, mem, path};

use borsh::{self, BorshDeserialize, BorshSerialize};
use chrono::Utc;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use openssl::pkey::{Private, Public};
use openssl::rsa;
use openssl::rsa::{Padding, Rsa};
use openssl::sha::sha256;
use rocket::fs::{relative, FileServer};
use rocket::serde::{Deserialize, Serialize};
use rocket::{Build, Rocket};
use rocket_dyn_templates::Template;

use crate::blockchain::{start_blockchain_for_new_bill, Block, Chain, OperationCode};
use crate::constants::{
    BILLS_FOLDER_PATH, BILLS_KEYS_FOLDER_PATH, BOOTSTRAP_FOLDER_PATH,
    COMPOUNDING_INTEREST_RATE_ZERO, CONTACT_MAP_FILE_PATH, CONTACT_MAP_FOLDER_PATH,
    CSS_FOLDER_PATH, IDENTITY_ED_25529_KEYS_FILE_PATH, IDENTITY_FILE_PATH, IDENTITY_FOLDER_PATH,
    IDENTITY_PEER_ID_FILE_PATH, IMAGE_FOLDER_PATH, SATOSHI, TEMPLATES_FOLDER_PATH, USEDNET,
};
use crate::numbers_to_words::encode;

mod api;
mod blockchain;
mod constants;
mod dht;
mod numbers_to_words;
mod test;
mod web;

// MAIN
// #[rocket::main]
#[tokio::main]
async fn main() {
    env::set_var("RUST_BACKTRACE", "full");

    env_logger::init();

    init_folders();

    let mut dht = dht::dht_main().await.expect("DHT failed to start");

    let local_peer_id = read_peer_id_from_file();
    dht.check_new_bills(local_peer_id.to_string().clone()).await;
    dht.upgrade_table(local_peer_id.to_string().clone()).await;
    dht.subscribe_to_all_bills_topics().await;
    dht.start_provide().await;
    dht.receive_updates_for_all_bills_topics().await;
    dht.put_identity_public_data_in_dht().await;
    let _rocket = rocket_main(dht).launch().await.unwrap();
}

fn rocket_main(dht: dht::network::Client) -> Rocket<Build> {
    let rocket = rocket::build()
        .register("/", catchers![web::not_found])
        .manage(dht)
        .mount("/image", FileServer::from(IMAGE_FOLDER_PATH))
        .mount("/css", FileServer::from(CSS_FOLDER_PATH))
        .mount("/", routes![web::start])
        .mount("/exit", routes![web::exit])
        .mount(
            "/identity",
            routes![
                web::get_identity,
                web::create_identity,
                web::return_identity
            ],
        )
        .mount("/bills", routes![web::bills_list])
        .mount("/info", routes![web::info])
        .mount(
            "/contacts",
            routes![
                web::add_contact,
                web::new_contact,
                web::contacts,
                web::return_contacts
            ],
        )
        .mount(
            "/bill",
            routes![
                web::get_bill,
                web::issue_bill,
                web::endorse_bill,
                web::search_bill,
                web::request_to_accept_bill,
                web::accept_bill_form,
                web::request_to_pay_bill,
                web::get_bill_history,
                web::get_bill_chain,
                web::get_block,
                web::new_bill,
            ],
        )
        .attach(Template::custom(|engines| {
            web::customize(&mut engines.handlebars);
        }));

    open::that("http://127.0.0.1:8000").expect("Can't open browser.");

    rocket
}

fn init_folders() {
    if !Path::new(CONTACT_MAP_FOLDER_PATH).exists() {
        fs::create_dir(CONTACT_MAP_FOLDER_PATH).expect("Can't create folder contacts.");
    }
    if !Path::new(IDENTITY_FOLDER_PATH).exists() {
        fs::create_dir(IDENTITY_FOLDER_PATH).expect("Can't create folder identity.");
    }
    if !Path::new(BILLS_FOLDER_PATH).exists() {
        fs::create_dir(BILLS_FOLDER_PATH).expect("Can't create folder bills.");
    }
    if !Path::new(BILLS_KEYS_FOLDER_PATH).exists() {
        fs::create_dir(BILLS_KEYS_FOLDER_PATH).expect("Can't create folder bills_keys.");
    }
    if !Path::new(CSS_FOLDER_PATH).exists() {
        fs::create_dir(CSS_FOLDER_PATH).expect("Can't create folder css.");
    }
    if !Path::new(IMAGE_FOLDER_PATH).exists() {
        fs::create_dir(IMAGE_FOLDER_PATH).expect("Can't create folder image.");
    }
    if !Path::new(TEMPLATES_FOLDER_PATH).exists() {
        fs::create_dir(TEMPLATES_FOLDER_PATH).expect("Can't create folder templates.");
    }
    if !Path::new(BOOTSTRAP_FOLDER_PATH).exists() {
        fs::create_dir(BOOTSTRAP_FOLDER_PATH).expect("Can't create folder bootstrap.");
    }
}

//-------------------------Contacts map-------------------------
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct Contact {
    name: String,
    peer_id: String,
}

fn get_contacts_vec() -> Vec<Contact> {
    if !Path::new(CONTACT_MAP_FILE_PATH).exists() {
        create_contacts_map();
    }
    let data: Vec<u8> = fs::read(CONTACT_MAP_FILE_PATH).expect("Unable to read contacts.");
    let contacts: HashMap<String, String> = HashMap::try_from_slice(&data).unwrap();
    let mut contacts_vec: Vec<Contact> = Vec::new();
    for (name, peer_id) in contacts {
        contacts_vec.push(Contact { name, peer_id });
    }
    contacts_vec
}

fn read_contacts_map() -> HashMap<String, String> {
    if !Path::new(CONTACT_MAP_FILE_PATH).exists() {
        create_contacts_map();
    }
    let data: Vec<u8> = fs::read(CONTACT_MAP_FILE_PATH).expect("Unable to read contacts.");
    let contacts: HashMap<String, String> = HashMap::try_from_slice(&data).unwrap();
    contacts
}

fn add_in_contacts_map(name: String, peer_id: String) {
    if !Path::new(CONTACT_MAP_FILE_PATH).exists() {
        create_contacts_map();
    }
    let mut contacts: HashMap<String, String> = read_contacts_map();
    contacts.insert(name, peer_id);
    write_contacts_map(contacts);
}

fn create_contacts_map() {
    let contacts: HashMap<String, String> = HashMap::new();
    write_contacts_map(contacts);
}

fn write_contacts_map(map: HashMap<String, String>) {
    let contacts_byte = map.try_to_vec().unwrap();
    fs::write(CONTACT_MAP_FILE_PATH, contacts_byte).expect("Unable to write peer id in file.");
}

fn get_contact_from_map(name: &String) -> String {
    let contacts = read_contacts_map();
    if contacts.contains_key(name) {
        contacts.get(name).unwrap().to_string()
    } else {
        String::new()
    }
}
//--------------------------------------------------------------

//-------------------------RSA----------------------------------
fn generation_rsa_key() -> Rsa<Private> {
    Rsa::generate(2048).unwrap()
}

fn pem_private_key_from_rsa(rsa: &Rsa<Private>) -> String {
    let private_key: Vec<u8> = rsa.private_key_to_pem().unwrap();
    String::from_utf8(private_key).unwrap()
}

fn pem_public_key_from_rsa(rsa: &Rsa<Private>) -> String {
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();
    String::from_utf8(public_key).unwrap()
}

fn private_key_from_pem_u8(private_key_u8: &Vec<u8>) -> Rsa<Private> {
    rsa::Rsa::private_key_from_pem(private_key_u8).unwrap()
}

fn public_key_from_pem_u8(public_key_u8: &Vec<u8>) -> Rsa<Public> {
    rsa::Rsa::public_key_from_pem(public_key_u8).unwrap()
}
//--------------------------------------------------------------

//-------------------------Bytes common-------------------------
fn encrypt_bytes_with_public_key(bytes: &Vec<u8>, public_key: String) -> Vec<u8> {
    let public_key = Rsa::public_key_from_pem(public_key.as_bytes()).unwrap();

    let key_size: usize = (public_key.size() / 2) as usize; //128

    let mut whole_encrypted_buff: Vec<u8> = Vec::new();
    let mut temp_buff: Vec<u8> = vec![0; key_size];
    let mut temp_buff_encrypted: Vec<u8> = vec![0; public_key.size() as usize];

    let number_of_key_size_in_whole_bill: usize = bytes.len() / key_size;
    let remainder: usize = bytes.len() - key_size * number_of_key_size_in_whole_bill;

    for i in 0..number_of_key_size_in_whole_bill {
        for j in 0..key_size {
            let byte_number: usize = key_size * i + j;
            temp_buff[j] = bytes[byte_number];
        }

        let _encrypted_len: usize = public_key
            .public_encrypt(&temp_buff, &mut temp_buff_encrypted, Padding::PKCS1)
            .unwrap();

        whole_encrypted_buff.append(&mut temp_buff_encrypted);
        temp_buff = vec![0; key_size];
        temp_buff_encrypted = vec![0; public_key.size() as usize];
    }

    if remainder != 0 {
        temp_buff = vec![0; remainder];

        let position: usize = key_size * number_of_key_size_in_whole_bill;
        let mut index_in_temp_buff: usize = 0;

        for i in position..bytes.len() {
            temp_buff[index_in_temp_buff] = bytes[i];
            index_in_temp_buff += 1;
        }

        index_in_temp_buff = 0;

        let _encrypted_len: usize = public_key
            .public_encrypt(&temp_buff, &mut temp_buff_encrypted, Padding::PKCS1)
            .unwrap();

        whole_encrypted_buff.append(&mut temp_buff_encrypted);
        temp_buff.clear();
        temp_buff_encrypted.clear();
    }

    whole_encrypted_buff
}

fn decrypt_bytes_with_private_key(bytes: &Vec<u8>, private_key: String) -> Vec<u8> {
    let private_key = Rsa::private_key_from_pem(private_key.as_bytes()).unwrap();

    let key_size: usize = private_key.size() as usize; //256

    let mut whole_decrypted_buff: Vec<u8> = Vec::new();
    let mut temp_buff: Vec<u8> = vec![0; private_key.size() as usize];
    let mut temp_buff_decrypted: Vec<u8> = vec![0; private_key.size() as usize];

    let number_of_key_size_in_whole_bill: usize = bytes.len() / key_size;
    // let remainder = bill_bytes.len() - key_size * number_of_key_size_in_whole_bill;

    for i in 0..number_of_key_size_in_whole_bill {
        for j in 0..key_size {
            let byte_number = key_size * i + j;
            temp_buff[j] = bytes[byte_number];
        }

        let decrypted_len: usize = private_key
            .private_decrypt(&temp_buff, &mut temp_buff_decrypted, Padding::PKCS1)
            .unwrap();

        whole_decrypted_buff.append(&mut temp_buff_decrypted[0..decrypted_len].to_vec());
        temp_buff = vec![0; private_key.size() as usize];
        temp_buff_decrypted = vec![0; private_key.size() as usize];
    }

    // if remainder != 0 {
    //     let position = key_size * number_of_key_size_in_whole_bill;
    //     let mut index_in_temp_buff = 0;
    //
    //     for i in position..bill_bytes.len() {
    //         temp_buff[index_in_temp_buff] = bill_bytes[i];
    //         index_in_temp_buff = index_in_temp_buff + 1;
    //     }
    //
    //     index_in_temp_buff = 0;
    //
    //     let decrypted_len = rsa_key
    //         .public_decrypt(&*temp_buff, &mut temp_buff_decrypted, Padding::PKCS1)
    //         .unwrap();
    //
    //     whole_decrypted_buff.append(&mut temp_buff_decrypted);
    //     temp_buff.clear();
    //     temp_buff_decrypted.clear();
    // }

    whole_decrypted_buff
}

fn encrypt_bytes(bytes: &Vec<u8>, rsa_key: &Rsa<Private>) -> Vec<u8> {
    let key_size: usize = (rsa_key.size() / 2) as usize; //128

    let mut whole_encrypted_buff: Vec<u8> = Vec::new();
    let mut temp_buff: Vec<u8> = vec![0; key_size];
    let mut temp_buff_encrypted: Vec<u8> = vec![0; rsa_key.size() as usize];

    let number_of_key_size_in_whole_bill: usize = bytes.len() / key_size;
    let remainder: usize = bytes.len() - key_size * number_of_key_size_in_whole_bill;

    for i in 0..number_of_key_size_in_whole_bill {
        for j in 0..key_size {
            let byte_number: usize = key_size * i + j;
            temp_buff[j] = bytes[byte_number];
        }

        let _encrypted_len: usize = rsa_key
            .public_encrypt(&temp_buff, &mut temp_buff_encrypted, Padding::PKCS1)
            .unwrap();

        whole_encrypted_buff.append(&mut temp_buff_encrypted);
        temp_buff = vec![0; key_size];
        temp_buff_encrypted = vec![0; rsa_key.size() as usize];
    }

    if remainder != 0 {
        temp_buff = vec![0; remainder];

        let position: usize = key_size * number_of_key_size_in_whole_bill;
        let mut index_in_temp_buff: usize = 0;

        for i in position..bytes.len() {
            temp_buff[index_in_temp_buff] = bytes[i];
            index_in_temp_buff += 1;
        }

        index_in_temp_buff = 0;

        let _encrypted_len: usize = rsa_key
            .public_encrypt(&temp_buff, &mut temp_buff_encrypted, Padding::PKCS1)
            .unwrap();

        whole_encrypted_buff.append(&mut temp_buff_encrypted);
        temp_buff.clear();
        temp_buff_encrypted.clear();
    }

    whole_encrypted_buff
}

fn decrypt_bytes(bytes: &Vec<u8>, rsa_key: &Rsa<Private>) -> Vec<u8> {
    let key_size: usize = rsa_key.size() as usize; //256

    let mut whole_decrypted_buff: Vec<u8> = Vec::new();
    let mut temp_buff: Vec<u8> = vec![0; rsa_key.size() as usize];
    let mut temp_buff_decrypted: Vec<u8> = vec![0; rsa_key.size() as usize];

    let number_of_key_size_in_whole_bill: usize = bytes.len() / key_size;
    // let remainder = bill_bytes.len() - key_size * number_of_key_size_in_whole_bill;

    for i in 0..number_of_key_size_in_whole_bill {
        for j in 0..key_size {
            let byte_number = key_size * i + j;
            temp_buff[j] = bytes[byte_number];
        }

        let decrypted_len: usize = rsa_key
            .private_decrypt(&temp_buff, &mut temp_buff_decrypted, Padding::PKCS1)
            .unwrap();

        whole_decrypted_buff.append(&mut temp_buff_decrypted[0..decrypted_len].to_vec());
        temp_buff = vec![0; rsa_key.size() as usize];
        temp_buff_decrypted = vec![0; rsa_key.size() as usize];
    }

    // if remainder != 0 {
    //     let position = key_size * number_of_key_size_in_whole_bill;
    //     let mut index_in_temp_buff = 0;
    //
    //     for i in position..bill_bytes.len() {
    //         temp_buff[index_in_temp_buff] = bill_bytes[i];
    //         index_in_temp_buff = index_in_temp_buff + 1;
    //     }
    //
    //     index_in_temp_buff = 0;
    //
    //     let decrypted_len = rsa_key
    //         .public_decrypt(&*temp_buff, &mut temp_buff_decrypted, Padding::PKCS1)
    //         .unwrap();
    //
    //     whole_decrypted_buff.append(&mut temp_buff_decrypted);
    //     temp_buff.clear();
    //     temp_buff_decrypted.clear();
    // }

    whole_decrypted_buff
}

unsafe fn structure_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

fn is_not_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| !s.starts_with("."))
        .unwrap_or(false)
}
//--------------------------------------------------------------

//-------------------------Identity-----------------------------
#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone, FromForm)]
pub struct IdentityPublicData {
    peer_id: String,
    name: String,
    bitcoin_public_key: String,
    postal_address: String,
    email: String,
    rsa_public_key_pem: String,
}

impl IdentityPublicData {
    pub fn new(identity: Identity, peer_id: String) -> Self {
        Self {
            peer_id,
            name: identity.name,
            bitcoin_public_key: identity.bitcoin_public_key,
            postal_address: identity.postal_address,
            email: identity.email,
            rsa_public_key_pem: identity.public_key_pem,
        }
    }
}

#[derive(Clone)]
pub struct IdentityWithAll {
    identity: Identity,
    peer_id: PeerId,
    key_pair: Keypair,
}

#[derive(BorshSerialize, BorshDeserialize, FromForm, Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Identity {
    name: String,
    date_of_birth: String,
    city_of_birth: String,
    country_of_birth: String,
    email: String,
    postal_address: String,
    public_key_pem: String,
    private_key_pem: String,
    bitcoin_public_key: String,
    bitcoin_private_key: String,
}

pub fn get_whole_identity() -> IdentityWithAll {
    let identity: Identity = read_identity_from_file();
    let ed25519_keys: Keypair = read_ed25519_keypair_from_file();
    let peer_id: PeerId = read_peer_id_from_file();

    IdentityWithAll {
        identity,
        peer_id,
        key_pair: ed25519_keys,
    }
}

pub fn create_whole_identity(
    name: String,
    date_of_birth: String,
    city_of_birth: String,
    country_of_birth: String,
    email: String,
    postal_address: String,
) -> IdentityWithAll {
    let identity = create_new_identity(
        name,
        date_of_birth,
        city_of_birth,
        country_of_birth,
        email,
        postal_address,
    );

    let ed25519_keys = read_ed25519_keypair_from_file();
    let peer_id = read_peer_id_from_file();

    write_identity_to_file(&identity);

    IdentityWithAll {
        identity,
        peer_id,
        key_pair: ed25519_keys,
    }
}

pub fn generate_dht_logic() {
    let ed25519_keys = Keypair::generate_ed25519();
    let peer_id = ed25519_keys.public().to_peer_id();

    write_dht_logic(&peer_id, &ed25519_keys);
}

fn write_dht_logic(peer_id: &PeerId, ed25519_keys: &Keypair) {
    write_peer_id_to_file(peer_id);
    write_ed25519_keypair_to_file(ed25519_keys);
}

fn create_new_identity(
    name: String,
    date_of_birth: String,
    city_of_birth: String,
    country_of_birth: String,
    email: String,
    postal_address: String,
) -> Identity {
    let rsa: Rsa<Private> = generation_rsa_key();
    let private_key_pem: String = pem_private_key_from_rsa(&rsa);
    let public_key_pem: String = pem_public_key_from_rsa(&rsa);

    let s = bitcoin::secp256k1::Secp256k1::new();
    let private_key = bitcoin::PrivateKey::new(
        s.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng())
            .0,
        USEDNET,
    );
    let public_key = private_key.public_key(&s).to_string();
    let private_key = private_key.to_string();

    Identity {
        name,
        date_of_birth,
        city_of_birth,
        country_of_birth,
        email,
        postal_address,
        public_key_pem,
        private_key_pem,
        bitcoin_public_key: public_key,
        bitcoin_private_key: private_key.clone(),
    }
}

fn write_identity_to_file(identity: &Identity) {
    let data: Vec<u8> = identity_to_byte_array(identity);
    fs::write(IDENTITY_FILE_PATH, data).expect("Unable to write file identity");
}

fn write_ed25519_keypair_to_file(ed25519_keys: &Keypair) {
    let data: &[u8] = unsafe { structure_as_u8_slice(ed25519_keys) };
    let data_sized = byte_array_to_size_array_keypair(data);
    fs::write(IDENTITY_ED_25529_KEYS_FILE_PATH, *data_sized)
        .expect("Unable to write keypair ed25519 in file");
}

fn write_peer_id_to_file(peer_id: &PeerId) {
    let data: &[u8] = unsafe { structure_as_u8_slice(peer_id) };
    let data_sized = byte_array_to_size_array_peer_id(data);
    fs::write(IDENTITY_PEER_ID_FILE_PATH, *data_sized).expect("Unable to write peer id in file");
}

fn read_identity_from_file() -> Identity {
    let data: Vec<u8> = fs::read(IDENTITY_FILE_PATH).expect("Unable to read file identity");
    identity_from_byte_array(&data)
}

fn read_ed25519_keypair_from_file() -> Keypair {
    let data: Vec<u8> =
        fs::read(IDENTITY_ED_25529_KEYS_FILE_PATH).expect("Unable to read file keypair");
    let key_pair_bytes_sized = byte_array_to_size_array_keypair(data.as_slice());
    let key_pair: Keypair = unsafe { mem::transmute_copy(key_pair_bytes_sized) };
    key_pair
}

fn read_peer_id_from_file() -> PeerId {
    let data: Vec<u8> =
        fs::read(IDENTITY_PEER_ID_FILE_PATH).expect("Unable to read file with peer id");
    let peer_id_bytes_sized = byte_array_to_size_array_peer_id(data.as_slice());
    let peer_id: PeerId = unsafe { mem::transmute_copy(peer_id_bytes_sized) };
    peer_id
}

fn identity_to_byte_array(identity: &Identity) -> Vec<u8> {
    identity.try_to_vec().unwrap()
}

fn identity_from_byte_array(identity: &Vec<u8>) -> Identity {
    Identity::try_from_slice(identity).unwrap()
}

fn byte_array_to_size_array_keypair(array: &[u8]) -> &[u8; ::std::mem::size_of::<Keypair>()] {
    array.try_into().expect("slice with incorrect length")
}

fn byte_array_to_size_array_peer_id(array: &[u8]) -> &[u8; ::std::mem::size_of::<PeerId>()] {
    array.try_into().expect("slice with incorrect length")
}
//--------------------------------------------------------------

//-------------------------Bill---------------------------------
#[derive(BorshSerialize, BorshDeserialize, FromForm, Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct BitcreditBill {
    name: String,
    to_payee: bool,
    bill_jurisdiction: String,
    timestamp_at_drawing: i64,
    // The party obliged to pay a Bill
    drawee: IdentityPublicData,
    // The party issuing a Bill
    drawer: IdentityPublicData,
    // The person to whom the Payee or a Endorsee endorses a bill
    payee: IdentityPublicData,
    endorsee: IdentityPublicData,
    place_of_drawing: String,
    currency_code: String,
    //TODO: f64
    amount_numbers: u64,
    amounts_letters: String,
    maturity_date: String,
    date_of_issue: String,
    compounding_interest_rate: u64,
    type_of_interest_calculation: bool,
    // Defaulting to the drawee’s id/ address.
    place_of_payment: String,
    public_key: String,
    private_key: String,
    language: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BillKeys {
    private_key_pem: String,
    public_key_pem: String,
}

pub fn issue_new_bill(
    bill_jurisdiction: String,
    place_of_drawing: String,
    amount_numbers: u64,
    place_of_payment: String,
    maturity_date: String,
    drawer: IdentityWithAll,
    language: String,
    public_data_drawee: IdentityPublicData,
    public_data_payee: IdentityPublicData,
) -> BitcreditBill {
    let s = bitcoin::secp256k1::Secp256k1::new();
    let private_key = bitcoin::PrivateKey::new(
        s.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng())
            .0,
        USEDNET,
    );
    let public_key = private_key.public_key(&s);

    let bill_name: String = create_bill_name(&public_key);

    let private_key_bitcoin: String = private_key.to_string();
    let public_key_bitcoin: String = public_key.to_string();

    let rsa: Rsa<Private> = generation_rsa_key();
    let private_key_pem: String = pem_private_key_from_rsa(&rsa);
    let public_key_pem: String = pem_public_key_from_rsa(&rsa);
    write_bill_keys_to_file(
        bill_name.clone(),
        private_key_pem.clone(),
        public_key_pem.clone(),
    );

    let amount_letters: String = encode(&amount_numbers);

    let public_data_drawer =
        IdentityPublicData::new(drawer.identity.clone(), drawer.peer_id.to_string().clone());

    let utc = Utc::now();
    let timestamp_at_drawing = utc.timestamp();
    let date_of_issue = utc.naive_local().date().to_string();
    // let maturity_date = utc
    //     .checked_add_days(Days::new(BILL_VALIDITY_PERIOD))
    //     .unwrap()
    //     .naive_local()
    //     .date()
    //     .to_string();

    let new_bill = BitcreditBill {
        name: bill_name.clone(),
        to_payee: false,
        bill_jurisdiction,
        timestamp_at_drawing,
        place_of_drawing,
        currency_code: SATOSHI.to_string(),
        amount_numbers,
        amounts_letters: amount_letters,
        maturity_date,
        date_of_issue,
        compounding_interest_rate: COMPOUNDING_INTEREST_RATE_ZERO,
        type_of_interest_calculation: false,
        place_of_payment,
        public_key: public_key_bitcoin,
        private_key: private_key_bitcoin,
        language,
        drawee: public_data_drawee,
        drawer: public_data_drawer,
        payee: public_data_payee,
        endorsee: IdentityPublicData {
            peer_id: "".to_string(),
            name: "".to_string(),
            bitcoin_public_key: "".to_string(),
            postal_address: "".to_string(),
            email: "".to_string(),
            rsa_public_key_pem: "".to_string(),
        },
    };

    start_blockchain_for_new_bill(
        &new_bill,
        OperationCode::Issue,
        drawer.identity.public_key_pem.clone(),
        drawer.identity.private_key_pem.clone(),
        private_key_pem.clone(),
    );

    new_bill
}

fn write_bill_keys_to_file(bill_name: String, private_key: String, public_key: String) {
    let keys: BillKeys = BillKeys {
        private_key_pem: private_key,
        public_key_pem: public_key,
    };

    let output_path = BILLS_KEYS_FOLDER_PATH.to_string() + "/" + bill_name.as_str() + ".json";
    std::fs::write(
        output_path.clone(),
        serde_json::to_string_pretty(&keys).unwrap(),
    )
    .unwrap();
}

fn create_bill_name(public_key: &PublicKey) -> String {
    let bill_name_hash: Vec<u8> = sha256(&public_key.to_bytes()).to_vec();
    let bill_name_readable = hex::encode(bill_name_hash);
    bill_name_readable
}

pub fn get_bills() -> Vec<BitcreditBill> {
    let mut bills = Vec::new();
    let paths = fs::read_dir(BILLS_FOLDER_PATH).unwrap();
    for _path in paths {
        let dir = _path.unwrap();
        if is_not_hidden(&dir) {
            let mut file_name = dir
                .file_name()
                .to_str()
                .expect("File name error")
                .to_string();
            //TODO change
            let path_without_extension = path::Path::file_stem(path::Path::new(&file_name))
                .expect("File name error")
                .to_str()
                .expect("File name error")
                .to_string();
            let bill = read_bill_from_file(&path_without_extension);
            bills.push(bill);
        }
    }
    bills
}

pub fn endorse_bitcredit_bill(bill_name: &String, endorsee: IdentityPublicData) -> bool {
    let my_peer_id = read_peer_id_from_file().to_string();
    let mut bill = read_bill_from_file(&bill_name);

    let mut blockchain_from_file = Chain::read_chain_from_file(bill_name);
    let last_block = blockchain_from_file.get_latest_block();

    let exist_block_with_code_endorse =
        blockchain_from_file.exist_block_with_operation_code(OperationCode::Endorse);

    if (my_peer_id.eq(&bill.payee.peer_id) && !exist_block_with_code_endorse)
        || (my_peer_id.eq(&bill.endorsee.peer_id))
    {
        let identity = get_whole_identity();

        let my_identity_public =
            IdentityPublicData::new(identity.identity.clone(), identity.peer_id.to_string());
        let endorsed_by = serde_json::to_vec(&my_identity_public).unwrap();

        let data_for_new_block_in_bytes = serde_json::to_vec(&endorsee).unwrap();
        let data_for_new_block = "Endorsed to ".to_string()
            + &hex::encode(data_for_new_block_in_bytes)
            + " endorsed by "
            + &hex::encode(endorsed_by);

        let keys = read_keys_from_bill_file(&bill_name);
        let key: Rsa<Private> = Rsa::private_key_from_pem(keys.private_key_pem.as_bytes()).unwrap();

        let data_for_new_block_in_bytes = data_for_new_block.as_bytes().to_vec();
        let data_for_new_block_encrypted = encrypt_bytes(&data_for_new_block_in_bytes, &key);
        let data_for_new_block_encrypted_in_string_format =
            hex::encode(data_for_new_block_encrypted);

        let new_block = Block::new(
            last_block.id + 1,
            last_block.hash.clone(),
            data_for_new_block_encrypted_in_string_format,
            bill_name.clone(),
            identity.identity.public_key_pem.clone(),
            OperationCode::Endorse,
            identity.identity.private_key_pem.clone(),
        );

        let try_add_block = blockchain_from_file.try_add_block(new_block.clone());
        if try_add_block && blockchain_from_file.is_chain_valid() {
            blockchain_from_file.write_chain_to_file(&bill.name);
            true
        } else {
            false
        }
    } else {
        false
    }
}

pub fn request_pay(bill_name: &String) -> bool {
    let my_peer_id = read_peer_id_from_file().to_string();
    let bill = read_bill_from_file(bill_name);

    let mut blockchain_from_file = Chain::read_chain_from_file(bill_name);
    let last_block = blockchain_from_file.get_latest_block();

    let exist_block_with_code_endorse =
        blockchain_from_file.exist_block_with_operation_code(OperationCode::Endorse);

    if (my_peer_id.eq(&bill.payee.peer_id) && !exist_block_with_code_endorse)
        || (my_peer_id.eq(&bill.endorsee.peer_id))
    {
        let identity = get_whole_identity();

        let my_identity_public =
            IdentityPublicData::new(identity.identity.clone(), identity.peer_id.to_string());

        let data_for_new_block_in_bytes = serde_json::to_vec(&my_identity_public).unwrap();
        let data_for_new_block =
            "Requested to pay by ".to_string() + &hex::encode(data_for_new_block_in_bytes);

        let keys = read_keys_from_bill_file(&bill_name);
        let key: Rsa<Private> = Rsa::private_key_from_pem(keys.private_key_pem.as_bytes()).unwrap();

        let data_for_new_block_in_bytes = data_for_new_block.as_bytes().to_vec();
        let data_for_new_block_encrypted = encrypt_bytes(&data_for_new_block_in_bytes, &key);
        let data_for_new_block_encrypted_in_string_format =
            hex::encode(data_for_new_block_encrypted);

        let new_block = Block::new(
            last_block.id + 1,
            last_block.hash.clone(),
            data_for_new_block_encrypted_in_string_format,
            bill_name.clone(),
            identity.identity.public_key_pem.clone(),
            OperationCode::RequestToPay,
            identity.identity.private_key_pem.clone(),
        );

        let try_add_block = blockchain_from_file.try_add_block(new_block.clone());
        if try_add_block && blockchain_from_file.is_chain_valid() {
            blockchain_from_file.write_chain_to_file(&bill.name);
            true
        } else {
            false
        }
    } else {
        false
    }
}

pub fn request_acceptance(bill_name: &String) -> bool {
    let my_peer_id = read_peer_id_from_file().to_string();
    let bill = read_bill_from_file(bill_name);

    let mut blockchain_from_file = Chain::read_chain_from_file(bill_name);
    let last_block = blockchain_from_file.get_latest_block();

    let exist_block_with_code_endorse =
        blockchain_from_file.exist_block_with_operation_code(OperationCode::Endorse);

    if (my_peer_id.eq(&bill.payee.peer_id) && !exist_block_with_code_endorse)
        || (my_peer_id.eq(&bill.endorsee.peer_id))
    {
        let identity = get_whole_identity();

        let my_identity_public =
            IdentityPublicData::new(identity.identity.clone(), identity.peer_id.to_string());

        let data_for_new_block_in_bytes = serde_json::to_vec(&my_identity_public).unwrap();
        let data_for_new_block =
            "Requested to accept by ".to_string() + &hex::encode(data_for_new_block_in_bytes);

        let keys = read_keys_from_bill_file(&bill_name);
        let key: Rsa<Private> = Rsa::private_key_from_pem(keys.private_key_pem.as_bytes()).unwrap();

        let data_for_new_block_in_bytes = data_for_new_block.as_bytes().to_vec();
        let data_for_new_block_encrypted = encrypt_bytes(&data_for_new_block_in_bytes, &key);
        let data_for_new_block_encrypted_in_string_format =
            hex::encode(data_for_new_block_encrypted);

        let new_block = Block::new(
            last_block.id + 1,
            last_block.hash.clone(),
            data_for_new_block_encrypted_in_string_format,
            bill_name.clone(),
            identity.identity.public_key_pem.clone(),
            OperationCode::RequestToAccept,
            identity.identity.private_key_pem.clone(),
        );

        let try_add_block = blockchain_from_file.try_add_block(new_block.clone());
        if try_add_block && blockchain_from_file.is_chain_valid() {
            blockchain_from_file.write_chain_to_file(&bill.name);
            true
        } else {
            false
        }
    } else {
        false
    }
}

pub fn accept_bill(bill_name: &String) -> bool {
    let my_peer_id = read_peer_id_from_file().to_string();
    let bill = read_bill_from_file(bill_name);

    let mut blockchain_from_file = Chain::read_chain_from_file(bill_name);
    let last_block = blockchain_from_file.get_latest_block();

    if bill.drawee.peer_id.eq(&my_peer_id) {
        let identity = get_whole_identity();

        let my_identity_public =
            IdentityPublicData::new(identity.identity.clone(), identity.peer_id.to_string());

        let data_for_new_block_in_bytes = serde_json::to_vec(&my_identity_public).unwrap();
        let data_for_new_block =
            "Accepted by ".to_string() + &hex::encode(data_for_new_block_in_bytes);

        let keys = read_keys_from_bill_file(&bill_name);
        let key: Rsa<Private> = Rsa::private_key_from_pem(keys.private_key_pem.as_bytes()).unwrap();

        let data_for_new_block_in_bytes = data_for_new_block.as_bytes().to_vec();
        let data_for_new_block_encrypted = encrypt_bytes(&data_for_new_block_in_bytes, &key);
        let data_for_new_block_encrypted_in_string_format =
            hex::encode(data_for_new_block_encrypted);

        let new_block = Block::new(
            last_block.id + 1,
            last_block.hash.clone(),
            data_for_new_block_encrypted_in_string_format,
            bill_name.clone(),
            identity.identity.public_key_pem.clone(),
            OperationCode::Accept,
            identity.identity.private_key_pem.clone(),
        );

        let try_add_block = blockchain_from_file.try_add_block(new_block.clone());
        if try_add_block && blockchain_from_file.is_chain_valid() {
            blockchain_from_file.write_chain_to_file(&bill.name);
            true
        } else {
            false
        }
    } else {
        false
    }
}

fn read_bill_from_file(bill_name: &String) -> BitcreditBill {
    let chain = Chain::read_chain_from_file(bill_name);
    let bill = chain.get_last_version_bill();
    bill
}

fn bill_to_byte_array(bill: &BitcreditBill) -> Vec<u8> {
    bill.try_to_vec().unwrap()
}

fn bill_from_byte_array(bill: &Vec<u8>) -> BitcreditBill {
    BitcreditBill::try_from_slice(bill).unwrap()
}

fn read_keys_from_bill_file(bill_name: &String) -> BillKeys {
    let input_path = BILLS_KEYS_FOLDER_PATH.to_string() + "/" + bill_name.as_str() + ".json";
    let blockchain_from_file = std::fs::read(input_path.clone()).expect("file not found");
    serde_json::from_slice(blockchain_from_file.as_slice()).unwrap()
}
//--------------------------------------------------------------

//-------------------------Forms--------------------------------
#[derive(FromForm, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct BitcreditBillForm {
    pub bill_jurisdiction: String,
    pub place_of_drawing: String,
    pub amount_numbers: u64,
    pub language: String,
    pub drawee_name: String,
    pub payee_name: String,
    pub place_of_payment: String,
    pub maturity_date: String,
}

#[derive(FromForm, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct EndorseBitcreditBillForm {
    pub endorsee: String,
    pub bill_name: String,
}

#[derive(FromForm, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct RequestToAcceptBitcreditBillForm {
    pub bill_name: String,
}

#[derive(FromForm, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct RequestToPayBitcreditBillForm {
    pub bill_name: String,
}

#[derive(FromForm, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AcceptBitcreditBillForm {
    pub bill_name: String,
    pub operation_code: String,
}

#[derive(FromForm, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct IdentityForm {
    name: String,
    date_of_birth: String,
    city_of_birth: String,
    country_of_birth: String,
    email: String,
    postal_address: String,
}

#[derive(FromForm, Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct NewContactForm {
    pub name: String,
    pub node_id: String,
}
//-------------------------------------------------------------
