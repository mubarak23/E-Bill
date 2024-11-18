use crate::blockchain::ChainToReturn;
use crate::constants::{BILLS_FOLDER_PATH, BILLS_KEYS_FOLDER_PATH};
use crate::service::contact_service::IdentityPublicData;
use borsh::BorshDeserialize;
use borsh_derive::{BorshDeserialize, BorshSerialize};
use rocket::serde::{Deserialize, Serialize};
use rocket::FromForm;
use std::fs;
use std::path::PathBuf;

pub mod quotes;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct BitcreditBillToReturn {
    pub name: String,
    pub to_payee: bool,
    pub bill_jurisdiction: String,
    pub timestamp_at_drawing: i64,
    pub drawee: IdentityPublicData,
    pub drawer: IdentityPublicData,
    pub payee: IdentityPublicData,
    pub endorsee: IdentityPublicData,
    pub place_of_drawing: String,
    pub currency_code: String,
    pub amount_numbers: u64,
    pub amounts_letters: String,
    pub maturity_date: String,
    pub date_of_issue: String,
    pub compounding_interest_rate: u64,
    pub type_of_interest_calculation: bool,
    pub place_of_payment: String,
    pub public_key: String,
    pub private_key: String,
    pub language: String,
    pub accepted: bool,
    pub endorsed: bool,
    pub requested_to_pay: bool,
    pub requested_to_accept: bool,
    pub paid: bool,
    pub waited_for_payment: bool,
    pub address_for_selling: String,
    pub amount_for_selling: u64,
    pub buyer: IdentityPublicData,
    pub seller: IdentityPublicData,
    pub link_for_buy: String,
    pub link_to_pay: String,
    pub pr_key_bill: String,
    pub number_of_confirmations: u64,
    pub pending: bool,
    pub address_to_pay: String,
    pub chain_of_blocks: ChainToReturn,
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct BitcreditEbillQuote {
    pub bill_id: String,
    pub quote_id: String,
    pub amount: u64,
    pub mint_node_id: String,
    pub mint_url: String,
    pub accepted: bool,
    pub token: String,
}

impl BitcreditEbillQuote {
    pub fn new_empty() -> Self {
        Self {
            bill_id: "".to_string(),
            quote_id: "".to_string(),
            amount: 0,
            mint_node_id: "".to_string(),
            mint_url: "".to_string(),
            accepted: false,
            token: "".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct BitcreditBillForList {
    name: String,
    to_payee: bool,
    bill_jurisdiction: String,
    timestamp_at_drawing: i64,
    drawee: IdentityPublicData,
    drawer: IdentityPublicData,
    payee: IdentityPublicData,
    endorsee: IdentityPublicData,
    place_of_drawing: String,
    currency_code: String,
    amount_numbers: u64,
    amounts_letters: String,
    maturity_date: String,
    date_of_issue: String,
    compounding_interest_rate: u64,
    type_of_interest_calculation: bool,
    place_of_payment: String,
    public_key: String,
    private_key: String,
    language: String,
    chain_of_blocks: ChainToReturn,
}

#[derive(BorshSerialize, BorshDeserialize, FromForm, Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
pub struct BitcreditBill {
    pub name: String,
    pub to_payee: bool,
    pub bill_jurisdiction: String,
    pub timestamp_at_drawing: i64,
    // The party obliged to pay a Bill
    pub drawee: IdentityPublicData,
    // The party issuing a Bill
    pub drawer: IdentityPublicData,
    // The person to whom the Payee or an Endorsee endorses a bill
    pub payee: IdentityPublicData,
    pub endorsee: IdentityPublicData,
    pub place_of_drawing: String,
    pub currency_code: String,
    //TODO: f64
    pub amount_numbers: u64,
    pub amounts_letters: String,
    pub maturity_date: String,
    pub date_of_issue: String,
    pub compounding_interest_rate: u64,
    pub type_of_interest_calculation: bool,
    // Defaulting to the drawee’s id/ address.
    pub place_of_payment: String,
    pub public_key: String,
    pub private_key: String,
    pub language: String,
    pub files: Vec<BillFile>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, FromForm, Debug, Clone)]
#[serde(crate = "rocket::serde")]
pub struct BillFile {
    pub name: String,
    pub hash: String,
}

#[cfg(test)]
impl BitcreditBill {
    pub fn new_empty() -> Self {
        Self {
            name: "".to_string(),
            to_payee: false,
            bill_jurisdiction: "".to_string(),
            timestamp_at_drawing: 0,
            drawee: IdentityPublicData::new_empty(),
            drawer: IdentityPublicData::new_empty(),
            payee: IdentityPublicData::new_empty(),
            endorsee: IdentityPublicData::new_empty(),
            place_of_drawing: "".to_string(),
            currency_code: "".to_string(),
            amount_numbers: 0,
            amounts_letters: "".to_string(),
            maturity_date: "".to_string(),
            date_of_issue: "".to_string(),
            compounding_interest_rate: 0,
            type_of_interest_calculation: false,
            place_of_payment: "".to_string(),
            public_key: "".to_string(),
            private_key: "".to_string(),
            language: "".to_string(),
            files: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BillKeys {
    pub private_key_pem: String,
    pub public_key_pem: String,
}

pub fn get_path_for_bill(bill_name: &str) -> PathBuf {
    let mut path = PathBuf::from(BILLS_FOLDER_PATH).join(bill_name);
    path.set_extension("json");
    path
}

pub fn get_path_for_bill_keys(key_name: &str) -> PathBuf {
    let mut path = PathBuf::from(BILLS_KEYS_FOLDER_PATH).join(key_name);
    path.set_extension("json");
    path
}

pub fn bill_from_byte_array(bill: &[u8]) -> BitcreditBill {
    BitcreditBill::try_from_slice(bill).unwrap()
}

pub fn read_keys_from_bill_file(bill_name: &str) -> BillKeys {
    let input_path = get_path_for_bill_keys(bill_name);
    let blockchain_from_file = fs::read(input_path.clone()).expect("file not found");
    serde_json::from_slice(blockchain_from_file.as_slice()).unwrap()
}
