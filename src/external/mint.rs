use crate::constants::QUOTE_MAP_FILE_PATH;
use crate::service::bill_service::BillKeys as LocalBillKeys;
use crate::service::bill_service::BitcreditEbillQuote;
use crate::util::base58_decode;
use crate::web::data::RequestToMintBitcreditBillPayload;
use crate::CONFIG;
use borsh::{to_vec, BorshDeserialize};
use moksha_core::primitives::CheckBitcreditQuoteResponse;
use moksha_core::primitives::{
    BillKeys, CurrencyUnit, PaymentMethod, PostMintQuoteBitcreditResponse,
    PostRequestToMintBitcreditResponse,
};
use moksha_core::token::TokenV3;
use moksha_wallet::http::CrossPlatformHttpClient;
use moksha_wallet::localstore::sqlite::SqliteLocalStore;
use moksha_wallet::wallet::Wallet;
use std::collections::HashMap;
use std::path::Path;
use std::{fs, path::PathBuf};
use url::Url;

// Usage of tokio::main to spawn a new runtime is necessary here, because Wallet is'nt Send - but
// this logic will be replaced soon
#[tokio::main]
pub async fn accept_mint_bitcredit(
    sum: u64,
    bill_id: String,
    node_id: String,
) -> PostMintQuoteBitcreditResponse {
    let bill_id_u8 = base58_decode(&bill_id).unwrap();
    let bill_id_hex = hex::encode(bill_id_u8);

    let dir = PathBuf::from("./data/wallet".to_string());
    let db_path = dir.join("wallet.db").to_str().unwrap().to_string();
    let localstore = SqliteLocalStore::with_path(db_path.clone())
        .await
        .expect("Cannot parse local store");

    let mint_url = Url::parse(CONFIG.mint_url.as_str()).expect("Invalid url");

    let wallet: Wallet<_, CrossPlatformHttpClient> = Wallet::builder()
        .with_localstore(localstore)
        .build()
        .await
        .expect("Could not create wallet");

    let req = wallet.create_quote_bitcredit(&mint_url, bill_id_hex, node_id, sum);

    req.await.unwrap()
}

// Usage of tokio::main to spawn a new runtime is necessary here, because Wallet is'nt Send - but
// this logic will be replaced soon
#[tokio::main]
pub async fn check_bitcredit_quote(bill_id_hex: &str, node_id: &str, bill_id_base58: String) {
    let dir = PathBuf::from("./data/wallet".to_string());
    let db_path = dir.join("wallet.db").to_str().unwrap().to_string();
    let localstore = SqliteLocalStore::with_path(db_path.clone())
        .await
        .expect("Cannot parse local store");

    let mint_url = Url::parse(CONFIG.mint_url.as_str()).expect("Invalid url");

    let wallet: Wallet<_, CrossPlatformHttpClient> = Wallet::builder()
        .with_localstore(localstore)
        .build()
        .await
        .expect("Could not create wallet");

    let result = wallet
        .check_bitcredit_quote(&mint_url, bill_id_hex.to_owned(), node_id.to_owned())
        .await;

    let quote = result.unwrap();

    if !quote.quote.is_empty() {
        add_bitcredit_quote_and_amount_in_quotes_map(quote.clone(), bill_id_base58);
    }

    // quote
}

// Usage of tokio::main to spawn a new runtime is necessary here, because Wallet isn't Send - but
// this logic will be replaced soon
#[tokio::main]
pub async fn client_accept_bitcredit_quote(bill_id_hex: &str, bill_id_base58: &String) -> String {
    let dir = PathBuf::from("./data/wallet".to_string());
    let db_path = dir.join("wallet.db").to_str().unwrap().to_string();

    let localstore = SqliteLocalStore::with_path(db_path.clone())
        .await
        .expect("Cannot parse local store");

    let mint_url = Url::parse(CONFIG.mint_url.as_str()).expect("Invalid url");

    let wallet: Wallet<_, CrossPlatformHttpClient> = Wallet::builder()
        .with_localstore(localstore)
        .build()
        .await
        .expect("Could not create wallet");

    let clone_bill_id_hex = bill_id_hex.to_owned();
    let wallet_keysets = wallet
        .add_mint_keysets_by_id(&mint_url, "cr-sat".to_string(), clone_bill_id_hex)
        .await
        .unwrap();
    let wallet_keyset = wallet_keysets.first().unwrap();

    let quote = get_quote_from_map(bill_id_base58).unwrap();
    let quote_id = quote.quote_id.clone();
    let sum = quote.sum;

    let mut token = "".to_string();

    if !quote_id.is_empty() && sum > 0 {
        let result = wallet
            .mint_tokens(
                wallet_keyset,
                &PaymentMethod::Bitcredit,
                sum.into(),
                quote_id,
                CurrencyUnit::CrSat,
            )
            .await;

        let bill_mint_path = format!("/{}/cr-sat", &bill_id_hex);
        let token_mint_url =
            Url::parse(&format!("{}{}", CONFIG.mint_url, bill_mint_path)).expect("Invalid url");

        token = TokenV3::from((
            token_mint_url,
            CurrencyUnit::CrSat,
            result.unwrap().proofs(),
        ))
        .serialize(Option::from(CurrencyUnit::CrSat))
        .unwrap();

        add_bitcredit_token_in_quotes_map(token.clone(), bill_id_base58.clone());
    }

    token
}

// Usage of tokio::main to spawn a new runtime is necessary here, because Wallet is'nt Send - but
// this logic will be replaced soon
#[tokio::main]
pub async fn request_to_mint_bitcredit(
    payload: RequestToMintBitcreditBillPayload,
    bill_keys: LocalBillKeys,
    maturity_date_timestamp: i64,
    bill_amount: u64,
) -> PostRequestToMintBitcreditResponse {
    let dir = PathBuf::from("./data/wallet".to_string());
    let db_path = dir.join("wallet.db").to_str().unwrap().to_string();
    let localstore = SqliteLocalStore::with_path(db_path.clone())
        .await
        .expect("Cannot parse local store");

    let mint_url = Url::parse(CONFIG.mint_url.as_str()).expect("Invalid url");

    let wallet: Wallet<_, CrossPlatformHttpClient> = Wallet::builder()
        .with_localstore(localstore)
        .build()
        .await
        .expect("Could not create wallet");

    let keys: BillKeys = BillKeys {
        private_key_pem: bill_keys.private_key,
        public_key_pem: bill_keys.public_key,
    };

    let bill_id_u8 = base58_decode(&payload.bill_id).unwrap();
    let bill_id_hex = hex::encode(bill_id_u8);

    let req = wallet.send_request_to_mint_bitcredit(
        &mint_url,
        bill_id_hex.clone(),
        keys,
        maturity_date_timestamp,
        bill_amount,
    );

    let quote: BitcreditEbillQuote = BitcreditEbillQuote {
        bill_id: payload.bill_id.clone(),
        quote_id: "".to_string(),
        sum: 0,
        mint_node_id: payload.mint_node.clone(),
        mint_url: mint_url.to_string().clone(),
        accepted: false,
        token: "".to_string(),
    };
    safe_ebill_quote_locally(quote);

    req.await.unwrap()
}

pub fn safe_ebill_quote_locally(quote: BitcreditEbillQuote) {
    let map = read_quotes_map();
    if !map.contains_key(&quote.bill_id) {
        add_in_quotes_map(quote);
    }
}

pub async fn init_wallet() {
    let dir = PathBuf::from("./data/wallet".to_string());
    if !dir.exists() {
        fs::create_dir_all(dir.clone()).unwrap();
    }
    let db_path = dir.join("wallet.db").to_str().unwrap().to_string();

    let _localstore = SqliteLocalStore::with_path(db_path.clone())
        .await
        .expect("Cannot parse local store");

    // //TODO: take from params
    // let mint_url = Url::parse(CONFIG.mint_url.as_str()).expect("Invalid url");
    //
    // let identity: Identity = read_identity_from_file();
    // let bitcoin_key = identity.node_id.clone();
    //
    // let wallet: Wallet<_, CrossPlatformHttpClient> = Wallet::builder()
    //     .with_localstore(localstore)
    //     .build()
    //     .await
    //     .expect("Could not create wallet");
}

// ---------------------------------------------
// Quotes Logic --------------------------------
// ---------------------------------------------

pub fn read_quotes_map() -> HashMap<String, BitcreditEbillQuote> {
    if !Path::new(QUOTE_MAP_FILE_PATH).exists() {
        create_quotes_map();
    }
    let data: Vec<u8> = fs::read(QUOTE_MAP_FILE_PATH).expect("Unable to read quotes.");
    let quotes: HashMap<String, BitcreditEbillQuote> = HashMap::try_from_slice(&data).unwrap();
    quotes
}

pub fn create_quotes_map() {
    let quotes: HashMap<String, BitcreditEbillQuote> = HashMap::new();
    write_quotes_map(quotes);
}

pub fn write_quotes_map(map: HashMap<String, BitcreditEbillQuote>) {
    let quotes_byte = to_vec(&map).unwrap();
    fs::write(QUOTE_MAP_FILE_PATH, quotes_byte).expect("Unable to write quote in file.");
}

pub fn add_in_quotes_map(quote: BitcreditEbillQuote) {
    if !Path::new(QUOTE_MAP_FILE_PATH).exists() {
        create_quotes_map();
    }

    let mut quotes: HashMap<String, BitcreditEbillQuote> = read_quotes_map();

    quotes.insert(quote.bill_id.clone(), quote);
    write_quotes_map(quotes);
}

pub fn get_quote_from_map(bill_id: &String) -> Option<BitcreditEbillQuote> {
    let quotes = read_quotes_map();
    if quotes.contains_key(bill_id) {
        let data = quotes.get(bill_id).unwrap().clone();
        Some(data)
    } else {
        None
    }
}

pub fn add_bitcredit_quote_and_amount_in_quotes_map(
    response: CheckBitcreditQuoteResponse,
    bill_id: String,
) {
    if !Path::new(QUOTE_MAP_FILE_PATH).exists() {
        create_quotes_map();
    }

    let mut quotes: HashMap<String, BitcreditEbillQuote> = read_quotes_map();
    let mut quote = get_quote_from_map(&bill_id).unwrap();

    quote.sum = response.amount;
    quote.quote_id = response.quote.clone();

    quotes.remove(&bill_id);
    quotes.insert(bill_id.clone(), quote);
    write_quotes_map(quotes);
}

pub fn add_bitcredit_token_in_quotes_map(token: String, bill_id: String) {
    if !Path::new(QUOTE_MAP_FILE_PATH).exists() {
        create_quotes_map();
    }

    let mut quotes: HashMap<String, BitcreditEbillQuote> = read_quotes_map();
    let mut quote = get_quote_from_map(&bill_id).unwrap();

    quote.token = token.clone();

    quotes.remove(&bill_id);
    quotes.insert(bill_id.clone(), quote);
    write_quotes_map(quotes);
}
