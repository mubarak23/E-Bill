use serde_derive::Deserialize;

#[derive(Deserialize, Debug)]
pub struct ChainStats {
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
    pub tx_count: u64,
}

#[derive(Deserialize, Debug)]
pub struct MempoolStats {
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
    pub tx_count: u64,
}

#[derive(Deserialize, Debug)]
pub struct AddressInfo {
    address: String,
    pub chain_stats: ChainStats,
    pub mempool_stats: MempoolStats,
}

impl AddressInfo {
    pub async fn get_testnet_address_info(address: String) -> Self {
        let request_url = format!(
            "https://blockstream.info/testnet/api/address/{address}",
            address = address
        );
        let address: AddressInfo = reqwest::get(&request_url)
            .await
            .expect("Failed to send request")
            .json()
            .await
            .expect("Failed to read response");

        address
    }

    async fn get_mainnet_address_info(address: String) -> Self {
        let request_url = format!(
            "https://blockstream.info/api/address/{address}",
            address = address
        );
        let address: AddressInfo = reqwest::get(&request_url)
            .await
            .expect("Failed to send request")
            .json()
            .await
            .expect("Failed to read response");

        address
    }
}

#[derive(Deserialize, Debug)]
pub struct TimeApi {
    status: String,
    message: String,
    countryCode: String,
    countryName: String,
    regionName: String,
    cityName: String,
    zoneName: String,
    abbreviation: String,
    gmtOffset: i64,
    dst: String,
    zoneStart: i64,
    zoneEnd: i64,
    nextAbbreviation: String,
    pub timestamp: i64,
    formatted: String,
}

impl TimeApi {
    pub async fn get_atomic_time() -> Self {
        let request_url = "https://api.timezonedb.com/v2.1/get-time-zone?key=RQ6ZFDOXPVLR&format=json&by=zone&zone=Europe/Vienna".to_string();

        reqwest::get(&request_url)
            .await
            .expect("Failed to send request")
            .json()
            .await
            .expect("Failed to read response")
    }
}

pub type Transactions = Vec<Txid>;

#[derive(Deserialize, Debug, Clone)]
pub struct Txid {
    pub txid: String,
    pub version: u64,
    pub locktime: u64,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    pub size: u64,
    pub weight: u64,
    pub fee: u64,
    pub status: Status,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Status {
    pub block_hash: String,
    pub block_height: u64,
    pub block_time: u64,
    pub confirmed: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Vin {
    pub txid: String,
    pub vout: i64,
    pub prevout: Vout,
    pub scriptsig: String,
    pub scriptsig_asm: String,
    pub witness: Vec<String>,
    pub is_coinbase: bool,
    pub sequence: i64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Vout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: String,
    pub value: i64,
}

pub async fn get_transactions_testet(address: String) -> Transactions {
    let request_url = format!(
        "https://blockstream.info/testnet/api/address/{address}/txs",
        address = address
    );
    let transactions: Transactions = reqwest::get(&request_url)
        .await
        .expect("Failed to send request")
        .json()
        .await
        .expect("Failed to read response");

    transactions
}

pub async fn get_transactions_mainnet(address: String) -> Transactions {
    let request_url = format!(
        "https://blockstream.info/api/address/{address}/txs",
        address = address
    );
    let transactions: Transactions = reqwest::get(&request_url)
        .await
        .expect("Failed to send request")
        .json()
        .await
        .expect("Failed to read response");

    transactions
}

impl Txid {
    pub async fn get_first_transaction(transactions: Transactions) -> Self {
        transactions.last().unwrap().clone()
    }
}

pub async fn get_testnet_last_block_height() -> u64 {
    let request_url = "https://blockstream.info/testnet/api/blocks/tip/height".to_string();
    let height: u64 = reqwest::get(&request_url)
        .await
        .expect("Failed to send request")
        .json()
        .await
        .expect("Failed to read response");

    height
}

pub async fn get_mainnet_last_block_height() -> u64 {
    let request_url = "https://blockstream.info/api/blocks/tip/height".to_string();
    let height: u64 = reqwest::get(&request_url)
        .await
        .expect("Failed to send request")
        .json()
        .await
        .expect("Failed to read response");

    height
}
