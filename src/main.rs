use crate::constants::{
    BILLS_FOLDER_PATH, BILLS_KEYS_FOLDER_PATH, BOOTSTRAP_FOLDER_PATH, CONTACT_MAP_FOLDER_PATH,
    IDENTITY_FOLDER_PATH, QUOTES_MAP_FOLDER_PATH,
};
use clap::Parser;
use config::Config;
use std::path::Path;
use std::{env, fs};
use anyhow::Result;

mod bill;
mod blockchain;
mod config;
mod constants;
mod dht;
mod external;
#[cfg(test)]
mod tests;
mod util;
mod web;

// MAIN
#[tokio::main]
async fn main() -> Result<()> {
    env::set_var("RUST_BACKTRACE", "full");

    env_logger::init();

    // Parse command line arguments and env vars with clap
    let conf = Config::parse();

    init_folders();

    external::mint::init_wallet().await;

    let mut dht = dht::dht_main(&conf).await.expect("DHT failed to start");

    let local_peer_id = bill::identity::read_peer_id_from_file();
    dht.check_new_bills(local_peer_id.to_string().clone()).await;
    dht.upgrade_table(local_peer_id.to_string().clone()).await;
    dht.subscribe_to_all_bills_topics().await;
    dht.put_bills_for_parties().await;
    dht.start_provide().await;
    dht.receive_updates_for_all_bills_topics().await;
    dht.put_identity_public_data_in_dht().await;
    let service_context = create_service_context(conf.clone(), dht.clone()).await?;
    let _rocket = web::rocket_main(service_context)
        .launch()
        .await?;
    Ok(())
}

fn init_folders() {
    if !Path::new(QUOTES_MAP_FOLDER_PATH).exists() {
        fs::create_dir(QUOTES_MAP_FOLDER_PATH).expect("Can't create folder quotes.");
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
    if !Path::new(BOOTSTRAP_FOLDER_PATH).exists() {
        fs::create_dir(BOOTSTRAP_FOLDER_PATH).expect("Can't create folder bootstrap.");
    }
}
