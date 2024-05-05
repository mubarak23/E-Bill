use crate::{read_identity_from_file, Identity};
use futures::executor::block_on;
use moksha_core::amount::Amount;
use moksha_core::primitives::{CurrencyUnit, PaymentMethod};
use moksha_wallet::http::CrossPlatformHttpClient;
use moksha_wallet::localstore::sqlite::SqliteLocalStore;
use moksha_wallet::wallet::{Wallet, WalletBuilder};
use std::fs;
use std::path::PathBuf;
use tokio::runtime::Handle;
use url::Url;

// pub fn mint_with_handle(handle: Handle, amount: u64, bill_id: String) {
//     block_on(async {
//         handle
//             .spawn(async {
//                 let dir = PathBuf::from("./data/wallet".to_string());
//                 fs::create_dir_all(dir.clone()).unwrap();
//                 let db_path = dir.join("wallet.db").to_str().unwrap().to_string();
//
//                 let localstore = SqliteLocalStore::with_path(db_path.clone())
//                     .await
//                     .expect("Cannot parse local store");
//                 let client = HttpClient::default();
//                 let mint_url = Url::parse("http://127.0.0.1:3338").expect("Invalid url");
//
//                 // block_on(async {
//                 let wallet = WalletBuilder::default()
//                     .with_client(client)
//                     .with_localstore(localstore)
//                     .with_mint_url(mint_url)
//                     .build()
//                     .await
//                     .expect("Could not create wallet");
//
//                 loop {
//                     tokio::time::sleep_until(
//                         tokio::time::Instant::now() + std::time::Duration::from_millis(1_000),
//                     )
//                     .await;
//
//                     let req = wallet
//                         .get_mint_payment_request(50)
//                         .await
//                         .expect("Cannot get mint payment request");
//
//                     let mint_result = wallet.mint_tokens(50.into(), req.hash.clone()).await;
//
//                     match mint_result {
//                         Ok(_) => {
//                             println!(
//                                 "Tokens minted successfully.\nNew balance {} sats",
//                                 wallet.get_balance().await.unwrap()
//                             );
//                             break;
//                         }
//                         Err(moksha_wallet::error::MokshaWalletError::InvoiceNotPaidYet(_, _)) => {
//                             continue;
//                         }
//                         Err(e) => {
//                             println!("General Error: {}", e);
//                             break;
//                         }
//                     }
//                 }
//             })
//             .await
//             .expect("Task mint spawned in Tokio executor panicked")
//     })
// }

#[tokio::main]
pub async fn mint(
    amount: u64,
    bill_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = PathBuf::from("./data/wallet".to_string());
    let db_path = dir.join("wallet.db").to_str().unwrap().to_string();
    let localstore = SqliteLocalStore::with_path(db_path.clone())
        .await
        .expect("Cannot parse local store");

    //TODO change to some conf in settings
    let mint_url = Url::parse("http://127.0.0.1:3338").expect("Invalid url");

    let identity: Identity = read_identity_from_file();
    let bitcoin_key = identity.bitcoin_public_key.clone();

    let wallet: Wallet<_, CrossPlatformHttpClient> = Wallet::builder()
        .with_localstore(localstore)
        .with_mint_url(mint_url)
        .build()
        .await
        .expect("Could not create wallet");

    loop {
        tokio::time::sleep_until(
            tokio::time::Instant::now() + std::time::Duration::from_millis(1_000),
        )
        .await;

        let req = wallet
            .get_mint_quote(Amount::from(amount), CurrencyUnit::Sat)
            .await
            .expect("Cannot get mint payment request");

        let result = wallet
            .mint_tokens(&PaymentMethod::Bolt11, amount.into(), req.quote)
            .await;

        match result {
            Ok(_) => {
                println!(
                    "Tokens minted successfully.\nNew balance {} sats",
                    wallet.get_balance().await.unwrap()
                );
                break;
            }
            Err(moksha_wallet::error::MokshaWalletError::InvoiceNotPaidYet(_, _)) => {
                continue;
            }
            Err(e) => {
                println!("General Error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
