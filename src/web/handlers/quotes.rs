use crate::bill::{
    contacts::get_identity_public_data, endorse_bitcredit_bill, quotes::get_quote_from_map,
    BitcreditEbillQuote,
};
use crate::dht::Client;
use crate::external;
use crate::external::mint::{check_bitcredit_quote, client_accept_bitcredit_quote};
use rocket::serde::json::Json;
use rocket::{get, put, State};
use std::thread;

#[get("/return/<id>")]
pub async fn return_quote(id: String) -> Json<BitcreditEbillQuote> {
    let mut quote = get_quote_from_map(&id);
    let copy_id = id.clone();
    if !quote.bill_id.is_empty() && quote.quote_id.is_empty() {
        thread::spawn(move || check_bitcredit_quote(&copy_id))
            .join()
            .expect("Thread panicked");
    }
    quote = get_quote_from_map(&id);
    Json(quote)
}

#[put("/accept/<id>")]
pub async fn accept_quote(state: &State<Client>, id: String) -> Json<BitcreditEbillQuote> {
    let mut quote = get_quote_from_map(&id);
    let client = state.inner().clone();

    let public_data_endorsee =
        get_identity_public_data(quote.mint_node_id.clone(), client.clone()).await;
    if !public_data_endorsee.name.is_empty() {
        let timestamp = external::time::TimeApi::get_atomic_time().await.timestamp;
        endorse_bitcredit_bill(&quote.bill_id, public_data_endorsee.clone(), timestamp);
    }

    let copy_id = id.clone();
    if !quote.bill_id.is_empty() && !quote.quote_id.is_empty() {
        thread::spawn(move || client_accept_bitcredit_quote(&copy_id))
            .join()
            .expect("Thread panicked");
    }
    quote = get_quote_from_map(&id);
    Json(quote)
}
