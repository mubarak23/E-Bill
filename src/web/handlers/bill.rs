use super::super::data::{
    AcceptBitcreditBillForm, AcceptMintBitcreditBillForm, BitcreditBillForm,
    EndorseBitcreditBillForm, MintBitcreditBillForm, RequestToAcceptBitcreditBillForm,
    RequestToMintBitcreditBillForm, RequestToPayBitcreditBillForm, SellBitcreditBillForm,
};
use crate::bill::get_path_for_bill;
use crate::blockchain::{Chain, ChainToReturn, GossipsubEvent, GossipsubEventId, OperationCode};
use crate::external::mint::{accept_mint_bitcredit, request_to_mint_bitcredit};
use crate::service::{contact_service::IdentityPublicData, Result};
use crate::util::file::{detect_content_type_for_bytes, UploadFileHandler};
use crate::util::get_current_payee_private_key;
use crate::{
    bill::{get_bills_for_list, read_bill_from_file, BitcreditBill, BitcreditBillToReturn},
    service::ServiceContext,
};
use crate::{external, service};
use rocket::form::Form;
use rocket::http::{ContentType, Status};
use rocket::serde::json::Json;
use rocket::{get, post, put, State};
use std::{fs, thread};

#[get("/holder/<id>")]
pub async fn holder(state: &State<ServiceContext>, id: String) -> Result<Json<bool>> {
    let identity = state.identity_service.get_full_identity().await?;
    let bill: BitcreditBill = read_bill_from_file(&id).await;
    let am_i_holder = identity.peer_id.to_string().eq(&bill.payee.peer_id);
    Ok(Json(am_i_holder))
}

#[get("/attachment/<bill_name>/<file_name>")]
pub async fn attachment(
    state: &State<ServiceContext>,
    bill_name: &str,
    file_name: &str,
) -> Result<(ContentType, Vec<u8>)> {
    let keys = state.bill_service.get_bill_keys(bill_name).await?;
    let file_bytes = state
        .bill_service
        .open_and_decrypt_attached_file(bill_name, file_name, &keys.private_key_pem)
        .await?;

    let content_type = match detect_content_type_for_bytes(&file_bytes) {
        None => None,
        Some(t) => ContentType::parse_flexible(&t),
    }
    .ok_or(service::Error::Validation(String::from(
        "Content Type of the requested file could not be determined",
    )))?;

    Ok((content_type, file_bytes))
}

#[get("/return")]
pub async fn return_bills_list() -> Json<Vec<BitcreditBillToReturn>> {
    let bills: Vec<BitcreditBillToReturn> = get_bills_for_list().await;
    Json(bills)
}

#[get("/return/basic/<id>")]
pub async fn return_basic_bill(id: String) -> Json<BitcreditBill> {
    let bill: BitcreditBill = read_bill_from_file(&id).await;
    Json(bill)
}

#[get("/chain/return/<id>")]
pub async fn return_chain_of_blocks(id: String) -> Json<Chain> {
    let chain = Chain::read_chain_from_file(&id);
    Json(chain)
}

#[get("/find/<bill_id>")]
pub async fn find_bill_in_dht(state: &State<ServiceContext>, bill_id: String) {
    let mut client = state.dht_client();
    let bill_bytes = client.get_bill(bill_id.to_string().clone()).await;
    if !bill_bytes.is_empty() {
        let path = get_path_for_bill(&bill_id);
        fs::write(path, bill_bytes.clone()).expect("Can't write file.");
    }
}

#[get("/return/<id>")]
pub async fn return_bill(
    state: &State<ServiceContext>,
    id: String,
) -> Result<Json<BitcreditBillToReturn>> {
    let identity = state.identity_service.get_full_identity().await?;
    let bill: BitcreditBill = read_bill_from_file(&id).await;
    let chain = Chain::read_chain_from_file(&bill.name);
    let drawer = chain.get_drawer();
    let mut link_for_buy = "".to_string();
    let chain_to_return = ChainToReturn::new(chain.clone());
    let endorsed = chain.exist_block_with_operation_code(OperationCode::Endorse);
    let accepted = chain.exist_block_with_operation_code(OperationCode::Accept);
    let mut address_for_selling: String = String::new();
    let mut amount_for_selling = 0;
    let waiting_for_payment = chain.waiting_for_payment().await;
    let mut payment_deadline_has_passed = false;
    let mut waited_for_payment = waiting_for_payment.0;
    if waited_for_payment {
        payment_deadline_has_passed = chain.check_if_payment_deadline_has_passed().await;
    }
    if payment_deadline_has_passed {
        waited_for_payment = false;
    }
    let mut buyer = waiting_for_payment.1;
    let mut seller = waiting_for_payment.2;
    if waited_for_payment
        && (identity.peer_id.to_string().eq(&buyer.peer_id)
            || identity.peer_id.to_string().eq(&seller.peer_id))
    {
        address_for_selling = waiting_for_payment.3;
        amount_for_selling = waiting_for_payment.4;
        let message: String = format!("Payment in relation to a bill {}", bill.name.clone());
        link_for_buy = external::bitcoin::generate_link_to_pay(
            address_for_selling.clone(),
            amount_for_selling,
            message,
        )
        .await;
    } else {
        buyer = IdentityPublicData::new_empty();
        seller = IdentityPublicData::new_empty();
    }
    let requested_to_pay = chain.exist_block_with_operation_code(OperationCode::RequestToPay);
    let requested_to_accept = chain.exist_block_with_operation_code(OperationCode::RequestToAccept);
    let address_to_pay = external::bitcoin::get_address_to_pay(bill.clone());
    //TODO: add last_sell_block_paid
    // let check_if_already_paid =
    //     external::bitcoin::check_if_paid(address_to_pay.clone(), bill.amount_numbers).await;
    let mut check_if_already_paid = (false, 0u64);
    if requested_to_pay {
        check_if_already_paid =
            external::bitcoin::check_if_paid(address_to_pay.clone(), bill.amount_numbers).await;
    }
    let paid = check_if_already_paid.0;
    let mut number_of_confirmations: u64 = 0;
    let mut pending = false;
    if paid && check_if_already_paid.1.eq(&0) {
        pending = true;
    } else if paid && !check_if_already_paid.1.eq(&0) {
        let transaction = external::bitcoin::get_transactions(address_to_pay.clone()).await;
        let txid = external::bitcoin::Txid::get_first_transaction(transaction.clone()).await;
        let height = external::bitcoin::get_last_block_height().await;
        number_of_confirmations = height - txid.status.block_height + 1;
    }
    let address_to_pay = external::bitcoin::get_address_to_pay(bill.clone());
    let message: String = format!("Payment in relation to a bill {}", bill.name.clone());
    let link_to_pay = external::bitcoin::generate_link_to_pay(
        address_to_pay.clone(),
        bill.amount_numbers,
        message,
    )
    .await;
    let mut pr_key_bill = String::new();
    if (!endorsed
        && bill
            .payee
            .bitcoin_public_key
            .clone()
            .eq(&identity.identity.bitcoin_public_key))
        || (endorsed
            && bill
                .endorsee
                .bitcoin_public_key
                .eq(&identity.identity.bitcoin_public_key))
    {
        pr_key_bill = get_current_payee_private_key(identity.identity.clone(), bill.clone());
    }

    let full_bill = BitcreditBillToReturn {
        name: bill.name,
        to_payee: bill.to_payee,
        bill_jurisdiction: bill.bill_jurisdiction,
        timestamp_at_drawing: bill.timestamp_at_drawing,
        drawee: bill.drawee,
        drawer,
        payee: bill.payee,
        endorsee: bill.endorsee,
        place_of_drawing: bill.place_of_drawing,
        currency_code: bill.currency_code,
        amount_numbers: bill.amount_numbers,
        amounts_letters: bill.amounts_letters,
        maturity_date: bill.maturity_date,
        date_of_issue: bill.date_of_issue,
        compounding_interest_rate: bill.compounding_interest_rate,
        type_of_interest_calculation: bill.type_of_interest_calculation,
        place_of_payment: bill.place_of_payment,
        public_key: bill.public_key,
        private_key: bill.private_key,
        language: bill.language,
        accepted,
        endorsed,
        requested_to_pay,
        requested_to_accept,
        waited_for_payment,
        address_for_selling,
        amount_for_selling,
        buyer,
        seller,
        paid,
        link_for_buy,
        link_to_pay,
        address_to_pay,
        pr_key_bill,
        number_of_confirmations,
        pending,
        chain_of_blocks: chain_to_return,
    };
    Ok(Json(full_bill))
}

#[get("/dht")]
pub async fn search_bill(state: &State<ServiceContext>) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }
    let mut client = state.dht_client();
    let local_peer_id = state.identity_service.get_peer_id().await?;
    client.check_new_bills(local_peer_id.to_string()).await;

    Ok(Status::Ok)
}

#[post("/issue", data = "<bill_form>")]
pub async fn issue_bill(
    state: &State<ServiceContext>,
    bill_form: Form<BitcreditBillForm<'_>>,
) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }

    let files = &bill_form.files;
    let upload_file_handlers: Vec<&dyn UploadFileHandler> = files
        .iter()
        .map(|file| file as &dyn UploadFileHandler)
        .collect();
    // Validate Files
    for file in &upload_file_handlers {
        state.bill_service.validate_attached_file(*file).await?;
    }

    let drawer = state.identity_service.get_full_identity().await?;

    let (public_data_drawee, public_data_payee) =
        match (bill_form.drawer_is_payee, bill_form.drawer_is_drawee) {
            // Drawer is drawee and payee
            (true, true) => {
                return Err(service::Error::Validation(String::from(
                    "Drawer can't be Drawee and Payee at the same time",
                )));
            }
            // Drawer is payee
            (true, false) => {
                let public_data_drawee = state
                    .contact_service
                    .get_identity_by_name(&bill_form.drawee_name)
                    .await
                    .map_err(|_| {
                        service::Error::Validation(String::from("Can not get drawee identity."))
                    })?;

                let public_data_payee =
                    IdentityPublicData::new(drawer.identity.clone(), drawer.peer_id.to_string());

                (public_data_drawee, public_data_payee)
            }
            // Drawer is drawee
            (false, true) => {
                let public_data_drawee =
                    IdentityPublicData::new(drawer.identity.clone(), drawer.peer_id.to_string());

                let public_data_payee = state
                    .contact_service
                    .get_identity_by_name(&bill_form.payee_name)
                    .await
                    .map_err(|_| {
                        service::Error::Validation(String::from("Can not get payee identity."))
                    })?;

                (public_data_drawee, public_data_payee)
            }
            // Drawer is neither drawee nor payee
            (false, false) => {
                let public_data_drawee = state
                    .contact_service
                    .get_identity_by_name(&bill_form.drawee_name)
                    .await
                    .map_err(|_| {
                        service::Error::Validation(String::from("Can not get drawee identity."))
                    })?;

                let public_data_payee = state
                    .contact_service
                    .get_identity_by_name(&bill_form.payee_name)
                    .await
                    .map_err(|_| {
                        service::Error::Validation(String::from("Can not get payee identity."))
                    })?;
                (public_data_drawee, public_data_payee)
            }
        };

    if public_data_drawee.name.is_empty() {
        return Err(service::Error::Validation(String::from(
            "Drawee not found.",
        )));
    }

    if public_data_payee.name.is_empty() {
        return Err(service::Error::Validation(String::from("Payee not found.")));
    }

    if public_data_drawee.name == public_data_payee.name {
        return Err(service::Error::Validation(String::from(
            "Drawee and payee can't be the same.",
        )));
    }

    let bill = state
        .bill_service
        .issue_new_bill(
            bill_form.bill_jurisdiction.to_owned(),
            bill_form.place_of_drawing.to_owned(),
            bill_form.amount_numbers.to_owned(),
            bill_form.place_of_payment.to_owned(),
            bill_form.maturity_date.to_owned(),
            bill_form.currency_code.to_owned(),
            drawer,
            bill_form.language.to_owned(),
            public_data_drawee,
            public_data_payee,
            upload_file_handlers,
        )
        .await?;

    state
        .bill_service
        .propagate_bill(
            &bill.name,
            &bill.drawer.peer_id,
            &bill.drawee.peer_id,
            &bill.payee.peer_id,
        )
        .await?;

    // If we're the drawee, we immediately accept the bill
    if bill.drawer == bill.drawee {
        state.bill_service.accept_bill(&bill.name).await?;
    }

    Ok(Status::Ok)
}

#[put("/sell", data = "<sell_bill_form>")]
pub async fn sell_bill(
    state: &State<ServiceContext>,
    sell_bill_form: Form<SellBitcreditBillForm>,
) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }

    let public_data_buyer = state
        .contact_service
        .get_identity_by_name(&sell_bill_form.buyer)
        .await
        .expect("Can not get buyer identity.");

    if public_data_buyer.name.is_empty() {
        return Err(service::Error::PreconditionFailed);
    }
    let timestamp = external::time::TimeApi::get_atomic_time().await?.timestamp;

    let chain = state
        .bill_service
        .sell_bitcredit_bill(
            &sell_bill_form.bill_name,
            public_data_buyer.clone(),
            timestamp,
            sell_bill_form.amount_numbers,
        )
        .await?;

    let block = chain.get_latest_block();

    let block_bytes = serde_json::to_vec(block).expect("Error serializing block");
    let event = GossipsubEvent::new(GossipsubEventId::Block, block_bytes);
    let message = event.to_byte_array();

    let mut client = state.dht_client();
    client
        .add_message_to_topic(message, sell_bill_form.bill_name.clone())
        .await;

    client
        .add_bill_to_dht_for_node(
            &sell_bill_form.bill_name,
            &public_data_buyer.peer_id.to_string().clone(),
        )
        .await;
    Ok(Status::Ok)
}

#[put("/endorse", data = "<endorse_bill_form>")]
pub async fn endorse_bill(
    state: &State<ServiceContext>,
    endorse_bill_form: Form<EndorseBitcreditBillForm>,
) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }
    let mut client = state.dht_client();

    let public_data_endorsee = state
        .contact_service
        .get_identity_by_name(&endorse_bill_form.endorsee)
        .await
        .expect("Can not get endorsee identity.");

    if public_data_endorsee.name.is_empty() {
        return Err(service::Error::PreconditionFailed);
    }
    let timestamp = external::time::TimeApi::get_atomic_time().await?.timestamp;

    let chain = state
        .bill_service
        .endorse_bitcredit_bill(
            &endorse_bill_form.bill_name,
            public_data_endorsee.clone(),
            timestamp,
        )
        .await?;

    let block = chain.get_latest_block();

    let block_bytes = serde_json::to_vec(block).expect("Error serializing block");
    let event = GossipsubEvent::new(GossipsubEventId::Block, block_bytes);
    let message = event.to_byte_array();

    client
        .add_message_to_topic(message, endorse_bill_form.bill_name.clone())
        .await;

    client
        .add_bill_to_dht_for_node(
            &endorse_bill_form.bill_name,
            &public_data_endorsee.peer_id.to_string().clone(),
        )
        .await;
    Ok(Status::Ok)
}

#[put("/request_to_pay", data = "<request_to_pay_bill_form>")]
pub async fn request_to_pay_bill(
    state: &State<ServiceContext>,
    request_to_pay_bill_form: Form<RequestToPayBitcreditBillForm>,
) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }
    let mut client = state.dht_client();

    let timestamp = external::time::TimeApi::get_atomic_time().await?.timestamp;

    let chain = state
        .bill_service
        .request_pay(&request_to_pay_bill_form.bill_name, timestamp)
        .await?;

    let block = chain.get_latest_block();

    let block_bytes = serde_json::to_vec(block).expect("Error serializing block");
    let event = GossipsubEvent::new(GossipsubEventId::Block, block_bytes);
    let message = event.to_byte_array();

    client
        .add_message_to_topic(message, request_to_pay_bill_form.bill_name.clone())
        .await;
    Ok(Status::Ok)
}

#[put("/request_to_accept", data = "<request_to_accept_bill_form>")]
pub async fn request_to_accept_bill(
    state: &State<ServiceContext>,
    request_to_accept_bill_form: Form<RequestToAcceptBitcreditBillForm>,
) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }
    let mut client = state.dht_client();

    let timestamp = external::time::TimeApi::get_atomic_time().await?.timestamp;

    let chain = state
        .bill_service
        .request_acceptance(&request_to_accept_bill_form.bill_name, timestamp)
        .await?;

    let block = chain.get_latest_block();

    let block_bytes = serde_json::to_vec(block).expect("Error serializing block");
    let event = GossipsubEvent::new(GossipsubEventId::Block, block_bytes);
    let message = event.to_byte_array();

    client
        .add_message_to_topic(message, request_to_accept_bill_form.bill_name.clone())
        .await;
    Ok(Status::Ok)
}

#[put("/accept", data = "<accept_bill_form>")]
pub async fn accept_bill_form(
    state: &State<ServiceContext>,
    accept_bill_form: Form<AcceptBitcreditBillForm>,
) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }
    state
        .bill_service
        .accept_bill(&accept_bill_form.bill_name)
        .await?;
    Ok(Status::Ok)
}

// Mint

//PUT
// #[post("/try_mint", data = "<mint_bill_form>")]
// pub async fn try_mint_bill(
//     state: &State<ServiceContext>,
//     mint_bill_form: Form<MintBitcreditBillForm>,
// ) -> Status {
//     if !state.identity_service.identity_exists().await {
//         Err(service::Error::PreconditionFailed)
//     } else {
//         let mut client = state.inner().clone();
//
//         let public_mint_node =
//             get_identity_public_data(mint_bill_form.mint_node.clone(), client.clone()).await;
//
//         if !public_mint_node.name.is_empty() {
//             client
//                 .add_bill_to_dht_for_node(
//                     &mint_bill_form.bill_name,
//                     &public_mint_node.peer_id.to_string().clone(),
//                 )
//                 .await;
//
//             Status::Ok
//         } else {
//             Status::NotAcceptable
//         }
//     }
// }

//PUT
//TODO: add try_mint_bill here?
#[put("/request_to_mint", data = "<request_to_mint_bill_form>")]
pub async fn request_to_mint_bill(
    state: &State<ServiceContext>,
    request_to_mint_bill_form: Form<RequestToMintBitcreditBillForm>,
) -> Status {
    let mut client = state.dht_client();
    let public_mint_node = state
        .contact_service
        .get_identity_by_name(&request_to_mint_bill_form.mint_node)
        .await
        .expect("could not get identity by name");
    if !public_mint_node.name.is_empty() {
        client
            .add_bill_to_dht_for_node(
                &request_to_mint_bill_form.bill_name,
                &public_mint_node.peer_id.to_string().clone(),
            )
            .await;
    }

    // Usage of thread::spawn is necessary here, because we spawn a new tokio runtime in the
    // thread, but this logic will be replaced soon
    thread::spawn(move || request_to_mint_bitcredit(request_to_mint_bill_form.clone()))
        .join()
        .expect("Thread panicked");
    Status::Ok
}

//This is function for mint software
#[put("/accept_mint", data = "<accept_mint_bill_form>")]
pub async fn accept_mint_bill(accept_mint_bill_form: Form<AcceptMintBitcreditBillForm>) -> Status {
    let bill = read_bill_from_file(&accept_mint_bill_form.bill_name.clone()).await;
    let bill_amount = bill.amount_numbers;
    let holder_node_id = bill.payee.peer_id.clone();

    //TODO: calculate percent
    // Usage of thread::spawn is necessary here, because we spawn a new tokio runtime in the
    // thread, but this logic will be replaced soon
    thread::spawn(move || {
        accept_mint_bitcredit(
            bill_amount,
            accept_mint_bill_form.bill_name.clone(),
            holder_node_id,
        )
    })
    .join()
    .expect("Thread panicked");

    Status::Ok
}

//After accept mint on client side
#[put("/mint", data = "<mint_bill_form>")]
pub async fn mint_bill(
    state: &State<ServiceContext>,
    mint_bill_form: Form<MintBitcreditBillForm>,
) -> Result<Status> {
    if !state.identity_service.identity_exists().await {
        return Err(service::Error::PreconditionFailed);
    }
    let mut client = state.dht_client();

    let timestamp = external::time::TimeApi::get_atomic_time().await?.timestamp;

    let public_mint_node = state
        .contact_service
        .get_identity_by_name(&mint_bill_form.mint_node)
        .await
        .expect("could not get identity by name");

    if public_mint_node.name.is_empty() {
        return Err(service::Error::PreconditionFailed);
    }
    let chain = state
        .bill_service
        .mint_bitcredit_bill(
            &mint_bill_form.bill_name,
            public_mint_node.clone(),
            timestamp,
        )
        .await?;

    let block = chain.get_latest_block();

    let block_bytes = serde_json::to_vec(block)?;
    let event = GossipsubEvent::new(GossipsubEventId::Block, block_bytes);
    let message = event.to_byte_array();

    client
        .add_message_to_topic(message, mint_bill_form.bill_name.clone())
        .await;

    client
        .add_bill_to_dht_for_node(
            &mint_bill_form.bill_name,
            &public_mint_node.peer_id.to_string(),
        )
        .await;

    Ok(Status::Ok)
}
