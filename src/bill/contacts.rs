use super::identity::Identity;
use super::BitcreditBill;
use crate::constants::USEDNET;
use bitcoin::secp256k1::Scalar;
use std::str::FromStr;

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
