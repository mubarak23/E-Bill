use super::block::Block;
use super::calculate_hash;
use super::OperationCode;
use super::Result;
use crate::bill::get_path_for_bill;
use crate::blockchain::OperationCode::{
    Accept, Endorse, Issue, Mint, RequestToAccept, RequestToPay, Sell,
};
use crate::external;
use crate::service::bill_service::BillKeys;
use crate::service::bill_service::BitcreditBill;
use crate::service::contact_service::IdentityPublicData;
use crate::USERNETWORK;
use crate::{
    bill::{bill_from_byte_array, read_keys_from_bill_file},
    util::rsa::decrypt_bytes,
};
use borsh_derive::BorshDeserialize;
use borsh_derive::BorshSerialize;
use log::error;
use log::warn;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Chain {
    pub blocks: Vec<Block>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone)]
pub struct BlockForHistory {
    id: u64,
    text: String,
    bill_id: String,
}

impl Chain {
    #[cfg_attr(test, allow(dead_code))]
    pub fn new(first_block: Block) -> Self {
        let blocks = vec![first_block];

        Self { blocks }
    }

    /// Reads a blockchain from a file and deserializes it into a `Chain` object.
    /// # Returns
    /// Returns an instance of `Self` (typically a `Chain`) that is deserialized from the blockchain file.
    pub fn read_chain_from_file(bill_id: &str) -> Self {
        let input_path = get_path_for_bill(bill_id);

        let blockchain_from_file = std::fs::read(input_path).expect("file not found");
        serde_json::from_slice(blockchain_from_file.as_slice()).unwrap()
    }

    pub fn write_chain_to_file(&self, bill_id: &str) {
        let output_path = get_path_for_bill(bill_id);

        std::fs::write(output_path, serde_json::to_string_pretty(&self).unwrap()).unwrap();
    }

    pub fn to_pretty_printed_json(&self) -> Result<String> {
        let res = serde_json::to_string_pretty(&self)?;
        Ok(res)
    }

    /// Validates the integrity of the blockchain by checking the validity of each block in the chain.
    ///
    /// # Returns
    /// * `true` - If all blocks in the chain are valid.
    /// * `false` - If any block in the chain is found to be invalid.
    ///
    pub fn is_chain_valid(&self) -> bool {
        for i in 0..self.blocks.len() {
            if i == 0 {
                continue;
            }
            let first: &Block = &self.blocks[i - 1];
            let second: &Block = &self.blocks[i];
            if !is_block_valid(second, first) {
                return false;
            }
        }
        true
    }

    /// This function checks whether the provided `block` is valid by comparing it with the latest block
    /// in the current list of blocks. If the block is valid, it is added to the list and the function returns `true`.
    /// If the block is not valid, it logs an error and returns `false`.
    ///
    /// # Arguments
    /// * `block` - The `Block` to be added to the list.
    ///
    /// # Returns
    /// * `true` if the block is successfully added to the list.
    /// * `false` if the block is invalid and cannot be added.
    ///
    pub fn try_add_block(&mut self, block: Block) -> bool {
        let latest_block = self.blocks.last().expect("there is at least one block");
        if is_block_valid(&block, latest_block) {
            self.blocks.push(block);
            true
        } else {
            error!("could not add block - invalid");
            false
        }
    }
    /// Retrieves the latest (most recent) block in the blocks list.
    /// # Returns
    /// * A reference to the latest block in the blocks list.
    ///
    pub fn get_latest_block(&self) -> &Block {
        self.blocks.last().expect("there is at least one block")
    }

    /// Retrieves the first block in the blocks list.
    /// # Returns
    /// * A reference to the first block in the blocks list.
    pub fn get_first_block(&self) -> &Block {
        self.blocks.first().expect("there is at least one block")
    }

    /// Retrieves the last block with the specified operation code.
    /// # Arguments
    /// * `operation_code` - The `OperationCode` to search for in the blocks.
    ///
    /// # Returns
    /// * A reference to the last block with the specified operation code, or the first block if none is found.
    ///
    pub fn get_last_version_block_with_operation_code(
        &self,
        operation_code: OperationCode,
    ) -> &Block {
        let mut last_version_block: &Block = self.get_first_block();
        for block in &self.blocks {
            if block.operation_code == operation_code {
                last_version_block = block;
            }
        }
        last_version_block
    }

    /// Checks if there is any block with a given operation code in the current blocks list.
    ///
    /// # Arguments
    /// * `operation_code` - The `OperationCode` to search for within the blocks.
    ///
    /// # Returns
    /// * `true` if a block with the specified operation code exists in the blocks list, otherwise `false`.
    ///
    pub fn exist_block_with_operation_code(&self, operation_code: OperationCode) -> bool {
        for block in &self.blocks {
            if block.operation_code == operation_code {
                return true;
            }
        }
        false
    }

    pub fn has_been_endorsed_sold_or_minted(&self) -> bool {
        for block in &self.blocks {
            if block.operation_code == OperationCode::Mint {
                return true;
            }
            if block.operation_code == OperationCode::Sell {
                return true;
            }
            if block.operation_code == OperationCode::Endorse {
                return true;
            }
        }
        false
    }

    pub fn has_been_endorsed_or_sold(&self) -> bool {
        for block in &self.blocks {
            if block.operation_code == OperationCode::Sell {
                return true;
            }
            if block.operation_code == OperationCode::Endorse {
                return true;
            }
        }
        false
    }

    /// Retrieves the last version of the Bitcredit bill by decrypting and processing the relevant blocks.
    ///
    /// # Arguments
    /// * `bill_keys` - The keys for the bill.
    ///
    /// # Returns
    /// A `BitcreditBill` object containing the most recent version of the bill, including the payee, endorsee,
    /// and other associated information.
    ///
    pub async fn get_last_version_bill(&self, bill_keys: &BillKeys) -> BitcreditBill {
        let first_block = self.get_first_block();

        let key: Rsa<Private> =
            Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
        let bytes = hex::decode(first_block.data.clone()).unwrap();
        let decrypted_bytes = decrypt_bytes(&bytes, &key);
        let bill_first_version: BitcreditBill = bill_from_byte_array(&decrypted_bytes);

        let mut last_endorsee = IdentityPublicData {
            node_id: "".to_string(),
            name: "".to_string(),
            company: "".to_string(),
            bitcoin_public_key: "".to_string(),
            postal_address: "".to_string(),
            email: "".to_string(),
            rsa_public_key_pem: "".to_string(),
            nostr_npub: None,
            nostr_relay: None,
        };

        if self.blocks.len() > 1
            && (self.exist_block_with_operation_code(Endorse.clone())
                || self.exist_block_with_operation_code(Sell.clone())
                || self.exist_block_with_operation_code(Mint.clone()))
        {
            let last_version_block_endorse =
                self.get_last_version_block_with_operation_code(Endorse);
            let last_version_block_mint = self.get_last_version_block_with_operation_code(Mint);
            let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);
            let last_block = self.get_latest_block();

            let paid = Self::check_if_last_sell_block_is_paid(self).await;

            if (last_version_block_endorse.id < last_version_block_sell.id)
                && (last_version_block_mint.id < last_version_block_sell.id)
                && ((last_block.id > last_version_block_sell.id) || paid)
            {
                let bytes = hex::decode(last_version_block_sell.data.clone()).unwrap();
                let decrypted_bytes = decrypt_bytes(&bytes, &key);
                let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                let part_without_sold_to = block_data_decrypted
                    .split("Sold to ")
                    .collect::<Vec<&str>>()
                    .get(1)
                    .unwrap()
                    .to_string();

                let part_with_buyer = part_without_sold_to
                    .split(" sold by ")
                    .collect::<Vec<&str>>()
                    .first()
                    .unwrap()
                    .to_string();

                let buyer_bill_u8 = hex::decode(part_with_buyer).unwrap();
                let buyer_bill: IdentityPublicData =
                    serde_json::from_slice(&buyer_bill_u8).unwrap();

                last_endorsee = buyer_bill.clone();
            } else if self.exist_block_with_operation_code(Endorse.clone())
                && (last_version_block_endorse.id > last_version_block_mint.id)
            {
                let bytes = hex::decode(last_version_block_endorse.data.clone()).unwrap();
                let decrypted_bytes = decrypt_bytes(&bytes, &key);
                let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                let mut part_with_endorsee = block_data_decrypted
                    .split("Endorsed to ")
                    .collect::<Vec<&str>>()
                    .get(1)
                    .unwrap()
                    .to_string();

                part_with_endorsee = part_with_endorsee
                    .split(" endorsed by ")
                    .collect::<Vec<&str>>()
                    .first()
                    .unwrap()
                    .to_string();

                let endorsee = hex::decode(part_with_endorsee).unwrap();
                last_endorsee = serde_json::from_slice(&endorsee).unwrap();
            } else if self.exist_block_with_operation_code(Mint.clone())
                && (last_version_block_mint.id > last_version_block_endorse.id)
            {
                let bytes = hex::decode(last_version_block_mint.data.clone()).unwrap();
                let decrypted_bytes = decrypt_bytes(&bytes, &key);
                let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                let mut part_with_mint = block_data_decrypted
                    .split("Endorsed to ")
                    .collect::<Vec<&str>>()
                    .get(1)
                    .unwrap()
                    .to_string();

                part_with_mint = part_with_mint
                    .split(" endorsed by ")
                    .collect::<Vec<&str>>()
                    .first()
                    .unwrap()
                    .to_string();

                let mint = hex::decode(part_with_mint).unwrap();
                last_endorsee = serde_json::from_slice(&mint).unwrap();
            }
        }

        let mut payee = bill_first_version.payee.clone();

        if !last_endorsee.node_id.is_empty() {
            payee = last_endorsee.clone();
        }

        BitcreditBill {
            name: bill_first_version.name,
            to_payee: bill_first_version.to_payee,
            bill_jurisdiction: bill_first_version.bill_jurisdiction,
            timestamp_at_drawing: bill_first_version.timestamp_at_drawing,
            drawee: bill_first_version.drawee,
            drawer: bill_first_version.drawer,
            payee: payee.clone(),
            endorsee: last_endorsee.clone(),
            place_of_drawing: bill_first_version.place_of_drawing,
            currency_code: bill_first_version.currency_code,
            amount_numbers: bill_first_version.amount_numbers,
            amounts_letters: bill_first_version.amounts_letters,
            maturity_date: bill_first_version.maturity_date,
            date_of_issue: bill_first_version.date_of_issue,
            compounding_interest_rate: bill_first_version.compounding_interest_rate,
            type_of_interest_calculation: bill_first_version.type_of_interest_calculation,
            place_of_payment: bill_first_version.place_of_payment,
            public_key: bill_first_version.public_key,
            private_key: bill_first_version.private_key,
            language: bill_first_version.language,
            files: bill_first_version.files,
        }
    }

    /// Checks if the payment for the latest sell block has been made, and returns relevant information about the buyer, seller, and the payment status.
    ///
    /// # Returns
    /// A tuple with the following information:
    /// - A boolean (`true` if payment is pending, `false` if already paid).
    /// - The identity data of the buyer (`IdentityPublicData`).
    /// - The identity data of the seller (`IdentityPublicData`).
    /// - A string representing the address to which the payment should be made.
    /// - The amount for the transaction (`u64`).
    ///
    pub async fn waiting_for_payment(
        &self,
    ) -> (bool, IdentityPublicData, IdentityPublicData, String, u64) {
        let last_block = self.get_latest_block();
        let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);
        let identity_buyer = IdentityPublicData::new_empty();
        let identity_seller = IdentityPublicData::new_empty();

        if self.exist_block_with_operation_code(Sell.clone())
            && last_block.id == last_version_block_sell.id
        {
            let bill_keys = read_keys_from_bill_file(&last_version_block_sell.bill_id);
            let key: Rsa<Private> =
                Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
            let bytes = hex::decode(last_version_block_sell.data.clone()).unwrap();
            let decrypted_bytes = decrypt_bytes(&bytes, &key);
            let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

            let part_without_sold_to = block_data_decrypted
                .split("Sold to ")
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string();

            let part_with_buyer = part_without_sold_to
                .split(" sold by ")
                .collect::<Vec<&str>>()
                .first()
                .unwrap()
                .to_string();

            let part_with_seller_and_amount = part_without_sold_to
                .clone()
                .split(" sold by ")
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string();

            let amount: u64 = part_with_seller_and_amount
                .clone()
                .split(" amount: ")
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string()
                .parse()
                .unwrap();

            let part_with_seller = part_with_seller_and_amount
                .clone()
                .split(" amount: ")
                .collect::<Vec<&str>>()
                .first()
                .unwrap()
                .to_string();

            let buyer_bill_u8 = hex::decode(part_with_buyer).unwrap();
            let buyer_bill: IdentityPublicData = serde_json::from_slice(&buyer_bill_u8).unwrap();
            let identity_buyer = buyer_bill;

            let seller_bill_u8 = hex::decode(part_with_seller).unwrap();
            let seller_bill: IdentityPublicData = serde_json::from_slice(&seller_bill_u8).unwrap();
            let identity_seller = seller_bill;

            let bill = self.get_first_version_bill();

            let address_to_pay =
                Self::get_address_to_pay_for_block_sell(last_version_block_sell.clone(), bill);

            let address_to_pay_for_async = address_to_pay.clone();

            let (paid, _amount) =
                external::bitcoin::check_if_paid(address_to_pay_for_async, amount).await;

            (
                !paid,
                identity_buyer,
                identity_seller,
                address_to_pay,
                amount,
            )
        } else {
            (false, identity_buyer, identity_seller, String::new(), 0)
        }
    }

    /// This asynchronous function checks if the payment deadline associated with the most recent sell block
    /// has passed.
    /// # Returns
    ///
    /// - `true` if the payment deadline for the last sell block has passed.
    /// - `false` if no sell block exists or the deadline has not passed.
    ///
    pub async fn check_if_payment_deadline_has_passed(&self) -> bool {
        if self.exist_block_with_operation_code(Sell) {
            let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);

            let timestamp = last_version_block_sell.timestamp;

            Self::payment_deadline_has_passed(timestamp, 2).await
        } else {
            false
        }
    }

    /// This asynchronous function checks whether the specified payment deadline, represented by a
    /// timestamp, has passed based on the given number of days. It compares the current timestamp with
    /// the provided timestamp and returns `true` if the difference exceeds the specified number of days.
    ///
    /// # Parameters
    /// - `timestamp`: The timestamp of the payment deadline to compare against (in seconds).
    /// - `day`: The number of days defining the deadline period.
    ///
    /// # Returns
    ///
    /// `true` if the payment deadline has passed, otherwise `false`.
    ///
    async fn payment_deadline_has_passed(timestamp: i64, day: i32) -> bool {
        let period: i64 = (86400 * day) as i64;
        let current_timestamp = external::time::TimeApi::get_atomic_time()
            .await
            .unwrap()
            .timestamp;
        let diference = current_timestamp - timestamp;
        diference > period
    }

    /// This asynchronous function verifies whether the last block that involves a "Sell" operation
    /// has been paid. It decrypts the block's data to extract the amount and the recipient's payment address,
    /// then checks the payment status by querying an external Bitcoin service.
    ///
    /// # Returns
    ///
    /// `true` if the payment has been made, otherwise `false`. If no "Sell" block exists, it returns `false`.
    ///
    async fn check_if_last_sell_block_is_paid(&self) -> bool {
        if self.exist_block_with_operation_code(Sell) {
            let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);

            let bill_keys = read_keys_from_bill_file(&last_version_block_sell.bill_id);
            let key: Rsa<Private> =
                Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
            let bytes = hex::decode(last_version_block_sell.data.clone()).unwrap();
            let decrypted_bytes = decrypt_bytes(&bytes, &key);
            let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

            let part_without_sold_to = block_data_decrypted
                .split("Sold to ")
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string();

            let part_with_seller_and_amount = part_without_sold_to
                .clone()
                .split(" sold by ")
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string();

            let amount: u64 = part_with_seller_and_amount
                .clone()
                .split(" amount: ")
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string()
                .parse()
                .unwrap();

            let bill = self.get_first_version_bill();

            let address_to_pay =
                Self::get_address_to_pay_for_block_sell(last_version_block_sell.clone(), bill);

            external::bitcoin::check_if_paid(address_to_pay, amount)
                .await
                .0
        } else {
            false
        }
    }

    /// This function computes the Bitcoin payment address associated with a specific block sell.
    /// It decrypts and processes the data from the last version of the block sell, extracts
    /// relevant seller information, and combines public keys to generate the final payment address.
    ///
    /// # Parameters
    ///
    /// - `last_version_block_sell`: The most recent block sell version, containing encrypted
    ///   transaction data and the associated bill name.
    /// - `bill`: The `BitcreditBill` containing the public key associated with the transaction.
    ///
    /// # Returns
    ///
    /// A `String` representing the Bitcoin payment address (P2PKH format) for the transaction.
    ///

    fn get_address_to_pay_for_block_sell(
        last_version_block_sell: Block,
        bill: BitcreditBill,
    ) -> String {
        let public_key_bill = bitcoin::PublicKey::from_str(&bill.public_key).unwrap();

        let bill_keys = read_keys_from_bill_file(&last_version_block_sell.bill_id);
        let key: Rsa<Private> =
            Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
        let bytes = hex::decode(last_version_block_sell.data.clone()).unwrap();
        let decrypted_bytes = decrypt_bytes(&bytes, &key);
        let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

        let part_without_sold_to = block_data_decrypted
            .split("Sold to ")
            .collect::<Vec<&str>>()
            .get(1)
            .unwrap()
            .to_string();

        let part_with_seller_and_amount = part_without_sold_to
            .clone()
            .split(" sold by ")
            .collect::<Vec<&str>>()
            .get(1)
            .unwrap()
            .to_string();

        let part_with_seller = part_with_seller_and_amount
            .clone()
            .split(" amount: ")
            .collect::<Vec<&str>>()
            .first()
            .unwrap()
            .to_string();

        let seller_bill_u8 = hex::decode(part_with_seller).unwrap();
        let seller_bill: IdentityPublicData = serde_json::from_slice(&seller_bill_u8).unwrap();

        let public_key_seller = seller_bill.bitcoin_public_key;
        let public_key_bill_seller = bitcoin::PublicKey::from_str(&public_key_seller).unwrap();

        let public_key_bill = public_key_bill
            .inner
            .combine(&public_key_bill_seller.inner)
            .unwrap();
        let pub_key_bill = bitcoin::PublicKey::new(public_key_bill);

        bitcoin::Address::p2pkh(pub_key_bill, *USERNETWORK).to_string()
    }

    /// This function extracts the first block's data, decrypts it using the private key
    /// associated with the bill, and then deserializes the decrypted data into a `BitcreditBill`
    /// object. The function assumes that the first block contains the encrypted data for the bill's first version.
    ///
    /// # Arguments
    /// * `bill_keys` - The keys for the bill.
    ///
    /// # Returns
    ///
    /// * `BitcreditBill` - The first version of the bill, decrypted and deserialized from
    ///   the data in the first block.
    pub fn get_first_version_bill_with_keys(&self, bill_keys: &BillKeys) -> BitcreditBill {
        let first_block_data = &self.get_first_block();
        let key: Rsa<Private> =
            Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
        let bytes = hex::decode(first_block_data.data.clone()).unwrap();
        let decrypted_bytes = decrypt_bytes(&bytes, &key);
        let bill_first_version: BitcreditBill = bill_from_byte_array(&decrypted_bytes);
        bill_first_version
    }

    pub fn get_first_version_bill(&self) -> BitcreditBill {
        let first_block_data = &self.get_first_block();
        let bill_keys = read_keys_from_bill_file(&first_block_data.bill_id);
        self.get_first_version_bill_with_keys(&bill_keys)
    }

    /// This function iterates over the list of blocks in the chain and returns the first block
    /// that matches the provided `id`. If no block is found with the given ID, the function
    /// returns a clone of the first block in the chain as a fallback.
    /// # Arguments
    ///
    /// * `id` - A `u64` representing the ID of the block to retrieve.
    ///
    /// # Returns
    ///
    /// * `Block` - The block corresponding to the given `id`, or the first block in the chain
    ///   if no match is found.
    pub fn get_block_by_id(&self, id: u64) -> Block {
        let mut block = self.get_first_block().clone();
        for b in &self.blocks {
            if b.id == id {
                block = b.clone();
            }
        }
        block
    }

    /// This function compares the latest block ID of the local chain (`self`) with that
    /// of the `other_chain`. If the `other_chain` is ahead, it attempts to add missing
    /// blocks from the `other_chain` to the local chain. If the addition of a block
    /// fails or the resulting chain becomes invalid, the synchronization is aborted.
    ///
    /// # Parameters
    /// - `other_chain: Chain`  
    ///   The chain to compare and synchronize with.
    /// - `bill_id: &str`  
    ///   The name of the bill, used to persist the updated chain to a file if synchronization is successful.
    ///
    pub fn compare_chain(&mut self, other_chain: Chain, bill_id: &str) {
        let local_chain_last_id = self.get_latest_block().id;
        let other_chain_last_id = other_chain.get_latest_block().id;
        if local_chain_last_id.eq(&other_chain_last_id) {
        } else if local_chain_last_id > other_chain_last_id {
            return;
        } else {
            let difference_in_id = other_chain_last_id - local_chain_last_id;
            for block_id in 1..difference_in_id + 1 {
                let block = other_chain.get_block_by_id(local_chain_last_id + block_id);
                let try_add_block = self.try_add_block(block);
                if try_add_block && self.is_chain_valid() {
                    self.write_chain_to_file(bill_id);
                } else {
                    return;
                }
            }
        }
    }

    /// This function iterates over all the blocks in the blockchain, extracts the nodes
    /// from each block, and compiles a unique list of non-empty nodes. Duplicate nodes
    /// are ignored.
    ///
    /// # Returns
    /// `Vec<String>`:  
    /// - A vector containing the unique identifiers of nodes associated with the bill.
    ///
    pub fn get_all_nodes_from_bill(&self) -> Vec<String> {
        let mut nodes: Vec<String> = Vec::new();

        for block in &self.blocks {
            let bill = self.get_first_version_bill();
            let nodes_in_block = block.get_nodes_from_block(bill);
            for node in nodes_in_block {
                if !node.is_empty() && !nodes.contains(&node) {
                    nodes.push(node);
                }
            }
        }
        nodes
    }

    /// This function determines the drawer of the bill by evaluating the following conditions:
    /// 1. If the drawer's name is not empty, it directly returns the drawer.
    /// 2. If the bill is directed to the payee (`to_payee` is `true`), it assigns the payee as the drawer.
    /// 3. Otherwise, the drawee is assigned as the drawer.
    ///
    /// # Returns
    /// `IdentityPublicData`:  
    /// - The identity data of the drawer, payee, or drawee depending on the evaluated conditions.
    ///
    pub fn get_drawer(&self, bill_keys: &BillKeys) -> IdentityPublicData {
        let drawer: IdentityPublicData;
        let bill = self.get_first_version_bill_with_keys(bill_keys);
        if !bill.drawer.name.is_empty() {
            drawer = bill.drawer.clone();
        } else if bill.to_payee {
            drawer = bill.payee.clone();
        } else {
            drawer = bill.drawee.clone();
        }
        drawer
    }

    /// This function iterates through all blocks in a bill's blockchain and verifies
    /// whether the node specified by `request_node_id` has participated in any operation
    /// related to the bill. The involvement can be as a drawer, drawee, payee, endorser,
    /// endorsee, minter, requester, accepter, buyer, or seller.
    ///
    /// # Parameters
    /// - `request_node_id`: A string slice representing the unique identifier of the node
    ///   to check for involvement.
    ///
    /// # Returns
    /// `bool`:
    /// - `true` if the specified node is involved in any operation related to the bill.
    /// - `false` otherwise.

    pub fn bill_contains_node(&self, request_node_id: &str) -> bool {
        for block in &self.blocks {
            match block.operation_code {
                Issue => {
                    let bill = self.get_first_version_bill();
                    if bill.drawer.node_id.eq(request_node_id)
                        || bill.drawee.node_id.eq(request_node_id)
                        || bill.payee.node_id.eq(request_node_id)
                    {
                        return true;
                    }
                }
                Endorse => {
                    let block = self.get_block_by_id(block.id);

                    let bill_keys = read_keys_from_bill_file(&block.bill_id);
                    let key: Rsa<Private> =
                        Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
                    let bytes = hex::decode(block.data.clone()).unwrap();
                    let decrypted_bytes = decrypt_bytes(&bytes, &key);
                    let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    let mut part_with_endorsee = block_data_decrypted
                        .split("Endorsed to ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();

                    let part_with_endorsed_by = part_with_endorsee
                        .clone()
                        .split(" endorsed by ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();

                    part_with_endorsee = part_with_endorsee
                        .split(" endorsed by ")
                        .collect::<Vec<&str>>()
                        .first()
                        .unwrap()
                        .to_string();

                    let endorsee_bill_u8 = hex::decode(part_with_endorsee).unwrap();
                    let endorsee_bill: IdentityPublicData =
                        serde_json::from_slice(&endorsee_bill_u8).unwrap();

                    let endorser_bill_u8 = hex::decode(part_with_endorsed_by).unwrap();
                    let endorser_bill: IdentityPublicData =
                        serde_json::from_slice(&endorser_bill_u8).unwrap();

                    if endorsee_bill.node_id.eq(request_node_id)
                        || endorser_bill.node_id.eq(request_node_id)
                    {
                        return true;
                    }
                }
                Mint => {
                    let block = self.get_block_by_id(block.id);

                    let bill_keys = read_keys_from_bill_file(&block.bill_id);
                    let key: Rsa<Private> =
                        Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
                    let bytes = hex::decode(block.data.clone()).unwrap();
                    let decrypted_bytes = decrypt_bytes(&bytes, &key);
                    let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    let mut part_with_mint = block_data_decrypted
                        .split("Endorsed to ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();

                    let part_with_minter = part_with_mint
                        .clone()
                        .split(" endorsed by ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();

                    part_with_mint = part_with_mint
                        .split(" endorsed by ")
                        .collect::<Vec<&str>>()
                        .first()
                        .unwrap()
                        .to_string();

                    let minter_bill_u8 = hex::decode(part_with_minter).unwrap();
                    let minter_bill: IdentityPublicData =
                        serde_json::from_slice(&minter_bill_u8).unwrap();

                    let mint_bill_u8 = hex::decode(part_with_mint).unwrap();
                    let mint_bill: IdentityPublicData =
                        serde_json::from_slice(&mint_bill_u8).unwrap();

                    if minter_bill.node_id.eq(request_node_id)
                        || mint_bill.node_id.eq(request_node_id)
                    {
                        return true;
                    }
                }
                RequestToAccept => {
                    let block = self.get_block_by_id(block.id);

                    let bill_keys = read_keys_from_bill_file(&block.bill_id);
                    let key: Rsa<Private> =
                        Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
                    let bytes = hex::decode(block.data.clone()).unwrap();
                    let decrypted_bytes = decrypt_bytes(&bytes, &key);
                    let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    let part_with_identity = block_data_decrypted
                        .split("Requested to accept by ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();
                    let requester_to_accept_bill_u8 = hex::decode(part_with_identity).unwrap();
                    let requester_to_accept_bill: IdentityPublicData =
                        serde_json::from_slice(&requester_to_accept_bill_u8).unwrap();

                    if requester_to_accept_bill.node_id.eq(request_node_id) {
                        return true;
                    }
                }
                Accept => {
                    let block = self.get_block_by_id(block.id);

                    let bill_keys = read_keys_from_bill_file(&block.bill_id);
                    let key: Rsa<Private> =
                        Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
                    let bytes = hex::decode(block.data.clone()).unwrap();
                    let decrypted_bytes = decrypt_bytes(&bytes, &key);
                    let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    let part_with_identity = block_data_decrypted
                        .split("Accepted by ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();
                    let accepter_bill_u8 = hex::decode(part_with_identity).unwrap();
                    let accepter_bill: IdentityPublicData =
                        serde_json::from_slice(&accepter_bill_u8).unwrap();

                    if accepter_bill.node_id.eq(request_node_id) {
                        return true;
                    }
                }
                RequestToPay => {
                    let block = self.get_block_by_id(block.id);

                    let bill_keys = read_keys_from_bill_file(&block.bill_id);
                    let key: Rsa<Private> =
                        Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
                    let bytes = hex::decode(block.data.clone()).unwrap();
                    let decrypted_bytes = decrypt_bytes(&bytes, &key);
                    let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    let part_with_identity = block_data_decrypted
                        .split("Requested to pay by ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();
                    let requester_to_pay_bill_u8 = hex::decode(part_with_identity).unwrap();
                    let requester_to_pay_bill: IdentityPublicData =
                        serde_json::from_slice(&requester_to_pay_bill_u8).unwrap();

                    if requester_to_pay_bill.node_id.eq(request_node_id) {
                        return true;
                    }
                }
                Sell => {
                    let block = self.get_block_by_id(block.id);

                    let bill_keys = read_keys_from_bill_file(&block.bill_id);
                    let key: Rsa<Private> =
                        Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
                    let bytes = hex::decode(block.data.clone()).unwrap();
                    let decrypted_bytes = decrypt_bytes(&bytes, &key);
                    let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    let part_without_sold_to = block_data_decrypted
                        .split("Sold to ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();

                    let part_with_buyer = part_without_sold_to
                        .split(" sold by ")
                        .collect::<Vec<&str>>()
                        .first()
                        .unwrap()
                        .to_string();

                    let part_with_seller_and_amount = part_without_sold_to
                        .clone()
                        .split(" sold by ")
                        .collect::<Vec<&str>>()
                        .get(1)
                        .unwrap()
                        .to_string();

                    let part_with_seller = part_with_seller_and_amount
                        .clone()
                        .split(" amount: ")
                        .collect::<Vec<&str>>()
                        .first()
                        .unwrap()
                        .to_string();

                    let buyer_bill_u8 = hex::decode(part_with_buyer).unwrap();
                    let buyer_bill: IdentityPublicData =
                        serde_json::from_slice(&buyer_bill_u8).unwrap();

                    let seller_bill_u8 = hex::decode(part_with_seller).unwrap();
                    let seller_bill: IdentityPublicData =
                        serde_json::from_slice(&seller_bill_u8).unwrap();

                    if buyer_bill.node_id.eq(request_node_id)
                        || seller_bill.node_id.eq(request_node_id)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// This function performs a series of checks to ensure the integrity of the current block
/// in relation to the previous block in the blockchain. These checks include verifying
/// the hash chain, sequential IDs, hash validity, and block signature.
///
/// # Parameters
/// - `block`: A reference to the current `Block` that needs validation.
/// - `previous_block`: A reference to the previous `Block` in the chain for comparison.
///
/// # Returns
/// `bool`:
/// - `true` if the block is valid.
/// - `false` if any of the validation checks fail.
///

fn is_block_valid(block: &Block, previous_block: &Block) -> bool {
    if block.previous_hash != previous_block.hash {
        warn!("block with id: {} has wrong previous hash", block.id);
        return false;
    } else if block.id != &previous_block.id + 1 {
        warn!(
            "block with id: {} is not the next block after the latest: {}",
            block.id, previous_block.id
        );
        return false;
    } else if hex::encode(calculate_hash(
        &block.id,
        &block.bill_id,
        &block.previous_hash,
        &block.data,
        &block.timestamp,
        &block.public_key,
        &block.operation_code,
    )) != block.hash
    {
        warn!("block with id: {} has invalid hash", block.id);
        return false;
    } else if !block.verifier() {
        warn!("block with id: {} has invalid signature", block.id);
        return false;
    }
    true
}
