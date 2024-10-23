use crate::config::Config;
use futures::prelude::*;
use std::error::Error;
use tokio::{io::AsyncBufReadExt, spawn};
use tokio_stream::wrappers::LinesStream;

mod network;

pub use network::Client;

pub async fn dht_main(conf: &Config) -> Result<Client, Box<dyn Error + Send + Sync>> {
    let (network_client, network_events, network_event_loop) = network::new(conf)
        .await
        .expect("Can not to create network module in dht.");

    //Need for testing from console.
    let stdin = LinesStream::new(tokio::io::BufReader::new(tokio::io::stdin()).lines()).fuse();

    spawn(network_event_loop.run());

    let network_client_to_return = network_client.clone();

    spawn(network_client.run(stdin, network_events));

    Ok(network_client_to_return)
}
