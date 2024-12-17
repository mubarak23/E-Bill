use super::behaviour::{Command, ComposedEvent, Event, MyBehaviour};
use crate::blockchain::{Block, Chain, GossipsubEvent, GossipsubEventId};
use crate::constants::{
    RELAY_BOOTSTRAP_NODE_ONE_IP, RELAY_BOOTSTRAP_NODE_ONE_NODE_ID, RELAY_BOOTSTRAP_NODE_ONE_TCP,
};
use crate::dht::behaviour::{FileRequest, FileResponse};
use anyhow::Result;
use futures::channel::mpsc::Receiver;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::core::Multiaddr;
use libp2p::kad::record::{Key, Record};
use libp2p::kad::{
    self, GetProvidersOk, GetRecordError, GetRecordOk, KademliaEvent, PeerRecord, QueryId,
    QueryResult, Quorum,
};
use libp2p::multiaddr::Protocol;
use libp2p::multihash::Multihash;
use libp2p::request_response::{self, RequestId};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{gossipsub, relay, PeerId};
use log::{error, info, warn};
use std::collections::{HashMap, HashSet};
use std::iter;
use tokio::sync::broadcast;

type PendingDial = HashMap<PeerId, oneshot::Sender<Result<()>>>;
type PendingRequestFile = HashMap<RequestId, oneshot::Sender<Result<Vec<u8>>>>;

pub struct EventLoop {
    swarm: Swarm<MyBehaviour>,
    command_receiver: Receiver<Command>,
    event_sender: mpsc::Sender<Event>,
    pending_dial: PendingDial,
    pending_start_providing: HashMap<QueryId, oneshot::Sender<()>>,
    pending_get_providers: HashMap<QueryId, oneshot::Sender<HashSet<PeerId>>>,
    pending_get_records: HashMap<QueryId, oneshot::Sender<Record>>,
    pending_request_file: PendingRequestFile,
}

impl EventLoop {
    pub fn new(
        swarm: Swarm<MyBehaviour>,
        command_receiver: Receiver<Command>,
        event_sender: mpsc::Sender<Event>,
    ) -> Self {
        Self {
            swarm,
            command_receiver,
            event_sender,
            pending_dial: Default::default(),
            pending_start_providing: Default::default(),
            pending_get_providers: Default::default(),
            pending_get_records: Default::default(),
            pending_request_file: Default::default(),
        }
    }

    pub async fn run(mut self, mut shutdown_event_loop_receiver: broadcast::Receiver<bool>) {
        loop {
            tokio::select! {
                event = self.swarm.next() => self.handle_event(event.expect("Swarm stream to be infinite.")).await,
                command = self.command_receiver.next() => if let Some(c) = command { self.handle_command(c).await },
                _ = shutdown_event_loop_receiver.recv() => {
                    info!("Shutting down event loop...");
                    break;
                }
            }
        }
    }

    async fn handle_event<T>(&mut self, event: SwarmEvent<ComposedEvent, T>)
    where
        T: std::fmt::Debug,
    {
        match event {
            //--------------KADEMLIA EVENTS--------------
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(
                KademliaEvent::OutboundQueryProgressed { result, id, .. },
            )) => match result {
                QueryResult::StartProviding(Ok(kad::AddProviderOk { key: _ })) => {
                    info!("Successfully started providing query id: {id:?}");
                    let sender: oneshot::Sender<()> = self
                        .pending_start_providing
                        .remove(&id)
                        .expect("Completed query to be previously pending.");
                    let _ = sender.send(());
                }

                QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord {
                    record, ..
                }))) => {
                    if let Some(sender) = self.pending_get_records.remove(&id) {
                        info!(
                            "Got record {:?} {:?}",
                            std::str::from_utf8(record.key.as_ref()).unwrap(),
                            std::str::from_utf8(&record.value).unwrap(),
                        );

                        sender.send(record).expect("Receiver not to be dropped.");

                        // Finish the query. We are only interested in the first result.
                        //TODO: think how to do it better.
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .query_mut(&id)
                            .unwrap()
                            .finish();
                    }
                }

                QueryResult::GetRecord(Ok(GetRecordOk::FinishedWithNoAdditionalRecord {
                    ..
                })) => {
                    self.pending_get_records.remove(&id);
                    info!("No records.");
                }

                QueryResult::GetRecord(Err(GetRecordError::NotFound { key, .. })) => {
                    //TODO: its bad.
                    let record = Record {
                        key,
                        value: vec![],
                        publisher: None,
                        expires: None,
                    };
                    let _ = self
                        .pending_get_records
                        .remove(&id)
                        .expect("Request to still be pending.")
                        .send(record);
                }

                QueryResult::GetRecord(Err(GetRecordError::Timeout { key })) => {
                    //TODO: its bad.
                    let record = Record {
                        key,
                        value: vec![],
                        publisher: None,
                        expires: None,
                    };
                    let _ = self
                        .pending_get_records
                        .remove(&id)
                        .expect("Request to still be pending.")
                        .send(record);
                }

                QueryResult::GetRecord(Err(GetRecordError::QuorumFailed { key, .. })) => {
                    //TODO: its bad.
                    let record = Record {
                        key,
                        value: vec![],
                        publisher: None,
                        expires: None,
                    };
                    let _ = self
                        .pending_get_records
                        .remove(&id)
                        .expect("Request to still be pending.")
                        .send(record);
                }

                QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
                    providers, ..
                })) => {
                    if let Some(sender) = self.pending_get_providers.remove(&id) {
                        for peer in &providers {
                            info!("Get Providers: PEER {peer:?}");
                        }

                        sender.send(providers).expect("Receiver not to be dropped.");

                        // Finish the query. We are only interested in the first result.
                        //TODO: think how to do it better.
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .query_mut(&id)
                            .unwrap()
                            .finish();
                    }
                }

                _ => {}
            },

            //--------------REQUEST RESPONSE EVENTS--------------
            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let _ = self
                    .pending_request_file
                    .remove(&request_id)
                    .expect("Request to still be pending.")
                    .send(Err(error.into()));
            }

            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                request_response::Event::Message { message, .. },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.event_sender
                        .send(Event::InboundRequest {
                            request: request.0,
                            channel,
                        })
                        .await
                        .expect("Event receiver not to be dropped.");
                }

                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let _ = self
                        .pending_request_file
                        .remove(&request_id)
                        .expect("Request to still be pending.")
                        .send(Ok(response.0));
                }
            },

            SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
                request_response::Event::ResponseSent { .. },
            )) => {
                info!("ResponseSent event: {event:?}")
            }

            //--------------IDENTIFY EVENTS--------------
            SwarmEvent::Behaviour(ComposedEvent::Identify(event)) => {
                info!("Identify event: {:?}", event)
            }

            //--------------DCUTR EVENTS--------------
            SwarmEvent::Behaviour(ComposedEvent::Dcutr(event)) => {
                info!("Dcutr event: {:?}", event)
            }

            //--------------RELAY EVENTS--------------
            SwarmEvent::Behaviour(ComposedEvent::Relay(
                relay::client::Event::ReservationReqAccepted { .. },
            )) => {
                info!("ReservationReqAccepted event: {event:?}");
                info!("Relay accepted our reservation request.");
            }

            SwarmEvent::Behaviour(ComposedEvent::Relay(event)) => {
                info!("{:?}", event)
            }

            //--------------GOSSIPSUB EVENTS--------------
            SwarmEvent::Behaviour(ComposedEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source: node_id,
                message_id: id,
                message,
            })) => {
                let bill_name = message.topic.clone().into_string();
                info!("Got message with id: {id} from peer: {node_id} in topic: {bill_name}",);
                let event = GossipsubEvent::from_byte_array(&message.data);

                if event.id.eq(&GossipsubEventId::Block) {
                    let block: Block =
                        serde_json::from_slice(&event.message).expect("Block are not valid.");
                    let mut chain: Chain = Chain::read_chain_from_file(&bill_name);
                    chain.try_add_block(block);
                    if chain.is_chain_valid() {
                        chain.write_chain_to_file(&bill_name);
                    }
                } else if event.id.eq(&GossipsubEventId::Chain) {
                    let receive_chain: Chain =
                        serde_json::from_slice(&event.message).expect("Chain are not valid.");
                    let mut local_chain = Chain::read_chain_from_file(&bill_name);
                    local_chain.compare_chain(receive_chain, &bill_name);
                } else if event.id.eq(&GossipsubEventId::CommandGetChain) {
                    let chain = Chain::read_chain_from_file(&bill_name);
                    let chain_bytes = serde_json::to_vec(&chain).expect("Can not serialize chain.");
                    let event = GossipsubEvent::new(GossipsubEventId::Chain, chain_bytes);
                    let message = event.to_byte_array();
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(gossipsub::IdentTopic::new(bill_name.clone()), message)
                        .expect("Can not publish message.");
                } else {
                    warn!("Unknown event id: {id} from peer: {node_id} in topic: {bill_name}");
                }
            }
            //--------------OTHERS BEHAVIOURS EVENTS--------------
            SwarmEvent::Behaviour(event) => {
                info!("Behaviour event: {event:?}")
            }

            //--------------COMMON EVENTS--------------
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {:?}", address);
            }

            SwarmEvent::IncomingConnection { .. } => {
                info!("IncomingConnection event: {event:?}")
            }

            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_dial.remove(&peer_id) {
                        let _ = sender.send(Ok(()));
                    }
                }
            }

            SwarmEvent::ConnectionClosed { .. } => {
                info!("ConnectionClosed event: {event:?}")
            }

            SwarmEvent::OutgoingConnectionError { .. } => {
                error!("OutgoingConnectionError event {event:?}");
                // if let Some(node_id) = node_id {
                //     if let Some(sender) = self.pending_dial.remove(&node_id) {
                //         let _ = sender.send(Err(Box::new(error)));
                //     }
                // }
            }

            SwarmEvent::IncomingConnectionError { .. } => {
                error!("IncomingConnectionError event: {event:?}")
            }

            _ => {}
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::StartProviding { file_name, sender } => {
                info!("Start providing {file_name:?}");
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .start_providing(file_name.into_bytes().into())
                    .expect("Can not provide.");
                self.pending_start_providing.insert(query_id, sender);
            }

            Command::PutRecord { key, value } => {
                info!("Put record {key:?}");
                let key_record = Key::new(&key);
                let value_bytes = value.as_bytes().to_vec();
                let record = Record {
                    key: key_record,
                    value: value_bytes,
                    publisher: None,
                    expires: None,
                };

                let relay_node_id: PeerId = RELAY_BOOTSTRAP_NODE_ONE_NODE_ID
                    .to_string()
                    .parse()
                    .expect("Can not to parse relay peer id.");

                let _query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    //TODO: what quorum use?
                    .put_record_to(record, iter::once(relay_node_id), Quorum::All);
            }

            Command::SendMessage { msg, topic } => {
                info!("Send message to topic {topic:?}");
                let swarm = self.swarm.behaviour_mut();
                //TODO: check if topic not empty.
                swarm
                    .gossipsub
                    .publish(gossipsub::IdentTopic::new(topic), msg)
                    .expect("Can not publish message.");
            }

            Command::SubscribeToTopic { topic } => {
                info!("Subscribe to topic {topic:?}");
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(topic))
                    .expect("TODO: panic message");
            }

            Command::GetRecord { key, sender } => {
                info!("Get record {key:?}");
                let key_record = Key::new(&key);
                let query_id = self.swarm.behaviour_mut().kademlia.get_record(key_record);
                self.pending_get_records.insert(query_id, sender);
            }

            Command::GetProviders { file_name, sender } => {
                info!("Get providers {file_name:?}");
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(file_name.into_bytes().into());
                self.pending_get_providers.insert(query_id, sender);
            }

            Command::RequestFile {
                file_name,
                peer,
                sender,
            } => {
                info!("Request file {file_name:?}");

                let relay_node_id: PeerId = RELAY_BOOTSTRAP_NODE_ONE_NODE_ID
                    .to_string()
                    .parse()
                    .expect("Can not to parse relay peer id.");
                let relay_address = Multiaddr::empty()
                    .with(Protocol::Ip4(RELAY_BOOTSTRAP_NODE_ONE_IP))
                    .with(Protocol::Tcp(RELAY_BOOTSTRAP_NODE_ONE_TCP))
                    .with(Protocol::P2p(Multihash::from(relay_node_id)))
                    .with(Protocol::P2pCircuit)
                    .with(Protocol::P2p(Multihash::from(peer)));

                let swarm = self.swarm.behaviour_mut();
                swarm.request_response.add_address(&peer, relay_address);
                let request_id = swarm
                    .request_response
                    .send_request(&peer, FileRequest(file_name));
                self.pending_request_file.insert(request_id, sender);
            }

            Command::RespondFile { file, channel } => {
                info!("Respond file");
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, FileResponse(file))
                    .expect("Connection to peer to be still open.");
            }
        }
    }
}
