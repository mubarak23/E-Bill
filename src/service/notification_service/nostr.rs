use async_trait::async_trait;
use log::{error, trace, warn};
use nostr_sdk::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

use crate::service::contact_service::ContactServiceApi;

use super::super::contact_service::IdentityPublicData;
use super::handler::NotificationHandlerApi;
use super::{EventEnvelope, NotificationJsonTransportApi, Result};

#[derive(Clone, Debug)]
pub struct NostrConfig {
    nsec: String,
    relays: Vec<String>,
    name: String,
    timeout: Option<Duration>,
}

/// A wrapper around nostr_sdk that implements the NotificationJsonTransportApi.
///
/// # Example:
/// ```
/// let config = NostrConfig {
///     nsec: "nsec1...".to_string(),
///     relays: vec!["wss://relay.example.com".to_string()],
///     name: "My Company".to_string(),
///     timeout: Some(Duration::from_secs(10)),
/// };
/// let transport = NostrClient::new(&config).await.unwrap();
/// transport.send(&recipient, event).await.unwrap();
/// ```
/// We use the latest GiftWrap and PrivateDirectMessage already with this if I
/// understand the nostr-sdk docs and sources correctly.
/// @see https://nips.nostr.com/59 and https://nips.nostr.com/17
#[derive(Clone, Debug)]
pub struct NostrClient {
    pub public_key: PublicKey,
    pub client: Client,
}

impl NostrClient {
    #[allow(dead_code)]
    pub async fn new(config: &NostrConfig) -> Result<Self> {
        let keys = Keys::parse(&config.nsec)?;
        let options = Options::new().connection_timeout(config.timeout);
        let client = Client::builder().signer(keys.clone()).opts(options).build();
        for relay in &config.relays {
            client.add_relay(relay).await?;
        }
        client.connect().await;
        let metadata = Metadata::new()
            .name(&config.name)
            .display_name(&config.name);
        client.set_metadata(&metadata).await?;
        Ok(Self {
            public_key: keys.public_key(),
            client,
        })
    }

    /// Subscribe to some nostr events with a filter
    pub async fn subscribe(&self, subscription: Filter) -> Result<()> {
        self.client.subscribe(vec![subscription], None).await?;
        Ok(())
    }

    /// Unwrap envelope from private direct message
    pub async fn unwrap_envelope(
        &self,
        note: RelayPoolNotification,
    ) -> Option<(EventEnvelope, PublicKey)> {
        let mut result: Option<(EventEnvelope, PublicKey)> = None;
        if let RelayPoolNotification::Event { event, .. } = note {
            if event.kind == Kind::GiftWrap {
                result = match self.client.unwrap_gift_wrap(&event).await {
                    Ok(UnwrappedGift { rumor, sender }) => {
                        extract_event_envelope(rumor).map(|e| (e, sender))
                    }
                    Err(e) => {
                        error!("Unwrapping gift wrap failed: {e}");
                        None
                    }
                }
            }
        }
        result
    }
}

#[async_trait]
impl NotificationJsonTransportApi for NostrClient {
    async fn send(&self, recipient: &IdentityPublicData, event: EventEnvelope) -> Result<()> {
        if let Some(npub) = &recipient.nostr_npub {
            let public_key = PublicKey::from_str(npub)?;
            let message = serde_json::to_string(&event)?;
            if let Some(relay) = &recipient.nostr_relay {
                self.client
                    .send_private_msg_to(vec![relay], public_key, message, None)
                    .await?;
            } else {
                self.client
                    .send_private_msg(public_key, message, None)
                    .await?;
            }
        } else {
            error!(
                "Try to send Nostr message but Nostr npub not found in contact {}",
                recipient.name
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct NostrConsumer {
    client: NostrClient,
    event_handlers: Arc<Vec<Box<dyn NotificationHandlerApi>>>,
    contact_service: Arc<dyn ContactServiceApi>,
}

impl NostrConsumer {
    #[allow(dead_code)]
    pub fn new(
        client: NostrClient,
        contact_service: Arc<dyn ContactServiceApi>,
        event_handlers: Vec<Box<dyn NotificationHandlerApi>>,
    ) -> Self {
        Self {
            client,
            event_handlers: Arc::new(event_handlers),
            contact_service,
        }
    }

    #[allow(dead_code)]
    pub fn start(&self) -> Result<JoinHandle<()>> {
        // move dependencies into thread scope
        let client = self.client.clone();
        let event_handlers = self.event_handlers.clone();
        let contact_service = self.contact_service.clone();

        // run subscription in a tokio task
        let handle = tokio::spawn(async move {
            // TODO: keep track of a timestamp that signifies when we last received a message
            // to ensure that we can pick up where we left off at last shutdown. It might even be
            // necessary to keep track of all already received events and filter processed ones>.

            // only private messages sent to our pubkey
            client
                .subscribe(Filter::new().pubkey(client.public_key).kind(Kind::GiftWrap))
                .await
                .expect("Failed to subscribe to Nostr events");

            client
                .client
                .handle_notifications(|note| async {
                    if let Some((envelope, sender)) = client.unwrap_envelope(note).await {
                        // We only want to handle events from known contacts
                        if contact_service
                            .is_known_npub(sender.to_hex().as_str())
                            .await?
                        {
                            trace!("Received event: {envelope:?} from {sender:?}");
                            handle_event(envelope, &event_handlers).await?;
                        }
                    };
                    Ok(false)
                })
                .await
                .expect("Nostr notification handler failed");
        });
        Ok(handle)
    }
}

fn extract_event_envelope(rumor: UnsignedEvent) -> Option<EventEnvelope> {
    if rumor.kind == Kind::PrivateDirectMessage {
        match serde_json::from_str::<EventEnvelope>(rumor.content.as_str()) {
            Ok(envelope) => Some(envelope),
            Err(e) => {
                error!("Json deserializing event envelope failed: {e}");
                None
            }
        }
    } else {
        None
    }
}

/// Handle extracted event with given handlers.
async fn handle_event(
    event: EventEnvelope,
    handlers: &Arc<Vec<Box<dyn NotificationHandlerApi>>>,
) -> Result<()> {
    let event_type = &event.event_type;
    let mut times = 0;
    for handler in handlers.iter() {
        if handler.handles_event(event_type) {
            match handler.handle_event(event.to_owned()).await {
                Ok(_) => times += 1,
                Err(e) => error!("Nostr event handler failed: {e}"),
            }
        }
    }
    if times < 1 {
        warn!("No handler subscribed for event: {event:?}");
    } else {
        trace!("{event_type:?} event handled successfully {times} times");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::NOSTR_KEY1;
    use super::*;
    use crate::service::notification_service::test_utils::NOSTR_RELAY1;

    #[tokio::test]
    async fn test_create_nostr_client() {
        let config = NostrConfig {
            nsec: NOSTR_KEY1.to_string(),
            relays: vec![NOSTR_RELAY1.to_string()],
            name: "BcrDamus1".to_string(),
            timeout: Some(Duration::from_secs(10)),
        };

        let _ = NostrClient::new(&config)
            .await
            .expect("failed to create nostr client");
    }

    // this test is super expensive so do not run it to often
    // as you will likely get banned from damus relay.
    // I will remove this as soon as I can confirm that we can
    // send and receive. Profile is already populated correctly.
    #[tokio::test]
    async fn test_create_nostr_consumer() {
        // let config1 = NostrConfig {
        //     nsec: NOSTR_KEY1.to_string(),
        //     relays: vec![NOSTR_RELAY1.to_string()],
        //     name: "BcrDamus1".to_string(),
        //     timeout: Some(Duration::from_secs(10)),
        // };
        //
        // let config2 = NostrConfig {
        //     nsec: NOSTR_KEY2.to_string(),
        //     relays: vec![NOSTR_RELAY1.to_string()],
        //     name: "BcrDamus2".to_string(),
        //     timeout: Some(Duration::from_secs(10)),
        // };

        // let contact2 = get_identity_public_data(
        //     "payee",
        //     "payee@example.com",
        //     Some(NOSTR_NPUB2),
        //     Some(NOSTR_RELAY1),
        // );

        // let contact_service = MockContactServiceApi::new();
        // let handler = MockNotificationHandlerApi::new();
        //
        // let client1 = NostrClient::new(&config1)
        //     .await
        //     .expect("failed to create nostr client 1");
        //
        // let mut event = create_test_event(&EventType::BillSigned);
        // event.peer_id = contact2.peer_id.to_owned();
        //
        // client1
        //     .send(
        //         &contact2,
        //         event.try_into().expect("could not convert event"),
        //     )
        //     .await
        //     .expect("failed to send event");

        // let client2 = NostrClient::new(&config2)
        //     .await
        //     .expect("failed to create nostr client 2");
        //
        // let consumer =
        //     NostrConsumer::new(client2, Arc::new(contact_service), vec![Box::new(handler)]);
        // let handle = consumer.start().expect("failed to start nostr consumer");
        // handle.abort();
    }
}
