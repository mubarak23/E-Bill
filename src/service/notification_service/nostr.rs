use async_trait::async_trait;
use log::{debug, error, info, warn};
use nostr_sdk::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

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
            self.client
                .send_private_msg(public_key, message, None)
                .await?;
        } else {
            error!("Nostr npub not found");
        }
        Ok(())
    }
}

pub struct NostrConsumer {
    client: NostrClient,
    event_handlers: Arc<Vec<Box<dyn NotificationHandlerApi>>>,
}

impl NostrConsumer {
    #[allow(dead_code)]
    pub fn new(client: NostrClient, event_handlers: Vec<Box<dyn NotificationHandlerApi>>) -> Self {
        Self {
            client,
            event_handlers: Arc::new(event_handlers),
        }
    }

    #[allow(dead_code)]
    pub async fn start(&self) -> Result<JoinHandle<()>> {
        let client = self.client.clone();
        let event_handlers = self.event_handlers.clone();
        let handle = tokio::spawn(async move {
            // only new private messages sent to our pubkey
            client
                .subscribe(
                    Filter::new()
                        .pubkey(client.public_key)
                        .kind(Kind::GiftWrap)
                        .limit(0),
                )
                .await
                .expect("Failed to subscribe to Nostr events");

            client
                .client
                .handle_notifications(|note| async {
                    if let Some((envelope, sender)) = client.unwrap_envelope(note).await {
                        // TODO: check if sender is in our contacts otherwise it could be spam or
                        // an attack so we want to ignore it.
                        debug!("Received event: {envelope:?} from {sender:?}");
                        let event_type = &envelope.event_type;
                        let mut times = 0;
                        for handler in event_handlers.iter() {
                            if handler.handles_event(event_type) {
                                match handler.handle_event(envelope.to_owned()).await {
                                    Ok(_) => times += 1,
                                    Err(e) => {
                                        error!("Nostr event handler failed: {e}")
                                    }
                                }
                            }
                        }
                        if times < 1 {
                            warn!("No handler subscribed for event: {envelope:?}");
                        } else {
                            info!("{event_type:?} event handled successfully");
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
