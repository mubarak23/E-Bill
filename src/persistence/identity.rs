use super::{file_storage_path, Result};
use async_trait::async_trait;
use borsh::{to_vec, BorshDeserialize};
use libp2p::{identity::Keypair, PeerId};
use tokio::{fs, task};

use crate::service::identity_service::{Identity, IdentityWithAll};
#[cfg(test)]
use mockall::automock;
use std::path::Path;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait IdentityStoreApi: Send + Sync {
    /// Checks if the identity has been created
    async fn exists(&self) -> bool;
    /// Saves the given identity
    async fn save(&self, identity: &Identity) -> Result<()>;
    /// Gets the local identity
    async fn get(&self) -> Result<Identity>;
    /// Gets the local identity with it's peer id and key pair
    async fn get_full(&self) -> Result<IdentityWithAll>;
    /// Saves the node id
    async fn save_node_id(&self, node_id: &PeerId) -> Result<()>;
    /// Gets the local peer id
    async fn get_node_id(&self) -> Result<PeerId>;
    /// Saves the given key pair
    async fn save_key_pair(&self, key_pair: &Keypair) -> Result<()>;
    /// Gets the local key pair
    async fn get_key_pair(&self) -> Result<Keypair>;
}

#[derive(Clone)]
pub struct FileBasedIdentityStore {
    identity_file: String,
    node_id_file: String,
    key_pair_file: String,
}

impl FileBasedIdentityStore {
    pub async fn new(
        data_dir: &str,
        path: &str,
        identity_file_name: &str,
        node_id_file_name: &str,
        key_pair_file_name: &str,
    ) -> Result<Self> {
        let directory = file_storage_path(data_dir, path).await?;
        Ok(Self {
            identity_file: format!("{}/{}", directory, identity_file_name),
            node_id_file: format!("{}/{}", directory, node_id_file_name),
            key_pair_file: format!("{}/{}", directory, key_pair_file_name),
        })
    }
}

#[async_trait]
impl IdentityStoreApi for FileBasedIdentityStore {
    async fn exists(&self) -> bool {
        let identity_path = self.identity_file.clone();
        let node_id_path = self.node_id_file.clone();
        let key_pair_path = self.key_pair_file.clone();
        task::spawn_blocking(move || {
            Path::new(&identity_path).exists()
                && Path::new(&node_id_path).exists()
                && Path::new(&key_pair_path).exists()
        })
        .await
        .unwrap_or(false)
    }

    async fn get(&self) -> Result<Identity> {
        let data = fs::read(&self.identity_file).await?;
        let identity = Identity::try_from_slice(&data)?;
        Ok(identity)
    }

    async fn get_full(&self) -> Result<IdentityWithAll> {
        let results = tokio::join!(self.get(), self.get_node_id(), self.get_key_pair());
        match results {
            (Ok(identity), Ok(node_id), Ok(key_pair)) => Ok(IdentityWithAll {
                identity,
                node_id,
                key_pair,
            }),
            _ => {
                if let Err(e) = results.0 {
                    Err(e)
                } else if let Err(e) = results.1 {
                    Err(e)
                } else if let Err(e) = results.2 {
                    Err(e)
                } else {
                    unreachable!("one of the tasks has to have failed");
                }
            }
        }
    }

    async fn save(&self, identity: &Identity) -> Result<()> {
        let data = to_vec(identity)?;
        fs::write(&self.identity_file, &data).await?;
        Ok(())
    }

    async fn save_node_id(&self, node_id: &PeerId) -> Result<()> {
        let data = node_id.to_bytes();
        fs::write(&self.node_id_file, &data).await?;
        Ok(())
    }

    async fn get_node_id(&self) -> Result<PeerId> {
        let data = fs::read(&self.node_id_file).await?;
        let node_id = PeerId::from_bytes(&data)?;
        Ok(node_id)
    }

    async fn save_key_pair(&self, key_pair: &Keypair) -> Result<()> {
        let data = key_pair.to_protobuf_encoding()?;
        fs::write(&self.key_pair_file, &data).await?;
        Ok(())
    }

    async fn get_key_pair(&self) -> Result<Keypair> {
        let data = fs::read(&self.key_pair_file).await?;
        let key_pair = Keypair::from_protobuf_encoding(&data)?;
        Ok(key_pair)
    }
}
