use crate::{
  arbiter::models::{
    ApiKey,
    ApiKeyWithKeyWithoutUID,
    ApiKeyWithoutUID,
    User,
    UserWithId,
  },
  client::ClientStatus,
  user::NexusUser,
  utils::{
    gen_api_key_with_check,
    gen_uid_with_check,
  },
};
use log::info;
use serde::{
  Deserialize,
  Serialize,
};
use std::{
  collections::HashMap,
  sync::Arc,
};
use tokio::sync::{
  Mutex,
  broadcast,
};
use tokio_util::sync::CancellationToken;

use super::{
  MAX_SIZE,
  websockets::WsIn,
};

// TODO: Define defaults via `Default` trait impl.

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IPCMessage {
  pub author: String,
  pub kind: String,
  pub message: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IPCMessageWithId {
  pub author: String,
  pub kind: String,
  pub message: String,
  pub id: String,
}

impl Into<IPCMessage> for IPCMessageWithId {
  fn into(self) -> IPCMessage {
    IPCMessage {
      author: self.author,
      kind: self.kind,
      message: self.message,
    }
  }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Client {
  pub api_key: String,
  pub user_id: String,
  pub active: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClientWithId {
  pub id: String,
  pub api_key: String,
  pub user_id: String,
  pub active: bool,
}

impl Into<Client> for ClientWithId {
  fn into(self) -> Client {
    Client {
      api_key: self.api_key,
      user_id: self.user_id,
      active: self.active,
    }
  }
}

#[derive(Debug, Clone)]
pub struct Session {
  pub start_time: String,
  pub end_time: String,
  pub api_key: String,
}

// TODO: Move User and API Key models to Arbiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreUserConfig {
  pub id: String,
  pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfigWithId {
  pub user_type: String,
  pub pretty_name: String,
  pub id: String,
  pub api_keys: Vec<ApiKeyWithKeyWithoutUID>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
  pub user_type: String,
  pub pretty_name: String,
  pub api_keys: Vec<ApiKeyWithoutUID>,
}

// TODO: Add serialization/deserialization functions...
// TODO: Add options for making certain models ephemeral or persistent.
#[derive(Debug, Clone)]
pub struct NexusStore {
  pub users: Arc<Mutex<HashMap<String, User>>>,
  pub api_keys: Arc<Mutex<HashMap<String, ApiKey>>>,
  pub clients: Arc<Mutex<HashMap<String, Client>>>,
  pub messages: Arc<Mutex<HashMap<String, IPCMessage>>>,
}

impl NexusStore {
  const MASTER_USER_TYPE: &str = "com.reboot-codes.nexus.master";

  /// Create a new store with a set master user.
  pub async fn new(master_user_pretty_name: &String) -> (NexusStore, UserWithId) {
    let mut ret = NexusStore {
      users: Arc::new(Mutex::new(HashMap::new())),
      api_keys: Arc::new(Mutex::new(HashMap::new())),
      clients: Arc::new(Mutex::new(HashMap::new())),
      messages: Arc::new(Mutex::new(HashMap::new())),
    };

    let master_user = ret.add_master_user(&master_user_pretty_name).await;

    (ret, master_user)
  }

  pub async fn add_user(
    &mut self,
    user_config: UserConfig,
    parent: Option<String>,
  ) -> Result<UserWithId, anyhow::Error> {
    let mut parent_id = None;
    let mut error = None;

    match parent.clone() {
      Some(target_parent_id) => match self.users.lock().await.get(&target_parent_id) {
        Some(_parent) => {
          parent_id = parent.clone();
        }
        None => {
          error = Some(anyhow::anyhow!("Parent ID does not exist in store!"));
        }
      },
      None => {}
    }

    match error {
      Some(e) => Err(e),
      None => {
        let mut key_ids = vec![];
        let mut key_configs = vec![];
        for key_config in user_config.api_keys.iter() {
          let key = gen_api_key_with_check(self).await;

          key_ids.push(key.clone());
          key_configs.push((key.clone(), key_config.clone()));
        }
        let id = gen_uid_with_check(self).await;

        self.users.lock().await.insert(
          id.clone(),
          User {
            pretty_name: user_config.pretty_name.clone(),
            user_type: user_config.user_type.clone(),
            api_keys: key_ids.clone(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            parent_id: parent.clone(),
            children: Vec::new(),
          },
        );

        for (key, key_config) in key_configs {
          self.api_keys.lock().await.insert(
            key.clone(),
            ApiKey {
              allowed_events_to: key_config.allowed_events_to.clone(),
              allowed_events_from: key_config.allowed_events_from.clone(),
              user_id: id.clone(),
              echo: key_config.echo,
              proxy: key_config.proxy,
            },
          );
        }

        Ok(UserWithId {
          pretty_name: user_config.pretty_name,
          user_type: user_config.user_type,
          api_keys: key_ids,
          sessions: Arc::new(Mutex::new(HashMap::new())),
          parent_id: parent,
          children: Vec::new(),
          id: id.clone(),
        })
      }
    }
  }

  pub async fn add_master_user(&mut self, pretty_name: &String) -> UserWithId {
    let ret = UserConfig {
      pretty_name: pretty_name.clone(),
      user_type: NexusStore::MASTER_USER_TYPE.to_string(),
      api_keys: vec![ApiKeyWithoutUID {
        allowed_events_to: vec![".*".to_string()],
        allowed_events_from: vec![".*".to_string()],
        echo: true,
        proxy: true,
      }],
    };

    self.add_user(ret.clone(), None).await.unwrap()
  }

  pub async fn connect_user(
    &mut self,
    api_key_str: &String,
  ) -> Result<
    (
      NexusUser,
      broadcast::Sender<WsIn>,
      broadcast::Sender<IPCMessageWithId>,
    ),
    anyhow::Error,
  > {
    match self.api_keys.lock().await.get(&api_key_str.clone()) {
      Some(api_key) => {
        let status = Arc::new(Mutex::new(ClientStatus::new(true)));
        let cancellation_token = CancellationToken::new();
        let (to_server, _) = broadcast::channel(MAX_SIZE);
        let (from_server_tx, _) = broadcast::channel(MAX_SIZE);

        let user_to_server = to_server.clone();
        let user_from_server_tx = from_server_tx.clone();
        Ok((
          NexusUser::new(
            false,
            status,
            cancellation_token,
            api_key.to_api_key_with_key(&api_key_str.clone()),
            user_to_server,
            user_from_server_tx,
          ),
          to_server,
          from_server_tx,
        ))
      }
      None => Err(anyhow::anyhow!(
        "Client's API key does not exist in the store... sure ya have the right one?"
      )),
    }
  }
}
