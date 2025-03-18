use crate::{
  arbiter::models::{
    ApiKey,
    ApiKeyWithKeyWithoutUID,
    User,
  },
  utils::{
    gen_api_key_with_check,
    gen_uid_with_check,
  },
};
use serde::{
  Deserialize,
  Serialize,
};
use std::{
  collections::HashMap,
  sync::Arc,
};
use tokio::sync::Mutex;

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
pub struct UserConfig {
  pub user_type: String,
  pub pretty_name: String,
  pub id: String,
  pub api_keys: Vec<ApiKeyWithKeyWithoutUID>,
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
  pub async fn new(master_user_pretty_name: &String) -> (NexusStore, UserConfig) {
    let mut ret = NexusStore {
      users: Arc::new(Mutex::new(HashMap::new())),
      api_keys: Arc::new(Mutex::new(HashMap::new())),
      clients: Arc::new(Mutex::new(HashMap::new())),
      messages: Arc::new(Mutex::new(HashMap::new())),
    };

    let master_user_config = ret.add_master_user(&master_user_pretty_name).await;

    (ret, master_user_config)
  }

  pub async fn add_user(&mut self, user_config: UserConfig) {
    let mut key_ids: Vec<String> = vec![];
    for key_config in user_config.api_keys.iter() {
      key_ids.push(key_config.key.clone());
    }

    self.users.lock().await.insert(
      user_config.id.clone(),
      User {
        pretty_name: user_config.pretty_name,
        user_type: user_config.user_type,
        api_keys: key_ids,
        sessions: Arc::new(Mutex::new(HashMap::new())),
      },
    );

    for key_config in user_config.api_keys.iter() {
      self.api_keys.lock().await.insert(
        key_config.key.clone(),
        ApiKey {
          allowed_events_to: key_config.allowed_events_to.clone(),
          allowed_events_from: key_config.allowed_events_from.clone(),
          user_id: user_config.id.clone(),
          echo: key_config.echo.clone(),
        },
      );
    }
  }

  pub async fn add_master_user(&mut self, pretty_name: &String) -> UserConfig {
    let ret = UserConfig {
      id: gen_uid_with_check(self).await,
      pretty_name: pretty_name.clone(),
      user_type: NexusStore::MASTER_USER_TYPE.to_string(),
      api_keys: vec![ApiKeyWithKeyWithoutUID {
        allowed_events_to: vec![".*".to_string()],
        allowed_events_from: vec![".*".to_string()],
        key: gen_api_key_with_check(self).await,
        echo: true,
      }],
    };

    self.add_user(ret.clone()).await;

    ret
  }
}
