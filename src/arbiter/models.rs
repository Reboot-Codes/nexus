use crate::server::models::{Session, UserConfigWithId};
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

#[derive(Debug, Clone)]
pub struct User {
  /// A vector of API keys associated with this user.
  pub api_keys: Vec<String>,
  pub sessions: Arc<Mutex<HashMap<String, Session>>>,
  pub user_type: String,
  pub pretty_name: String,
  pub parent_id: Option<String>,
  pub children: Vec<String>,
}

impl User {
  pub fn to_user_with_id(self, id: String) -> UserWithId {
    UserWithId {
      id,
      api_keys: self.api_keys,
      sessions: self.sessions,
      user_type: self.user_type,
      pretty_name: self.pretty_name,
      parent_id: self.parent_id,
      children: self.children
    }
  }
}

#[derive(Debug, Clone)]
pub struct UserWithId {
  pub id: String,
  pub api_keys: Vec<String>,
  pub sessions: Arc<Mutex<HashMap<String, Session>>>,
  pub user_type: String,
  pub pretty_name: String,
  pub parent_id: Option<String>,
  pub children: Vec<String>,
}

impl Into<User> for UserWithId {
  fn into(self) -> User {
    User {
      api_keys: self.api_keys,
      sessions: self.sessions,
      user_type: self.user_type,
      pretty_name: self.pretty_name,
      parent_id: self.parent_id,
      children: self.children
    }
  }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKey {
  pub allowed_events_to: Vec<String>,
  pub allowed_events_from: Vec<String>,
  pub user_id: String,
  pub echo: bool,
  pub proxy: bool
}

impl ApiKey {
  pub fn to_api_key_with_key(&self, key: &String) -> ApiKeyWithKey {
    ApiKeyWithKey {
      key: key.clone(),
      allowed_events_to: self.allowed_events_to.clone(),
      allowed_events_from: self.allowed_events_from.clone(),
      user_id: self.user_id.clone(),
      echo: self.echo,
      proxy: self.proxy
    }
  }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKeyWithKey {
  pub key: String,
  pub allowed_events_to: Vec<String>,
  pub allowed_events_from: Vec<String>,
  pub user_id: String,
  pub echo: bool,
  pub proxy: bool
}

impl Into<ApiKey> for ApiKeyWithKey {
  fn into(self) -> ApiKey {
    ApiKey {
      allowed_events_to: self.allowed_events_to,
      allowed_events_from: self.allowed_events_from,
      user_id: self.user_id,
      echo: self.echo,
      proxy: self.proxy
    }
  }
}

impl Into<ApiKeyWithKeyWithoutUID> for ApiKeyWithKey {
  fn into(self) -> ApiKeyWithKeyWithoutUID {
    ApiKeyWithKeyWithoutUID {
      key: self.key,
      allowed_events_to: self.allowed_events_to,
      allowed_events_from: self.allowed_events_from,
      echo: self.echo,
      proxy: self.proxy
    }
  }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKeyWithKeyWithoutUID {
  pub key: String,
  pub allowed_events_to: Vec<String>,
  pub allowed_events_from: Vec<String>,
  pub echo: bool,
  pub proxy: bool
}

impl Into<ApiKeyWithoutUID> for ApiKey {
  fn into(self) -> ApiKeyWithoutUID {
    ApiKeyWithoutUID {
      allowed_events_to: self.allowed_events_to,
      allowed_events_from: self.allowed_events_from,
      echo: self.echo,
      proxy: self.proxy
    }
  }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKeyWithoutUID {
  pub allowed_events_to: Vec<String>,
  pub allowed_events_from: Vec<String>,
  pub echo: bool,
  pub proxy: bool
}
