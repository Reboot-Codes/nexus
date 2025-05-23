use crate::server::models::NexusStore;
use api_key::types::{
  ApiKeyResults,
  Default,
  StringGenerator,
};
use chrono::prelude::{
  DateTime,
  Utc,
};
use os_path::OsPath;
use simple_error::SimpleError;
use std::hash::{
  DefaultHasher,
  Hash,
  Hasher,
};
use tokio::{
  fs,
  io::AsyncReadExt,
};
use uuid::Uuid;

pub struct RecvSync<T>(pub std::sync::mpsc::Receiver<T>);

unsafe impl<T> Sync for RecvSync<T> {}

/// formats like "2001-07-08T00:34:60.026490+09:30"
pub fn iso8601(st: &std::time::SystemTime) -> String {
  let dt: DateTime<Utc> = st.clone().into();
  format!("{}", dt.format("%+"))
}

#[allow(dead_code)]
pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
  let mut s = DefaultHasher::new();
  t.hash(&mut s);
  s.finish()
}

/// Generates a new api key. Please use [`gen_api_key_with_check`] to ensure that its' unique!
pub fn gen_api_key() -> String {
  let options = StringGenerator {
    prefix: "CLOVER:".to_string(),
    length: 50,
    ..StringGenerator::default()
  };
  let key: ApiKeyResults = api_key::string(options);

  match key {
    ApiKeyResults::String(res) => res,
    ApiKeyResults::StringArray(res_vec) => res_vec.join(""),
  }
}

/// Generates a new API key after checking that it is not currently in the Store.
pub async fn gen_api_key_with_check(store: &NexusStore) -> String {
  loop {
    let api_key = gen_api_key();
    match store.api_keys.lock().await.get(&api_key.clone()) {
      Some(_) => {}
      None => {
        break api_key;
      }
    }
  }
}

/// Generates a new UID after checking that it is currently not in the Store.
pub async fn gen_uid_with_check(store: &NexusStore) -> String {
  loop {
    let uid = Uuid::new_v4().to_string();
    match store.users.lock().await.get(&uid.clone()) {
      Some(_) => {}
      None => {
        break uid;
      }
    }
  }
}

pub async fn gen_message_id_with_check(store: &NexusStore) -> String {
  loop {
    let message_id = Uuid::new_v4().to_string();
    match store.messages.lock().await.get(&message_id.clone()) {
      Some(_) => {}
      None => {
        break message_id;
      }
    }
  }
}

pub async fn gen_cid_with_check(store: &NexusStore) -> String {
  loop {
    let client_id = Uuid::new_v4().to_string();
    match store.clients.lock().await.get(&client_id.clone()) {
      Some(_) => {}
      None => {
        break client_id;
      }
    }
  }
}

pub async fn read_file(path: OsPath) -> Result<String, SimpleError> {
  let mut err = None;
  let mut ret = None;
  let mut contents = String::new();

  if path.exists() {
    match fs::File::open(path.to_path()).await {
      Ok(mut file) => match file.read_to_string(&mut contents).await {
        Ok(_) => {
          ret = Some(contents);
        }
        Err(e) => {
          err = Some(SimpleError::from(e));
        }
      },
      Err(e) => err = Some(SimpleError::from(e)),
    }
  } else {
    err = Some(SimpleError::new("Path does not exist!"));
  }

  match err {
    Some(e) => Err(e),
    None => match ret {
      Some(val) => Ok(val),
      None => Err(SimpleError::new(
        "Impossible state, no error reported but return value is missing!",
      )),
    },
  }
}
