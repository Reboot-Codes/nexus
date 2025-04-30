use crate::{
  arbiter::models::ApiKeyWithKey,
  client::ClientStatus,
  server::{
    models::IPCMessageWithId,
    websockets::WsIn,
  },
};
use log::error;
use regex::Regex;
use std::sync::Arc;
use tokio::{
  sync::{
    Mutex,
    broadcast,
    mpsc::{
      UnboundedReceiver,
      UnboundedSender,
      unbounded_channel,
    },
  },
  task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

/// Use in a thread to connect to send messages to/recieve messages from nexus with.
/// Requires a [NexusClient](nexus::client::NexusClient) or a tokio IPC channel
/// connected to an embedded Nexus server to actually send messages.
///
/// This struct basically just ensures that messages are formatted properly.
#[derive(Debug, Clone)]
pub struct NexusUser {
  pub is_child: bool,
  connected: Arc<Mutex<ClientStatus>>,
  pub cancellation_token: CancellationToken,
  api_key: ApiKeyWithKey,
  to_client: broadcast::Sender<WsIn>,
  from_server_tx: broadcast::Sender<IPCMessageWithId>,
}

impl NexusUser {
  pub fn new(
    is_child: bool,
    connected: Arc<Mutex<ClientStatus>>,
    cancellation_token: CancellationToken,
    api_key: ApiKeyWithKey,
    to_client: broadcast::Sender<WsIn>,
    from_server_tx: broadcast::Sender<IPCMessageWithId>,
  ) -> Self {
    NexusUser {
      is_child,
      connected,
      cancellation_token,
      api_key,
      to_client,
      from_server_tx,
    }
  }

  pub fn send(
    &self,
    kind: &String,
    message: &String,
    replying_to: &Option<String>,
  ) -> Result<(), anyhow::Error> {
    match self.to_client.send(WsIn {
      kind: kind.clone(),
      message: message.clone(),
      api_key: Some(self.api_key.key.clone()),
      replying_to: replying_to.clone(),
    }) {
      Ok(_) => Ok(()),
      Err(e) => Err(e.into()),
    }
  }

  pub fn subscribe(&self) -> (UnboundedReceiver<IPCMessageWithId>, JoinHandle<()>) {
    let (tx, rx) = unbounded_channel::<IPCMessageWithId>();
    let mut from_client = self.from_server_tx.subscribe();
    let cancellation_token = self.cancellation_token.clone();
    let this = self.clone();

    (
      rx,
      tokio::task::spawn(async move {
        cancellation_token
          .run_until_cancelled(async move {
            while let Ok(message) = from_client.recv().await {
              for allowed_event_regex in &this.api_key.allowed_events_to.clone() {
                match Regex::new(&allowed_event_regex) {
                  Ok(regex) => {
                    if regex.is_match(&message.kind.clone()) {
                      match tx.send(message.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                          error!(
                            "Failed to send message to user: {}, due to:\n{}",
                            this.api_key.user_id.clone(),
                            e
                          );
                        }
                      };

                      break;
                    }
                  }
                  Err(e) => {
                    error!(
                      "Allowed event regular expression: \"{}\", for user id: {}, errored with: {}",
                      allowed_event_regex.clone(),
                      this.api_key.user_id.clone(),
                      e
                    );
                  }
                }
              }
            }
          })
          .await;
      }),
    )
  }
}
