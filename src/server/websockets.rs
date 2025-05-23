use crate::arbiter::models::{
  ApiKeyWithKey,
  UserWithId,
};
use crate::server::models::{
  Client,
  ClientWithId,
  IPCMessageWithId,
  NexusStore,
  Session,
};
use crate::server::{
  DEAUTH_EVENT,
  MAX_SIZE,
};
use crate::utils::iso8601;
use futures::{
  SinkExt,
  StreamExt,
};
use log::{
  debug,
  error,
  info,
  warn,
};
use regex::Regex;
use serde::{
  Deserialize,
  Serialize,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{
  Mutex,
  broadcast,
};
use url::Url;
use uuid::Uuid;
use warp::filters::ws::{
  Message,
  WebSocket,
};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct WsIn {
  pub kind: String,
  pub message: String,
  pub api_key: Option<String>,
  pub replying_to: Option<String>,
}

pub async fn handle_ws_client(
  auth: (UserWithId, ApiKeyWithKey, ClientWithId, Session),
  ws: warp::ws::Ws,
  store: Arc<Arc<NexusStore>>,
  to_clients_tx: Arc<Arc<Mutex<HashMap<String, broadcast::Sender<IPCMessageWithId>>>>>,
  from_clients_tx: Arc<UnboundedSender<IPCMessageWithId>>,
) -> Result<impl warp::Reply, warp::Rejection> {
  let user = auth.0.clone();
  let api_key = auth.1.clone();
  let client = auth.2.clone();
  let session = auth.3.clone();

  info!(
    "Upgrading client: {}, to websocket connection...",
    client.id.clone()
  );

  let ws_client = Arc::new(client.clone());
  Ok(ws.on_upgrade(move |websocket: WebSocket| async move {
    info!("Upgraded client: {}, to websocket connection!", ws_client.id.clone());

    let (mut sender, mut receiver) = websocket.split();
    let (to_client_tx, mut to_client_rx) = broadcast::channel::<IPCMessageWithId>(MAX_SIZE);
    let mut deauthed = false;

    to_clients_tx.lock().await.insert(ws_client.id.clone(), to_client_tx);

    let recv_api_key = Arc::new(api_key.clone());
    let recv_user = Arc::new(user.clone());
    let recv_client = Arc::new(client.clone());
    let recv_store = Arc::new(store.clone());
    let recv_handle = tokio::task::spawn(async move {
      while !deauthed && let Some(body) = receiver.next().await {
        match body {
          Ok(msg) => {
            // Skip any non-Text messages...
            let message = if let Ok(s) = msg.to_str() {
              s
            } else {
              if msg.is_close() {
                info!("Client: {}, disconnected!", recv_client.id.clone());
                (#[allow(unused_assignments)]
                deauthed) = true;
                break;
              }

              return;
            };

            match serde_json::from_str::<WsIn>(message) {
              Ok(msg) => {
                let message_id = loop {
                  let message_id = Uuid::new_v4().to_string();
                  match recv_store.messages.lock().await.get(&message_id.clone()) {
                    Some(_) => {
                      debug!("Message: {}, exists, retrying...", message_id.clone());
                    },
                    None => {
                      break message_id;
                    }
                  }
                };
                debug!("Client: {}, send message: {{ \"id\": \"{}\",  \"kind\": \"{}\", \"message\": \"{}\" }}...", ws_client.id.clone(), message_id.clone(), msg.kind.clone(), msg.message.clone());

                let mut allowed_to_send = false;

                // Check if this message can be sent by this API key.
                for allowed_send_pattern in recv_api_key.allowed_events_from.clone() {
                  match Regex::new(&allowed_send_pattern) {
                    Ok(pattern) => {
                      if pattern.is_match(&msg.kind.clone()) {
                        // Check if this message is being proxied via nexus::client...
                        match msg.api_key.clone() {
                          Some(proxied_key) => {
                            // If so, make sure to run through the API key verification process for this message independantly.
                            if recv_api_key.proxy {
                              match recv_store.api_keys.lock().await.get(&proxied_key.clone()) {
                                Some(proxied_api_key) => {
                                  match recv_store.users.lock().await.get(&proxied_api_key.user_id.clone()) {
                                    Some(_proxied_user) => {
                                      for proxied_allowed_send_pattern in proxied_api_key.allowed_events_from.clone() {
                                        match Regex::new(&proxied_allowed_send_pattern) {
                                          Ok(proxied_pattern) => {
                                            if proxied_pattern.is_match(&msg.kind.clone()) {
                                              allowed_to_send = true;
                                              break;
                                            }
                                          },
                                          Err(e) => {
                                            warn!("Allowed send from pattern: \"{}\" (for user: \"{}\"), is not valid, due to:\n{}", proxied_allowed_send_pattern.clone(), proxied_api_key.user_id.clone(), e);
                                          }
                                        }
                                      }
                                    },
                                    None => {
                                      // TODO: Proxied API key exists in store, but the associated User does not exist, refusing message.
                                      // *This is a critical bug!*
                                      // Theoretically, this shouldn't happen, but it could, and any cases should be refused and reported to the bug tracker.
                                    }
                                  }
                                },
                                None => {
                                  // TODO: Proxied API key does not exist in the store, discard message.
                                }
                              }
                            } else {
                              // TODO: The *session's* api key is NOT permitted to proxy messages, and the message will be discarded.
                            }
                          },
                          None => {
                            // Or just send the message since no proxying is occuring.
                            allowed_to_send = true;
                            break;
                          }
                        }
                      }
                    },
                    Err(e) => {
                      warn!("Allowed \"send from\" pattern: \"{}\" (for user: \"{}\"), is not valid, due to:\n{}", allowed_send_pattern.clone(), recv_user.id.clone(), e);
                    }
                  }
                }

                if allowed_to_send {
                  let generated_message = IPCMessageWithId { id: message_id.clone(), author: format!("ws://{}?client={}", recv_api_key.user_id.clone(), ws_client.id.clone()), kind: msg.kind.clone(), message: msg.message.clone(), replying_to: msg.replying_to.clone() };

                  recv_store.messages.lock().await.insert(message_id.clone(), generated_message.clone().into());

                  match from_clients_tx.send(generated_message.clone()) {
                    Ok(_) => {
                      debug!("Client: {}, successfully sent message: {{ \"id\": \"{}\", \"kind\": \"{}\", \"message\": \"{}\" }}, over to dispatch IPC thread!", recv_client.id.clone(), message_id.clone(), msg.kind.clone(), msg.message.clone());
                    },
                    Err(e) => {
                      error!("Client: {}, failed to send message: {{ \"id\": \"{}\", \"kind\": \"{}\", \"message\": \"{}\" }}, over to dispatch IPC thread, due to:\n  {}", recv_client.id.clone(), message_id.clone(), msg.kind.clone(), msg.message.clone(), e);
                    }
                  };
                } else {
                  warn!("Client: {}, attempted to send message of {{ \"id\": \"{}\", \"kind\": \"{}\", \"message\": \"{}\" }} when unauthorized!", recv_client.id.clone(), message_id.clone(), msg.kind.clone(), msg.message.clone());
                  // TODO: Send unauthorized warning.
                }
              },
              Err(e) => {
                warn!("Client: {}, error reading message: \"{}\", due to:\n{}", recv_client.id.clone(), message, e);
                // TODO: Send err?
              }
            };
          },
          Err(e) => {
            error!("Error reading message on client: \"{}\", due to:\n{}", ws_client.id.clone(), e);
            // TODO: send error?
          }
        };
      }

      // Client closed connection.
      (#[allow(unused_assignments)]
      deauthed) = true;
    });

    let send_api_key = Arc::new(api_key.clone());
    let send_client = Arc::new(client.clone());
    let send_handle = tokio::task::spawn(async move {
      while let Ok(msg) = to_client_rx.recv().await {
        if msg.kind == Url::parse(DEAUTH_EVENT)
        .unwrap()
        .query_pairs_mut()
        .append_pair("id", send_client.id.clone().as_str())
        .finish()
        .to_string() {
          match sender.close().await {
            Ok(_) => {},
            Err(e) => {
              error!("Client: {}, failed to close connection due to:\n  {}", send_client.id.clone(), e);
            }
          };

          (#[allow(unused_assignments)]
          deauthed) = true;
          break;
        } else if deauthed {
          break;
        } else {
          let msg_author = msg.author.clone();
          let msg_client_id = if msg.author.clone().split("?client=").collect::<Vec<_>>().len() > 1 {
            msg_author.split("?client=").collect::<Vec<_>>()[1]
          } else {
            ""
          };

          if (msg_client_id != send_client.id.clone()) || send_api_key.echo.clone() {
            let response = serde_json::to_string(&IPCMessageWithId {
              id: msg.id.clone(),
              author: msg.author.clone(),
              kind: msg.kind.clone(),
              message: msg.message.clone(),
              replying_to: msg.replying_to.clone()
            })
            .unwrap();
            match sender.send(Message::text(response)).await {
              Ok(_) => {

              },
              Err(err) => {
                error!("Client: {}, error sending message: {{ \"id\": \"{}\", \"kind\": \"{}\", \"message\": \"{}\" }}, {}", send_client.id.clone(), msg.id.clone(), msg.kind.clone(), msg.message.clone(), err);
              }
            }
          }
        }
      }
    });

    let clean_up_client = Arc::new(client.clone());
    let clean_up_store = Arc::new(store.clone());
    let clean_up_handle = tokio::task::spawn(async move {
      while !deauthed {if deauthed { break; }}

      info!("Client: {}, disconnected, cleaning up...", clean_up_client.id.clone());
      debug!("Ending session for: {}...", clean_up_client.id.clone());
      clean_up_store.users.clone().lock().await.get(&user.id.clone()).unwrap().sessions.lock().await.insert(clean_up_client.id.clone(), Session { start_time: session.start_time.clone(), end_time: iso8601(&SystemTime::now()), api_key: api_key.key.clone() });
      debug!("Deactivating client: {}...", clean_up_client.id.clone());
      clean_up_store.clients.clone().lock().await.insert(clean_up_client.id.clone(), Client { api_key: api_key.key.clone(), user_id: user.id.clone(), active: false });
    });

    futures::future::join_all(vec![recv_handle, send_handle, clean_up_handle]).await;
  }))
}
