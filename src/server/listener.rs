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
use crate::server::websockets::handle_ws_client;
use crate::server::{
  AUTH_HEADER,
  DEAUTH_EVENT,
};
use crate::utils::{
  gen_cid_with_check,
  gen_message_id_with_check,
  iso8601,
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
use std::convert::Infallible;
use std::net::{
  IpAddr,
  Ipv4Addr,
  SocketAddr,
};
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::{
  Mutex,
  broadcast,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use warp::{
  Filter,
  http::StatusCode,
};

use super::websockets::WsIn;

// example error response
#[derive(Serialize, Debug)]
struct ApiErrorResult {
  detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPCWithKey {
  kind: String,
  message: String,
  api_key: String,
}

// errors thrown by handlers and custom filters,
// such as `ensure_authentication` filter
#[derive(Error, Debug)]
enum ApiErrors {
  #[error("user not authorized")]
  NotAuthorized(String),
}

// ensure that warp`s Reject recognizes `ApiErrors`
impl warp::reject::Reject for ApiErrors {}

// generic errors handler for all api errors
// ensures unified error structure
async fn handle_rejection(
  err: warp::reject::Rejection,
) -> std::result::Result<impl warp::reply::Reply, Infallible> {
  let code;
  let message;

  if err.is_not_found() {
    code = StatusCode::NOT_FOUND;
    message = "Not found";
  } else if let Some(_) = err.find::<warp::filters::body::BodyDeserializeError>() {
    code = StatusCode::BAD_REQUEST;
    message = "Invalid Body";
  } else if let Some(e) = err.find::<ApiErrors>() {
    match e {
      ApiErrors::NotAuthorized(_error_message) => {
        code = StatusCode::UNAUTHORIZED;
        message = "Action not authorized";
      }
    }
  } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
    code = StatusCode::METHOD_NOT_ALLOWED;
    message = "Method not allowed";
  } else {
    // We should have expected this... Just log and say its a 500
    error!("unhandled rejection: {:?}", err);
    code = StatusCode::INTERNAL_SERVER_ERROR;
    message = "Internal server error";
  }

  let json = warp::reply::json(&ApiErrorResult {
    detail: message.into(),
  });

  Ok(warp::reply::with_status(json, code))
}

// middleware that looks for authorization header and validates it
async fn ensure_authentication(
  path: String,
  store: Arc<Arc<NexusStore>>,
  auth_header: Option<String>,
) -> Result<(UserWithId, ApiKeyWithKey, ClientWithId, Session), warp::reject::Rejection> {
  let client_id = gen_cid_with_check(&store).await;
  let mut client = ClientWithId {
    api_key: "".to_string(),
    user_id: "".to_string(),
    id: client_id.clone(),
    active: true,
  };
  store
    .clients
    .lock()
    .await
    .insert(client_id.clone(), client.clone().into());

  info!(
    "Client: {}, hit secure path: {}, attempting authentication...",
    client.id.clone(),
    path.clone()
  );

  match auth_header {
    Some(header) => {
      debug!("got auth header, verifying: {}", header);
      let parts: Vec<&str> = header.split(" ").collect();
      let mut authenticated = false;
      let mut api_key_str = "".to_string();

      if parts.len() == 2 && parts[0] == "Token" {
        api_key_str = parts[1].to_string();
        debug!("parsed key: {}", api_key_str.clone());
        for registered_api_key in store.clone().api_keys.lock().await.clone().into_iter() {
          debug!("testing against: {}", registered_api_key.0.clone());
          if api_key_str == registered_api_key.0 {
            authenticated = true;
            break;
          }
        }
      }

      if authenticated {
        debug!(
          "Running through client registration for api_key: {}",
          api_key_str.clone()
        );
        let api_keys = store.clone().api_keys.clone();
        let api_keys_locked = api_keys.lock().await;
        let api_key = api_keys_locked
          .get(&api_key_str.clone())
          .unwrap()
          .clone()
          .to_api_key_with_key(&api_key_str.clone());

        let user_id = api_key.clone().user_id;
        debug!("Registering as client: {}", client_id.clone());
        client = ClientWithId {
          api_key: api_key_str.clone(),
          user_id: user_id.clone(),
          id: client_id.clone(),
          active: true,
        };
        store
          .clients
          .lock()
          .await
          .insert(client_id.clone(), client.clone().into());

        let user = store
          .users
          .clone()
          .lock()
          .await
          .get(&user_id.clone())
          .unwrap()
          .clone()
          .to_user_with_id(user_id.clone());
        let session = Session {
          start_time: iso8601(&SystemTime::now()),
          end_time: "".to_string(),
          api_key: api_key.key.clone(),
        };
        user
          .sessions
          .lock()
          .await
          .insert(client_id.clone(), session.clone());

        debug!("Registered: {}!", client_id.clone());

        info!(
          "Client: {}, authenticated as user: {}!",
          client_id.clone(),
          api_key.clone().user_id
        );
        return Ok((
          user.clone(),
          api_key.clone(),
          client.clone(),
          session.clone(),
        ));
      } else {
        warn!(
          "Client: {}, attempted to connect with an invalid api key, disconnecting...",
          client.id.clone()
        );
        client = ClientWithId {
          api_key: client.api_key,
          user_id: client.user_id,
          id: client.id,
          active: false,
        };
        store
          .clients
          .lock()
          .await
          .insert(client_id.clone(), client.clone().into());
        return Err(warp::reject::custom(ApiErrors::NotAuthorized(
          "api key not registered".to_string(),
        )));
      }
    }
    None => {
      warn!(
        "Client: {}, attempted to connect without an api key, disconnecting...",
        client.id.clone()
      );
      client = ClientWithId {
        api_key: client.api_key,
        user_id: client.user_id,
        id: client.id,
        active: false,
      };
      store
        .clients
        .lock()
        .await
        .insert(client_id.clone(), client.clone().into());
      Err(warp::reject::custom(ApiErrors::NotAuthorized(
        "no authorization header".to_string(),
      )))
    }
  }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerHealth {
  up_since: String,
}

pub async fn nexus_listener(
  port: u16,
  store: Arc<NexusStore>,
  internal_client_senders: Vec<(Arc<UserWithId>, usize, broadcast::Sender<IPCMessageWithId>)>,
  internal_client_recivers: Vec<(Arc<UserWithId>, usize, broadcast::Sender<WsIn>)>,
  cancellation_tokens: (CancellationToken, CancellationToken),
) {
  info!("Starting nexus on port: {}...", port);
  let clients_tx: Arc<Mutex<HashMap<String, broadcast::Sender<IPCMessageWithId>>>> =
    Arc::new(Mutex::new(HashMap::new()));

  // For everything connected via thread IPC, we still need a client or else everything freaks out.
  for client in internal_client_senders {
    let client_obj = Client {
      api_key: client.0.api_keys[client.1].clone(),
      user_id: client.0.id.clone(),
      active: true,
    };
    let cid = gen_cid_with_check(&store).await;

    debug!(
      "Registering internal client \"{}\":\n{:#?}",
      cid.clone(),
      client_obj.clone()
    );

    store
      .clients
      .lock()
      .await
      .insert(cid.clone(), client_obj.clone());
    clients_tx.lock().await.insert(cid.clone(), client.2);
  }

  let (from_client_tx, mut from_client_rx) = mpsc::unbounded_channel::<IPCMessageWithId>();

  let filter_to_clients_tx = Arc::new(clients_tx.clone());
  let to_clients_tx_filter = warp::any().map(move || filter_to_clients_tx.clone());

  let filter_from_clients_tx = Arc::new(from_client_tx.clone());
  let from_clients_tx_filter = warp::any().map(move || filter_from_clients_tx.clone());

  let filter_store = Arc::new(store.clone());
  let store_filter = warp::any().map(move || filter_store.clone());

  let start_up_time = iso8601(&SystemTime::now());
  let health_check_path = warp::path("health-check").map(move || {
    let current_health = ServerHealth {
      up_since: start_up_time.clone(),
    };
    warp::reply::json(&current_health)
  });

  let ws_path = warp::path("ws")
    .and(warp::any().map(|| "/ws".to_string()))
    .and(store_filter.clone())
    .and(warp::header::optional::<String>(AUTH_HEADER))
    .and_then(ensure_authentication)
    .and(warp::ws())
    .and(store_filter.clone())
    .and(to_clients_tx_filter.clone())
    .and(from_clients_tx_filter.clone())
    .and_then(handle_ws_client);

  let routes = health_check_path
    .or(ws_path)
    .with(warp::cors().allow_any_origin())
    .recover(handle_rejection);

  // TODO: Add control REST API for start up and shut down.

  // TODO: Start creating GQL API endpoint.

  let server_port = Arc::new(port.clone());
  let http_token = cancellation_tokens.0.clone();
  let http_handle = tokio::task::spawn(async move {
    let (_, server) = warp::serve(routes)
      // TODO: Add option for listening address.
      .try_bind_with_graceful_shutdown(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), *server_port),
        async move {
          tokio::select! {
            _ = http_token.cancelled() => {}
          }
        },
      )
      // TODO: Handle bind errors!
      .expect("");
    server.await;
    info!("Server stopped.");
  });

  let ipc_dispatch_store = Arc::new(store.clone());
  let ipc_dispatch_clients_tx = Arc::new(clients_tx.clone());
  let ipc_dispatch_token = cancellation_tokens.0.clone();
  let ipc_dispatch_handle = tokio::task::spawn(async move {
    tokio::select! {
      _ = ipc_dispatch_token.cancelled() => {
        debug!("ipc_dispatch exited");
      },
      _ = async move {
        while let Some(message) = from_client_rx.recv().await {
          debug!("Got message type: {}, with data:\n  {}", message.kind.clone(), message.message.clone());
          match Url::parse(&message.kind.clone()) {
            Ok (_kind) => {
              for client in ipc_dispatch_store.clients.lock().await.clone().into_iter() {
                let client_id = Arc::new(client.0);
                let mutex = &ipc_dispatch_clients_tx.to_owned();
                let client_senders = mutex.lock();
                let hash_map = &client_senders.await;
                let mut message_sent = false;

                match hash_map.get(&client_id.to_string()) {
                  Some(client_sender) => {
                    if client.1.active {
                      match ipc_dispatch_store.clone().api_keys.lock().await.get(&client.1.api_key) {
                        Some(api_key) => {
                          for allowed_event_regex in &api_key.allowed_events_to {
                            match Regex::new(&allowed_event_regex) {
                              Ok(regex) => {
                                // TODO: Generate an internal CID in CoreUserConfig!
                                if regex.is_match(&message.kind.clone()) { // && !(message.author.clone().split("?client=").collect::<Vec<_>>()[1] == *client_id.clone()) {
                                  debug!("Sending event: \"{}\", to client: {}...", message.kind.clone(), client_id.clone());
                                  match client_sender.send(message.clone()) {
                                    Ok(_) => {
                                      message_sent = true;
                                    },
                                    Err(e) => {
                                      error!("Failed to send message to client: {}, due to:\n{}", client_id.clone(), e);
                                    }
                                  };

                                  break;
                                } else {
                                  // TODO: Not permitted to send message
                                }
                              },
                              Err(e) => {
                                error!("Message: \"{}\", failed, allowed event regular expression for client: {}, errored with: {}", message.kind, client_id.clone(), e);
                              }
                            }
                          }

                          let message_author = message.author.clone();
                          let message_client_vec = message_author.split("?client=").collect::<Vec<_>>();
                          if message_client_vec.len() > 1 {
                            if (!message_sent) && api_key.echo && (message_client_vec[1] == *client_id.clone()) {
                              debug!("Echoing event: \"{}\", to client: {}...", message.kind.clone(), client_id.clone());
                              match client_sender.send(message.clone()) {
                                Ok(_) => {
                                  message_sent = true;
                                },
                                Err(e) => {
                                  error!("Failed to send message to client: {}, due to:\n{}", client_id.clone(), e);
                                }

                              };
                            }
                          }
                        },
                        None => {
                          error!("DANGER! Client: {}, had API key removed from store without closing connection on removal, THIS IS BAD; please report this! Closing connection...", client_id.clone());

                          let kind = Url::parse(DEAUTH_EVENT)
                            .unwrap()
                            .query_pairs_mut()
                            .append_pair("id", &client_id.clone())
                            .finish()
                            .to_string();

                          let generated_message = IPCMessageWithId {
                            // TODO: fix this!!!!!
                            author: "ipc://com.reboot-codes.nexus.listener".to_string(),
                            kind,
                            message: "api key removed from store".to_string(),
                            id: gen_message_id_with_check(&ipc_dispatch_store).await,
                            replying_to: Some("".to_string())
                          };

                          ipc_dispatch_store.messages.lock().await.insert(generated_message.id.clone(), generated_message.clone().into());

                          let _ = client_sender.send(generated_message.clone());
                        }
                      }
                    }
                  },
                  None => {
                    error!("Client: {}, does not exist in the client map!", client_id.clone());
                  }
                }

                if !message_sent { debug!("Message: \"{}\", not sent to client: {}", message.kind.clone(), client_id.clone()); }
              }
            },
            Err(e) => {
              error!("Message: {{ \"id\": \"{}\", \"kind\": \"{}\", \"message\": \"{}\" }}, error parsing `kind`: {}", message.id.clone(), message.kind.clone(), message.message.clone(), e);
            }
          }
        }
      } => {}
    }
  });

  let mut internal_ipc_handles = vec![];

  for client in internal_client_recivers {
    // Internal IPC Handles
    let internal_ipc_store = Arc::new(store.clone());
    let internal_ipc_tx = Arc::new(from_client_tx.clone());
    let internal_ipc_token = cancellation_tokens.0.clone();
    internal_ipc_handles.push(tokio::task::spawn(async move {
      tokio::select! {
        _ = internal_ipc_token.cancelled() => {
          debug!("Internal IPC Handle Exited!");
        },
        _ = async move {
          let mut client_rx = client.2.subscribe();
          while let Ok(msg) = client_rx.recv().await {
            let msg_api_key = match msg.api_key {
              Some(api_key) => {
                &api_key.clone()
              },
              None => {
                client.0.api_keys.get(client.1).unwrap()
              }
            };

            match internal_ipc_store.api_keys.lock().await.get(msg_api_key) {
              Some(api_key) => {
                match internal_ipc_store.users.lock().await.get(&api_key.user_id) {
                  Some(_user) => {
                    for allowed_event_regex in api_key.allowed_events_from.clone() {
                        match Regex::new(&allowed_event_regex.clone()) {
                          Ok(regex) => {
                            if regex.is_match(&msg.kind.clone()) {
                              let author = format!("ipc://{}", api_key.user_id.clone());
                              match internal_ipc_tx.send(IPCMessageWithId {
                                author: author.clone(),
                                kind: msg.kind.clone(),
                                message: msg.message.clone(),
                                id: gen_message_id_with_check(&internal_ipc_store).await,
                                replying_to: msg.replying_to.clone()
                              }) {
                                Ok(_) => {}
                                Err(e) => {
                                  error!(
                                    "IPC user: {}, Failed to send message: {{ \"author\": \"{}\", \"kind\": \"{}\", \"message\": \"{}\" }}, due to:\n{}",
                                    api_key.user_id.clone(),
                                    author.clone(),
                                    msg.kind.clone(),
                                    msg.message.clone(),
                                    e
                                  );
                                }
                              };
                            }
                          }
                          Err(e) => {
                            error!(
                              "IPC user: {}, api key's \"allowed events from\", regex: {}, is invalid! Regex Error: {}",
                              api_key.user_id.clone(),
                              allowed_event_regex.clone(),
                              e
                            );
                          }
                        }
                      }
                  },
                  None => {
                    // TODO:
                  }
                }
              },
              None => {
                // TODO:
              }
            }
          }
        } => {}
      }
    }));
  }

  let mut handles = Vec::new();
  handles.push(http_handle);
  handles.push(ipc_dispatch_handle);
  handles.append(&mut internal_ipc_handles);

  let cleanup_token = cancellation_tokens.0.clone();
  tokio::select! {
    _ = cleanup_token.cancelled() => {
      info!("Cleaning and saving store...");
      // TODO: Clean up registered sessions when server is shutting down.

      std::mem::drop(store);

      cancellation_tokens.1.cancel();
    }
  }

  tokio::select! {
    _ = futures::future::join_all(handles) => {
    info!("Nexus server has stopped!");
  }}
}
