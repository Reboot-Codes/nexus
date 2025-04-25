use crate::{
  arbiter::models::ApiKey,
  server::{
    AUTH_HEADER,
    MAX_SIZE,
    models::IPCMessageWithId,
    websockets::WsIn,
  },
  user::NexusUser,
};
use fastwebsockets::{
  FragmentCollector,
  Frame,
  OpCode,
  handshake,
};
use http_body_util::Empty;
use hyper::{
  Request,
  body::Bytes,
  header::{
    CONNECTION,
    UPGRADE,
  },
};
use log::error;
use log::info;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
  net::TcpStream,
  sync::broadcast,
};
use tokio::{
  sync::Mutex,
  task::{
    JoinHandle,
    spawn,
  },
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct ClientStatus {
  pub connected: bool,
}

impl ClientStatus {
  pub fn new(connected: bool) -> Self {
    ClientStatus { connected }
  }

  pub fn set(&mut self, connected: bool) {
    self.connected = connected
  }

  pub fn get(&self) -> bool {
    self.connected
  }
}

/// Use when connecting a program to nexus *remotely*. Use the nexus::server::listener's
/// nexus_listener() function to run an embedded server.
pub struct NexusClient {
  secure: bool,
  url: String,
  // TODO: Make optional as we can connect via OS socket as well.
  port: u16,
  api_key: String,
  status: Arc<Mutex<ClientStatus>>,
  keep_trying: bool,
  to_server_tx: broadcast::Sender<WsIn>,
  from_server: broadcast::Sender<IPCMessageWithId>,
  handles: Vec<JoinHandle<()>>,
  api_keys: Arc<Mutex<HashMap<String, ApiKey>>>,
  cancellation_token: CancellationToken, // TODO: Add user registry to see if a user is connected via this client to route back instead of sending to server.
}

struct AddSend<T>(T);

unsafe impl<T> Send for AddSend<T> {}
unsafe impl<T> Sync for AddSend<T> {}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
  Fut: Future + Send + 'static,
  Fut::Output: Send + 'static,
{
  fn execute(&self, fut: Fut) {
    tokio::task::spawn(fut);
  }
}

impl NexusClient {
  pub fn new(secure: bool, url: &String, port: &u16, api_key: &String, keep_trying: bool) -> Self {
    let (from_server, _) = broadcast::channel::<IPCMessageWithId>(MAX_SIZE);
    let (to_server_tx, _) = broadcast::channel::<WsIn>(MAX_SIZE);

    NexusClient {
      secure,
      url: url.clone(),
      port: port.clone(),
      api_key: api_key.clone(),
      status: Arc::new(Mutex::new(ClientStatus::new(false))),
      keep_trying,
      to_server_tx,
      from_server,
      handles: Vec::new(),
      api_keys: Arc::new(Mutex::new(HashMap::new())),
      cancellation_token: CancellationToken::new(),
    }
  }

  // TODO: Send as connected API key. (ensure routing is supported)
  // TODO: Send as proxied API key. (ensure routing is supported)

  pub async fn connect_to_ws(&mut self) -> Result<JoinHandle<()>, anyhow::Error> {
    let mut keep_trying = true;
    let mut ws_opt = None;
    let mut error: Option<anyhow::Error> = None;
    let host = format!("{}:{}", self.url.clone(), self.port.clone().to_string());
    let uri = format!(
      "{}://{}:{}/ws",
      (if self.secure { "https" } else { "http" }),
      self.url.clone(),
      self.port.clone().to_string()
    );

    while keep_trying {
      match TcpStream::connect(host.clone()).await {
        Ok(stream) => {
          match Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("Host", host.clone())
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "upgrade")
            .header(
              "Sec-WebSocket-Key",
              fastwebsockets::handshake::generate_key(),
            )
            .header(AUTH_HEADER, self.api_key.clone())
            .header("Sec-WebSocket-Version", "13")
            .body(Empty::<Bytes>::new())
          {
            Ok(req) => match handshake::client(&SpawnExecutor, req, stream).await {
              Ok((the_socket, _)) => {
                ws_opt = Some(the_socket);
              }
              Err(e) => {
                error!(
                  "Failed to perform WebSocket Handshake with \"{}\":\n{}",
                  uri.clone(),
                  e
                );
                if self.keep_trying {
                  error!("Retrying WebSocket Handshake with \"{}\"...", uri.clone());
                  tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                  error = Some(e.into());
                  keep_trying = false;
                }
              }
            },
            Err(e) => {
              error!(
                "Failed to send WebSocket Upgrade request to \"{}\":\n{}",
                uri.clone(),
                e
              );
              if self.keep_trying {
                info!(
                  "Retrying WebSocket Upgrade request for \"{}\"...",
                  uri.clone()
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
              } else {
                error = Some(e.into());
                keep_trying = false;
              }
            }
          }
        }
        Err(e) => {
          error!(
            "Failed to open TCP connection to \"{}\":\n{}",
            host.clone(),
            e
          );
          if self.keep_trying {
            info!("Retrying TCP connection to \"{}\"...", host.clone());
            tokio::time::sleep(Duration::from_secs(1)).await;
          } else {
            error = Some(e.into());
            keep_trying = false;
          }
        }
      }
    }

    match ws_opt {
      Some(ws) => {
        self.status.lock().await.set(true);

        let (mut reader, og_writer) = ws.split(tokio::io::split);
        let writer = Arc::new(Mutex::new(AddSend(og_writer)));
        let (from_tx, _) = broadcast::channel::<IPCMessageWithId>(MAX_SIZE);

        let senders_writer = writer.clone();
        let mut sender = move |frame| {
          let senders_writer_two = senders_writer.clone();
          async move { senders_writer_two.lock().await.0.write_frame(frame).await }
        };

        let handle_from_tx = from_tx.clone();
        let handle_token = self.cancellation_token.clone();
        let mut handle_to_rx = self.to_server_tx.subscribe();
        let handle = spawn(async move {
          let recv_token = Arc::new(handle_token.clone());
          let recv_handle = spawn(async move {
            recv_token
              .run_until_cancelled(async move {
                // TODO: Use FragmentCollector!
                while let Ok(mut message) = reader.read_frame(&mut sender).await {
                  match std::str::from_utf8(message.payload.to_mut()) {
                    Ok(str) => {
                      match serde_jsonc::from_str::<IPCMessageWithId>(&str) {
                        Ok(msg) => {
                          match handle_from_tx.send(msg) {
                            Ok(_) => {
                              // TODO:
                            }
                            Err(e) => {
                              // TODO:
                            }
                          }
                        }
                        Err(e) => {
                          // TODO:
                        }
                      }
                    }
                    Err(e) => {
                      // TODO:
                    }
                  }
                }
              })
              .await;
          });

          let send_token = Arc::new(handle_token.clone());
          let send_handle = spawn(async move {
            let sender_writer = writer.clone();
            send_token
              .run_until_cancelled(async move {
                while let Ok(message) = handle_to_rx.recv().await {
                  match sender_writer
                    .lock()
                    .await
                    .0
                    .write_frame(Frame::text(
                      serde_jsonc::to_string(&message).unwrap().as_bytes().into(),
                    ))
                    .await
                  {
                    Ok(_) => {
                      // TODO:
                    }
                    Err(e) => {
                      // TODO:
                    }
                  }
                }
              })
              .await;
            match writer
              .lock()
              .await
              .0
              .write_frame(Frame::close(
                OpCode::Close as u16,
                "Client Shutdown.".as_bytes(),
              ))
              .await
            {
              Ok(_) => {
                // TODO:
              }
              Err(e) => {
                // TODO:
              }
            }
          });

          tokio::select! {_ = futures::future::join_all(vec![
            recv_handle,
            send_handle
          ]) => {
            info!("WS threads have exited!");
          }}
        });

        Ok(handle)
      }
      None => {
        return Err(error.unwrap());
      }
    }
  }

  pub async fn new_user(&self, api_key_str: &String) -> Result<NexusUser, anyhow::Error> {
    if self.status.lock().await.get() {
      match self.api_keys.lock().await.get(&api_key_str.clone()) {
        Some(api_key) => {
          let status = self.status.clone();
          let cancellation_token = self.cancellation_token.clone();
          let to_server = self.to_server_tx.clone();
          let from_server_tx = self.from_server.clone();

          Ok(NexusUser::new(
            false,
            status,
            cancellation_token,
            api_key.to_api_key_with_key(&api_key_str.clone()),
            to_server,
            from_server_tx,
          ))
        }
        None => Err(anyhow::anyhow!(
          "Client's API key does not exist in the mini-store... sure ya have the right one?"
        )),
      }
    } else {
      Err(anyhow::anyhow!("Client is not connected yet!"))
    }
  }

  // TODO: Get API keys that this proxy user registered.
}
