use crate::server::models::{
  IPCMessageWithId,
  UserConfig,
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
use log::info;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::{
  sync::{
    Mutex,
    mpsc::{
      UnboundedReceiver,
      UnboundedSender,
      unbounded_channel,
    },
  },
  task::{
    JoinHandle,
    spawn,
  },
};
use tokio_util::sync::CancellationToken;

/// Use when connecting a program to nexus *remotely*. Use the nexus::server::listener's
/// nexus_listener() function to run an embedded server.
pub struct NexusClient {
  secure: bool,
  url: String,
  // TODO: Make optional as we can connect via OS socket as well.
  port: u16,
  config: UserConfig,
  connected: bool,
  keep_trying: bool,
  to_server: Option<UnboundedSender<IPCMessageWithId>>,
  from_server: Option<UnboundedReceiver<IPCMessageWithId>>,
  // TODO: Add user registry to see if a user is connected via this client to route back instead of sending to server.
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
  pub fn new(
    secure: bool,
    url: &String,
    port: &u16,
    config: &UserConfig,
    keep_trying: bool,
  ) -> Self {
    NexusClient {
      secure,
      url: url.clone(),
      port: port.clone(),
      config: config.clone(),
      connected: false,
      keep_trying,
      to_server: None,
      from_server: None
    }
  }

  // TODO: Send as connected API key. (ensure routing is supported)
  // TODO: Send as proxied API key. (ensure routing is supported)

  pub async fn connect_to_ws(
    &mut self,
  ) -> Result<
    (
      JoinHandle<()>,
      (CancellationToken, CancellationToken)
    ),
    anyhow::Error,
  > {
    let mut keep_trying = true;
    let cancellation_tokens = (CancellationToken::new(), CancellationToken::new());
    let mut ws_opt = None;
    let mut error: Option<anyhow::Error> = None;

    while keep_trying {
      match TcpStream::connect(format!(
        "{}:{}",
        self.url.clone(),
        self.port.clone().to_string()
      )).await {
        Ok(stream) => {
          match Request::builder()
            .method("GET")
            .uri(format!(
              "{}://{}:{}/",
              (if self.secure { "https" } else { "http" }),
              self.url.clone(),
              self.port.clone().to_string()
            ))
            .header(
              "Host",
              format!("{}:{}", self.url.clone(), self.port.clone().to_string()),
            )
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "upgrade")
            .header(
              "Sec-WebSocket-Key",
              fastwebsockets::handshake::generate_key(),
            )
            // TODO: Add API key!
            .header("Sec-WebSocket-Version", "13")
            .body(Empty::<Bytes>::new())
          {
            Ok(req) => match handshake::client(&SpawnExecutor, req, stream).await {
              Ok((the_socket, _)) => {
                ws_opt = Some(the_socket);
              }
              Err(e) => {
                if self.keep_trying {
                  tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                  error = Some(e.into());
                  keep_trying = false;
                }
              }
            },
            Err(e) => {
              if self.keep_trying {
                tokio::time::sleep(Duration::from_secs(1)).await;
              } else {
                error = Some(e.into());
                keep_trying = false;
              }
            }
          }
        }
        Err(e) => {
          if self.keep_trying {
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
        self.connected = true;

        let (mut reader, og_writer) = ws.split(tokio::io::split);
        let writer = Arc::new(Mutex::new(AddSend(og_writer)));
        let (handle_from_tx, handle_from_rx) = unbounded_channel::<IPCMessageWithId>();
        let (handle_to_tx, mut handle_to_rx) = unbounded_channel::<IPCMessageWithId>();

        let senders_writer = writer.clone();
        let mut sender = move |frame| {
          let senders_writer_two = senders_writer.clone();
          async move { senders_writer_two.lock().await.0.write_frame(frame).await }
        };

        let handle_tokens = cancellation_tokens.clone();
        let handle = spawn(async move {
          let recv_tokens = Arc::new(handle_tokens.clone());
          let recv_handle = spawn(async move {
            recv_tokens
              .0
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

          let send_tokens = Arc::new(handle_tokens.clone());
          let send_handle = spawn(async move {
            let sender_writer = writer.clone();
            send_tokens
              .0
              .run_until_cancelled(async move {
                while let Some(message) = handle_to_rx.recv().await {
                  match sender_writer
                    .lock()
                    .await
                    .0
                    .write_frame(Frame::text(
                      serde_jsonc::to_string(&message).unwrap().as_bytes().into(),
                    ))
                    .await
                  {
                    Ok(_) => {}
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
            handle_tokens.1.cancel();
          }}
        });

        self.to_server = Some(handle_to_tx);
        self.from_server = Some(handle_from_rx);

        Ok((handle, cancellation_tokens))
      }
      None => {
        return Err(error.unwrap());
      }
    }
  }
}
