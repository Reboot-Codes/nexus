/// Use in a thread to connect to send messages to/recieve messages from nexus with.
/// Requires a [NexusClient](nexus::client::NexusClient) or a tokio IPC channel
/// connected to an embedded Nexus server to actually send messages.
///
/// This struct basically just ensures that messages are formatted properly.
pub struct NexusUser {}
