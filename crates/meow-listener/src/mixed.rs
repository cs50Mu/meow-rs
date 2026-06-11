use crate::http_proxy;
use crate::sniffer::SnifferRuntime;
use crate::socks5;
use crate::tproxy::orig_dest;
use meow_common::AuthConfig;
use meow_common::{ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf, ConnectionGuard, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Default cap on in-flight inbound connections per listener.
/// `0` means no cap — the listener accepts as many concurrent connections as
/// the kernel and tokio runtime can hold. Set a positive value (via the
/// `max-connections` config key, top-level or per-listener) to back-pressure
/// the TCP listen queue and bound RSS under burst load: each live
/// VLESS+WS+TLS+ECH tunnel costs ~90 KB of userland memory, so a cap of 256
/// holds RSS to ~50 MB on top of an ~18 MB idle baseline.
pub const DEFAULT_MAX_CONNECTIONS: usize = 0;

pub struct MixedListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
    auth: Option<Arc<AuthConfig>>,
    max_connections: usize,
}

impl MixedListener {
    pub fn new(tunnel: Tunnel, listen_addr: SocketAddr, name: String) -> Self {
        Self {
            tunnel,
            listen_addr,
            sniffer: None,
            name,
            auth: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    /// Override the cap on in-flight inbound connections (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    pub fn with_sniffer(mut self, sniffer: Arc<SnifferRuntime>) -> Self {
        if sniffer.is_enabled() {
            self.sniffer = Some(sniffer);
        }
        self
    }

    pub fn with_auth(mut self, auth: Arc<AuthConfig>) -> Self {
        if !auth.credentials.is_empty() {
            self.auth = Some(auth);
        }
        self
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        if self.max_connections == 0 {
            info!(
                "Mixed listener '{}' on {} (max_connections=unlimited)",
                self.name, self.listen_addr
            );
        } else {
            info!(
                "Mixed listener '{}' on {} (max_connections={})",
                self.name, self.listen_addr, self.max_connections
            );
        }

        // Bound the number of in-flight connection-handler tasks so RSS stays
        // capped under burst load. The semaphore is None when max=0
        // (cap disabled).
        let conn_limit: Option<Arc<Semaphore>> = if self.max_connections > 0 {
            Some(Arc::new(Semaphore::new(self.max_connections)))
        } else {
            None
        };
        let mut warned_saturated = false;

        loop {
            // Acquire a slot before accepting — back-pressures the TCP listen
            // queue when the cap is reached rather than spawning unbounded
            // tasks and bloating RSS.
            let permit = if let Some(sem) = &conn_limit {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "Mixed listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, self.max_connections
                    );
                    warned_saturated = true;
                }
                match sem.acquire_owned().await {
                    Ok(p) => {
                        if warned_saturated {
                            debug!("Mixed listener '{}' has free capacity again", self.name);
                            warned_saturated = false;
                        }
                        Some(p)
                    }
                    Err(_) => return Ok(()), // semaphore closed → shutdown
                }
            } else {
                None
            };

            let (stream, src_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!("Accept error: {}", e);
                    drop(permit);
                    continue;
                }
            };

            let tunnel = self.tunnel.clone();
            let sniffer = self.sniffer.clone();
            let name = self.name.clone();
            let port = self.listen_addr.port();
            let auth = self.auth.clone();
            tokio::spawn(async move {
                handle_connection(tunnel, stream, src_addr, sniffer, name, port, auth).await;
                drop(permit);
            });
        }
    }
}

async fn handle_connection(
    tunnel: Tunnel,
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
    port: u16,
    auth: Option<Arc<AuthConfig>>,
) {
    // Peek first bytes to determine protocol.
    let mut peek = [0u8; 8];
    let n = match stream.peek(&mut peek).await {
        Ok(0) => return,
        Ok(n) => n,
        Err(e) => {
            debug!("Peek error: {}", e);
            return;
        }
    };

    if peek[0] == 0x05 {
        // SOCKS5
        socks5::handle_socks5(
            &tunnel,
            stream,
            src_addr,
            sniffer.as_deref(),
            auth.as_deref(),
            &name,
            port,
        )
        .await;
    } else if is_http_proxy_request(&peek[..n]) {
        // HTTP proxy (CONNECT or GET http://host/path)
        http_proxy::handle_http(
            &tunnel,
            stream,
            src_addr,
            sniffer.as_deref(),
            auth.as_deref(),
            &name,
            port,
        )
        .await;
    } else {
        // Transparent proxy (TLS ClientHello, bare HTTP, or other TCP)
        handle_transparent_proxy(&tunnel, stream, src_addr, sniffer, &name, port).await;
    }
}

/// Returns true if the peeked bytes look like an HTTP proxy request:
/// starts with an ASCII HTTP method and has an absolute URI or CONNECT target.
fn is_http_proxy_request(peek: &[u8]) -> bool {
    let head = String::from_utf8_lossy(peek);
    let first_line = head.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return false;
    }
    let method = parts[0];
    let target = parts[1];
    // Valid HTTP method — all uppercase ASCII letters
    if !method
        .as_bytes()
        .iter()
        .all(|b| b.is_ascii_uppercase())
    {
        return false;
    }
    // CONNECT always goes to HTTP proxy handler
    if method.eq_ignore_ascii_case("CONNECT") {
        return true;
    }
    // Absolute URI (http://host/path) → proxy request
    target.starts_with("http://") || target.starts_with("https://")
}

/// Handle a transparent proxy connection: recover the original destination
/// from the socket, sniff the hostname, and relay through the tunnel.
async fn handle_transparent_proxy(
    tunnel: &Tunnel,
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: &str,
    in_port: u16,
) {
    // Try to recover the original destination (works with iptables REDIRECT
    // via SO_ORIGINAL_DST on Linux).
    let listen_addr = stream
        .local_addr()
        .ok()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], in_port)));
    let orig_dst = match orig_dest::get_original_dst(&stream, listen_addr) {
        Ok(dst) => dst,
        Err(e) => {
            debug!("Failed to get original dst for {}: {}", src_addr, e);
            return;
        }
    };
    if orig_dst == listen_addr {
        return;
    }

    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::TProxy,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip: Some(orig_dst.ip()),
        dst_port: orig_dst.port(),
        in_name: name.into(),
        in_port,
        ..Default::default()
    };

    // Sniff TLS SNI or HTTP Host header for the hostname.
    if let Some(rt) = sniffer.as_deref() {
        rt.sniff(&stream, &mut metadata).await;
    }
    let mut hostname = metadata.sniff_host.clone();
    if hostname.is_empty() {
        if let Some(domain) = tunnel.resolver().reverse_lookup(orig_dst.ip()) {
            hostname = domain;
        }
    }
    metadata.host = hostname;

    let inner = tunnel.inner();
    let Some((proxy, rule_name, rule_payload)) = inner.resolve_proxy(&metadata) else {
        debug!("No matching rule for transparent proxy from {}", src_addr);
        return;
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    let _guard = ConnectionGuard::track(
        &inner.stats,
        metadata.pure(),
        rule_name,
        rule_payload,
        smallvec![Arc::from(proxy.name())],
    );

    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => {
            let mut buf1 = vec![0u8; RELAY_BUF_SIZE];
            let mut buf2 = vec![0u8; RELAY_BUF_SIZE];
            let _ = copy_bidirectional_buf(
                &mut stream,
                &mut remote,
                &mut buf1,
                &mut buf2,
            )
            .await;
        }
        Err(e) => {
            debug!(
                "Transparent proxy dial error for {} -> {}: {}",
                src_addr, orig_dst, e
            );
        }
    }
}
