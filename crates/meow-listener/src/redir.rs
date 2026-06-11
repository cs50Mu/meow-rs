use crate::sniffer::SnifferRuntime;
use crate::tproxy::orig_dest;
use meow_common::{ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf, ConnectionGuard, Tunnel, RELAY_BUF_SIZE};
use smallvec::smallvec;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info};

pub struct RedirListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
}

impl RedirListener {
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        sniffer: Option<Arc<SnifferRuntime>>,
        name: String,
    ) -> Self {
        Self {
            tunnel,
            listen_addr,
            sniffer,
            name,
        }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(
            "Redir listener '{}' started on {}",
            self.name, self.listen_addr
        );

        loop {
            let (stream, src_addr) = listener.accept().await?;
            let tunnel = self.tunnel.clone();
            let listen_addr = self.listen_addr;
            let sniffer = self.sniffer.clone();
            let name = self.name.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_redir(tunnel, stream, src_addr, listen_addr, sniffer, &name).await
                {
                    debug!("Redir connection error from {src_addr}: {e}");
                }
            });
        }
    }
}

async fn handle_redir(
    tunnel: Tunnel,
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Recover the original destination (set by iptables REDIRECT via SO_ORIGINAL_DST).
    let orig_dst = orig_dest::get_original_dst(&stream, listen_addr)?;
    if orig_dst == listen_addr {
        return Ok(());
    }

    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::TProxy,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip: Some(orig_dst.ip()),
        dst_port: orig_dst.port(),
        in_name: name.into(),
        in_port: listen_addr.port(),
        ..Default::default()
    };

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
        debug!("No matching rule for redir {} -> {}", src_addr, orig_dst);
        return Ok(());
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    let guard = ConnectionGuard::track(
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
            let (up, down) =
                copy_bidirectional_buf(&mut stream, &mut remote, &mut buf1, &mut buf2).await
                    .unwrap_or((0, 0));
            guard.record_traffic(up, down);
        }
        Err(e) => debug!("Redir dial error {} -> {}: {}", src_addr, orig_dst, e),
    }
    Ok(())
}
