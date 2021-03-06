use std::{
    cmp::min,
    collections::HashSet,
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use chrono::{TimeZone, Utc};
use futures::{SinkExt, StreamExt};
use tokio::{net::TcpStream, time::timeout};
use tokio_util::codec::Framed;
use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;
use zebra_chain::{
    block,
    chain_tip::{ChainTip, NoChainTip},
    parameters::Network,
};
use zebra_network::{
    Config,
    constants,
    peer::HandshakeError,
    protocol::external::{
        Codec,
        Message, types::{Nonce, PeerServices, Version},
    },
};

/// Negotiate the Zcash network protocol version with the remote peer
/// at `connected_addr`, using the connection `peer_conn`.
#[allow(clippy::too_many_arguments)]
pub async fn negotiate_version(
    peer_conn: &mut Framed<TcpStream, Codec>,
    connected_addr: &SocketAddr,
    config: Config,
    nonces: Arc<futures::lock::Mutex<HashSet<Nonce>>>,
    user_agent: String,
    our_services: PeerServices,
    relay: bool,
    latest_chain_tip: impl ChainTip,
) -> Result<(Version, PeerServices, SocketAddr), HandshakeError> {


    // Create a random nonce for this connection
    let local_nonce = Nonce::default();
    nonces.lock().await.insert(local_nonce);

    let now = Utc::now().timestamp();
    let timestamp = Utc.timestamp(now - now.rem_euclid(5 * 60), 0);
    let their_addr = connected_addr;
    let our_listen_addr =  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9909);


    let our_version = Message::Version {
        version: constants::CURRENT_NETWORK_PROTOCOL_VERSION,
        services: our_services,
        timestamp,
        address_recv: (PeerServices::NODE_NETWORK, *their_addr),
        address_from: (our_services, our_listen_addr),
        nonce: local_nonce,
        user_agent: user_agent.clone(),
        // The protocol works fine if we don't reveal our current block height,
        // and not sending it means we don't need to be connected to the chain state.
        start_height: block::Height(0),
        relay,
    };

    debug!(?our_version, "sending initial version message");
    peer_conn.send(our_version).await?;

    let remote_msg = peer_conn
        .next()
        .await
        .ok_or(HandshakeError::ConnectionClosed)??;

    // Check that we got a Version and destructure its fields into the local scope.
    debug!(?remote_msg, "got message from remote peer");
    let (remote_nonce, remote_services, remote_version, remote_canonical_addr, user_agent) =
        if let Message::Version {
            version,
            services,
            address_from,
            nonce,
            user_agent,
            ..
        } = remote_msg
        {
            let (address_services, canonical_addr) = address_from;
            if address_services != services {
                info!(
                    ?services,
                    ?address_services,
                    "peer with inconsistent version services and version address services"
                );
            }

            (nonce, services, version, canonical_addr, user_agent)
        } else {
            Err(HandshakeError::UnexpectedMessage(Box::new(remote_msg)))?
        };

    let nonce_reuse = {
        let mut locked_nonces = nonces.lock().await;
        let nonce_reuse = locked_nonces.contains(&remote_nonce);
        // Regardless of whether we observed nonce reuse, clean up the nonce set.
        locked_nonces.remove(&local_nonce);
        nonce_reuse
    };
    if nonce_reuse {
        Err(HandshakeError::NonceReuse)?;
    }

    // SECURITY: Reject connections to peers on old versions, because they might not know about all
    // network upgrades and could lead to chain forks or slower block propagation.
    let height = latest_chain_tip.best_tip_height();
    let min_version = Version::min_remote_for_height(config.network, height);
    if remote_version < min_version {
        debug!(
            remote_ip = ?their_addr,
            ?remote_version,
            ?min_version,
            "disconnecting from peer with obsolete network protocol version"
        );
        // Disconnect if peer is using an obsolete version.
        Err(HandshakeError::ObsoleteVersion(remote_version))?;
    } else {
        let negotiated_version = min(constants::CURRENT_NETWORK_PROTOCOL_VERSION, remote_version);

        debug!(
            remote_ip = ?their_addr,
            ?remote_version,
            ?negotiated_version,
            ?min_version,
            "negotiated network protocol version with peer"
        );
    }

    peer_conn.send(Message::Verack).await?;

    let remote_msg = peer_conn
        .next()
        .await
        .ok_or(HandshakeError::ConnectionClosed)??;
    if let Message::Verack = remote_msg {
        debug!("got verack from remote peer");
    } else {
        Err(HandshakeError::UnexpectedMessage(Box::new(remote_msg)))?;
    }

    Ok((remote_version, remote_services, remote_canonical_addr))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::DEBUG)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let config = Config {
        network: Network::Mainnet,
        ..Config::default()
    };

    //let connected_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18233);
    let connected_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(47, 253, 8, 99)), 8233);
    let mut tcp_stream = TcpStream::connect(connected_addr).await?;
    let mut peer_conn = Framed::new(
        tcp_stream,
        Codec::builder()
            .for_network(config.network)
            .with_metrics_addr_label("this-label-is-not-used".to_string())
            .finish(),
    );
    let nonces = Arc::new(futures::lock::Mutex::new(HashSet::new()));
    let user_agent = String::from("/MyRustUserAgent/");
    let our_services = PeerServices::NODE_NETWORK;
    let relay = false;
    let latest_chain_tip = NoChainTip;

    let (remote_version, remote_services, remote_canonical_addr) = timeout(
        Duration::from_secs(4),
        negotiate_version(
            &mut peer_conn,
            &connected_addr,
            config,
            nonces,
            user_agent,
            our_services,
            relay,
            latest_chain_tip,
        ),
    ).await??;

    Ok(())
}
