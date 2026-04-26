use server_mieru_rs::acl;
use server_mieru_rs::business;
use server_mieru_rs::config;
use server_mieru_rs::connection;
use server_mieru_rs::core;
use server_mieru_rs::logger;
use server_mieru_rs::net;
use server_mieru_rs::outbound;

use logger::log;

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use acl::OutboundType;
use business::{
    ApiManager, MieruStatsCollector, MieruUserManager, PanelStatsCollector, StatsCollector,
    TaskConfig,
};
use connection::ConnectionManager;
use core::session::{SessionManager, SessionStream};
use core::underlay::registry::UserRegistry;
use core::underlay::tcp::TcpUnderlay;
use panel_core::PanelApi;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let cli = config::CliArgs::parse_args();
    cli.validate()?;

    logger::init_logger(&cli.log_mode);

    log::info!(
        api = %cli.api,
        node = cli.node,
        "Starting Mieru server"
    );

    let panel_config = business::PanelConfig {
        api: cli.api.clone(),
        token: cli.token.clone(),
        node_id: cli.node,
        node_type: panel_core::NodeType::Mieru,
        api_timeout: cli.api_timeout.as_secs(),
        debug: cli.log_mode == "debug",
        data_dir: cli.data_dir.clone(),
        ip_version: cli.panel_ip_version,
    };

    let api_manager = Arc::new(ApiManager::new(panel_config)?);
    let user_manager = Arc::new(MieruUserManager::new(business::uuid_key));

    let node_config = api_manager.fetch_config().await?;
    let remote_config = config::parse_mieru_config(node_config)?;
    let listen_config = config::parse_listen_config(&remote_config);

    log::info!(
        server_port = remote_config.server_port,
        transport = ?remote_config.transport,
        port_range = ?remote_config.port_range,
        ports = ?listen_config.ports,
        "Mieru config loaded"
    );

    api_manager.initialize(remote_config.server_port).await?;
    log::info!("Node initialized");

    let users = api_manager.fetch_users().await?;
    if let Some(users) = users {
        let count = users.len();
        user_manager.init(&users);
        log::info!(count, "Users loaded");
    }

    let router: Arc<dyn acl::OutboundRouter> = if let Some(ref acl_path) = cli.acl_conf_file {
        let acl_config = acl::load_acl_config(acl_path).await?;
        let engine = acl::AclEngine::new(
            acl_config,
            Some(cli.data_dir.as_path()),
            cli.refresh_geodata,
        )
        .await?;
        Arc::new(acl::AclRouter::with_block_private_ip(
            engine,
            cli.block_private_ip,
        ))
    } else if cli.block_private_ip {
        let engine = acl::AclEngine::new_default()?;
        Arc::new(acl::AclRouter::with_block_private_ip(engine, true))
    } else {
        Arc::new(acl::DirectRouter)
    };

    let stats_collector = Arc::new(PanelStatsCollector::new());
    let mieru_stats: Arc<dyn StatsCollector> =
        Arc::new(MieruStatsCollector(Arc::clone(&stats_collector)));
    let connection_manager = ConnectionManager::new();
    let semaphore = Arc::new(Semaphore::new(cli.max_connections));

    let task_config = TaskConfig::new(
        cli.fetch_users_interval,
        cli.report_traffics_interval,
        cli.heartbeat_interval,
    );
    let conn_mgr_for_kick = connection_manager.clone();
    let on_diff = Arc::new(move |diff: panel_core::UserDiff| {
        for uid in diff.removed_ids.iter().chain(diff.uuid_changed_ids.iter()) {
            let kicked = conn_mgr_for_kick.kick_user(*uid);
            if kicked > 0 {
                log::info!(user_id = uid, kicked, "Kicked user connections");
            }
        }
    });
    let background_tasks = business::BackgroundTasks::new(
        task_config,
        Arc::clone(&api_manager),
        Arc::clone(&user_manager),
        Arc::clone(&stats_collector),
    )
    .on_user_diff(on_diff);
    let background_handle = background_tasks.start();

    let cancel_token = CancellationToken::new();

    for &port in &listen_config.ports {
        if listen_config.tcp_enabled {
            let listener = net::bind_tcp_dual_stack(port)?;
            let addr = listener.local_addr()?;
            log::info!(addr = %addr, "TCP listening");

            let user_mgr = Arc::clone(&user_manager);
            let stats = Arc::clone(&mieru_stats);
            let router = Arc::clone(&router);
            let sem = Arc::clone(&semaphore);
            let cancel = cancel_token.clone();
            let conn_mgr = connection_manager.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((mut stream, peer)) => {
                                    let permit = match sem.clone().try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            log::warn!("max connections reached, rejecting {}", peer);
                                            continue;
                                        }
                                    };
                                    let _ = stream.set_nodelay(true);

                                    let user_mgr = Arc::clone(&user_mgr);
                                    let stats = Arc::clone(&stats);
                                    let router = Arc::clone(&router);
                                    let conn_mgr = conn_mgr.clone();
                                    let cancel = cancel.clone();

                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Err(e) = handle_tcp_connection(
                                            &mut stream,
                                            &user_mgr,
                                            &stats,
                                            &router,
                                            &conn_mgr,
                                            cancel,
                                        ).await {
                                            log::debug!(peer = %peer, error = %e, "TCP connection ended");
                                        }
                                    });
                                }
                                Err(e) => {
                                    log::warn!(error = %e, "TCP accept error");
                                }
                            }
                        }
                        _ = cancel.cancelled() => break,
                    }
                }
            });
        }

        if listen_config.udp_enabled {
            let socket = Arc::new(net::bind_udp_dual_stack(port)?);
            let addr = socket.local_addr()?;
            log::info!(addr = %addr, "UDP listening");

            let user_mgr = Arc::clone(&user_manager);
            let stats = Arc::clone(&mieru_stats);
            let cancel = cancel_token.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 1500];
                loop {
                    tokio::select! {
                        result = socket.recv_from(&mut buf) => {
                            match result {
                                Ok((n, peer)) => {
                                    let packet = buf[..n].to_vec();
                                    let registry = UserRegistry::from_user_manager(&user_mgr);
                                    if let Some((user_id, _key, _nonce, _metadata, _payload)) =
                                        core::underlay::udp::authenticate_packet(&packet, &registry)
                                    {
                                        log::debug!(peer = %peer, user_id, "UDP packet authenticated");
                                        stats.record_upload(user_id, n as u64);
                                        stats.record_request(user_id);
                                    }
                                }
                                Err(e) => {
                                    log::warn!(error = %e, "UDP recv error");
                                }
                            }
                        }
                        _ = cancel.cancelled() => break,
                    }
                }
            });
        }
    }

    let cancel_clone = cancel_token.clone();
    let api_for_shutdown = Arc::clone(&api_manager);
    let shutdown_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM");
            tokio::select! {
                _ = sigint.recv() => log::info!("SIGINT received, shutting down..."),
                _ = sigterm.recv() => log::info!("SIGTERM received, shutting down..."),
                _ = cancel_clone.cancelled() => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => log::info!("Shutdown signal received..."),
                _ = cancel_clone.cancelled() => {}
            }
        }
        cancel_clone.cancel();
        api_for_shutdown
    });

    let api_for_shutdown = shutdown_handle.await?;

    log::info!("Server stopped, performing graceful shutdown...");

    let active = connection_manager.connection_count();
    if active > 0 {
        log::info!(active, "Draining active connections");
        connection_manager
            .shutdown_drain(Duration::from_secs(5))
            .await;
        let remaining = connection_manager.connection_count();
        if remaining > 0 {
            log::warn!(remaining, "Drain timeout, forcing shutdown");
        } else {
            log::info!("All connections drained");
        }
    }

    log::info!("Unregistering node...");
    if let Err(e) = api_for_shutdown.unregister().await {
        log::warn!(error = %e, "Failed to unregister node");
    } else {
        log::info!("Node unregistered successfully");
    }
    background_handle.shutdown().await;

    log::info!("Shutdown complete");
    Ok(())
}

async fn handle_tcp_connection(
    stream: &mut tokio::net::TcpStream,
    user_manager: &MieruUserManager,
    stats: &Arc<dyn StatsCollector>,
    router: &Arc<dyn acl::OutboundRouter>,
    conn_mgr: &ConnectionManager,
    cancel: CancellationToken,
) -> Result<()> {
    let registry = UserRegistry::from_user_manager(user_manager);

    let (mut underlay, first_meta, first_payload) =
        TcpUnderlay::authenticate(stream, &registry).await?;

    let user_id = underlay.user_id;
    let guard = conn_mgr.register(user_id);
    stats.record_request(user_id);

    let (mut session_mgr, mut outbound_rx) = SessionManager::new();

    if let Some(session_stream) = session_mgr.dispatch(&first_meta, first_payload) {
        let router = Arc::clone(router);
        let stats = Arc::clone(stats);
        tokio::spawn(async move {
            handle_session(session_stream, &*router, user_id, &*stats).await;
        });
    }

    loop {
        tokio::select! {
            result = underlay.read_segment(stream) => {
                match result {
                    Ok((metadata, payload)) => {
                        let upload_bytes = payload.len() as u64;
                        if upload_bytes > 0 {
                            stats.record_upload(user_id, upload_bytes);
                        }
                        if let Some(session_stream) = session_mgr.dispatch(&metadata, payload) {
                            let router = Arc::clone(router);
                            let stats = Arc::clone(stats);
                            tokio::spawn(async move {
                                handle_session(session_stream, &*router, user_id, &*stats).await;
                            });
                        }
                    }
                    Err(_) => break,
                }
            }
            seg = outbound_rx.recv() => {
                match seg {
                    Some(seg) => {
                        if let Err(e) = underlay.write_segment(stream, &seg.metadata, &seg.payload).await {
                            log::debug!(error = %e, "Write segment failed");
                            break;
                        }
                        let download_bytes = seg.payload.len() as u64;
                        if download_bytes > 0 {
                            stats.record_download(user_id, download_bytes);
                        }
                    }
                    None => break,
                }
            }
            _ = guard.cancel.cancelled() => break,
            _ = cancel.cancelled() => break,
        }
    }

    session_mgr.close_all();
    Ok(())
}

async fn handle_session(
    mut session: SessionStream,
    router: &dyn acl::OutboundRouter,
    user_id: business::UserId,
    _stats: &dyn StatsCollector,
) {
    let first_data = match session.recv().await {
        Some(data) => data,
        None => return,
    };

    let (target, consumed) = match outbound::parse_socks_address(&first_data) {
        Ok(r) => r,
        Err(e) => {
            log::debug!(error = %e, "Failed to parse target address");
            return;
        }
    };

    log::debug!(target = %target, user_id, "Session opened");

    let route = router.route(&target).await;
    match route {
        OutboundType::Direct { resolved } => {
            match outbound::connect_target(&target, resolved, CONNECT_TIMEOUT).await {
                Ok(mut remote) => {
                    let remaining = &first_data[consumed..];
                    if !remaining.is_empty()
                        && let Err(e) = remote.write_all(remaining).await
                    {
                        log::debug!(error = %e, "Failed to send initial data");
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut session, &mut remote).await;
                }
                Err(e) => {
                    log::debug!(target = %target, error = %e, "Failed to connect");
                }
            }
        }
        OutboundType::Reject => {
            log::debug!(target = %target, "Connection rejected by ACL");
        }
        _ => {
            log::debug!(target = %target, "Proxy outbound");
        }
    }
}
