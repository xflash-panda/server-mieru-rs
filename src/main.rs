use logger::log;
use server_mieru_rs::acl;
use server_mieru_rs::business;
use server_mieru_rs::config;
use server_mieru_rs::connection;
use server_mieru_rs::core;
use server_mieru_rs::logger;
use server_mieru_rs::net;

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use business::{
    ApiManager, MieruStatsCollector, MieruUserManager, NodeType, PanelStatsCollector,
    StatsCollector, TaskConfig,
};
use connection::ConnectionManager;
use core::session::SessionManager;
use core::underlay::registry::UserRegistry;
use core::underlay::tcp::TcpUnderlay;
use core::underlay::udp_relay::handle_session;
use panel_core::PanelApi;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = config::CliArgs::parse_args();
    cli.validate()?;

    logger::init_logger(&cli.log_mode);

    log::info!(
        server_host = %cli.server_host,
        port = cli.port,
        node = cli.node,
        "Starting Mieru server agent"
    );

    let panel_config = business::PanelConfig {
        server_host: cli.server_host.clone(),
        server_port: cli.port,
        node_id: cli.node,
        node_type: NodeType::Mieru,
        data_dir: cli.data_dir.clone(),
        api_timeout: cli.api_timeout,
        server_name: cli
            .server_name
            .clone()
            .unwrap_or_else(|| cli.server_host.clone()),
        ca_cert_path: cli.ca_file.clone(),
        ip_version: cli.panel_ip_version,
    };

    let api_manager = Arc::new(ApiManager::new(panel_config));
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
    let relay_idle_timeout = cli.relay_idle_timeout;

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

    // Shared registry for TCP listeners, refreshed every 2 minutes.
    // Build initial registry on blocking thread to avoid starving async runtime.
    let initial_registry = {
        let mgr = Arc::clone(&user_manager);
        tokio::task::spawn_blocking(move || UserRegistry::from_user_manager(&mgr))
            .await?
    };
    let tcp_registry: Arc<tokio::sync::RwLock<Arc<UserRegistry>>> = Arc::new(
        tokio::sync::RwLock::new(Arc::new(initial_registry)),
    );
    {
        let user_mgr = Arc::clone(&user_manager);
        let registry = Arc::clone(&tcp_registry);
        let cancel = cancel_token.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(120));
            tick.tick().await; // skip first immediate tick
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let mgr = Arc::clone(&user_mgr);
                        match tokio::task::spawn_blocking(move || {
                            UserRegistry::from_user_manager(&mgr)
                        }).await {
                            Ok(new) => *registry.write().await = Arc::new(new),
                            Err(e) => log::warn!(error = %e, "registry refresh failed"),
                        }
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        });
    }

    for &port in &listen_config.ports {
        if listen_config.tcp_enabled {
            let listener = net::bind_tcp_dual_stack(port)?;
            let addr = listener.local_addr()?;
            log::info!(addr = %addr, "TCP listening");

            let tcp_registry = Arc::clone(&tcp_registry);
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
                                Ok((stream, peer)) => {
                                    log::debug!(peer = %peer, "new connection");
                                    let permit = match sem.clone().try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            log::warn!("max connections reached, rejecting {}", peer);
                                            continue;
                                        }
                                    };
                                    let _ = stream.set_nodelay(true);
                                    net::set_tcp_keepalive(&stream);

                                    let registry = Arc::clone(&*tcp_registry.read().await);
                                    let stats = Arc::clone(&stats);
                                    let router = Arc::clone(&router);
                                    let conn_mgr = conn_mgr.clone();
                                    let cancel = cancel.clone();

                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Err(e) = handle_tcp_connection(
                                            stream,
                                            &registry,
                                            &stats,
                                            &router,
                                            &conn_mgr,
                                            cancel,
                                            relay_idle_timeout,
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
            let router = Arc::clone(&router);
            let cancel = cancel_token.clone();
            let conn_mgr = connection_manager.clone();

            tokio::spawn(async move {
                let relay = core::underlay::udp_relay::UdpRelay::new(socket);
                relay
                    .run(
                        user_mgr,
                        stats,
                        router,
                        conn_mgr,
                        cancel,
                        relay_idle_timeout,
                    )
                    .await;
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
    mut stream: tokio::net::TcpStream,
    registry: &UserRegistry,
    stats: &Arc<dyn StatsCollector>,
    router: &Arc<dyn acl::OutboundRouter>,
    conn_mgr: &ConnectionManager,
    cancel: CancellationToken,
    relay_idle_timeout: Duration,
) -> Result<()> {
    let (underlay, first_meta, first_payload) =
        TcpUnderlay::authenticate(&mut stream, registry).await?;

    let user_id = underlay.user_id;
    let guard = conn_mgr.register(user_id);
    stats.record_request(user_id);

    let (mut reader, mut writer) = underlay.split();
    let (mut session_mgr, outbound_rx) = SessionManager::new();

    // Split TCP stream so read and write can run independently.
    let (mut read_half, mut write_half) = stream.into_split();

    if let Some(session_stream) = session_mgr.dispatch(&first_meta, first_payload).await {
        let router = Arc::clone(router);
        let stats = Arc::clone(stats);
        tokio::spawn(async move {
            handle_session(
                session_stream,
                &*router,
                user_id,
                &*stats,
                relay_idle_timeout,
            )
            .await;
        });
    }

    // Independent write task: drains outbound_rx → TCP.
    // This prevents deadlock: even when dispatch().await blocks the read
    // loop, outbound segments continue flowing to the client, allowing
    // sessions to drain their data channels and unblock dispatch.
    let stats_w = Arc::clone(stats);
    let cancel_w = cancel.clone();
    let guard_cancel_w = guard.cancel.clone();
    let write_done = CancellationToken::new();
    let write_done_signal = write_done.clone();
    let write_task = tokio::spawn(async move {
        let mut outbound_rx = outbound_rx;
        loop {
            tokio::select! {
                seg = outbound_rx.recv() => {
                    match seg {
                        Some(seg) => {
                            log::debug!(
                                protocol = ?seg.metadata.protocol_type(),
                                session_id = seg.metadata.session_id(),
                                payload_len = seg.payload.len(),
                                "writing outbound segment to TCP"
                            );
                            let download_bytes = seg.payload.len() as u64;
                            if let Err(e) = writer.write_segment(
                                &mut write_half,
                                &seg.metadata,
                                &seg.payload,
                                &seg.prefix_padding,
                                &seg.suffix_padding,
                            ).await {
                                log::debug!(error = %e, "Write segment failed");
                                break;
                            }
                            if download_bytes > 0 {
                                stats_w.record_download(user_id, download_bytes);
                            }
                        }
                        None => break,
                    }
                }
                _ = guard_cancel_w.cancelled() => break,
                _ = cancel_w.cancelled() => break,
            }
        }
        write_done_signal.cancel();
    });

    // Read loop: reads from TCP → dispatches to sessions.
    // dispatch().await may block when a session channel is full — this is
    // correct TCP backpressure. The write task runs independently so
    // outbound data keeps flowing even while dispatch blocks.
    loop {
        tokio::select! {
            result = reader.read_segment(&mut read_half) => {
                match result {
                    Ok((metadata, payload)) => {
                        let upload_bytes = payload.len() as u64;
                        if upload_bytes > 0 {
                            stats.record_upload(user_id, upload_bytes);
                        }
                        if let Some(session_stream) = session_mgr.dispatch(&metadata, payload).await {
                            let router = Arc::clone(router);
                            let stats = Arc::clone(stats);
                            tokio::spawn(async move {
                                handle_session(session_stream, &*router, user_id, &*stats, relay_idle_timeout).await;
                            });
                        }
                    }
                    Err(e) => {
                        log::debug!(error = %e, "read_segment failed, closing underlay");
                        break;
                    }
                }
            }
            _ = write_done.cancelled() => {
                log::debug!("write task exited, stopping read loop");
                break;
            }
            _ = guard.cancel.cancelled() => break,
            _ = cancel.cancelled() => break,
        }
    }

    session_mgr.close_all().await;
    drop(session_mgr); // drop outbound_tx → write task sees None → exits
    let _ = tokio::time::timeout(Duration::from_secs(2), write_task).await;
    Ok(())
}
