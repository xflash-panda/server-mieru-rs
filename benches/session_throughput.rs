//! Benchmarks for session dispatch and relay throughput.
//!
//! Compares:
//! - "combined" (old): single select! loop does both dispatch and outbound drain
//! - "split" (new): dispatch in one task, outbound drain in another task
//! - try_dispatch_data: non-blocking UDP path

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use server_mieru_rs::core::metadata::{
    DataMetadata, Metadata, ProtocolType, SessionMetadata, current_timestamp_minutes,
};
use server_mieru_rs::core::session::SessionManager;
use tokio::runtime::Runtime;

fn open_session_meta(session_id: u32) -> Metadata {
    Metadata::Session(SessionMetadata {
        protocol_type: ProtocolType::OpenSessionRequest,
        timestamp: current_timestamp_minutes(),
        session_id,
        sequence: 0,
        status_code: 0,
        payload_length: 0,
        suffix_padding_length: 0,
    })
}

fn data_meta(session_id: u32, payload_len: u16) -> Metadata {
    Metadata::Data(DataMetadata {
        protocol_type: ProtocolType::DataClientToServer,
        timestamp: current_timestamp_minutes(),
        session_id,
        sequence: 1,
        unack_seq: 0,
        window_size: 256,
        fragment_number: 0,
        prefix_padding_length: 0,
        payload_length: payload_len,
        suffix_padding_length: 0,
    })
}

/// OLD architecture: single task does both dispatch + outbound drain in one select! loop.
/// This is what the code looked like before the split.
fn bench_combined_single_task(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("old_combined_1session_1000msg", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut mgr, mut outbound_rx) = SessionManager::new();

                let meta = open_session_meta(1);
                let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();

                let total = 1000u32;

                // Session handler: reads + echoes (simulates copy_bidirectional)
                let session_task = tokio::spawn(async move {
                    let mut n = 0u32;
                    while let Some(data) = stream.recv().await {
                        if stream.send(data).await.is_err() {
                            break;
                        }
                        n += 1;
                        if n >= total {
                            break;
                        }
                    }
                    n
                });

                // OLD pattern: single loop doing both dispatch and outbound drain.
                let payload = vec![0x42; 1024];
                let mut dispatched = 0u32;
                loop {
                    tokio::select! {
                        // Simulate "read_segment" → dispatch
                        result = async {
                            if dispatched < total {
                                let dm = data_meta(1, payload.len() as u16);
                                mgr.dispatch(&dm, payload.clone()).await;
                                dispatched += 1;
                                true
                            } else {
                                // After all dispatched, just wait forever (let outbound drain)
                                std::future::pending::<bool>().await
                            }
                        } => {
                            if !result { break; }
                        }
                        // Simulate outbound writer in SAME select
                        seg = outbound_rx.recv() => {
                            match seg {
                                Some(_seg) => { /* "write_segment" */ }
                                None => break,
                            }
                        }
                    }
                    if dispatched >= total {
                        // Drain remaining outbound
                        break;
                    }
                }
                // Drain remaining outbound segments
                mgr.close_session(1).await;
                drop(mgr);
                while outbound_rx.recv().await.is_some() {}

                let processed = session_task.await.unwrap();
                assert_eq!(processed, total);
            })
        })
    });
}

/// NEW architecture: dispatch in read task, outbound drain in separate write task.
fn bench_split_two_tasks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("new_split_1session_1000msg", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut mgr, outbound_rx) = SessionManager::new();

                let meta = open_session_meta(1);
                let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();

                let total = 1000u32;

                // Write task: drains outbound (independent)
                let write_task = tokio::spawn(async move {
                    let mut outbound_rx = outbound_rx;
                    while let Some(_seg) = outbound_rx.recv().await {
                        // "write_segment"
                    }
                });

                // Session handler: reads + echoes
                let session_task = tokio::spawn(async move {
                    let mut n = 0u32;
                    while let Some(data) = stream.recv().await {
                        if stream.send(data).await.is_err() {
                            break;
                        }
                        n += 1;
                        if n >= total {
                            break;
                        }
                    }
                    n
                });

                // Read task: dispatches incoming data
                let payload = vec![0x42; 1024];
                for _ in 0..total {
                    let dm = data_meta(1, payload.len() as u16);
                    mgr.dispatch(&dm, payload.clone()).await;
                }

                mgr.close_session(1).await;
                drop(mgr);

                let processed = session_task.await.unwrap();
                assert_eq!(processed, total);
                write_task.await.unwrap();
            })
        })
    });
}

/// Compare old vs new with multiple sessions (the scenario where split helps most).
fn bench_multi_session_comparison(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let sessions = 10u32;
    let msgs_per_session = 100u32;

    let mut group = c.benchmark_group("multi_session_10x100");

    group.bench_function("old_combined", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut mgr, mut outbound_rx) = SessionManager::new();
                let mut consumers = Vec::new();

                for id in 1..=sessions {
                    let meta = open_session_meta(id);
                    let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
                    consumers.push(tokio::spawn(async move {
                        let mut n = 0u32;
                        while let Some(data) = stream.recv().await {
                            if stream.send(data).await.is_err() {
                                break;
                            }
                            n += 1;
                            if n >= msgs_per_session {
                                break;
                            }
                        }
                        n
                    }));
                }

                // OLD: single select loop
                let payload = vec![0xCD; 512];
                let mut dispatched = 0u32;
                let total = sessions * msgs_per_session;
                loop {
                    tokio::select! {
                        _ = async {
                            if dispatched < total {
                                let id = (dispatched % sessions) + 1;
                                let dm = data_meta(id, payload.len() as u16);
                                mgr.dispatch(&dm, payload.clone()).await;
                                dispatched += 1;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => {}
                        seg = outbound_rx.recv() => {
                            if seg.is_none() { break; }
                        }
                    }
                    if dispatched >= total {
                        break;
                    }
                }

                for id in 1..=sessions {
                    mgr.close_session(id).await;
                }
                drop(mgr);
                while outbound_rx.recv().await.is_some() {}

                for c in consumers {
                    let n = c.await.unwrap();
                    assert_eq!(n, msgs_per_session);
                }
            })
        })
    });

    group.bench_function("new_split", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut mgr, outbound_rx) = SessionManager::new();
                let mut consumers = Vec::new();

                for id in 1..=sessions {
                    let meta = open_session_meta(id);
                    let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
                    consumers.push(tokio::spawn(async move {
                        let mut n = 0u32;
                        while let Some(data) = stream.recv().await {
                            if stream.send(data).await.is_err() {
                                break;
                            }
                            n += 1;
                            if n >= msgs_per_session {
                                break;
                            }
                        }
                        n
                    }));
                }

                // NEW: separate write task
                let write_task = tokio::spawn(async move {
                    let mut outbound_rx = outbound_rx;
                    while let Some(_seg) = outbound_rx.recv().await {}
                });

                let payload = vec![0xCD; 512];
                for round in 0..(sessions * msgs_per_session) {
                    let id = (round % sessions) + 1;
                    let dm = data_meta(id, payload.len() as u16);
                    mgr.dispatch(&dm, payload.clone()).await;
                }

                for id in 1..=sessions {
                    mgr.close_session(id).await;
                }
                drop(mgr);

                for c in consumers {
                    let n = c.await.unwrap();
                    assert_eq!(n, msgs_per_session);
                }
                write_task.await.unwrap();
            })
        })
    });

    group.finish();
}

/// UDP non-blocking path benchmark.
fn bench_try_dispatch_data(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("udp_try_dispatch_3000msg", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut mgr, mut outbound_rx) = SessionManager::new();

                let meta = open_session_meta(1);
                let mut stream = mgr.dispatch(&meta, vec![]).await.unwrap();
                let _ = outbound_rx.try_recv();

                let total = 3000u32;
                let consumer = tokio::spawn(async move {
                    let mut n = 0u32;
                    while let Some(_) = stream.recv().await {
                        n += 1;
                        if n >= total {
                            break;
                        }
                    }
                    n
                });

                tokio::task::yield_now().await;

                let payload = vec![0xEF; 256];
                for _ in 0..total {
                    mgr.try_dispatch_data(1, payload.clone());
                }

                mgr.close_session(1).await;
                let received = consumer.await.unwrap();
                assert!(received >= total - 10, "too many drops: {received}/{total}");
            })
        })
    });
}

criterion_group!(
    benches,
    bench_combined_single_task,
    bench_split_two_tasks,
    bench_multi_session_comparison,
    bench_try_dispatch_data,
);
criterion_main!(benches);
