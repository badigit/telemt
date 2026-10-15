use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn socks(blackhole: bool, wrong_nonce: bool) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(5), async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                seen.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(4), async {
                        let mut greeting = [0; 3];
                        stream.read_exact(&mut greeting).await?;
                        stream.write_all(&[5, 0]).await?;
                        let mut connect = [0; 10];
                        stream.read_exact(&mut connect).await?;
                        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34]).await?;
                        if blackhole {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                        } else {
                            let mut request = [0; 48];
                            if stream.read_exact(&mut request).await.is_ok() {
                                let mut response = [0; 40];
                                response[20..24].copy_from_slice(&0x05162463u32.to_le_bytes());
                                response[24..40].copy_from_slice(&request[32..48]);
                                if wrong_nonce { response[24] ^= 1; }
                                stream.write_all(&40u32.to_le_bytes()).await?;
                                stream.write_all(&response).await?;
                            }
                        }
                        Ok::<_, std::io::Error>(())
                    }).await;
                });
            }
        }).await;
    });
    (address, count, task)
}

fn config(address: SocketAddr, scope: &str) -> UpstreamConfig {
    toml::from_str(&format!("type = 'socks5'\naddress = '{address}'\nscopes = '{scope}'")).unwrap()
}

fn manager(configs: Vec<UpstreamConfig>, budget: u64) -> UpstreamManager {
    UpstreamManager::new(configs, 3, 0, budget, 1, 1, true, Arc::new(Stats::new()))
        .with_failover(true, true)
}

#[tokio::test]
async fn priority_keeps_healthy_primary_and_successful_egress() {
    let (first, first_count, a) = socks(false, false).await;
    let (second, second_count, b) = socks(false, false).await;
    let m = manager(vec![config(first, ""), config(second, "")], 1500);
    let (_, egress) = tokio::time::timeout(Duration::from_secs(2),
        m.connect_failover("127.0.0.1:443".parse().unwrap(), None, None, true)).await.unwrap().unwrap();
    assert_eq!(egress.upstream_id, 0);
    assert_eq!(egress.socks_proxy_addr, Some(first));
    assert_eq!(first_count.load(Ordering::Relaxed), 2);
    assert_eq!(second_count.load(Ordering::Relaxed), 0);
    a.abort(); b.abort();
}

#[tokio::test]
async fn refused_primary_fails_over_even_with_hard_failfast() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first = closed.local_addr().unwrap();
    drop(closed);
    let (second, _, task) = socks(false, false).await;
    let m = manager(vec![config(first, ""), config(second, "")], 1500);
    let (_, egress) = tokio::time::timeout(Duration::from_secs(2),
        m.connect_failover("127.0.0.1:443".parse().unwrap(), None, None, true)).await.unwrap().unwrap();
    assert_eq!(egress.upstream_id, 1);
    assert!(!m.upstreams.read().await[0].healthy);
    task.abort();
}

#[tokio::test]
async fn socks_success_followed_by_blackhole_uses_reserve() {
    let (first, first_count, a) = socks(true, false).await;
    let (second, _, b) = socks(false, false).await;
    let m = manager(vec![config(first, ""), config(second, "")], 1800);
    let started = Instant::now();
    let (_, egress) = tokio::time::timeout(Duration::from_secs(2),
        m.connect_failover("127.0.0.1:443".parse().unwrap(), None, None, true)).await.unwrap().unwrap();
    assert_eq!(egress.upstream_id, 1);
    assert_eq!(first_count.load(Ordering::Relaxed), 1);
    assert!(started.elapsed() < Duration::from_millis(1800));
    a.abort(); b.abort();
}

#[tokio::test]
async fn mismatched_probe_nonce_is_rejected_and_third_route_is_used() {
    let (first, _, a) = socks(false, true).await;
    let (second, _, b) = socks(false, true).await;
    let (third, _, c) = socks(false, false).await;
    let m = manager(vec![config(first, ""), config(second, ""), config(third, "")], 1500);
    let (_, egress) = tokio::time::timeout(Duration::from_secs(2),
        m.connect_failover("127.0.0.1:443".parse().unwrap(), None, None, true)).await.unwrap().unwrap();
    assert_eq!(egress.upstream_id, 2);
    a.abort(); b.abort(); c.abort();
}

#[tokio::test]
async fn blackhole_respects_total_budget_and_does_not_repeat_a_route() {
    let (first, count, task) = socks(true, false).await;
    let m = manager(vec![config(first, "")], 100);
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(1),
        m.connect_failover("127.0.0.1:443".parse().unwrap(), None, None, true)).await.unwrap();
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_millis(400));
    assert_eq!(count.load(Ordering::Relaxed), 1);
    task.abort();
}

#[tokio::test]
async fn scope_never_leaks_to_another_scope_or_default() {
    let (first, count, task) = socks(false, false).await;
    let m = manager(vec![config(first, "other"), config(first, "")], 100);
    assert!(m.connect_failover("127.0.0.1:443".parse().unwrap(), None, Some("required"), false).await.is_err());
    assert_eq!(count.load(Ordering::Relaxed), 0);
    task.abort();
}

#[test]
fn failover_is_opt_in_and_config_keys_deserialize() {
    let m = UpstreamManager::new(Vec::new(), 3, 0, 100, 1, 1, true, Arc::new(Stats::new()));
    assert!(!m.failover && !m.failover_probe);
    let config: crate::config::GeneralConfig = toml::from_str("upstream_failover = true\nupstream_failover_probe = true").unwrap();
    assert!(config.upstream_failover && config.upstream_failover_probe);
}
