use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::Notify;

use crate::nfs::{AuthCreds, NfsConnector, NfsFh, NfsOps};

use super::error::ScannerError;

type PoolKey = (String, String, u32, u32);

struct PoolEntry {
    ops: Box<dyn NfsOps>,
    last_used: Instant,
}

struct KeyPool {
    idle: VecDeque<PoolEntry>,
    outstanding: usize,
    waiters: Arc<Notify>,
}

pub struct SharedConnectionPool {
    pools: DashMap<PoolKey, Arc<Mutex<KeyPool>>>,
    max_idle_per_key: usize,
    max_total_per_key: usize,
    connect_timeout: Duration,
    max_idle_age: Duration,
    health_check_age: Duration,
}

pub struct CheckedOut {
    ops: Option<Box<dyn NfsOps>>,
    key: PoolKey,
    pool: Arc<SharedConnectionPool>,
}

impl std::fmt::Debug for CheckedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedOut")
            .field("key", &self.key)
            .field("poisoned", &self.ops.is_none())
            .finish()
    }
}

impl CheckedOut {
    pub fn ops_mut(&mut self) -> &mut dyn NfsOps {
        &mut **self.ops.as_mut().expect("connection already poisoned")
    }

    pub fn root_handle(&self) -> &NfsFh {
        self.ops
            .as_ref()
            .expect("connection already poisoned")
            .root_handle()
    }

    pub fn poison(mut self) {
        self.ops.take();
    }
}

impl Drop for CheckedOut {
    fn drop(&mut self) {
        if let Some(ops) = self.ops.take() {
            self.pool.return_connection(self.key.clone(), ops);
        } else {
            self.pool.record_poison(&self.key);
        }
    }
}

impl SharedConnectionPool {
    #[must_use]
    pub fn new(
        max_idle_per_key: usize,
        max_total_per_key: usize,
        connect_timeout: Duration,
        max_idle_age: Duration,
    ) -> Self {
        Self {
            pools: DashMap::new(),
            max_idle_per_key,
            max_total_per_key,
            connect_timeout,
            max_idle_age,
            health_check_age: Duration::from_secs(5),
        }
    }

    pub async fn checkout(
        self: &Arc<Self>,
        connector: &dyn NfsConnector,
        host: &str,
        export: &str,
        creds: &AuthCreds,
    ) -> Result<CheckedOut, ScannerError> {
        let key: PoolKey = (host.into(), export.into(), creds.uid, creds.gid);

        enum Step {
            Reuse(PoolEntry, bool),
            Connect,
            Wait(Arc<Notify>),
        }

        loop {
            let kp_arc = self
                .pools
                .entry(key.clone())
                .or_insert_with(|| {
                    Arc::new(Mutex::new(KeyPool {
                        idle: VecDeque::new(),
                        outstanding: 0,
                        waiters: Arc::new(Notify::new()),
                    }))
                })
                .clone();

            let step = {
                let mut kp = kp_arc.lock().unwrap_or_else(PoisonError::into_inner);
                let now = Instant::now();
                while kp
                    .idle
                    .front()
                    .is_some_and(|e| now.duration_since(e.last_used) > self.max_idle_age)
                {
                    kp.idle.pop_front();
                }

                if let Some(entry) = kp.idle.pop_back() {
                    kp.outstanding += 1;
                    let is_fresh = now.duration_since(entry.last_used) < self.health_check_age;
                    Step::Reuse(entry, is_fresh)
                } else if kp.outstanding < self.max_total_per_key {
                    kp.outstanding += 1;
                    Step::Connect
                } else {
                    Step::Wait(Arc::clone(&kp.waiters))
                }
            };

            match step {
                Step::Reuse(entry, is_fresh) => {
                    let mut ops = entry.ops;
                    if is_fresh {
                        return Ok(CheckedOut {
                            ops: Some(ops),
                            key,
                            pool: Arc::clone(self),
                        });
                    }
                    let root = ops.root_handle().clone();
                    match tokio::time::timeout(Duration::from_secs(2), ops.getattr(&root)).await {
                        Ok(Ok(_)) => {
                            return Ok(CheckedOut {
                                ops: Some(ops),
                                key,
                                pool: Arc::clone(self),
                            });
                        }
                        _ => {
                            self.decrement_outstanding(&key);
                            continue;
                        }
                    }
                }
                Step::Connect => {
                    match tokio::time::timeout(
                        self.connect_timeout,
                        connector.connect(host, export, creds),
                    )
                    .await
                    {
                        Ok(Ok(ops)) => {
                            return Ok(CheckedOut {
                                ops: Some(ops),
                                key,
                                pool: Arc::clone(self),
                            });
                        }
                        Ok(Err(e)) => {
                            self.decrement_outstanding(&key);
                            return Err(ScannerError::from(e));
                        }
                        Err(_elapsed) => {
                            self.decrement_outstanding(&key);
                            return Err(ScannerError::Timeout(format!(
                                "connect to {host}:{export}"
                            )));
                        }
                    }
                }
                Step::Wait(notify) => {
                    notify.notified().await;
                }
            }
        }
    }

    fn with_key_pool<R>(&self, key: &PoolKey, f: impl FnOnce(&mut KeyPool) -> R) -> Option<R> {
        let kp_arc = self.pools.get(key).map(|r| Arc::clone(&r))?;
        let mut kp = kp_arc.lock().unwrap_or_else(PoisonError::into_inner);
        Some(f(&mut kp))
    }

    fn return_connection(&self, key: PoolKey, ops: Box<dyn NfsOps>) {
        self.with_key_pool(&key, |kp| {
            kp.outstanding = kp.outstanding.saturating_sub(1);
            if kp.idle.len() < self.max_idle_per_key {
                kp.idle.push_back(PoolEntry {
                    ops,
                    last_used: Instant::now(),
                });
            }
            kp.waiters.notify_one();
        });
    }

    fn record_poison(&self, key: &PoolKey) {
        self.with_key_pool(key, |kp| {
            kp.outstanding = kp.outstanding.saturating_sub(1);
            kp.waiters.notify_one();
        });
    }

    fn decrement_outstanding(&self, key: &PoolKey) {
        self.with_key_pool(key, |kp| {
            kp.outstanding = kp.outstanding.saturating_sub(1);
            kp.waiters.notify_one();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{NfsAttrs, NfsError, NfsFh, ReadResult};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn test_pool(max_idle: usize, max_total: usize) -> Arc<SharedConnectionPool> {
        Arc::new(SharedConnectionPool::new(
            max_idle,
            max_total,
            Duration::from_secs(5),
            Duration::from_secs(300),
        ))
    }

    fn default_pool() -> Arc<SharedConnectionPool> {
        test_pool(8, 16)
    }

    fn test_creds() -> AuthCreds {
        AuthCreds::root()
    }

    #[tokio::test]
    async fn checkout_creates_connection() {
        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(1)
            .returning(move |_, _, _| {
                cc.fetch_add(1, Ordering::Relaxed);
                let mock = MockNfsOps::new();
                Ok(Box::new(mock))
            });

        let pool = default_pool();
        let _conn = pool
            .checkout(&connector, "host1", "/data", &test_creds())
            .await
            .unwrap();

        assert_eq!(connect_count.load(Ordering::Relaxed), 1);
    }

    fn healthy_mock() -> MockNfsOps {
        let mut mock = MockNfsOps::new();
        mock.expect_root_handle()
            .return_const(NfsFh::new(vec![1, 2, 3]));
        mock.expect_getattr().returning(|_| {
            Ok(NfsAttrs {
                file_type: crate::nfs::NfsFileType::Directory,
                size: 4096,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
            })
        });
        mock.expect_read().returning(|_, _, _| {
            Ok(ReadResult {
                data: b"data".to_vec(),
                eof: true,
            })
        });
        mock
    }

    #[tokio::test]
    async fn checkout_reuses_idle_connection() {
        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(1)
            .returning(move |_, _, _| {
                cc.fetch_add(1, Ordering::Relaxed);
                Ok(Box::new(healthy_mock()))
            });

        let pool = default_pool();
        let conn = pool
            .checkout(&connector, "host1", "/data", &test_creds())
            .await
            .unwrap();
        drop(conn);
        tokio::task::yield_now().await;

        let _conn2 = pool
            .checkout(&connector, "host1", "/data", &test_creds())
            .await
            .unwrap();

        assert_eq!(connect_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn poison_discards_connection() {
        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(2)
            .returning(move |_, _, _| {
                cc.fetch_add(1, Ordering::Relaxed);
                let mock = MockNfsOps::new();
                Ok(Box::new(mock))
            });

        let pool = default_pool();
        let conn = pool
            .checkout(&connector, "host1", "/data", &test_creds())
            .await
            .unwrap();
        conn.poison();
        tokio::task::yield_now().await;

        let _conn2 = pool
            .checkout(&connector, "host1", "/data", &test_creds())
            .await
            .unwrap();

        assert_eq!(connect_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn max_total_limits_concurrent() {
        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(move |_, _, _| {
            cc.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(healthy_mock()))
        });

        let pool = test_pool(1, 1);
        let creds = test_creds();

        let conn1 = pool
            .checkout(&connector, "host1", "/data", &creds)
            .await
            .unwrap();

        let pool2 = Arc::clone(&pool);
        let connector2 = {
            let cc2 = Arc::clone(&connect_count);
            let mut c = MockNfsConnector::new();
            c.expect_connect().returning(move |_, _, _| {
                cc2.fetch_add(1, Ordering::Relaxed);
                Ok(Box::new(healthy_mock()))
            });
            c
        };

        let checkout_handle = tokio::spawn(async move {
            pool2
                .checkout(&connector2, "host1", "/data", &AuthCreds::root())
                .await
                .unwrap()
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            connect_count.load(Ordering::Relaxed),
            1,
            "second checkout should be waiting"
        );

        drop(conn1);
        let _conn2 = tokio::time::timeout(Duration::from_secs(2), checkout_handle)
            .await
            .expect("second checkout should complete after first is returned")
            .unwrap();
    }

    #[tokio::test]
    async fn stale_connections_evicted() {
        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);
        let mut connector = MockNfsConnector::new();
        connector
            .expect_connect()
            .times(2)
            .returning(move |_, _, _| {
                cc.fetch_add(1, Ordering::Relaxed);
                let mock = MockNfsOps::new();
                Ok(Box::new(mock))
            });

        let pool = Arc::new(SharedConnectionPool::new(
            8,
            16,
            Duration::from_secs(5),
            Duration::from_millis(1),
        ));
        let creds = test_creds();

        let conn = pool
            .checkout(&connector, "host1", "/data", &creds)
            .await
            .unwrap();
        drop(conn);
        tokio::task::yield_now().await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        let _conn2 = pool
            .checkout(&connector, "host1", "/data", &creds)
            .await
            .unwrap();

        assert_eq!(
            connect_count.load(Ordering::Relaxed),
            2,
            "stale connection should be evicted, requiring a new connect"
        );
    }

    #[tokio::test]
    async fn connect_failure_does_not_leak_outstanding() {
        let mut connector = MockNfsConnector::new();
        connector.expect_connect().times(2).returning(|_, _, _| {
            Err(Box::new(NfsError::ConnectionLost) as Box<dyn std::error::Error + Send + Sync>)
        });

        let pool = test_pool(8, 1);
        let creds = test_creds();

        let err = pool
            .checkout(&connector, "host1", "/data", &creds)
            .await
            .unwrap_err();
        assert!(matches!(err, ScannerError::Nfs(NfsError::ConnectionLost)));

        let err2 = pool
            .checkout(&connector, "host1", "/data", &creds)
            .await
            .unwrap_err();
        assert!(
            matches!(err2, ScannerError::Nfs(NfsError::ConnectionLost)),
            "second checkout should not deadlock; outstanding was decremented after first failure"
        );
    }

    #[tokio::test]
    async fn health_check_evicts_dead_idle_connection() {
        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);

        // Pool with zero health_check_age so health checks always run
        let mut pool =
            SharedConnectionPool::new(8, 16, Duration::from_secs(5), Duration::from_secs(300));
        pool.health_check_age = Duration::ZERO;
        let pool = Arc::new(pool);

        let mut connector = MockNfsConnector::new();
        connector.expect_connect().returning(move |_, _, _| {
            let n = cc.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                let mut mock = MockNfsOps::new();
                mock.expect_root_handle()
                    .return_const(NfsFh::new(vec![1, 2, 3]));
                mock.expect_getattr().returning(|_| {
                    Err(Box::new(NfsError::ConnectionLost)
                        as Box<dyn std::error::Error + Send + Sync>)
                });
                Ok(Box::new(mock))
            } else {
                Ok(Box::new(healthy_mock()))
            }
        });

        let creds = test_creds();

        let conn = pool
            .checkout(&connector, "host1", "/data", &creds)
            .await
            .unwrap();
        drop(conn);
        tokio::task::yield_now().await;

        assert_eq!(connect_count.load(Ordering::Relaxed), 1);

        let _conn2 = pool
            .checkout(&connector, "host1", "/data", &creds)
            .await
            .unwrap();

        assert_eq!(
            connect_count.load(Ordering::Relaxed),
            2,
            "health check should evict dead connection, forcing a new connect"
        );
    }
}
