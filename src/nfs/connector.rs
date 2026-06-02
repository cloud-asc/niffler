use std::sync::Arc;

use crate::nfs::auth::AuthCreds;
use crate::nfs::ops::NfsOps;
use crate::nfs::types::NfsVersion;

/// Result alias for NFS connector operations
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Selects an NFS connector by protocol version, so a single scan can walk and
/// read v3 and v4 exports concurrently (the version is discovered per export).
///
/// An optional `forced` version overrides per-export selection — this backs the
/// `--nfs-version` flag, which pins every connection to one protocol.
#[derive(Clone)]
pub struct ConnectorFactory {
    v3: Arc<dyn NfsConnector>,
    v4: Arc<dyn NfsConnector>,
    forced: Option<NfsVersion>,
}

impl ConnectorFactory {
    #[must_use]
    pub fn new(
        v3: Arc<dyn NfsConnector>,
        v4: Arc<dyn NfsConnector>,
        forced: Option<NfsVersion>,
    ) -> Self {
        Self { v3, v4, forced }
    }

    /// A factory that returns the same connector for every version. For tests
    /// and single-protocol callers that don't need version-aware selection.
    #[must_use]
    pub fn uniform(connector: Arc<dyn NfsConnector>) -> Self {
        Self {
            v3: Arc::clone(&connector),
            v4: connector,
            forced: None,
        }
    }

    /// The connector to use for an export/file of the given version, honoring any
    /// forced override.
    #[must_use]
    pub fn get(&self, version: NfsVersion) -> Arc<dyn NfsConnector> {
        match self.forced.unwrap_or(version) {
            NfsVersion::V3 => Arc::clone(&self.v3),
            NfsVersion::V4 => Arc::clone(&self.v4),
        }
    }
}

/// Factory for creating NFS connections with specific credentials.
/// Each call to connect() returns an independent connection.
/// UID cycling is achieved by calling connect() with different AuthCreds.
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
#[async_trait::async_trait]
pub trait NfsConnector: Send + Sync {
    /// Create a new NFS connection to host:export with the given credentials.
    async fn connect(&self, host: &str, export: &str, creds: &AuthCreds)
    -> Result<Box<dyn NfsOps>>;

    /// Detect which NFS version the server supports.
    async fn detect_version(&self, host: &str) -> Result<NfsVersion>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::ops::MockNfsOps;
    use std::sync::Arc;

    #[test]
    fn factory_selects_connector_by_version() {
        let v3: Arc<dyn NfsConnector> = Arc::new(MockNfsConnector::new());
        let v4: Arc<dyn NfsConnector> = Arc::new(MockNfsConnector::new());
        let factory = ConnectorFactory::new(Arc::clone(&v3), Arc::clone(&v4), None);
        assert!(Arc::ptr_eq(&factory.get(NfsVersion::V3), &v3));
        assert!(Arc::ptr_eq(&factory.get(NfsVersion::V4), &v4));
    }

    #[test]
    fn factory_forced_version_overrides_selection() {
        let v3: Arc<dyn NfsConnector> = Arc::new(MockNfsConnector::new());
        let v4: Arc<dyn NfsConnector> = Arc::new(MockNfsConnector::new());
        let factory = ConnectorFactory::new(Arc::clone(&v3), Arc::clone(&v4), Some(NfsVersion::V4));
        // Even a V3 export is served by the v4 connector when forced.
        assert!(Arc::ptr_eq(&factory.get(NfsVersion::V3), &v4));
        assert!(Arc::ptr_eq(&factory.get(NfsVersion::V4), &v4));
    }

    #[test]
    fn factory_uniform_returns_same_connector() {
        let c: Arc<dyn NfsConnector> = Arc::new(MockNfsConnector::new());
        let factory = ConnectorFactory::uniform(Arc::clone(&c));
        assert!(Arc::ptr_eq(&factory.get(NfsVersion::V3), &c));
        assert!(Arc::ptr_eq(&factory.get(NfsVersion::V4), &c));
    }

    #[tokio::test]
    async fn mock_nfs_connector_returns_ops() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let ops = MockNfsOps::new();
            Ok(Box::new(ops))
        });

        let result = mock
            .connect("192.168.1.1", "/exports/share", &AuthCreds::root())
            .await;
        assert!(result.is_ok());

        let _: Arc<dyn NfsConnector> = Arc::new(mock);
    }
}
