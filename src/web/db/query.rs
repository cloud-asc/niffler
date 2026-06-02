use std::collections::HashMap;

use anyhow::Result;
use rusqlite::OptionalExtension;
use rusqlite::params;

use super::{
    Database, ExportCount, ExportRecord, Finding, FindingsQuery, HostCount, Scan, ScanStats,
    ShowFilter, TopologyExport,
};

pub(super) const FINDING_SELECT: &str = "SELECT f.id, f.scan_id, f.timestamp, f.host, f.export_path, \
    f.file_path, f.triage, f.rule_name, f.matched_pattern, f.context, \
    f.file_size, f.file_mode, f.file_uid, f.file_gid, f.last_modified, \
    COALESCE(a.starred, 0), COALESCE(a.reviewed, 0) \
    FROM findings f LEFT JOIN annotations a ON a.finding_id = f.id";

pub(super) fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        timestamp: row.get(2)?,
        host: row.get(3)?,
        export_path: row.get(4)?,
        file_path: row.get(5)?,
        triage: row.get(6)?,
        rule_name: row.get(7)?,
        matched_pattern: row.get(8)?,
        context: row.get(9)?,
        file_size: row.get(10)?,
        file_mode: row.get(11)?,
        file_uid: row.get(12)?,
        file_gid: row.get(13)?,
        last_modified: row.get(14)?,
        starred: row.get::<_, i64>(15)? != 0,
        reviewed: row.get::<_, i64>(16)? != 0,
    })
}

fn sanitize_fts_query(q: &str) -> String {
    // Strip quotes to avoid FTS5 parse errors, then wrap for prefix matching.
    let cleaned: String = q.chars().filter(|&c| c != '"').collect();
    if cleaned.is_empty() {
        return String::new();
    }
    format!("\"{cleaned}\"*")
}

fn triage_to_int(t: &str) -> i64 {
    match t {
        "Black" => 3,
        "Red" => 2,
        "Yellow" => 1,
        _ => 0, // Green and anything unknown
    }
}

/// The `annotations` table is only referenced by the star/review `show` filters.
/// For every other query the LEFT JOIN is dead weight, so include it only when needed.
fn annotations_join(show: ShowFilter) -> &'static str {
    match show {
        ShowFilter::All => "",
        ShowFilter::Starred | ShowFilter::Unreviewed => {
            "LEFT JOIN annotations a ON a.finding_id = f.id "
        }
    }
}

fn build_findings_where(
    scan_id: Option<i64>,
    triage: &Option<String>,
    min_triage: &Option<String>,
    host: &Option<String>,
    rule: &Option<String>,
    q: &Option<String>,
    show: ShowFilter,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1usize;

    if let Some(sid) = scan_id {
        conditions.push(format!("f.scan_id = ?{idx}"));
        params.push(Box::new(sid));
        idx += 1;
    }
    if let Some(t) = triage {
        conditions.push(format!("f.triage = ?{idx}"));
        params.push(Box::new(t.clone()));
        idx += 1;
    }
    if let Some(mt) = min_triage {
        let min_val = triage_to_int(mt);
        conditions.push(format!(
            "CASE f.triage WHEN 'Black' THEN 3 WHEN 'Red' THEN 2 \
             WHEN 'Yellow' THEN 1 WHEN 'Green' THEN 0 END >= ?{idx}"
        ));
        params.push(Box::new(min_val));
        idx += 1;
    }
    if let Some(h) = host {
        conditions.push(format!("f.host = ?{idx}"));
        params.push(Box::new(h.clone()));
        idx += 1;
    }
    if let Some(r) = rule {
        conditions.push(format!("f.rule_name = ?{idx}"));
        params.push(Box::new(r.clone()));
        idx += 1;
    }
    if let Some(search) = q {
        conditions.push(format!(
            "f.id IN (SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?{idx})"
        ));
        params.push(Box::new(sanitize_fts_query(search)));
        idx += 1;
    }

    match show {
        ShowFilter::Starred => conditions.push("COALESCE(a.starred, 0) = 1".into()),
        ShowFilter::Unreviewed => conditions.push("COALESCE(a.reviewed, 0) = 0".into()),
        ShowFilter::All => {}
    }
    let _ = idx; // suppress unused warning

    let clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (clause, params)
}

impl Database {
    pub async fn severity_counts(&self, scan_id: Option<i64>) -> Result<HashMap<String, u64>> {
        self.conn
            .call(move |conn| {
                let row_mapper =
                    |row: &rusqlite::Row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?));
                let pairs: Vec<(String, u64)> = match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT triage, COUNT(*) FROM findings \
                             WHERE scan_id = ?1 GROUP BY triage",
                        )?;
                        stmt.query_map(params![id], row_mapper)?
                            .filter_map(Result::ok)
                            .collect()
                    }
                    None => {
                        let mut stmt =
                            conn.prepare("SELECT triage, COUNT(*) FROM findings GROUP BY triage")?;
                        stmt.query_map([], row_mapper)?
                            .filter_map(Result::ok)
                            .collect()
                    }
                };
                Ok::<_, rusqlite::Error>(pairs.into_iter().collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn top_hosts(&self, scan_id: Option<i64>, limit: usize) -> Result<Vec<HostCount>> {
        let limit = limit as i64;
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| {
                    Ok(HostCount {
                        host: row.get(0)?,
                        count: row.get(1)?,
                    })
                };
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT host, COUNT(*) as cnt FROM findings WHERE scan_id = ?1 \
                             GROUP BY host ORDER BY cnt DESC LIMIT ?2",
                        )?;
                        let rows = stmt.query_map(params![id, limit], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT host, COUNT(*) as cnt FROM findings \
                             GROUP BY host ORDER BY cnt DESC LIMIT ?1",
                        )?;
                        let rows = stmt.query_map(params![limit], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn list_hosts(&self, scan_id: Option<i64>) -> Result<Vec<HostCount>> {
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| {
                    Ok(HostCount {
                        host: row.get(0)?,
                        count: row.get(1)?,
                    })
                };
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT host, SUM(cnt) AS cnt FROM (
                                 SELECT host, COUNT(*) AS cnt FROM findings WHERE scan_id = ?1 GROUP BY host
                                 UNION ALL
                                 SELECT host, 0 AS cnt FROM (SELECT DISTINCT host FROM exports WHERE scan_id = ?1)
                             ) GROUP BY host ORDER BY cnt DESC, host",
                        )?;
                        let rows = stmt.query_map(params![id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT host, SUM(cnt) AS cnt FROM (
                                 SELECT host, COUNT(*) AS cnt FROM findings GROUP BY host
                                 UNION ALL
                                 SELECT host, 0 AS cnt FROM (SELECT DISTINCT host FROM exports)
                             ) GROUP BY host ORDER BY cnt DESC, host",
                        )?;
                        let rows = stmt.query_map([], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn recent_findings(
        &self,
        scan_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<Finding>> {
        let limit = limit as i64;
        self.conn
            .call(move |conn| match scan_id {
                Some(id) => {
                    let sql = format!(
                        "{FINDING_SELECT} WHERE f.scan_id = ?1 \
                         ORDER BY f.timestamp DESC LIMIT ?2"
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![id, limit], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                }
                None => {
                    let sql = format!("{FINDING_SELECT} ORDER BY f.timestamp DESC LIMIT ?1");
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![limit], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn finding_by_id(&self, id: i64) -> Result<Option<Finding>> {
        self.conn
            .call(move |conn| {
                let sql = format!("{FINDING_SELECT} WHERE f.id = ?1");
                conn.query_row(&sql, params![id], row_to_finding).optional()
            })
            .await
            .map_err(Into::into)
    }

    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT s.id, s.started_at, s.completed_at, s.targets, s.mode, s.status,
                            s.total_hosts, s.total_exports,
                            (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count
                     FROM scans s ORDER BY s.started_at DESC",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok(Scan {
                        id: row.get(0)?,
                        started_at: row.get(1)?,
                        completed_at: row.get(2)?,
                        targets: row.get(3)?,
                        mode: row.get(4)?,
                        status: row.get(5)?,
                        total_hosts: row.get(6)?,
                        total_exports: row.get(7)?,
                        total_findings: row.get(8)?,
                    })
                })?;
                Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn latest_scan(&self) -> Result<Option<Scan>> {
        self.conn
            .call(|conn| {
                conn.query_row(
                    "SELECT id, started_at, completed_at, targets, mode, status,
                            total_hosts, total_exports, total_findings
                     FROM scans ORDER BY started_at DESC LIMIT 1",
                    [],
                    |row| {
                        Ok(Scan {
                            id: row.get(0)?,
                            started_at: row.get(1)?,
                            completed_at: row.get(2)?,
                            targets: row.get(3)?,
                            mode: row.get(4)?,
                            status: row.get(5)?,
                            total_hosts: row.get(6)?,
                            total_exports: row.get(7)?,
                            total_findings: row.get(8)?,
                        })
                    },
                )
                .optional()
            })
            .await
            .map_err(Into::into)
    }

    pub async fn distinct_hosts(&self, scan_id: Option<i64>) -> Result<Vec<String>> {
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| row.get::<_, String>(0);
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT DISTINCT host FROM findings \
                             WHERE scan_id = ?1 ORDER BY host",
                        )?;
                        let rows = stmt.query_map(params![id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                    None => {
                        let mut stmt =
                            conn.prepare("SELECT DISTINCT host FROM findings ORDER BY host")?;
                        let rows = stmt.query_map([], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn distinct_rules(&self, scan_id: Option<i64>) -> Result<Vec<String>> {
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| row.get::<_, String>(0);
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT DISTINCT rule_name FROM findings \
                             WHERE scan_id = ?1 ORDER BY rule_name",
                        )?;
                        let rows = stmt.query_map(params![id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT DISTINCT rule_name FROM findings ORDER BY rule_name",
                        )?;
                        let rows = stmt.query_map([], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    pub async fn distinct_hosts_filtered(&self, query: &FindingsQuery) -> Result<Vec<String>> {
        let scan_id = query.scan_id;
        let triage = query.triage.clone();
        let min_triage = query.min_triage.clone();
        let host: Option<String> = None; // exclude host filter
        let rule = query.rule.clone();
        let q = query.q.clone();
        let show = query.show;

        self.conn
            .call(move |conn| {
                let (where_clause, params) =
                    build_findings_where(scan_id, &triage, &min_triage, &host, &rule, &q, show);
                let join = annotations_join(show);
                let sql = format!(
                    "SELECT DISTINCT f.host FROM findings f {join}{where_clause} ORDER BY f.host"
                );
                let refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(AsRef::as_ref).collect();
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(refs.as_slice(), |row| row.get::<_, String>(0))?;
                Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn distinct_rules_filtered(&self, query: &FindingsQuery) -> Result<Vec<String>> {
        let scan_id = query.scan_id;
        let triage = query.triage.clone();
        let min_triage = query.min_triage.clone();
        let host = query.host.clone();
        let rule: Option<String> = None; // exclude rule filter
        let q = query.q.clone();
        let show = query.show;

        self.conn
            .call(move |conn| {
                let (where_clause, params) =
                    build_findings_where(scan_id, &triage, &min_triage, &host, &rule, &q, show);
                let join = annotations_join(show);
                let sql = format!(
                    "SELECT DISTINCT f.rule_name FROM findings f {join}{where_clause} \
                     ORDER BY f.rule_name"
                );
                let refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(AsRef::as_ref).collect();
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(refs.as_slice(), |row| row.get::<_, String>(0))?;
                Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn list_findings(&self, query: &FindingsQuery) -> Result<Vec<Finding>> {
        let scan_id = query.scan_id;
        let triage = query.triage.clone();
        let min_triage = query.min_triage.clone();
        let host = query.host.clone();
        let rule = query.rule.clone();
        let q = query.q.clone();
        let sort_sql = query.sort.as_sql();
        let dir_sql = query.dir.as_sql();
        let show = query.show;
        let limit = query.per_page as i64;
        let offset = ((query.page.max(1) - 1) * query.per_page) as i64;

        self.conn
            .call(move |conn| {
                let (where_clause, params) =
                    build_findings_where(scan_id, &triage, &min_triage, &host, &rule, &q, show);
                let sql = format!(
                    "{FINDING_SELECT} {where_clause} ORDER BY {sort_sql} {dir_sql} LIMIT ?{} OFFSET ?{}",
                    params.len() + 1,
                    params.len() + 2,
                );
                let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = params;
                all_params.push(Box::new(limit));
                all_params.push(Box::new(offset));
                let refs: Vec<&dyn rusqlite::types::ToSql> =
                    all_params.iter().map(AsRef::as_ref).collect();

                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(refs.as_slice(), row_to_finding)?;
                Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
            })
            .await
            .map_err(Into::into)
    }

    pub async fn count_findings(&self, query: &FindingsQuery) -> Result<u64> {
        let scan_id = query.scan_id;
        let triage = query.triage.clone();
        let min_triage = query.min_triage.clone();
        let host = query.host.clone();
        let rule = query.rule.clone();
        let q = query.q.clone();
        let show = query.show;

        self.conn
            .call(move |conn| {
                let (where_clause, params) =
                    build_findings_where(scan_id, &triage, &min_triage, &host, &rule, &q, show);
                let join = annotations_join(show);
                let sql = format!("SELECT COUNT(*) FROM findings f {join}{where_clause}");
                let refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(AsRef::as_ref).collect();
                conn.query_row(&sql, refs.as_slice(), |row| row.get(0))
            })
            .await
            .map_err(Into::into)
    }

    pub async fn host_exports(&self, scan_id: Option<i64>, host: &str) -> Result<Vec<ExportCount>> {
        let host = host.to_string();
        self.conn
            .call(move |conn| {
                let row_mapper = |row: &rusqlite::Row| {
                    Ok(ExportCount {
                        export_path: row.get(0)?,
                        count: row.get(1)?,
                    })
                };
                match scan_id {
                    Some(id) => {
                        let mut stmt = conn.prepare(
                            "SELECT export_path, COUNT(*) as cnt FROM findings \
                             WHERE host = ?1 AND scan_id = ?2 \
                             GROUP BY export_path ORDER BY cnt DESC",
                        )?;
                        let rows = stmt.query_map(params![host, id], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT export_path, COUNT(*) as cnt FROM findings \
                             WHERE host = ?1 GROUP BY export_path ORDER BY cnt DESC",
                        )?;
                        let rows = stmt.query_map(params![host], row_mapper)?;
                        Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                    }
                }
            })
            .await
            .map_err(Into::into)
    }

    /// Persisted exports for a host (from the `exports` table), each with its
    /// misconfig kinds joined from `misconfigs`. Scoped to `scan_id` when given.
    pub async fn export_records(
        &self,
        scan_id: Option<i64>,
        host: &str,
    ) -> Result<Vec<ExportRecord>> {
        let host = host.to_string();
        self.conn
            .call(move |conn| {
                let (sql, bind_scan): (String, bool) = match scan_id {
                    Some(_) => (
                        "SELECT export_path, nfs_version, allowed_hosts FROM exports \
                         WHERE host = ?1 AND scan_id = ?2 ORDER BY export_path"
                            .into(),
                        true,
                    ),
                    None => (
                        "SELECT export_path, nfs_version, allowed_hosts FROM exports \
                         WHERE host = ?1 ORDER BY export_path"
                            .into(),
                        false,
                    ),
                };
                let mut stmt = conn.prepare(&sql)?;
                let misconfig_sql = match scan_id {
                    Some(_) => {
                        "SELECT kind FROM misconfigs WHERE host = ?1 AND export_path = ?2 \
                                AND scan_id = ?3 ORDER BY kind"
                    }
                    None => {
                        "SELECT kind FROM misconfigs WHERE host = ?1 AND export_path = ?2 \
                             ORDER BY kind"
                    }
                };
                let mut mstmt = conn.prepare(misconfig_sql)?;
                let rows: Vec<(String, String, Option<String>)> = if bind_scan {
                    stmt.query_map(rusqlite::params![host, scan_id.unwrap()], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect()
                } else {
                    stmt.query_map(rusqlite::params![host], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect()
                };
                let mut out: Vec<ExportRecord> = Vec::new();
                for (export_path, nfs_version, allowed_hosts) in rows {
                    let kinds: Vec<String> = match scan_id {
                        Some(id) => mstmt
                            .query_map(rusqlite::params![host, export_path, id], |r| {
                                r.get::<_, String>(0)
                            })?
                            .filter_map(std::result::Result::ok)
                            .collect(),
                        None => mstmt
                            .query_map(rusqlite::params![host, export_path], |r| {
                                r.get::<_, String>(0)
                            })?
                            .filter_map(std::result::Result::ok)
                            .collect(),
                    };
                    out.push(ExportRecord {
                        host: host.clone(),
                        export_path,
                        nfs_version,
                        allowed_hosts,
                        misconfigs: kinds,
                    });
                }
                Ok::<_, rusqlite::Error>(out)
            })
            .await
            .map_err(Into::into)
    }

    /// Topology rows for a host: every persisted export plus any
    /// findings-only export paths, each with finding count and misconfigs.
    pub async fn host_topology(
        &self,
        scan_id: Option<i64>,
        host: &str,
    ) -> Result<Vec<TopologyExport>> {
        use std::collections::BTreeMap;
        let persisted = self.export_records(scan_id, host).await?;
        let counts = self.host_exports(scan_id, host).await?;

        let mut by_path: BTreeMap<String, TopologyExport> = BTreeMap::new();
        for e in persisted {
            by_path.insert(
                e.export_path.clone(),
                TopologyExport {
                    export_path: e.export_path,
                    nfs_version: Some(e.nfs_version),
                    allowed_hosts: e.allowed_hosts,
                    misconfigs: e.misconfigs,
                    finding_count: 0,
                },
            );
        }
        for c in counts {
            by_path
                .entry(c.export_path.clone())
                .and_modify(|t| t.finding_count = c.count)
                .or_insert(TopologyExport {
                    export_path: c.export_path,
                    nfs_version: None,
                    allowed_hosts: None,
                    misconfigs: Vec::new(),
                    finding_count: c.count,
                });
        }
        Ok(by_path.into_values().collect())
    }

    pub async fn findings_for_host_export(
        &self,
        scan_id: Option<i64>,
        host: &str,
        export: &str,
    ) -> Result<Vec<Finding>> {
        let host = host.to_string();
        let export = export.to_string();
        self.conn
            .call(move |conn| match scan_id {
                Some(id) => {
                    let sql = format!(
                        "{FINDING_SELECT} WHERE f.host = ?1 AND f.export_path = ?2 \
                         AND f.scan_id = ?3 ORDER BY CASE f.triage \
                         WHEN 'Black' THEN 3 WHEN 'Red' THEN 2 \
                         WHEN 'Yellow' THEN 1 WHEN 'Green' THEN 0 END DESC"
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![host, export, id], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                }
                None => {
                    let sql = format!(
                        "{FINDING_SELECT} WHERE f.host = ?1 AND f.export_path = ?2 \
                         ORDER BY CASE f.triage \
                         WHEN 'Black' THEN 3 WHEN 'Red' THEN 2 \
                         WHEN 'Yellow' THEN 1 WHEN 'Green' THEN 0 END DESC"
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let rows = stmt.query_map(params![host, export], row_to_finding)?;
                    Ok::<_, rusqlite::Error>(rows.filter_map(Result::ok).collect())
                }
            })
            .await
            .map_err(Into::into)
    }

    /// Fetch specific findings by id (for "export selected"). Empty input
    /// returns an empty Vec without querying.
    pub async fn list_findings_by_ids(&self, ids: &[i64]) -> Result<Vec<Finding>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = ids.to_vec();
        self.conn
            .call(move |conn| {
                let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let sql = format!("{FINDING_SELECT} WHERE f.id IN ({placeholders})");
                let mut stmt = conn.prepare(&sql)?;
                let params = rusqlite::params_from_iter(ids.iter());
                let rows = stmt.query_map(params, row_to_finding)?;
                let out: Vec<Finding> = rows.filter_map(std::result::Result::ok).collect();
                Ok::<_, rusqlite::Error>(out)
            })
            .await
            .map_err(Into::into)
    }

    pub async fn get_stats(&self) -> Result<ScanStats> {
        self.conn
            .call(|conn| {
                let total_findings: i64 = conn
                    .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
                    .unwrap_or(0);
                let total_hosts: i64 = conn
                    .query_row("SELECT COUNT(DISTINCT host) FROM findings", [], |r| {
                        r.get(0)
                    })
                    .unwrap_or(0);
                let total_scans: i64 = conn
                    .query_row("SELECT COUNT(DISTINCT scan_id) FROM findings", [], |r| {
                        r.get(0)
                    })
                    .unwrap_or(0);

                let mut severity_counts = std::collections::HashMap::new();
                let mut stmt =
                    conn.prepare("SELECT triage, COUNT(*) FROM findings GROUP BY triage")?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                for row in rows {
                    let (triage, count) = row?;
                    severity_counts.insert(triage, count);
                }

                Ok::<_, rusqlite::Error>(ScanStats {
                    total_findings,
                    total_hosts,
                    total_scans,
                    severity_counts,
                })
            })
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::classifier::Triage;
    use crate::web::db::test_helpers::{seed_many_findings, seed_test_data};
    use crate::web::db::{Database, FindingsQuery, SortColumn, SortDir};

    #[tokio::test]
    async fn test_severity_counts() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let counts = db.severity_counts(Some(scan_id)).await.unwrap();
        assert_eq!(counts.get("Black").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("Red").copied().unwrap_or(0), 4);
        assert_eq!(counts.get("Yellow").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("Green").copied().unwrap_or(0), 2);
    }

    #[tokio::test]
    async fn test_top_hosts() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let hosts = db.top_hosts(Some(scan_id), 10).await.unwrap();
        assert_eq!(hosts.len(), 2);
        // Both have 5 findings; order is desc by count
        assert_eq!(hosts[0].count, 5);
        assert_eq!(hosts[1].count, 5);
    }

    #[tokio::test]
    async fn test_recent_findings() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let recent = db.recent_findings(Some(scan_id), 5).await.unwrap();
        assert_eq!(recent.len(), 5);
        // All should default to not starred/reviewed
        for f in &recent {
            assert!(!f.starred);
            assert!(!f.reviewed);
        }
    }

    #[tokio::test]
    async fn test_findings_filter_by_triage() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            triage: Some("Red".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 4);
        for f in &results {
            assert_eq!(f.triage, "Red");
        }
    }

    #[tokio::test]
    async fn test_findings_filter_by_host() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            host: Some("10.0.0.2".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 5);
        for f in &results {
            assert_eq!(f.host, "10.0.0.2");
        }
    }

    #[tokio::test]
    async fn test_findings_filter_by_rule() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            rule: Some("SSHPrivateKey".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_findings_sort_by_column() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            sort: SortColumn::FileSize,
            dir: SortDir::Desc,
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 10);
        // All file_size=1024 so just verify ordering doesn't error
        for window in results.windows(2) {
            assert!(window[0].file_size >= window[1].file_size);
        }
    }

    #[tokio::test]
    async fn test_findings_pagination() {
        let db = Database::open_memory().await.unwrap();
        let _scan_id = seed_many_findings(&db, 120).await;

        let page1 = db
            .list_findings(&FindingsQuery {
                page: 1,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page1.len(), 50);

        let page2 = db
            .list_findings(&FindingsQuery {
                page: 2,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page2.len(), 50);

        let page3 = db
            .list_findings(&FindingsQuery {
                page: 3,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page3.len(), 20);

        let page4 = db
            .list_findings(&FindingsQuery {
                page: 4,
                per_page: 50,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page4.len(), 0);
    }

    #[tokio::test]
    async fn test_findings_fts_search() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Search for "ssh" — matches .ssh in file_path (FTS tokenizes on punctuation)
        let results = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                q: Some("ssh".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            !results.is_empty(),
            "FTS search for 'ssh' should match >=1, got 0"
        );

        // Search for "test_pattern" — matches all findings via matched_pattern
        let all_match = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                q: Some("test_pattern".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            all_match.len(),
            10,
            "all findings have matched_pattern='test_pattern'"
        );

        // Search for something that doesn't exist
        let none = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                q: Some("zzz_nonexistent_zzz".into()),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            none.is_empty(),
            "FTS search for nonexistent term should return 0"
        );
    }

    #[tokio::test]
    async fn test_finding_by_id() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = crate::web::db::test_helpers::make_test_result(
            "10.0.0.1",
            "/exports",
            "/home/.ssh/id_rsa",
            Triage::Black,
            "SSHKey",
        );
        db.insert_finding(scan_id, &msg).await.unwrap();

        // Find the inserted ID
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let found = db.finding_by_id(id).await.unwrap();
        assert!(found.is_some());
        let f = found.unwrap();
        assert_eq!(f.host, "10.0.0.1");
        assert_eq!(f.triage, "Black");
        assert!(!f.starred);
        assert!(!f.reviewed);

        // Nonexistent
        let missing = db.finding_by_id(99999).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_host_list_with_counts() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let hosts = db.list_hosts(Some(scan_id)).await.unwrap();
        assert_eq!(hosts.len(), 2);
        for h in &hosts {
            assert_eq!(h.count, 5);
        }
    }

    #[tokio::test]
    async fn test_host_exports() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let exports = db.host_exports(Some(scan_id), "10.0.0.1").await.unwrap();
        assert_eq!(exports.len(), 2);
        // Ordered by count desc: /exports/home(3), /exports/data(2)
        assert_eq!(exports[0].export_path, "/exports/home");
        assert_eq!(exports[0].count, 3);
        assert_eq!(exports[1].export_path, "/exports/data");
        assert_eq!(exports[1].count, 2);
    }

    #[tokio::test]
    async fn test_findings_for_host_export() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let findings = db
            .findings_for_host_export(Some(scan_id), "10.0.0.1", "/exports/home")
            .await
            .unwrap();
        assert_eq!(findings.len(), 3);
        for f in &findings {
            assert_eq!(f.host, "10.0.0.1");
            assert_eq!(f.export_path, "/exports/home");
        }
    }

    #[tokio::test]
    async fn test_scan_list() {
        let db = Database::open_memory().await.unwrap();
        let _id1 = db.create_scan(&["10.0.0.1".into()], "recon").await.unwrap();
        let _id2 = db.create_scan(&["10.0.0.2".into()], "scan").await.unwrap();
        let id3 = db.create_scan(&["10.0.0.3".into()], "scan").await.unwrap();

        let scans = db.list_scans().await.unwrap();
        assert_eq!(scans.len(), 3);
        // Ordered by started_at desc — last created first
        assert_eq!(scans[0].id, id3);

        let latest = db.latest_scan().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().id, id3);
    }

    #[tokio::test]
    async fn test_count_findings_with_filters() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Total
        let total = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(total, 10);

        // Red only
        let red = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                triage: Some("Red".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(red, 4);

        // Host filter
        let host = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                host: Some("10.0.0.1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(host, 5);
    }

    #[tokio::test]
    async fn test_count_findings_respects_show_starred() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let all = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(all, 10);

        let one = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        db.toggle_star(one[0].id).await.unwrap();

        let starred = db
            .count_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: crate::web::db::ShowFilter::Starred,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(starred, 1, "only the starred finding should be counted");
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_red() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: Some("Red".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        // seed_test_data has 2 Black + 4 Red = 6 at or above Red
        assert_eq!(results.len(), 6);
        for f in &results {
            assert!(
                f.triage == "Red" || f.triage == "Black",
                "expected Red or Black, got {}",
                f.triage
            );
        }
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_green_returns_all() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: Some("Green".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 10, "min_triage=Green should return all");
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_black() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: Some("Black".into()),
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(
            results.len(),
            2,
            "min_triage=Black should return only Black"
        );
        for f in &results {
            assert_eq!(f.triage, "Black");
        }
    }

    #[tokio::test]
    async fn test_findings_filter_min_triage_none_returns_all() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        let query = FindingsQuery {
            scan_id: Some(scan_id),
            min_triage: None,
            per_page: 100,
            ..Default::default()
        };
        let results = db.list_findings(&query).await.unwrap();
        assert_eq!(results.len(), 10, "min_triage=None should return all");
    }

    #[tokio::test]
    async fn test_export_records_roundtrip_via_raw_insert() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "recon").await.unwrap();
        db.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO exports (scan_id, host, export_path, nfs_version, allowed_hosts)
                     VALUES (?1, '10.0.0.1', '/exports/home', 'v3', '*')",
                    rusqlite::params![scan_id],
                )?;
                conn.execute(
                    "INSERT INTO misconfigs (scan_id, host, export_path, kind)
                     VALUES (?1, '10.0.0.1', '/exports/home', 'possible_no_root_squash')",
                    rusqlite::params![scan_id],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .unwrap();

        let recs = db.export_records(Some(scan_id), "10.0.0.1").await.unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].export_path, "/exports/home");
        assert_eq!(recs[0].nfs_version, "v3");
        assert_eq!(recs[0].allowed_hosts.as_deref(), Some("*"));
        assert_eq!(
            recs[0].misconfigs,
            vec!["possible_no_root_squash".to_string()]
        );
    }

    #[tokio::test]
    async fn test_host_topology_merges_persisted_and_findings() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;
        db.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO exports (scan_id, host, export_path, nfs_version, allowed_hosts)
                     VALUES (?1, '10.0.0.1', '/exports/empty', 'v3', '10.0.0.0/24')",
                    rusqlite::params![scan_id],
                )?;
                conn.execute(
                    "INSERT INTO misconfigs (scan_id, host, export_path, kind)
                     VALUES (?1, '10.0.0.1', '/exports/empty', 'insecure')",
                    rusqlite::params![scan_id],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .unwrap();

        let topo = db.host_topology(None, "10.0.0.1").await.unwrap();
        let empty = topo
            .iter()
            .find(|t| t.export_path == "/exports/empty")
            .unwrap();
        assert_eq!(empty.finding_count, 0);
        assert_eq!(empty.nfs_version.as_deref(), Some("v3"));
        assert_eq!(empty.misconfigs, vec!["insecure".to_string()]);
    }

    #[tokio::test]
    async fn test_list_hosts_includes_export_only_hosts() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db
            .create_scan(&["10.0.0.0/24".into()], "recon")
            .await
            .unwrap();
        db.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO exports (scan_id, host, export_path, nfs_version, allowed_hosts)
                     VALUES (?1, '10.9.9.9', '/only', 'v4', NULL)",
                    rusqlite::params![scan_id],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .unwrap();

        let hosts = db.list_hosts(None).await.unwrap();
        assert!(
            hosts.iter().any(|h| h.host == "10.9.9.9"),
            "export-only host must appear in the hosts list"
        );
    }

    #[tokio::test]
    async fn test_list_findings_by_ids() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let want: Vec<i64> = all.iter().take(3).map(|f| f.id).collect();

        let got = db.list_findings_by_ids(&want).await.unwrap();
        assert_eq!(got.len(), 3);
        let got_ids: std::collections::HashSet<i64> = got.iter().map(|f| f.id).collect();
        for id in &want {
            assert!(got_ids.contains(id), "id {id} should be returned");
        }

        assert!(db.list_findings_by_ids(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_export_records_misconfigs_are_scan_scoped() {
        let db = Database::open_memory().await.unwrap();
        let scan1 = db.create_scan(&["10.0.0.1".into()], "recon").await.unwrap();
        let scan2 = db.create_scan(&["10.0.0.1".into()], "recon").await.unwrap();
        // Same host+export in two scans, with DIFFERENT misconfigs.
        db.conn
            .call(move |conn| {
                for (sid, kind) in [(scan1, "insecure"), (scan2, "subtree")] {
                    conn.execute(
                        "INSERT INTO exports (scan_id, host, export_path, nfs_version, allowed_hosts)
                         VALUES (?1, '10.0.0.1', '/x', 'v3', NULL)",
                        rusqlite::params![sid],
                    )?;
                    conn.execute(
                        "INSERT INTO misconfigs (scan_id, host, export_path, kind)
                         VALUES (?1, '10.0.0.1', '/x', ?2)",
                        rusqlite::params![sid, kind],
                    )?;
                }
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .unwrap();

        let recs1 = db.export_records(Some(scan1), "10.0.0.1").await.unwrap();
        assert_eq!(recs1.len(), 1);
        assert_eq!(
            recs1[0].misconfigs,
            vec!["insecure".to_string()],
            "scan1 sees only its own misconfig"
        );

        let recs2 = db.export_records(Some(scan2), "10.0.0.1").await.unwrap();
        assert_eq!(
            recs2[0].misconfigs,
            vec!["subtree".to_string()],
            "scan2 sees only its own misconfig"
        );
    }
}
