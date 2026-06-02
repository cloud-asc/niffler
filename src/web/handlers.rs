use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::db::{Database, FindingsQuery, ShowFilter, SortColumn, SortDir};
use super::server::AppState;
use super::templates::{
    DashboardHost, DashboardTemplate, FindingDetailTemplate, FindingsRowsTemplate,
    FindingsTemplate, HostExportsTemplate, HostsTemplate, NoteSavedTemplate, ReviewButtonTemplate,
    ScansTemplate, StarButtonTemplate,
};

/// Upper bound on rows returned per interactive page load. Caps user-supplied
/// `per_page` so a crafted request cannot force an unbounded result set.
const MAX_PER_PAGE: u64 = 1000;

/// Parse a comma-separated id string into i64s, dropping any non-numeric tokens.
fn parse_id_list(s: &str) -> Vec<i64> {
    s.split(',')
        .filter_map(|x| x.trim().parse::<i64>().ok())
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct FindingsParams {
    pub scan_id: Option<i64>,
    pub triage: Option<String>,
    pub host: Option<String>,
    pub rule: Option<String>,
    pub q: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    pub show: Option<String>,
    /// Export-only: comma-separated finding ids for "export selected". Ignored by the findings page/query.
    pub ids: Option<String>,
}

impl FindingsParams {
    /// Convert empty strings from HTML form serialization into None.
    ///
    /// HTMX includes all form fields in requests. Dropdowns with a default
    /// "All" option (`value=""`) serialize as `triage=`, which serde
    /// deserializes as `Some("")` rather than `None`. Without normalization,
    /// `build_findings_where` adds `WHERE f.triage = ''`, matching zero rows.
    fn normalize(mut self) -> Self {
        fn none_if_empty(opt: Option<String>) -> Option<String> {
            opt.filter(|s| !s.is_empty())
        }
        self.triage = none_if_empty(self.triage);
        self.host = none_if_empty(self.host);
        self.rule = none_if_empty(self.rule);
        self.q = none_if_empty(self.q);
        self.sort = none_if_empty(self.sort);
        self.dir = none_if_empty(self.dir);
        self.show = none_if_empty(self.show);
        self.ids = none_if_empty(self.ids);
        self
    }

    fn into_query(self) -> FindingsQuery {
        let s = self.normalize();
        FindingsQuery {
            scan_id: s.scan_id,
            triage: s.triage,
            min_triage: None,
            host: s.host,
            rule: s.rule,
            q: s.q,
            sort: match s.sort.as_deref() {
                Some("triage") => SortColumn::Triage,
                Some("host") => SortColumn::Host,
                Some("rule_name") => SortColumn::RuleName,
                Some("file_size") => SortColumn::FileSize,
                Some("file_path") => SortColumn::FilePath,
                _ => SortColumn::Timestamp,
            },
            dir: match s.dir.as_deref() {
                Some("asc") => SortDir::Asc,
                _ => SortDir::Desc,
            },
            page: s.page.unwrap_or(1).max(1),
            per_page: s.per_page.unwrap_or(50).clamp(1, MAX_PER_PAGE),
            show: match s.show.as_deref() {
                Some("starred") => ShowFilter::Starred,
                Some("unreviewed") => ShowFilter::Unreviewed,
                _ => ShowFilter::All,
            },
        }
    }

    fn into_export_query(self) -> FindingsQuery {
        let s = self.normalize();
        FindingsQuery {
            scan_id: s.scan_id,
            triage: s.triage,
            min_triage: None,
            host: s.host,
            rule: s.rule,
            q: s.q,
            sort: match s.sort.as_deref() {
                Some("triage") => SortColumn::Triage,
                Some("host") => SortColumn::Host,
                Some("rule_name") => SortColumn::RuleName,
                Some("file_size") => SortColumn::FileSize,
                Some("file_path") => SortColumn::FilePath,
                _ => SortColumn::Timestamp,
            },
            dir: match s.dir.as_deref() {
                Some("asc") => SortDir::Asc,
                _ => SortDir::Desc,
            },
            page: 1,
            per_page: 1_000_000,
            show: match s.show.as_deref() {
                Some("starred") => ShowFilter::Starred,
                Some("unreviewed") => ShowFilter::Unreviewed,
                _ => ShowFilter::All,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BulkParams {
    /// Comma-separated finding ids, e.g. "1,2,3".
    pub ids: String,
    /// One of: "review" | "star" | "triage".
    pub action: String,
    /// Triage tier to apply when `action == "triage"`.
    pub bulk_triage: Option<String>,
    /// Filter passthrough, so we can re-render the same view.
    pub scan_id: Option<i64>,
    pub triage: Option<String>,
    pub host: Option<String>,
    pub rule: Option<String>,
    pub q: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    pub show: Option<String>,
}

impl BulkParams {
    fn parse_ids(&self) -> Vec<i64> {
        parse_id_list(&self.ids)
    }

    fn into_filter_params(self) -> FindingsParams {
        FindingsParams {
            scan_id: self.scan_id,
            triage: self.triage,
            host: self.host,
            rule: self.rule,
            q: self.q,
            sort: self.sort,
            dir: self.dir,
            page: self.page,
            per_page: self.per_page,
            show: self.show,
            ids: None,
        }
    }
}

struct FindingsData {
    query: FindingsQuery,
    findings: Vec<super::db::Finding>,
    total: u64,
    page: u64,
    per_page: u64,
    total_pages: u64,
    showing_start: u64,
    showing_end: u64,
    current_triage: String,
    current_host: String,
    current_rule: String,
    current_q: String,
    current_sort: String,
    current_dir: String,
    current_show: String,
}

async fn fetch_findings_data(db: &Database, params: FindingsParams) -> FindingsData {
    let current_triage = params.triage.clone().unwrap_or_default();
    let current_host = params.host.clone().unwrap_or_default();
    let current_rule = params.rule.clone().unwrap_or_default();
    let current_q = params.q.clone().unwrap_or_default();
    let current_sort = params.sort.clone().unwrap_or_default();
    let current_dir = params.dir.clone().unwrap_or_default();
    let current_show = params.show.clone().unwrap_or_default();

    let query = params.into_query();
    let page = query.page;
    let per_page = query.per_page;

    let findings = db.list_findings(&query).await.unwrap_or_default();
    let total = db.count_findings(&query).await.unwrap_or(0);

    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(per_page)
    };
    let showing_start = if total == 0 {
        0
    } else {
        (page - 1) * per_page + 1
    };
    let showing_end = showing_start.saturating_sub(1) + findings.len() as u64;

    FindingsData {
        query,
        findings,
        total,
        page,
        per_page,
        total_pages,
        showing_start,
        showing_end,
        current_triage,
        current_host,
        current_rule,
        current_q,
        current_sort,
        current_dir,
        current_show,
    }
}

pub async fn root_redirect() -> Redirect {
    Redirect::to("/dashboard")
}

pub async fn dashboard(State(state): State<Arc<AppState>>) -> DashboardTemplate {
    let counts = state.db.severity_counts(None).await.unwrap_or_else(|e| {
        tracing::warn!("dashboard severity_counts query failed: {e}");
        Default::default()
    });

    let count_black = counts.get("Black").copied().unwrap_or(0);
    let count_red = counts.get("Red").copied().unwrap_or(0);
    let count_yellow = counts.get("Yellow").copied().unwrap_or(0);
    let count_green = counts.get("Green").copied().unwrap_or(0);
    let total = count_black + count_red + count_yellow + count_green;

    let (pct_black, pct_red, pct_yellow, pct_green) = if total > 0 {
        let t = total as f64;
        (
            count_black as f64 / t * 100.0,
            count_red as f64 / t * 100.0,
            count_yellow as f64 / t * 100.0,
            count_green as f64 / t * 100.0,
        )
    } else {
        (0.0, 0.0, 0.0, 0.0)
    };

    let raw_hosts = state.db.top_hosts(None, 10).await.unwrap_or_else(|e| {
        tracing::warn!("dashboard top_hosts query failed: {e}");
        Vec::new()
    });
    let max = raw_hosts.first().map(|h| h.count).unwrap_or(1);
    let top_hosts = raw_hosts
        .iter()
        .map(|h| DashboardHost {
            host: h.host.clone(),
            count: h.count,
            bar_pct: h.count as f64 / max as f64 * 100.0,
        })
        .collect();

    let recent_findings = state
        .db
        .recent_findings(None, 10)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("dashboard recent_findings query failed: {e}");
            Vec::new()
        });

    let latest_scan = state.db.latest_scan().await.unwrap_or_else(|e| {
        tracing::warn!("dashboard latest_scan query failed: {e}");
        None
    });

    DashboardTemplate {
        active_nav: "dashboard",
        count_black,
        count_red,
        count_yellow,
        count_green,
        total,
        pct_black,
        pct_red,
        pct_yellow,
        pct_green,
        top_hosts,
        recent_findings,
        latest_scan,
    }
}

pub async fn findings(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> FindingsTemplate {
    let data = fetch_findings_data(&state.db, params).await;
    let hosts = state
        .db
        .distinct_hosts_filtered(&data.query)
        .await
        .unwrap_or_default();
    let rules = state
        .db
        .distinct_rules_filtered(&data.query)
        .await
        .unwrap_or_default();

    FindingsTemplate {
        active_nav: "findings",
        findings: data.findings,
        total: data.total,
        page: data.page,
        per_page: data.per_page,
        total_pages: data.total_pages,
        showing_start: data.showing_start,
        showing_end: data.showing_end,
        hosts,
        rules,
        is_fragment: false,
        current_triage: data.current_triage,
        current_host: data.current_host,
        current_rule: data.current_rule,
        current_q: data.current_q,
        current_sort: data.current_sort,
        current_dir: data.current_dir,
        current_show: data.current_show,
    }
}

pub async fn hosts(State(state): State<Arc<AppState>>) -> HostsTemplate {
    let hosts = state.db.list_hosts(None).await.unwrap_or_default();
    HostsTemplate {
        active_nav: "hosts",
        hosts,
    }
}

pub async fn scans(State(state): State<Arc<AppState>>) -> ScansTemplate {
    let scans = state.db.list_scans().await.unwrap_or_default();
    ScansTemplate {
        active_nav: "scans",
        scans,
    }
}

pub async fn api_findings(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> FindingsRowsTemplate {
    let data = fetch_findings_data(&state.db, params).await;
    let hosts = state
        .db
        .distinct_hosts_filtered(&data.query)
        .await
        .unwrap_or_default();
    let rules = state
        .db
        .distinct_rules_filtered(&data.query)
        .await
        .unwrap_or_default();

    FindingsRowsTemplate {
        findings: data.findings,
        total: data.total,
        page: data.page,
        per_page: data.per_page,
        total_pages: data.total_pages,
        showing_start: data.showing_start,
        showing_end: data.showing_end,
        hosts,
        rules,
        is_fragment: true,
        current_triage: data.current_triage,
        current_host: data.current_host,
        current_rule: data.current_rule,
        current_q: data.current_q,
        current_sort: data.current_sort,
        current_dir: data.current_dir,
        current_show: data.current_show,
    }
}

pub async fn api_findings_bulk(
    State(state): State<Arc<AppState>>,
    axum::extract::Form(params): axum::extract::Form<BulkParams>,
) -> FindingsRowsTemplate {
    let ids = params.parse_ids();
    if !ids.is_empty() {
        match params.action.as_str() {
            "review" => {
                if let Err(e) = state.db.bulk_set_reviewed(ids, true).await {
                    tracing::warn!("bulk review failed: {e}");
                }
            }
            "star" => {
                if let Err(e) = state.db.bulk_set_starred(ids, true).await {
                    tracing::warn!("bulk star failed: {e}");
                }
            }
            "triage" => {
                if let Some(t) = params.bulk_triage.clone()
                    && !t.is_empty()
                    && let Err(e) = state.db.bulk_set_triage(ids, t).await
                {
                    tracing::warn!("bulk triage failed: {e}");
                }
            }
            other => {
                tracing::warn!("unknown bulk action: {other}");
            }
        }
    }

    let filter_params = params.into_filter_params();
    let data = fetch_findings_data(&state.db, filter_params).await;
    let hosts = state
        .db
        .distinct_hosts_filtered(&data.query)
        .await
        .unwrap_or_default();
    let rules = state
        .db
        .distinct_rules_filtered(&data.query)
        .await
        .unwrap_or_default();

    FindingsRowsTemplate {
        findings: data.findings,
        total: data.total,
        page: data.page,
        per_page: data.per_page,
        total_pages: data.total_pages,
        showing_start: data.showing_start,
        showing_end: data.showing_end,
        hosts,
        rules,
        is_fragment: true,
        current_triage: data.current_triage,
        current_host: data.current_host,
        current_rule: data.current_rule,
        current_q: data.current_q,
        current_sort: data.current_sort,
        current_dir: data.current_dir,
        current_show: data.current_show,
    }
}

pub async fn api_finding_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<FindingDetailTemplate, StatusCode> {
    match state.db.finding_by_id(id).await {
        Ok(Some(finding)) => {
            let permissions = super::templates::format_mode(finding.file_mode);
            // On a read error, fall back to no note rather than failing the whole detail view.
            let note = state
                .db
                .get_note(id)
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
            Ok(FindingDetailTemplate {
                finding,
                permissions,
                note,
            })
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Debug, Deserialize)]
pub struct NoteParams {
    pub note: Option<String>,
}

pub async fn api_finding_note(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    axum::extract::Form(params): axum::extract::Form<NoteParams>,
) -> Result<NoteSavedTemplate, StatusCode> {
    let note = params
        .note
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match state.db.set_note(id, note).await {
        Ok(()) => Ok(NoteSavedTemplate { saved: true }),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn api_finding_star(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<StarButtonTemplate, StatusCode> {
    match state.db.toggle_star(id).await {
        Ok(starred) => Ok(StarButtonTemplate { id, starred }),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn api_finding_review(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<ReviewButtonTemplate, StatusCode> {
    match state.db.toggle_review(id).await {
        Ok(reviewed) => Ok(ReviewButtonTemplate { id, reviewed }),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn api_host_exports(
    State(state): State<Arc<AppState>>,
    Path(host): Path<String>,
) -> HostExportsTemplate {
    let topo = state
        .db
        .host_topology(None, &host)
        .await
        .unwrap_or_default();
    let max_count = topo
        .iter()
        .map(|t| t.finding_count)
        .max()
        .unwrap_or(1)
        .max(1);

    let mut details = Vec::with_capacity(topo.len());
    for t in topo {
        let findings = if t.finding_count > 0 {
            state
                .db
                .findings_for_host_export(None, &host, &t.export_path)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        details.push(super::templates::HostExportDetail {
            export_path: t.export_path,
            count: t.finding_count,
            bar_pct: t.finding_count as f64 / max_count as f64 * 100.0,
            nfs_version: t.nfs_version,
            allowed_hosts: t.allowed_hosts,
            misconfigs: t.misconfigs,
            findings,
        });
    }

    HostExportsTemplate { exports: details }
}

pub async fn api_stats(State(state): State<Arc<AppState>>) -> Response {
    match state.db.get_stats().await {
        Ok(stats) => axum::Json(stats).into_response(),
        Err(e) => {
            tracing::error!("stats query failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Findings to export: the explicit `ids` selection if present, else the
/// current filter query (capped large for a full export).
async fn select_export_findings(db: &Database, params: FindingsParams) -> Vec<super::db::Finding> {
    let id_list: Vec<i64> = params.ids.as_deref().map(parse_id_list).unwrap_or_default();
    if !id_list.is_empty() {
        return db.list_findings_by_ids(&id_list).await.unwrap_or_default();
    }
    let q = params.into_export_query();
    db.list_findings(&q).await.unwrap_or_default()
}

pub async fn api_export_csv(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> Response {
    let findings = select_export_findings(&state.db, params).await;
    let mut buf = Vec::new();
    if let Err(e) = crate::output::export::export_csv(&findings, &mut buf) {
        tracing::error!("CSV export failed: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"niffler-export.csv\"",
            ),
        ],
        buf,
    )
        .into_response()
}

pub async fn api_export_json(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> Response {
    let findings = select_export_findings(&state.db, params).await;
    let mut buf = Vec::new();
    if let Err(e) = crate::output::export::export_json(&findings, &mut buf) {
        tracing::error!("JSON export failed: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"niffler-export.jsonl\"",
            ),
        ],
        buf,
    )
        .into_response()
}

pub async fn api_export_markdown(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FindingsParams>,
) -> Response {
    let findings = select_export_findings(&state.db, params).await;
    let mut buf = Vec::new();
    if let Err(e) = crate::output::export::export_markdown(&findings, &mut buf) {
        tracing::error!("Markdown export failed: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"niffler-report.md\"",
            ),
        ],
        buf,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(per_page: Option<u64>, page: Option<u64>) -> FindingsParams {
        FindingsParams {
            scan_id: None,
            triage: None,
            host: None,
            rule: None,
            q: None,
            sort: None,
            dir: None,
            page,
            per_page,
            show: None,
            ids: None,
        }
    }

    #[test]
    fn per_page_clamped_to_max() {
        let q = params(Some(99_999_999), None).into_query();
        assert_eq!(q.per_page, MAX_PER_PAGE);
    }

    #[test]
    fn per_page_zero_becomes_at_least_one() {
        let q = params(Some(0), None).into_query();
        assert!(q.per_page >= 1);
    }

    #[test]
    fn page_zero_clamped_to_one() {
        let q = params(None, Some(0)).into_query();
        assert!(q.page >= 1);
    }

    #[test]
    fn per_page_default_preserved() {
        let q = params(None, None).into_query();
        assert_eq!(q.per_page, 50);
    }
}
