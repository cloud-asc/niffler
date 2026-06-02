use anyhow::Result;
use rusqlite::OptionalExtension;
use rusqlite::params;

use super::Database;

impl Database {
    pub async fn toggle_star(&self, finding_id: i64) -> Result<bool> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO annotations (finding_id, starred)
                     VALUES (?1, 1)
                     ON CONFLICT(finding_id) DO UPDATE SET starred = 1 - starred",
                    params![finding_id],
                )?;
                let new_state: bool = conn.query_row(
                    "SELECT starred FROM annotations WHERE finding_id = ?1",
                    params![finding_id],
                    |row| row.get(0),
                )?;
                Ok::<_, rusqlite::Error>(new_state)
            })
            .await
            .map_err(Into::into)
    }

    pub async fn toggle_review(&self, finding_id: i64) -> Result<bool> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO annotations (finding_id, reviewed)
                     VALUES (?1, 1)
                     ON CONFLICT(finding_id) DO UPDATE SET reviewed = 1 - reviewed",
                    params![finding_id],
                )?;
                let new_state: bool = conn.query_row(
                    "SELECT reviewed FROM annotations WHERE finding_id = ?1",
                    params![finding_id],
                    |row| row.get(0),
                )?;
                Ok::<_, rusqlite::Error>(new_state)
            })
            .await
            .map_err(Into::into)
    }

    /// Set the `starred` flag to `value` for every id, in one transaction.
    /// Returns the number of ids processed. Empty input is a no-op.
    pub async fn bulk_set_starred(&self, ids: Vec<i64>, value: bool) -> Result<usize> {
        self.bulk_set_annotation_flag("starred", ids, value).await
    }

    /// Set the `reviewed` flag to `value` for every id, in one transaction.
    pub async fn bulk_set_reviewed(&self, ids: Vec<i64>, value: bool) -> Result<usize> {
        self.bulk_set_annotation_flag("reviewed", ids, value).await
    }

    /// Read the operator note for a finding, if any.
    pub async fn get_note(&self, finding_id: i64) -> Result<Option<String>> {
        self.conn
            .call(move |conn| {
                // outer None = no annotations row; inner None = row exists but notes IS NULL
                let note: Option<String> = conn
                    .query_row(
                        "SELECT notes FROM annotations WHERE finding_id = ?1",
                        params![finding_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .flatten();
                Ok::<_, rusqlite::Error>(note)
            })
            .await
            .map_err(Into::into)
    }

    /// Set (or clear, with `None`) the operator note for a finding.
    pub async fn set_note(&self, finding_id: i64, note: Option<String>) -> Result<()> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO annotations (finding_id, notes) VALUES (?1, ?2)
                     ON CONFLICT(finding_id) DO UPDATE SET notes = ?2",
                    params![finding_id, note],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(Into::into)
    }

    /// Shared impl for the two boolean annotation flags. `column` is a trusted,
    /// hardcoded identifier ("starred" | "reviewed"), never user input.
    async fn bulk_set_annotation_flag(
        &self,
        column: &'static str,
        ids: Vec<i64>,
        value: bool,
    ) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let val: i64 = if value { 1 } else { 0 };
        let count = ids.len();
        self.conn
            .call(move |conn| {
                let sql = format!(
                    "INSERT INTO annotations (finding_id, {column}) VALUES (?1, ?2)
                     ON CONFLICT(finding_id) DO UPDATE SET {column} = ?2"
                );
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare_cached(&sql)?;
                    for id in &ids {
                        stmt.execute(rusqlite::params![id, val])?;
                    }
                }
                tx.commit()?;
                Ok::<_, rusqlite::Error>(())
            })
            .await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use crate::classifier::Triage;
    use crate::web::db::test_helpers::{make_test_result, seed_test_data};
    use crate::web::db::{Database, FindingsQuery, ShowFilter};

    #[tokio::test]
    async fn test_star_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let starred = db.toggle_star(id).await.unwrap();
        assert!(starred, "first toggle should star");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(f.starred);
    }

    #[tokio::test]
    async fn test_unstar_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        db.toggle_star(id).await.unwrap();
        let unstarred = db.toggle_star(id).await.unwrap();
        assert!(!unstarred, "second toggle should unstar");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(!f.starred);
    }

    #[tokio::test]
    async fn test_review_finding() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = db.create_scan(&["10.0.0.1".into()], "scan").await.unwrap();
        let msg = make_test_result("10.0.0.1", "/exports", "/file.txt", Triage::Red, "Rule");
        db.insert_finding(scan_id, &msg).await.unwrap();

        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let id = all[0].id;

        let reviewed = db.toggle_review(id).await.unwrap();
        assert!(reviewed, "first toggle should mark reviewed");

        let f = db.finding_by_id(id).await.unwrap().unwrap();
        assert!(f.reviewed);
    }

    #[tokio::test]
    async fn test_filter_starred() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Get first two finding IDs and star them
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        db.toggle_star(all[0].id).await.unwrap();
        db.toggle_star(all[1].id).await.unwrap();

        let starred = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Starred,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(starred.len(), 2, "should have exactly 2 starred findings");
    }

    #[tokio::test]
    async fn test_filter_unreviewed() {
        let db = Database::open_memory().await.unwrap();
        let scan_id = seed_test_data(&db).await;

        // Review 3 findings
        let all = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        db.toggle_review(all[0].id).await.unwrap();
        db.toggle_review(all[1].id).await.unwrap();
        db.toggle_review(all[2].id).await.unwrap();

        let unreviewed = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Unreviewed,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(unreviewed.len(), 7, "10 total - 3 reviewed = 7 unreviewed");
    }

    #[tokio::test]
    async fn test_bulk_set_starred() {
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
        let ids: Vec<i64> = all.iter().take(3).map(|f| f.id).collect();

        let n = db.bulk_set_starred(ids.clone(), true).await.unwrap();
        assert_eq!(n, 3);

        let starred = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Starred,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(starred.len(), 3, "3 findings should be starred");

        db.bulk_set_starred(ids.clone(), true).await.unwrap();
        db.bulk_set_starred(ids.clone(), false).await.unwrap();
        let starred2 = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Starred,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(starred2.len(), 0, "all unstarred after set-false");
    }

    #[tokio::test]
    async fn test_bulk_set_reviewed() {
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
        let ids: Vec<i64> = all.iter().take(4).map(|f| f.id).collect();

        let n = db.bulk_set_reviewed(ids, true).await.unwrap();
        assert_eq!(n, 4);

        let unreviewed = db
            .list_findings(&FindingsQuery {
                scan_id: Some(scan_id),
                show: ShowFilter::Unreviewed,
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(unreviewed.len(), 6, "10 - 4 reviewed = 6 unreviewed");
    }

    #[tokio::test]
    async fn test_bulk_empty_is_noop() {
        let db = Database::open_memory().await.unwrap();
        let n = db.bulk_set_starred(Vec::new(), true).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_set_and_get_note() {
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
        let id = all[0].id;

        assert_eq!(db.get_note(id).await.unwrap(), None, "no note initially");
        db.set_note(id, Some("pivot via this host".to_string()))
            .await
            .unwrap();
        assert_eq!(
            db.get_note(id).await.unwrap().as_deref(),
            Some("pivot via this host")
        );

        db.set_note(id, None).await.unwrap();
        assert_eq!(db.get_note(id).await.unwrap(), None);
    }
}
