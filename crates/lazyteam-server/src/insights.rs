use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{ApiError, AppState};

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/insights", get(insights))
}

#[derive(Debug, Deserialize)]
struct InsightsQuery {
    #[serde(default = "default_window")]
    window: String,
}

fn default_window() -> String {
    "30d".into()
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CountRate {
    pub(crate) count: i64,
    pub(crate) denominator: i64,
    pub(crate) rate: Option<f64>,
}

fn count_rate(count: i64, denominator: i64) -> CountRate {
    CountRate {
        count,
        denominator,
        rate: if denominator > 0 {
            Some(count as f64 / denominator as f64)
        } else {
            None
        },
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DurationSummary {
    pub(crate) sample: i64,
    pub(crate) median_secs: Option<f64>,
    pub(crate) avg_secs: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkerBreakdown {
    pub(crate) worker_id: Option<String>,
    pub(crate) worker_name: String,
    pub(crate) agent_type: String,
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) executions: i64,
    pub(crate) completed: i64,
    pub(crate) failed: i64,
    pub(crate) denominator: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ModelBreakdown {
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) executions: i64,
    pub(crate) completed: i64,
    pub(crate) denominator: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReviewerBreakdown {
    pub(crate) worker_id: Option<String>,
    pub(crate) worker_name: String,
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) completed: i64,
    pub(crate) approve: i64,
    pub(crate) retry: i64,
    pub(crate) runtime_failed: i64,
    pub(crate) denominator: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReasonItem {
    pub(crate) source: String,
    pub(crate) reason: String,
    pub(crate) task_id: String,
    pub(crate) task_title: Option<String>,
    pub(crate) execution_id: Option<String>,
    pub(crate) review_id: Option<String>,
    pub(crate) worker_name: Option<String>,
    pub(crate) reviewer_name: Option<String>,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TaskDetail {
    pub(crate) task_id: String,
    pub(crate) title: String,
    pub(crate) state: String,
    pub(crate) attempt: i64,
    pub(crate) review_rounds: i64,
    pub(crate) lifetime_retries: i64,
    pub(crate) current_cycle_retries: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InsightsResponse {
    pub(crate) window: String,
    pub(crate) cutoff: Option<String>,
    pub(crate) tasks_created: i64,
    pub(crate) tasks_done: i64,
    pub(crate) task_completion: DurationSummary,
    pub(crate) executions_total: i64,
    pub(crate) executions_completed: CountRate,
    pub(crate) executions_failed: CountRate,
    pub(crate) executions_lost: CountRate,
    pub(crate) executions_active: i64,
    pub(crate) execution_duration: DurationSummary,
    pub(crate) reviews_completed: i64,
    pub(crate) reviews_approve: CountRate,
    pub(crate) reviews_retry: CountRate,
    pub(crate) reviews_runtime_failed: i64,
    pub(crate) reviews_lost: i64,
    pub(crate) reviews_active: i64,
    /// Lifetime reviewer `retry` verdicts in window (all executions of each task).
    pub(crate) reviewer_retries_lifetime: i64,
    /// Current-cycle reviewer `retry` verdicts in window (latest execution only).
    pub(crate) reviewer_retries_current_cycle: i64,
    pub(crate) current_cycle_available: bool,
    pub(crate) main_gate_available: bool,
    pub(crate) main_gate_merged: i64,
    pub(crate) main_gate_sent_back: i64,
    pub(crate) main_gate_merge_conflict: i64,
    pub(crate) main_gate_upstream_moved: i64,
    pub(crate) impl_by_worker: Vec<WorkerBreakdown>,
    pub(crate) impl_by_model: Vec<ModelBreakdown>,
    pub(crate) impl_by_provider: Vec<ModelBreakdown>,
    pub(crate) reviewer_by_worker: Vec<ReviewerBreakdown>,
    pub(crate) reasons: Vec<ReasonItem>,
    pub(crate) tasks: Vec<TaskDetail>,
}

struct WorkerInfo {
    name: String,
    agent_type: String,
    provider: Option<String>,
    model: Option<String>,
}

fn parse_verdict_kind(raw: Option<&str>) -> Option<&'static str> {
    let raw = raw?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    match value.get("verdict")?.as_str()? {
        "approve" => Some("approve"),
        "retry" => Some("retry"),
        _ => None,
    }
}

fn parse_verdict_reason(raw: Option<&str>) -> String {
    raw.and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|value| {
            value
                .get("reason")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn parse_time(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .ok()
}

fn duration_summary(mut samples: Vec<f64>) -> DurationSummary {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples.len() as i64;
    if n == 0 {
        return DurationSummary {
            sample: 0,
            median_secs: None,
            avg_secs: None,
        };
    }
    let median = if n % 2 == 1 {
        samples[(n / 2) as usize]
    } else {
        (samples[(n / 2 - 1) as usize] + samples[(n / 2) as usize]) / 2.0
    };
    let avg = samples.iter().sum::<f64>() / n as f64;
    DurationSummary {
        sample: n,
        median_secs: Some(median),
        avg_secs: Some(avg),
    }
}

async fn table_exists(db: &sqlx::SqlitePool, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?")
        .bind(name)
        .fetch_one(db)
        .await
        .unwrap_or(0)
        > 0
}

async fn insights(
    State(state): State<Arc<AppState>>,
    Query(query): Query<InsightsQuery>,
) -> Result<Json<InsightsResponse>, ApiError> {
    let window = query.window.as_str();
    let days: Option<i64> = match window {
        "7d" => Some(7),
        "30d" => Some(30),
        "all" => None,
        _ => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "window must be 7d, 30d, or all".into(),
            ));
        }
    };
    let cutoff = days.map(|d| Utc::now() - chrono::Duration::days(d));
    let cutoff_str = cutoff.map(|value| value.to_rfc3339());

    let db = &state.db;
    let has_gate = table_exists(db, "main_gate_events").await;
    // reviews.execution_id has existed since the reviews table was introduced;
    // tolerate exotic prehistory by probing the schema instead of assuming.
    let reviews_have_execution: bool = if table_exists(db, "reviews").await {
        sqlx::query("PRAGMA table_info(reviews)")
            .fetch_all(db)
            .await
            .map(|rows| {
                rows.iter().any(|row| {
                    row.try_get::<String, _>("name")
                        .is_ok_and(|name| name == "execution_id")
                })
            })
            .unwrap_or(false)
    } else {
        false
    };

    // Worker catalog for breakdown labels (includes retired workers so old
    // history still resolves to a name/provider/model).
    let mut workers: HashMap<String, WorkerInfo> = HashMap::new();
    if table_exists(db, "workers").await {
        if let Ok(rows) = sqlx::query("SELECT id,name,agent_type,agent_provider,agent_model FROM workers")
            .fetch_all(db)
            .await
        {
            for row in rows {
                let id: String = row.try_get("id").unwrap_or_default();
                if id.is_empty() {
                    continue;
                }
                workers.insert(
                    id,
                    WorkerInfo {
                        name: row.try_get("name").unwrap_or_default(),
                        agent_type: row
                            .try_get::<Option<String>, _>("agent_type")
                            .unwrap_or(None)
                            .unwrap_or_else(|| "pi".into()),
                        provider: row
                            .try_get::<Option<String>, _>("agent_provider")
                            .unwrap_or(None)
                            .filter(|v| !v.is_empty()),
                        model: row
                            .try_get::<Option<String>, _>("agent_model")
                            .unwrap_or(None)
                            .filter(|v| !v.is_empty()),
                    },
                );
            }
        }
    }

    // ---- Tasks (durable task rows; created counts use created_at, done
    // counts use updated_at in window with state='done'). ----
    let (tasks_created, tasks_done) = if table_exists(db, "tasks").await {
        let created: i64 = match &cutoff_str {
            Some(cut) => sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE state!='cancelled' AND created_at>=?")
                .bind(cut).fetch_one(db).await.map_err(internal)?,
            None => sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE state!='cancelled'")
                .fetch_one(db).await.map_err(internal)?,
        };
        let done: i64 = match &cutoff_str {
            Some(cut) => sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE state='done' AND updated_at>=?")
                .bind(cut).fetch_one(db).await.map_err(internal)?,
            None => sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE state='done'")
                .fetch_one(db).await.map_err(internal)?,
        };
        (created, done)
    } else {
        (0, 0)
    };
    // Task completion time: done tasks in window, created_at -> updated_at.
    let mut task_durations: Vec<f64> = Vec::new();
    if table_exists(db, "tasks").await {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT created_at,updated_at FROM tasks WHERE state='done' AND updated_at>=?")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT created_at,updated_at FROM tasks WHERE state='done'")
                .fetch_all(db).await.map_err(internal)?,
        };
        for row in rows {
            let created: String = row.try_get("created_at").unwrap_or_default();
            let updated: String = row.try_get("updated_at").unwrap_or_default();
            if let (Some(a), Some(b)) = (parse_time(&created), parse_time(&updated)) {
                let secs = (b - a).num_seconds().max(0) as f64;
                task_durations.push(secs);
            }
        }
    }
    let task_completion = duration_summary(task_durations);

    // ---- Executions (durable execution rows). ----
    #[derive(Debug)]
    struct ExecRow {
        id: String,
        worker_id: String,
        state: String,
        created: String,
        started: Option<String>,
        finished: Option<String>,
    }
    let exec_rows: Vec<ExecRow> = if table_exists(db, "executions").await {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT id,worker_id,state,created_at,started_at,finished_at FROM executions WHERE created_at>=?")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT id,worker_id,state,created_at,started_at,finished_at FROM executions")
                .fetch_all(db).await.map_err(internal)?,
        };
        rows.into_iter().map(|row| ExecRow {
            id: row.try_get("id").unwrap_or_default(),
            worker_id: row.try_get("worker_id").unwrap_or_default(),
            state: row.try_get("state").unwrap_or_default(),
            created: row.try_get("created_at").unwrap_or_default(),
            started: row.try_get("started_at").unwrap_or(None),
            finished: row.try_get("finished_at").unwrap_or(None),
        }).collect()
    } else {
        Vec::new()
    };
    let total = exec_rows.len() as i64;
    let completed = exec_rows.iter().filter(|r| r.state == "completed").count() as i64;
    let failed = exec_rows.iter().filter(|r| r.state == "failed").count() as i64;
    let lost = exec_rows.iter().filter(|r| r.state == "lost").count() as i64;
    let active = exec_rows
        .iter()
        .filter(|r| r.state == "assigned" || r.state == "running")
        .count() as i64;
    let mut exec_durations: Vec<f64> = Vec::new();
    for row in exec_rows.iter().filter(|r| r.state == "completed") {
        let end = row.finished.as_deref().and_then(parse_time);
        let start = row
            .started
            .as_deref()
            .and_then(parse_time)
            .or_else(|| parse_time(&row.created));
        if let (Some(a), Some(b)) = (start, end) {
            exec_durations.push((b - a).num_seconds().max(0) as f64);
        }
    }
    let execution_duration = duration_summary(exec_durations);

    // Latest execution per task over all history (for current-cycle retries).
    let mut latest_execution: HashMap<String, String> = HashMap::new();
    let mut latest_attempt: HashMap<String, i64> = HashMap::new();
    if table_exists(db, "executions").await {
        if let Ok(rows) = sqlx::query(
            "SELECT task_id,id,attempt FROM executions ORDER BY task_id,attempt DESC",
        )
        .fetch_all(db)
        .await
        {
            for row in rows {
                let task_id: String = row.try_get("task_id").unwrap_or_default();
                if latest_execution.contains_key(&task_id) {
                    continue;
                }
                let exec_id: String = row.try_get("id").unwrap_or_default();
                let attempt: i64 = row.try_get("attempt").unwrap_or(0);
                latest_execution.insert(task_id.clone(), exec_id);
                latest_attempt.insert(task_id, attempt);
            }
        }
    }

    // ---- Reviews (durable review rows; verdict JSON only for quality). ----
    struct ReviewRow {
        id: String,
        task_id: String,
        execution_id: Option<String>,
        reviewer_id: String,
        state: String,
        verdict: Option<String>,
        created_at: String,
    }
    let review_rows: Vec<ReviewRow> = if table_exists(db, "reviews").await {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT id,task_id,execution_id,reviewer_worker_id,state,verdict,created_at FROM reviews WHERE created_at>=?")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT id,task_id,execution_id,reviewer_worker_id,state,verdict,created_at FROM reviews")
                .fetch_all(db).await.map_err(internal)?,
        };
        rows.into_iter().map(|row| ReviewRow {
            id: row.try_get("id").unwrap_or_default(),
            task_id: row.try_get("task_id").unwrap_or_default(),
            execution_id: row.try_get::<Option<String>, _>("execution_id").unwrap_or(None),
            reviewer_id: row.try_get("reviewer_worker_id").unwrap_or_default(),
            state: row.try_get("state").unwrap_or_default(),
            verdict: row.try_get("verdict").unwrap_or(None),
            created_at: row.try_get("created_at").unwrap_or_default(),
        }).collect()
    } else {
        Vec::new()
    };
    let completed_reviews: Vec<&ReviewRow> =
        review_rows.iter().filter(|r| r.state == "completed").collect();
    let approve = completed_reviews
        .iter()
        .filter(|r| parse_verdict_kind(r.verdict.as_deref()) == Some("approve"))
        .count() as i64;
    let retry = completed_reviews
        .iter()
        .filter(|r| parse_verdict_kind(r.verdict.as_deref()) == Some("retry"))
        .count() as i64;
    let completed_n = completed_reviews.len() as i64;
    let runtime_failed = review_rows.iter().filter(|r| r.state == "failed").count() as i64;
    let reviews_lost = review_rows.iter().filter(|r| r.state == "lost").count() as i64;
    let reviews_active = review_rows
        .iter()
        .filter(|r| r.state == "assigned" || r.state == "running")
        .count() as i64;
    // Current-cycle: retry verdicts on the task's latest execution. Lifetime:
    // retry verdicts on any execution. Tolerate pre-migration rows without
    // execution_id by reporting current-cycle as unavailable.
    let current_cycle_available = reviews_have_execution;
    let current_cycle_retries: i64 = if current_cycle_available {
        review_rows
            .iter()
            .filter(|r| {
                r.state == "completed"
                    && parse_verdict_kind(r.verdict.as_deref()) == Some("retry")
                    && r.execution_id.as_ref().is_some_and(|exec| {
                        latest_execution.get(&r.task_id).is_some_and(|latest| latest == exec)
                    })
            })
            .count() as i64
    } else {
        0
    };

    // ---- Main gate (durable gate events only; never inferred from task state). ----
    let (gate_merged, gate_sent_back, gate_conflict, gate_moved) = if has_gate {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT kind,reason FROM main_gate_events WHERE created_at>=?")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT kind,reason FROM main_gate_events")
                .fetch_all(db).await.map_err(internal)?,
        };
        let mut merged = 0_i64;
        let mut sent_back = 0_i64;
        let mut conflict = 0_i64;
        let mut moved = 0_i64;
        for row in rows {
            let kind: String = row.try_get("kind").unwrap_or_default();
            let reason: String = row.try_get("reason").unwrap_or_default();
            match kind.as_str() {
                "merged" => {
                    merged += 1;
                    if reason.contains("upstream moved") {
                        moved += 1;
                    }
                }
                "sent_back" => sent_back += 1,
                "merge_conflict" => conflict += 1,
                _ => {}
            }
        }
        (merged, sent_back, conflict, moved)
    } else {
        (0, 0, 0, 0)
    };

    // ---- Breakdowns by worker / model / provider (with denominators). ----
    let mut impl_worker_map: HashMap<String, (i64, i64, i64)> = HashMap::new();
    for row in &exec_rows {
        let entry = impl_worker_map.entry(row.worker_id.clone()).or_insert((0, 0, 0));
        entry.0 += 1;
        if row.state == "completed" {
            entry.1 += 1;
        }
        if row.state == "failed" {
            entry.2 += 1;
        }
    }
    let mut impl_by_worker: Vec<WorkerBreakdown> = impl_worker_map
        .into_iter()
        .map(|(worker_id, (executions, completed, failed))| {
            let info = workers.get(&worker_id);
            WorkerBreakdown {
                worker_id: Some(worker_id),
                worker_name: info.map(|w| w.name.clone()).unwrap_or_else(|| "unknown worker".into()),
                agent_type: info.map(|w| w.agent_type.clone()).unwrap_or_else(|| "pi".into()),
                provider: info.and_then(|w| w.provider.clone()),
                model: info.and_then(|w| w.model.clone()),
                executions,
                completed,
                failed,
                denominator: executions,
            }
        })
        .collect();
    impl_by_worker.sort_by(|a, b| b.executions.cmp(&a.executions));

    let mut model_map: HashMap<(Option<String>, Option<String>), (i64, i64)> = HashMap::new();
    let mut provider_map: HashMap<Option<String>, (i64, i64)> = HashMap::new();
    for row in &exec_rows {
        let info = workers.get(&row.worker_id);
        let provider = info.and_then(|w| w.provider.clone());
        let model = info.and_then(|w| w.model.clone());
        let entry = model_map.entry((provider.clone(), model)).or_insert((0, 0));
        entry.0 += 1;
        if row.state == "completed" {
            entry.1 += 1;
        }
        let entry = provider_map.entry(provider).or_insert((0, 0));
        entry.0 += 1;
        if row.state == "completed" {
            entry.1 += 1;
        }
    }
    let mut impl_by_model: Vec<ModelBreakdown> = model_map
        .into_iter()
        .map(|((provider, model), (executions, completed))| ModelBreakdown {
            provider,
            model,
            executions,
            completed,
            denominator: executions,
        })
        .collect();
    impl_by_model.sort_by(|a, b| b.executions.cmp(&a.executions));
    let mut impl_by_provider: Vec<ModelBreakdown> = provider_map
        .into_iter()
        .map(|(provider, (executions, completed))| ModelBreakdown {
            provider,
            model: None,
            executions,
            completed,
            denominator: executions,
        })
        .collect();
    impl_by_provider.sort_by(|a, b| b.executions.cmp(&a.executions));

    struct ReviewerAgg {
        completed: i64,
        approve: i64,
        retry: i64,
        failed: i64,
    }
    let mut reviewer_map: HashMap<String, ReviewerAgg> = HashMap::new();
    for row in &review_rows {
        let entry = reviewer_map.entry(row.reviewer_id.clone()).or_insert(ReviewerAgg {
            completed: 0,
            approve: 0,
            retry: 0,
            failed: 0,
        });
        if row.state == "completed" {
            entry.completed += 1;
            match parse_verdict_kind(row.verdict.as_deref()) {
                Some("approve") => entry.approve += 1,
                Some("retry") => entry.retry += 1,
                _ => {}
            }
        }
        if row.state == "failed" {
            entry.failed += 1;
        }
    }
    let mut reviewer_by_worker: Vec<ReviewerBreakdown> = reviewer_map
        .into_iter()
        .map(|(worker_id, agg)| {
            let info = workers.get(&worker_id);
            let denominator = agg.completed + agg.failed;
            ReviewerBreakdown {
                worker_id: Some(worker_id),
                worker_name: info.map(|w| w.name.clone()).unwrap_or_else(|| "unknown reviewer".into()),
                provider: info.and_then(|w| w.provider.clone()),
                model: info.and_then(|w| w.model.clone()),
                completed: agg.completed,
                approve: agg.approve,
                retry: agg.retry,
                runtime_failed: agg.failed,
                denominator,
            }
        })
        .collect();
    reviewer_by_worker.sort_by(|a, b| b.denominator.cmp(&a.denominator));

    // Task titles for drill-downs.
    let mut titles: HashMap<String, String> = HashMap::new();
    if table_exists(db, "tasks").await {
        if let Ok(rows) = sqlx::query("SELECT id,title FROM tasks").fetch_all(db).await {
            for row in rows {
                let id: String = row.try_get("id").unwrap_or_default();
                let title: String = row.try_get("title").unwrap_or_default();
                titles.insert(id, title);
            }
        }
    }
    let worker_name = |id: &str| workers.get(id).map(|w| w.name.clone());

    // ---- Reasons with drill-down evidence (verdict JSON + gate events). ----
    let mut reasons: Vec<ReasonItem> = Vec::new();
    let mut retry_rows: Vec<&ReviewRow> = review_rows
        .iter()
        .filter(|r| {
            r.state == "completed"
                && parse_verdict_kind(r.verdict.as_deref()) == Some("retry")
        })
        .collect();
    retry_rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    for row in retry_rows.into_iter().take(50) {
        let reason = parse_verdict_reason(row.verdict.as_deref());
        let exec_worker = latest_exec_worker(db, &row.execution_id).await;
        reasons.push(ReasonItem {
            source: "reviewer_retry".into(),
            reason: truncate(&reason, 500),
            task_id: row.task_id.clone(),
            task_title: titles.get(&row.task_id).cloned(),
            execution_id: row.execution_id.clone(),
            review_id: Some(row.id.clone()),
            worker_name: exec_worker
                .as_deref()
                .and_then(worker_name)
                .or(exec_worker),
            reviewer_name: worker_name(&row.reviewer_id),
            created_at: row.created_at.clone(),
        });
    }
    if has_gate {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT id,task_id,execution_id,kind,reason,created_at FROM main_gate_events WHERE created_at>=? AND kind IN ('sent_back','merge_conflict') ORDER BY created_at DESC LIMIT 50")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT id,task_id,execution_id,kind,reason,created_at FROM main_gate_events WHERE kind IN ('sent_back','merge_conflict') ORDER BY created_at DESC LIMIT 50")
                .fetch_all(db).await.map_err(internal)?,
        };
        for row in rows {
            let id: String = row.try_get("id").unwrap_or_default();
            let task_id: String = row.try_get("task_id").unwrap_or_default();
            let execution_id: Option<String> =
                row.try_get("execution_id").unwrap_or(None);
            let kind: String = row.try_get("kind").unwrap_or_default();
            let reason: String = row.try_get("reason").unwrap_or_default();
            let created_at: String = row.try_get("created_at").unwrap_or_default();
            let _ = id;
            reasons.push(ReasonItem {
                source: kind,
                reason: truncate(&reason, 500),
                task_id: task_id.clone(),
                task_title: titles.get(&task_id).cloned(),
                execution_id,
                review_id: None,
                worker_name: None,
                reviewer_name: None,
                created_at,
            });
        }
        reasons.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        reasons.truncate(100);
    }

    // ---- Per-task detail with lifetime + current-cycle retries. ----
    // Lifetime counts come from all durable review verdict rows for the task;
    // current-cycle counts restrict to the latest execution. Both derive from
    // history, never from task-state prose.
    let mut all_retries_lifetime: HashMap<String, i64> = HashMap::new();
    let mut all_retries_cycle: HashMap<String, i64> = HashMap::new();
    let mut all_rounds: HashMap<String, i64> = HashMap::new();
    if table_exists(db, "reviews").await {
        if let Ok(rows) =
            sqlx::query("SELECT task_id,execution_id,state,verdict FROM reviews").fetch_all(db).await
        {
            for row in rows {
                let task_id: String = row.try_get("task_id").unwrap_or_default();
                let state: String = row.try_get("state").unwrap_or_default();
                *all_rounds.entry(task_id.clone()).or_insert(0) += 1;
                if state != "completed" {
                    continue;
                }
                let verdict: Option<String> = row.try_get("verdict").unwrap_or(None);
                if parse_verdict_kind(verdict.as_deref()) != Some("retry") {
                    continue;
                }
                *all_retries_lifetime.entry(task_id.clone()).or_insert(0) += 1;
                let exec: Option<String> =
                    row.try_get("execution_id").unwrap_or(None);
                if current_cycle_available
                    && exec.as_ref().is_some_and(|e| {
                        latest_execution.get(&task_id).is_some_and(|latest| latest == e)
                    })
                {
                    *all_retries_cycle.entry(task_id).or_insert(0) += 1;
                }
            }
        }
    }
    let mut tasks_detail: Vec<TaskDetail> = Vec::new();
    if table_exists(db, "tasks").await {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT id,title,state FROM tasks WHERE state!='cancelled' AND created_at>=? ORDER BY created_at DESC LIMIT 100")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT id,title,state FROM tasks WHERE state!='cancelled' ORDER BY created_at DESC LIMIT 100")
                .fetch_all(db).await.map_err(internal)?,
        };
        for row in rows {
            let id: String = row.try_get("id").unwrap_or_default();
            tasks_detail.push(TaskDetail {
                task_id: id.clone(),
                title: row.try_get("title").unwrap_or_default(),
                state: row.try_get("state").unwrap_or_default(),
                attempt: latest_attempt.get(&id).copied().unwrap_or(0),
                review_rounds: all_rounds.get(&id).copied().unwrap_or(0),
                lifetime_retries: all_retries_lifetime.get(&id).copied().unwrap_or(0),
                current_cycle_retries: all_retries_cycle.get(&id).copied().unwrap_or(0),
            });
        }
    }

    Ok(Json(InsightsResponse {
        window: window.to_string(),
        cutoff: cutoff_str,
        tasks_created,
        tasks_done,
        task_completion,
        executions_total: total,
        executions_completed: count_rate(completed, total),
        executions_failed: count_rate(failed, total),
        executions_lost: count_rate(lost, total),
        executions_active: active,
        execution_duration,
        reviews_completed: completed_n,
        reviews_approve: count_rate(approve, completed_n),
        reviews_retry: count_rate(retry, completed_n),
        reviews_runtime_failed: runtime_failed,
        reviews_lost,
        reviews_active,
        reviewer_retries_lifetime: retry,
        reviewer_retries_current_cycle: current_cycle_retries,
        current_cycle_available,
        main_gate_available: has_gate,
        main_gate_merged: gate_merged,
        main_gate_sent_back: gate_sent_back,
        main_gate_merge_conflict: gate_conflict,
        main_gate_upstream_moved: gate_moved,
        impl_by_worker,
        impl_by_model,
        impl_by_provider,
        reviewer_by_worker,
        reasons,
        tasks: tasks_detail,
    }))
}

async fn latest_exec_worker(db: &sqlx::SqlitePool, execution_id: &Option<String>) -> Option<String> {
    let id = execution_id.as_ref()?;
    sqlx::query_scalar::<_, String>("SELECT worker_id FROM executions WHERE id=?")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

fn truncate(raw: &str, max: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    trimmed.chars().take(max).collect::<String>() + "…"
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        error.to_string(),
    )
}

#[allow(dead_code)]
fn uuid(value: String) -> Result<Uuid, ApiError> {
    Uuid::parse_str(&value).map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_db() -> sqlx::SqlitePool {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        db
    }

    fn state_with(db: sqlx::SqlitePool) -> Arc<AppState> {
        Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(),
        })
    }

    #[tokio::test]
    async fn insights_rejects_unknown_window() {
        let state = state_with(memory_db().await);
        let result = insights(
            State(state),
            Query(InsightsQuery { window: "90d".into() }),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn insights_separates_quality_retries_from_runtime_and_gate() {
        let db = memory_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,agent_type,agent_provider,agent_model,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&worker_id).bind("impl-01").bind("worker").bind("idle").bind("linux").bind("x86_64")
            .bind("pi").bind("acme").bind("cheap-1").bind(6_i64).bind("test").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,agent_type,agent_provider,agent_model,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&reviewer_id).bind("rev-01").bind("reviewer").bind("idle").bind("linux").bind("x86_64")
            .bind("pi").bind("acme").bind("critic-1").bind(6_i64).bind("test").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("t").bind("").bind("").bind("review").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let exec_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,started_at,finished_at,result,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(&exec_id).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now)
            .bind(&now).bind(&now)
            .bind(r#"{"status":"completed","summary":"s","commit_sha":"abc","base_sha":"base","review_ref":"r"}"#)
            .bind(&now)
            .execute(&db).await.unwrap();
        // One quality retry, one approve, one runtime failure.
        for (verdict, state) in [
            (r#"{"verdict":"retry","reason":"missing null check in foo.rs","validation":[]}"#, "completed"),
            (r#"{"verdict":"approve","reason":"looks good","validation":[]}"#, "completed"),
            (r#"{"error":"runner crashed"}"#, "failed"),
        ] {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,finished_at,verdict) VALUES(?,?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&exec_id).bind(&reviewer_id)
                .bind(state).bind(&now).bind(&now).bind(&now).bind(verdict)
                .execute(&db).await.unwrap();
        }
        // One merge-conflict gate event: must not count as reviewer retry.
        sqlx::query("INSERT INTO main_gate_events(id,task_id,execution_id,kind,reason,created_at) VALUES(?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&exec_id)
            .bind("merge_conflict").bind("merge conflict with current main abc: foo.rs").bind(&now)
            .execute(&db).await.unwrap();

        let state = state_with(db);
        let Json(body) = insights(State(state), Query(InsightsQuery { window: "all".into() }))
            .await
            .unwrap();
        assert_eq!(body.reviews_completed, 2);
        assert_eq!(body.reviews_retry.count, 1);
        assert_eq!(body.reviews_retry.denominator, 2);
        assert_eq!(body.reviews_approve.count, 1);
        assert_eq!(body.reviews_runtime_failed, 1);
        assert_eq!(body.reviewer_retries_lifetime, 1);
        assert_eq!(body.reviewer_retries_current_cycle, 1);
        assert!(body.current_cycle_available);
        assert!(body.main_gate_available);
        assert_eq!(body.main_gate_merge_conflict, 1);
        assert_eq!(body.main_gate_sent_back, 0);
        assert_eq!(body.main_gate_merged, 0);
        // Breakdowns always carry sample denominators.
        assert_eq!(body.impl_by_worker.len(), 1);
        assert_eq!(body.impl_by_worker[0].denominator, 1);
        assert_eq!(body.impl_by_model.len(), 1);
        assert_eq!(body.reviewer_by_worker.len(), 1);
        assert_eq!(body.reviewer_by_worker[0].denominator, 3);
        // Reasons drill down to durable evidence.
        assert!(body.reasons.iter().any(|r| r.source == "reviewer_retry"
            && r.task_id == task_id
            && r.reason.contains("missing null check")));
        assert!(body.reasons.iter().any(|r| r.source == "merge_conflict" && r.task_id == task_id));
        // Per-task detail shows both lifetime and current-cycle retries.
        assert_eq!(body.tasks.len(), 1);
        assert_eq!(body.tasks[0].lifetime_retries, 1);
        assert_eq!(body.tasks[0].current_cycle_retries, 1);
    }

    #[tokio::test]
    async fn insights_current_cycle_counts_only_latest_execution() {
        let db = memory_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (id, role) in [(&worker_id, "worker"), (&reviewer_id, "reviewer")] {
            sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(role).bind(role).bind("idle").bind("linux").bind("x86_64")
                .bind(6_i64).bind("test").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("t").bind("").bind("").bind("review").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let exec_old = Uuid::new_v4().to_string();
        let exec_new = Uuid::new_v4().to_string();
        for (exec, attempt) in [(&exec_old, 1_i64), (&exec_new, 2_i64)] {
            sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
                .bind(exec).bind(&task_id).bind(&worker_id).bind(attempt).bind("completed").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        // Two retries on the old cycle, none on the current cycle.
        for _ in 0..2 {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&exec_old).bind(&reviewer_id)
                .bind("completed").bind(&now).bind(&now)
                .bind(r#"{"verdict":"retry","reason":"old cycle","validation":[]}"#)
                .execute(&db).await.unwrap();
        }
        let state = state_with(db);
        let Json(body) = insights(State(state), Query(InsightsQuery { window: "all".into() }))
            .await
            .unwrap();
        assert_eq!(body.reviewer_retries_lifetime, 2);
        assert_eq!(body.reviewer_retries_current_cycle, 0);
        assert_eq!(body.tasks[0].lifetime_retries, 2);
        assert_eq!(body.tasks[0].current_cycle_retries, 0);
        assert_eq!(body.tasks[0].attempt, 2);
    }

    #[tokio::test]
    async fn insights_without_gate_table_stays_available() {
        let db = memory_db().await;
        sqlx::query("DROP TABLE main_gate_events").execute(&db).await.unwrap();
        let state = state_with(db);
        let Json(body) = insights(State(state), Query(InsightsQuery { window: "7d".into() }))
            .await
            .unwrap();
        assert_eq!(body.window, "7d");
        assert!(!body.main_gate_available);
        assert_eq!(body.main_gate_merged, 0);
        assert_eq!(body.main_gate_sent_back, 0);
        assert_eq!(body.main_gate_merge_conflict, 0);
    }
}
