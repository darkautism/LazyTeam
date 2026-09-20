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

/// Window semantics (all window filters compare durable timestamps only):
/// counts use `created_at` ("started/recorded in window"); durations use
/// `finished_at` / gate `created_at` ("finished in window").
#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkerBreakdown {
    pub(crate) worker_id: Option<String>,
    /// Best-effort display label from the workers table; grouping and all
    /// backend attribution below come from durable per-attempt snapshots.
    pub(crate) worker_name: String,
    pub(crate) agent_type: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) executions: i64,
    pub(crate) completed: i64,
    pub(crate) failed: i64,
    pub(crate) lost: i64,
    pub(crate) denominator: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ModelBreakdown {
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) executions: i64,
    pub(crate) completed: i64,
    pub(crate) failed: i64,
    pub(crate) lost: i64,
    pub(crate) denominator: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReviewerBreakdown {
    pub(crate) worker_id: Option<String>,
    /// Best-effort display label; grouping and backend attribution are durable.
    pub(crate) worker_name: String,
    pub(crate) agent_type: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) completed: i64,
    pub(crate) approve: i64,
    pub(crate) retry: i64,
    pub(crate) runtime_failed: i64,
    pub(crate) lost: i64,
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
    pub(crate) event_id: Option<String>,
    pub(crate) worker_name: Option<String>,
    pub(crate) reviewer_name: Option<String>,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TaskDetail {
    pub(crate) task_id: String,
    pub(crate) title: String,
    pub(crate) attempt: i64,
    pub(crate) review_rounds: i64,
    pub(crate) lifetime_retries: i64,
    pub(crate) current_cycle_retries: i64,
    /// Kind of the latest durable gate event for the task, if any. No current
    /// task-state inference is exposed here.
    pub(crate) gate_outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InsightsResponse {
    pub(crate) window: String,
    pub(crate) cutoff: Option<String>,
    /// Tasks with `created_at` in window (`created_at` is immutable).
    pub(crate) tasks_created: i64,
    /// Gate `merged` + `upstream_moved` events in window (durable; never
    /// derived from mutable `tasks.state`/`updated_at`).
    pub(crate) tasks_done: i64,
    /// Task `created_at` -> gate completion `created_at` for completions
    /// recorded in window.
    pub(crate) task_completion: DurationSummary,
    /// Executions with `created_at` in window ("started in window").
    pub(crate) executions_total: i64,
    pub(crate) executions_completed: CountRate,
    pub(crate) executions_failed: CountRate,
    pub(crate) executions_lost: CountRate,
    pub(crate) executions_active: i64,
    /// Completed executions with `finished_at` in window ("finished in window").
    pub(crate) execution_duration: DurationSummary,
    pub(crate) reviews_total: i64,
    pub(crate) reviews_completed: i64,
    pub(crate) reviews_approve: CountRate,
    pub(crate) reviews_retry: CountRate,
    pub(crate) reviews_runtime_failed: CountRate,
    pub(crate) reviews_lost: CountRate,
    pub(crate) reviews_active: i64,
    /// Lifetime reviewer `retry` verdicts in window (all executions of each task).
    pub(crate) reviewer_retries_lifetime: i64,
    /// Current-cycle reviewer `retry` verdicts in window (latest execution only).
    pub(crate) reviewer_retries_current_cycle: i64,
    pub(crate) current_cycle_available: bool,
    pub(crate) main_gate_available: bool,
    pub(crate) main_gate_total: i64,
    pub(crate) main_gate_merged: CountRate,
    pub(crate) main_gate_upstream_moved: CountRate,
    pub(crate) main_gate_sent_back: CountRate,
    pub(crate) main_gate_merge_conflict: CountRate,
    pub(crate) impl_by_worker: Vec<WorkerBreakdown>,
    pub(crate) impl_by_model: Vec<ModelBreakdown>,
    pub(crate) impl_by_provider: Vec<ModelBreakdown>,
    pub(crate) reviewer_by_worker: Vec<ReviewerBreakdown>,
    pub(crate) reasons: Vec<ReasonItem>,
    pub(crate) tasks: Vec<TaskDetail>,
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

/// Quality-retry reasons live under `reason`; reviewer runtime failures are
/// stored as `{"error": ...}` payloads. Both are surfaced so infrastructure
/// failures stay drillable separately from quality retries.
fn parse_verdict_reason(raw: Option<&str>) -> String {
    raw.and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|value| {
            value
                .get("reason")
                .or_else(|| value.get("error"))
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

async fn column_exists(db: &sqlx::SqlitePool, table: &str, column: &str) -> bool {
    let sql = format!("PRAGMA table_info({table})");
    sqlx::query(&sql)
        .fetch_all(db)
        .await
        .map(|rows| {
            rows.iter().any(|row| {
                row.try_get::<String, _>("name")
                    .is_ok_and(|name| name == column)
            })
        })
        .unwrap_or(false)
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
    // Pre-migration reviews tables may lack execution_id and the reviewer
    // backend snapshot columns. Probe the schema and build the SELECTs
    // dynamically so the page keeps working on older deployments.
    let reviews_have_execution = column_exists(db, "reviews", "execution_id").await;
    let reviews_have_snap = column_exists(db, "reviews", "reviewer_agent_type").await
        && column_exists(db, "reviews", "reviewer_provider").await
        && column_exists(db, "reviews", "reviewer_model").await;
    let execs_have_snap = column_exists(db, "executions", "worker_agent_type").await
        && column_exists(db, "executions", "worker_provider").await
        && column_exists(db, "executions", "worker_model").await;

    // Worker names are display labels only; every grouping and every
    // provider/model/backend attribution below comes from durable per-attempt
    // snapshot columns, never from this mutable table.
    let mut worker_names: HashMap<String, String> = HashMap::new();
    if table_exists(db, "workers").await {
        if let Ok(rows) = sqlx::query("SELECT id,name FROM workers").fetch_all(db).await {
            for row in rows {
                let id: String = row.try_get("id").unwrap_or_default();
                let name: String = row.try_get("name").unwrap_or_default();
                if !id.is_empty() {
                    worker_names.insert(id, name);
                }
            }
        }
    }

    // ---- Tasks completed + task completion time from durable gate events. ----
    // `tasks.created_at` is immutable, so the created count is durable.
    // Completion counts/durations join the immutable creation timestamp to the
    // durable gate completion event; mutable tasks.state/updated_at (rewritten
    // by every retry) are never read here.
    let tasks_created: i64 = if table_exists(db, "tasks").await {
        match &cutoff_str {
            Some(cut) => sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE state!='cancelled' AND created_at>=?")
                .bind(cut).fetch_one(db).await.map_err(internal)?,
            None => sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE state!='cancelled'")
                .fetch_one(db).await.map_err(internal)?,
        }
    } else {
        0
    };
    // (gate completion kind, gate created_at, task created_at) for completions
    // recorded in window.
    let mut completions: Vec<(String, String, Option<String>)> = Vec::new();
    if has_gate {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query(
                "SELECT g.kind,g.created_at,t.created_at AS task_created FROM main_gate_events g LEFT JOIN tasks t ON t.id=g.task_id WHERE g.created_at>=? AND g.kind IN ('merged','upstream_moved')",
            )
            .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query(
                "SELECT g.kind,g.created_at,t.created_at AS task_created FROM main_gate_events g LEFT JOIN tasks t ON t.id=g.task_id WHERE g.kind IN ('merged','upstream_moved')",
            )
            .fetch_all(db).await.map_err(internal)?,
        };
        for row in rows {
            completions.push((
                row.try_get("kind").unwrap_or_default(),
                row.try_get("created_at").unwrap_or_default(),
                row.try_get("task_created").unwrap_or(None),
            ));
        }
    }
    let tasks_done = completions.len() as i64;
    let mut task_durations: Vec<f64> = Vec::new();
    for (_, gate_at, task_at) in &completions {
        if let (Some(created), Some(done)) = (
            task_at.as_deref().and_then(parse_time),
            parse_time(gate_at),
        ) {
            task_durations.push((done - created).num_seconds().max(0) as f64);
        }
    }
    let task_completion = duration_summary(task_durations);

    // ---- Executions (durable execution rows). ----
    #[derive(Debug)]
    struct ExecRow {
        worker_id: String,
        state: String,
        created: String,
        started: Option<String>,
        finished: Option<String>,
        agent_type: Option<String>,
        provider: Option<String>,
        model: Option<String>,
    }
    let exec_select = if execs_have_snap {
        "SELECT worker_id,state,created_at,started_at,finished_at,worker_agent_type,worker_provider,worker_model FROM executions"
    } else {
        "SELECT worker_id,state,created_at,started_at,finished_at FROM executions"
    };
    // Counts cover executions started in window; durations cover executions
    // finished in window. Both filters use immutable timestamps.
    let started_rows: Vec<ExecRow> = if table_exists(db, "executions").await {
        let sql = match &cutoff_str {
            Some(_) => format!("{exec_select} WHERE created_at>=?"),
            None => exec_select.to_string(),
        };
        let mut query = sqlx::query(&sql);
        if cutoff_str.is_some() {
            query = query.bind(cutoff_str.clone().unwrap_or_default());
        }
        query
            .fetch_all(db)
            .await
            .map_err(internal)?
            .into_iter()
            .map(|row| ExecRow {
                worker_id: row.try_get("worker_id").unwrap_or_default(),
                state: row.try_get("state").unwrap_or_default(),
                created: row.try_get("created_at").unwrap_or_default(),
                started: row.try_get("started_at").unwrap_or(None),
                finished: row.try_get("finished_at").unwrap_or(None),
                agent_type: row.try_get("worker_agent_type").unwrap_or(None),
                provider: row.try_get("worker_provider").unwrap_or(None),
                model: row.try_get("worker_model").unwrap_or(None),
            })
            .collect()
    } else {
        Vec::new()
    };
    let total = started_rows.len() as i64;
    let completed = started_rows.iter().filter(|r| r.state == "completed").count() as i64;
    let failed = started_rows.iter().filter(|r| r.state == "failed").count() as i64;
    let lost = started_rows.iter().filter(|r| r.state == "lost").count() as i64;
    let active = started_rows
        .iter()
        .filter(|r| r.state == "assigned" || r.state == "running")
        .count() as i64;
    let finished_rows: Vec<&ExecRow> = match &cutoff_str {
        Some(cut) => started_rows
            .iter()
            .filter(|r| {
                r.state == "completed"
                    && r.finished.as_deref().and_then(parse_time).is_some_and(|t| t.to_rfc3339() >= *cut)
            })
            .collect(),
        None => started_rows.iter().filter(|r| r.state == "completed").collect(),
    };
    let mut exec_durations: Vec<f64> = Vec::new();
    for row in &finished_rows {
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
        agent_type: Option<String>,
        provider: Option<String>,
        model: Option<String>,
    }
    let review_select = match (reviews_have_execution, reviews_have_snap) {
        (true, true) => "SELECT id,task_id,execution_id,reviewer_worker_id,state,verdict,created_at,reviewer_agent_type,reviewer_provider,reviewer_model FROM reviews",
        (true, false) => "SELECT id,task_id,execution_id,reviewer_worker_id,state,verdict,created_at FROM reviews",
        (false, true) => "SELECT id,task_id,reviewer_worker_id,state,verdict,created_at,reviewer_agent_type,reviewer_provider,reviewer_model FROM reviews",
        (false, false) => "SELECT id,task_id,reviewer_worker_id,state,verdict,created_at FROM reviews",
    };
    let review_rows: Vec<ReviewRow> = if table_exists(db, "reviews").await {
        let sql = match &cutoff_str {
            Some(_) => format!("{review_select} WHERE created_at>=?"),
            None => review_select.to_string(),
        };
        let mut query = sqlx::query(&sql);
        if cutoff_str.is_some() {
            query = query.bind(cutoff_str.clone().unwrap_or_default());
        }
        query
            .fetch_all(db)
            .await
            .map_err(internal)?
            .into_iter()
            .map(|row| ReviewRow {
                id: row.try_get("id").unwrap_or_default(),
                task_id: row.try_get("task_id").unwrap_or_default(),
                execution_id: row.try_get::<Option<String>, _>("execution_id").unwrap_or(None),
                reviewer_id: row.try_get("reviewer_worker_id").unwrap_or_default(),
                state: row.try_get("state").unwrap_or_default(),
                verdict: row.try_get("verdict").unwrap_or(None),
                created_at: row.try_get("created_at").unwrap_or_default(),
                agent_type: row.try_get("reviewer_agent_type").unwrap_or(None),
                provider: row.try_get("reviewer_provider").unwrap_or(None),
                model: row.try_get("reviewer_model").unwrap_or(None),
            })
            .collect()
    } else {
        Vec::new()
    };
    let reviews_total = review_rows.len() as i64;
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
    // retry verdicts on any execution. Unavailable when the deployment's
    // reviews table has no execution_id column.
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

    // ---- Main gate (durable gate events only; kinds are distinct rows). ----
    let (gate_merged, gate_moved, gate_sent_back, gate_conflict) = if has_gate {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT kind FROM main_gate_events WHERE created_at>=?")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT kind FROM main_gate_events")
                .fetch_all(db).await.map_err(internal)?,
        };
        let mut merged = 0_i64;
        let mut moved = 0_i64;
        let mut sent_back = 0_i64;
        let mut conflict = 0_i64;
        for row in rows {
            match row.try_get::<String, _>("kind").unwrap_or_default().as_str() {
                "merged" => merged += 1,
                "upstream_moved" => moved += 1,
                "sent_back" => sent_back += 1,
                "merge_conflict" => conflict += 1,
                _ => {}
            }
        }
        (merged, moved, sent_back, conflict)
    } else {
        (0, 0, 0, 0)
    };
    let gate_total = gate_merged + gate_moved + gate_sent_back + gate_conflict;

    // ---- Breakdowns from durable per-attempt snapshots (with denominators).
    // Pre-migration rows have NULL snapshots and group under "unrecorded" so
    // sample sizes stay honest instead of borrowing current worker metadata.
    let mut impl_groups: HashMap<(String, Option<String>, Option<String>, Option<String>), (i64, i64, i64, i64)> =
        HashMap::new();
    for row in &started_rows {
        let key = (
            row.worker_id.clone(),
            row.agent_type.clone(),
            row.provider.clone(),
            row.model.clone(),
        );
        let entry = impl_groups.entry(key).or_insert((0, 0, 0, 0));
        entry.0 += 1;
        match row.state.as_str() {
            "completed" => entry.1 += 1,
            "failed" => entry.2 += 1,
            "lost" => entry.3 += 1,
            _ => {}
        }
    }
    let mut impl_by_worker: Vec<WorkerBreakdown> = impl_groups
        .into_iter()
        .map(|((worker_id, agent_type, provider, model), (executions, completed, failed, lost))| {
            WorkerBreakdown {
                worker_id: Some(worker_id.clone()),
                worker_name: worker_names
                    .get(&worker_id)
                    .cloned()
                    .unwrap_or_else(|| "unknown worker".into()),
                agent_type,
                provider,
                model,
                executions,
                completed,
                failed,
                lost,
                denominator: executions,
            }
        })
        .collect();
    impl_by_worker.sort_by(|a, b| b.executions.cmp(&a.executions));

    let mut model_groups: HashMap<(Option<String>, Option<String>), (i64, i64, i64, i64)> =
        HashMap::new();
    let mut provider_groups: HashMap<Option<String>, (i64, i64, i64, i64)> = HashMap::new();
    for row in &started_rows {
        let entry = model_groups
            .entry((row.provider.clone(), row.model.clone()))
            .or_insert((0, 0, 0, 0));
        entry.0 += 1;
        match row.state.as_str() {
            "completed" => entry.1 += 1,
            "failed" => entry.2 += 1,
            "lost" => entry.3 += 1,
            _ => {}
        }
        let entry = provider_groups.entry(row.provider.clone()).or_insert((0, 0, 0, 0));
        entry.0 += 1;
        match row.state.as_str() {
            "completed" => entry.1 += 1,
            "failed" => entry.2 += 1,
            "lost" => entry.3 += 1,
            _ => {}
        }
    }
    let mut impl_by_model: Vec<ModelBreakdown> = model_groups
        .into_iter()
        .map(|((provider, model), (executions, completed, failed, lost))| ModelBreakdown {
            provider,
            model,
            executions,
            completed,
            failed,
            lost,
            denominator: executions,
        })
        .collect();
    impl_by_model.sort_by(|a, b| b.executions.cmp(&a.executions));
    let mut impl_by_provider: Vec<ModelBreakdown> = provider_groups
        .into_iter()
        .map(|(provider, (executions, completed, failed, lost))| ModelBreakdown {
            provider,
            model: None,
            executions,
            completed,
            failed,
            lost,
            denominator: executions,
        })
        .collect();
    impl_by_provider.sort_by(|a, b| b.executions.cmp(&a.executions));

    struct ReviewerAgg {
        completed: i64,
        approve: i64,
        retry: i64,
        failed: i64,
        lost: i64,
    }
    let mut reviewer_groups: HashMap<
        (String, Option<String>, Option<String>, Option<String>),
        ReviewerAgg,
    > = HashMap::new();
    for row in &review_rows {
        let key = (
            row.reviewer_id.clone(),
            row.agent_type.clone(),
            row.provider.clone(),
            row.model.clone(),
        );
        let entry = reviewer_groups.entry(key).or_insert(ReviewerAgg {
            completed: 0,
            approve: 0,
            retry: 0,
            failed: 0,
            lost: 0,
        });
        match row.state.as_str() {
            "completed" => {
                entry.completed += 1;
                match parse_verdict_kind(row.verdict.as_deref()) {
                    Some("approve") => entry.approve += 1,
                    Some("retry") => entry.retry += 1,
                    _ => {}
                }
            }
            "failed" => entry.failed += 1,
            "lost" => entry.lost += 1,
            _ => {}
        }
    }
    let mut reviewer_by_worker: Vec<ReviewerBreakdown> = reviewer_groups
        .into_iter()
        .map(|((worker_id, agent_type, provider, model), agg)| {
            let denominator = agg.completed + agg.failed + agg.lost;
            ReviewerBreakdown {
                worker_id: Some(worker_id.clone()),
                worker_name: worker_names
                    .get(&worker_id)
                    .cloned()
                    .unwrap_or_else(|| "unknown reviewer".into()),
                agent_type,
                provider,
                model,
                completed: agg.completed,
                approve: agg.approve,
                retry: agg.retry,
                runtime_failed: agg.failed,
                lost: agg.lost,
                denominator,
            }
        })
        .collect();
    reviewer_by_worker.sort_by(|a, b| b.denominator.cmp(&a.denominator));

    // Task titles are labels only.
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
    let worker_label = |id: &str| worker_names.get(id).cloned();

    // ---- Reasons with drill-down evidence (verdict JSON + gate events). ----
    let mut reasons: Vec<ReasonItem> = Vec::new();
    // Reviewer quality retries.
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
            event_id: None,
            worker_name: exec_worker.clone().and_then(|id| worker_label(&id)).or(exec_worker),
            reviewer_name: worker_label(&row.reviewer_id),
            created_at: row.created_at.clone(),
        });
    }
    // Reviewer runtime failures (failed-row error payloads), kept separate
    // from quality retries.
    let mut failed_rows: Vec<&ReviewRow> = review_rows.iter().filter(|r| r.state == "failed").collect();
    failed_rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    for row in failed_rows.into_iter().take(50) {
        let reason = parse_verdict_reason(row.verdict.as_deref());
        let exec_worker = latest_exec_worker(db, &row.execution_id).await;
        reasons.push(ReasonItem {
            source: "reviewer_runtime_failed".into(),
            reason: truncate(&reason, 500),
            task_id: row.task_id.clone(),
            task_title: titles.get(&row.task_id).cloned(),
            execution_id: row.execution_id.clone(),
            review_id: Some(row.id.clone()),
            event_id: None,
            worker_name: exec_worker.clone().and_then(|id| worker_label(&id)).or(exec_worker),
            reviewer_name: worker_label(&row.reviewer_id),
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
            let execution_id: Option<String> = row.try_get("execution_id").unwrap_or(None);
            let kind: String = row.try_get("kind").unwrap_or_default();
            let reason: String = row.try_get("reason").unwrap_or_default();
            let created_at: String = row.try_get("created_at").unwrap_or_default();
            reasons.push(ReasonItem {
                source: kind,
                reason: truncate(&reason, 500),
                task_id: task_id.clone(),
                task_title: titles.get(&task_id).cloned(),
                execution_id,
                review_id: None,
                event_id: Some(id),
                worker_name: None,
                reviewer_name: None,
                created_at,
            });
        }
        reasons.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        reasons.truncate(150);
    }

    // ---- Per-task detail with lifetime + current-cycle retries. ----
    // Lifetime counts come from all durable review verdict rows for the task;
    // current-cycle counts restrict to the latest execution. Gate outcomes
    // come from durable gate events. No current task state is exposed.
    let mut all_retries_lifetime: HashMap<String, i64> = HashMap::new();
    let mut all_retries_cycle: HashMap<String, i64> = HashMap::new();
    let mut all_rounds: HashMap<String, i64> = HashMap::new();
    if table_exists(db, "reviews").await {
        let exec_select = if reviews_have_execution {
            "SELECT task_id,execution_id,state,verdict FROM reviews"
        } else {
            "SELECT task_id,state,verdict FROM reviews"
        };
        if let Ok(rows) = sqlx::query(exec_select).fetch_all(db).await {
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
                let exec: Option<String> = row.try_get("execution_id").unwrap_or(None);
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
    let mut gate_outcomes: HashMap<String, (String, String)> = HashMap::new();
    if has_gate {
        if let Ok(rows) =
            sqlx::query("SELECT task_id,kind,created_at FROM main_gate_events ORDER BY created_at ASC")
                .fetch_all(db)
                .await
        {
            for row in rows {
                let task_id: String = row.try_get("task_id").unwrap_or_default();
                let kind: String = row.try_get("kind").unwrap_or_default();
                let created_at: String = row.try_get("created_at").unwrap_or_default();
                gate_outcomes.insert(task_id, (kind, created_at));
            }
        }
    }
    let mut tasks_detail: Vec<TaskDetail> = Vec::new();
    if table_exists(db, "tasks").await {
        let rows = match &cutoff_str {
            Some(cut) => sqlx::query("SELECT id,title FROM tasks WHERE state!='cancelled' AND created_at>=? ORDER BY created_at DESC LIMIT 100")
                .bind(cut).fetch_all(db).await.map_err(internal)?,
            None => sqlx::query("SELECT id,title FROM tasks WHERE state!='cancelled' ORDER BY created_at DESC LIMIT 100")
                .fetch_all(db).await.map_err(internal)?,
        };
        for row in rows {
            let id: String = row.try_get("id").unwrap_or_default();
            tasks_detail.push(TaskDetail {
                task_id: id.clone(),
                title: row.try_get("title").unwrap_or_default(),
                attempt: latest_attempt.get(&id).copied().unwrap_or(0),
                review_rounds: all_rounds.get(&id).copied().unwrap_or(0),
                lifetime_retries: all_retries_lifetime.get(&id).copied().unwrap_or(0),
                current_cycle_retries: all_retries_cycle.get(&id).copied().unwrap_or(0),
                gate_outcome: gate_outcomes.get(&id).map(|(kind, _)| kind.clone()),
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
        reviews_total,
        reviews_completed: completed_n,
        reviews_approve: count_rate(approve, completed_n),
        reviews_retry: count_rate(retry, completed_n),
        reviews_runtime_failed: count_rate(runtime_failed, reviews_total),
        reviews_lost: count_rate(reviews_lost, reviews_total),
        reviews_active,
        reviewer_retries_lifetime: retry,
        reviewer_retries_current_cycle: current_cycle_retries,
        current_cycle_available,
        main_gate_available: has_gate,
        main_gate_total: gate_total,
        main_gate_merged: count_rate(gate_merged, gate_total),
        main_gate_upstream_moved: count_rate(gate_moved, gate_total),
        main_gate_sent_back: count_rate(gate_sent_back, gate_total),
        main_gate_merge_conflict: count_rate(gate_conflict, gate_total),
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
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,started_at,finished_at,result,created_at,worker_agent_type,worker_provider,worker_model) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&exec_id).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now)
            .bind(&now).bind(&now)
            .bind(r#"{"status":"completed","summary":"s","commit_sha":"abc","base_sha":"base","review_ref":"r"}"#)
            .bind(&now)
            .bind("pi").bind("acme").bind("cheap-1")
            .execute(&db).await.unwrap();
        // One quality retry, one approve, one runtime failure.
        for (verdict, state) in [
            (r#"{"verdict":"retry","reason":"missing null check in foo.rs","validation":[]}"#, "completed"),
            (r#"{"verdict":"approve","reason":"looks good","validation":[]}"#, "completed"),
            (r#"{"error":"runner crashed"}"#, "failed"),
        ] {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,finished_at,verdict,reviewer_agent_type,reviewer_provider,reviewer_model) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&exec_id).bind(&reviewer_id)
                .bind(state).bind(&now).bind(&now).bind(&now).bind(verdict)
                .bind("pi").bind("acme").bind("critic-1")
                .execute(&db).await.unwrap();
        }
        // One merge-conflict gate event: must not count as reviewer retry.
        let gate_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO main_gate_events(id,task_id,execution_id,kind,reason,created_at) VALUES(?,?,?,?,?,?)")
            .bind(&gate_id).bind(&task_id).bind(&exec_id)
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
        assert_eq!(body.reviews_runtime_failed.count, 1);
        assert_eq!(body.reviews_runtime_failed.denominator, 3);
        assert_eq!(body.reviewer_retries_lifetime, 1);
        assert_eq!(body.reviewer_retries_current_cycle, 1);
        assert!(body.current_cycle_available);
        assert!(body.main_gate_available);
        assert_eq!(body.main_gate_total, 1);
        assert_eq!(body.main_gate_merge_conflict.count, 1);
        assert_eq!(body.main_gate_merge_conflict.denominator, 1);
        assert_eq!(body.main_gate_sent_back.count, 0);
        assert_eq!(body.main_gate_merged.count, 0);
        assert_eq!(body.main_gate_upstream_moved.count, 0);
        // tasks_done comes from durable gate events, not tasks.state.
        assert_eq!(body.tasks_created, 1);
        assert_eq!(body.tasks_done, 0);
        // Breakdowns use durable snapshots and carry sample denominators.
        assert_eq!(body.impl_by_worker.len(), 1);
        assert_eq!(body.impl_by_worker[0].denominator, 1);
        assert_eq!(body.impl_by_worker[0].provider.as_deref(), Some("acme"));
        assert_eq!(body.impl_by_worker[0].model.as_deref(), Some("cheap-1"));
        assert_eq!(body.impl_by_model.len(), 1);
        assert_eq!(body.reviewer_by_worker.len(), 1);
        assert_eq!(body.reviewer_by_worker[0].denominator, 3);
        assert_eq!(body.reviewer_by_worker[0].runtime_failed, 1);
        assert_eq!(body.reviewer_by_worker[0].agent_type.as_deref(), Some("pi"));
        // Reasons drill down to durable evidence, including runtime failures
        // and gate event ids.
        assert!(body.reasons.iter().any(|r| r.source == "reviewer_retry"
            && r.task_id == task_id
            && r.review_id.is_some()
            && r.reason.contains("missing null check")));
        assert!(body.reasons.iter().any(|r| r.source == "reviewer_runtime_failed"
            && r.task_id == task_id
            && r.review_id.is_some()
            && r.reason.contains("runner crashed")));
        assert!(body.reasons.iter().any(|r| r.source == "merge_conflict"
            && r.task_id == task_id
            && r.event_id.as_deref() == Some(gate_id.as_str())));
        // Per-task detail shows both lifetime and current-cycle retries plus
        // the durable gate outcome (no current task state).
        assert_eq!(body.tasks.len(), 1);
        assert_eq!(body.tasks[0].lifetime_retries, 1);
        assert_eq!(body.tasks[0].current_cycle_retries, 1);
        assert_eq!(body.tasks[0].gate_outcome.as_deref(), Some("merge_conflict"));
    }

    #[tokio::test]
    async fn insights_tasks_done_comes_from_gate_events_not_task_state() {
        let db = memory_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        // Task claims to be done in mutable state but has no durable gate
        // event: it must not count, and its updated_at churn must not feed
        // completion timing.
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("t").bind("").bind("").bind("done").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let Json(body) = insights(State(state_with(db.clone())), Query(InsightsQuery { window: "all".into() }))
            .await
            .unwrap();
        assert_eq!(body.tasks_created, 1);
        assert_eq!(body.tasks_done, 0);
        assert_eq!(body.task_completion.sample, 0);
        assert_eq!(body.main_gate_total, 0);

        // A durable merged gate event counts, with task created_at -> gate
        // timing. Mutating tasks.updated_at afterwards must not move it.
        let created = (Utc::now() - chrono::Duration::hours(5)).to_rfc3339();
        sqlx::query("UPDATE tasks SET created_at=? WHERE id=?")
            .bind(&created).bind(&task_id).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO main_gate_events(id,task_id,kind,reason,merge_commit_sha,created_at) VALUES(?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id)
            .bind("merged").bind("fast-forward").bind("abc").bind(&now)
            .execute(&db).await.unwrap();
        let Json(body) = insights(State(state_with(db.clone())), Query(InsightsQuery { window: "all".into() }))
            .await
            .unwrap();
        assert_eq!(body.tasks_done, 1);
        assert_eq!(body.main_gate_merged.count, 1);
        assert_eq!(body.main_gate_total, 1);
        assert_eq!(body.task_completion.sample, 1);
        assert!(body.task_completion.median_secs.unwrap_or(0.0) >= 4.0 * 3600.0);
        assert_eq!(body.tasks[0].gate_outcome.as_deref(), Some("merged"));

        // Retry churn rewrites tasks.updated_at but must not change the
        // durable completion count or timing.
        let later = Utc::now().to_rfc3339();
        sqlx::query("UPDATE tasks SET state='queued',updated_at=? WHERE id=?")
            .bind(&later).bind(&task_id).execute(&db).await.unwrap();
        let Json(body) = insights(State(state_with(db)), Query(InsightsQuery { window: "all".into() }))
            .await
            .unwrap();
        assert_eq!(body.tasks_done, 1);
        assert_eq!(body.task_completion.sample, 1);
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
        assert_eq!(body.main_gate_total, 0);
        assert_eq!(body.main_gate_merged.count, 0);
        assert_eq!(body.main_gate_sent_back.count, 0);
        assert_eq!(body.main_gate_merge_conflict.count, 0);
        assert_eq!(body.main_gate_upstream_moved.count, 0);
        assert_eq!(body.tasks_done, 0);
    }

    #[tokio::test]
    async fn insights_without_reviews_execution_id_stays_available() {
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
        // Simulate a pre-migration reviews table without execution_id or
        // reviewer backend snapshot columns.
        sqlx::query("DROP TABLE reviews").execute(&db).await.unwrap();
        sqlx::query(
            "CREATE TABLE reviews (id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE, reviewer_worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE, state TEXT NOT NULL, lease_until TEXT NOT NULL, started_at TEXT, finished_at TEXT, verdict TEXT, created_at TEXT NOT NULL)",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO reviews(id,task_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&reviewer_id)
            .bind("completed").bind(&now).bind(&now)
            .bind(r#"{"verdict":"retry","reason":"old schema retry","validation":[]}"#)
            .execute(&db).await.unwrap();
        let state = state_with(db);
        let Json(body) = insights(State(state), Query(InsightsQuery { window: "all".into() }))
            .await
            .unwrap();
        assert!(!body.current_cycle_available);
        assert_eq!(body.reviewer_retries_current_cycle, 0);
        assert_eq!(body.reviewer_retries_lifetime, 1);
        assert_eq!(body.reviews_retry.count, 1);
        assert_eq!(body.tasks[0].lifetime_retries, 1);
        assert_eq!(body.tasks[0].current_cycle_retries, 0);
    }
}
