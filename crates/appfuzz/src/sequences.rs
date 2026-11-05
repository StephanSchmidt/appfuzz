//! Sequence artifacts deliberately bypass the stateless request cache.
use super::*;
use crate::cli::SequenceCmd;
use appfuzz_core::sequence::{self, Case, Report, Scenario};

fn output(report: &Report) -> Value {
    let fails = report.findings.iter().any(|f| f.severity == Severity::Fail);
    let warns = report.findings.iter().any(|f| f.severity == Severity::Warn);
    let (verdict, code) = if !report.errors.is_empty() {
        ("incomplete", 3)
    } else if fails {
        ("fail", 2)
    } else if warns {
        ("warn", 1)
    } else {
        ("pass", 0)
    };
    let mut value = serde_json::to_value(report).expect("report serializes");
    value["verdict"] = json!(verdict);
    value["exit_code"] = json!(code);
    value["status"] = json!(if report.errors.is_empty() { "complete" } else { "incomplete" });
    value
}
pub(super) fn command(app: &App, state: &Path, cmd: &SequenceCmd) -> Result<Value> {
    match cmd {
        SequenceCmd::Run { scenario, out } | SequenceCmd::Fuzz { scenario, out, .. } => {
            let scenario: Scenario = match scenario.to_str().and_then(|name| app.manifest.sequences.get(name)) {
                Some(s) => s.clone(),
                None => serde_json::from_slice(&std::fs::read(scenario)?)?,
            };
            let (scenario, report, evaluations, shrink_evaluations) = if let SequenceCmd::Fuzz { runs, search_seed, shrink_runs, .. } = cmd {
                let result = sequence::fuzz(app, &scenario, *runs, *search_seed, *shrink_runs)?;
                (result.scenario, result.report, result.evaluations, result.shrink_evaluations)
            } else {
                let report = sequence::run(app, &scenario)?;
                (scenario, report, 1, 0)
            };
            let case = Case {
                version: 1,
                component: app.hash.clone(),
                contract: app.contract.clone(),
                scenario,
                finding: report.findings.iter().find(|f| f.severity == Severity::Fail).map(|f| f.id.clone()),
                digest: report.digest(),
            };
            let bytes = serde_json::to_vec_pretty(&case)?;
            let path = out.clone().unwrap_or_else(|| state.join("sequences").join(format!("{}.json", &blake3_hex(&bytes)[..16])));
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            appfuzz_core::store::write_atomic(&path, &bytes)?;
            let mut value = output(&report);
            value["case"] = json!(path);
            value["evaluations"] = json!(evaluations);
            value["shrink_evaluations"] = json!(shrink_evaluations);
            Ok(value)
        }
        SequenceCmd::Replay { case, against_current } => {
            let artifact: Case = serde_json::from_slice(&std::fs::read(case)?)?;
            if artifact.version != 1 {
                bail!("unsupported sequence case version");
            }
            if !against_current && (artifact.component != app.hash || artifact.contract != app.contract) {
                bail!("sequence case belongs to another build or contract; use --against-current for regression");
            }
            let report = sequence::run(app, &artifact.scenario)?;
            let reproduced = if *against_current {
                artifact.finding.as_ref().is_some_and(|id| report.findings.iter().any(|f| f.matches_id(id)))
            } else {
                report.digest() == artifact.digest
            };
            let mut value = output(&report);
            if report.errors.is_empty() {
                value["exit_code"] = json!(if *against_current {
                    if report.findings.iter().any(|f| f.severity == Severity::Fail) {
                        2
                    } else if report.findings.iter().any(|f| f.severity == Severity::Warn) {
                        1
                    } else {
                        0
                    }
                } else if reproduced {
                    0
                } else {
                    2
                });
            }
            value["reproduced"] = json!(reproduced);
            value["mode"] = json!(if *against_current { "regression" } else { "exact" });
            value["case"] = json!(case);
            Ok(value)
        }
    }
}

pub(super) fn review_findings(report: &Value) -> Result<Vec<Finding>> {
    let mut findings: Vec<Finding> = serde_json::from_value(report["findings"].clone())?;
    for f in &mut findings {
        f.run = None;
        f.confirmed = report["case"].as_str().map(str::to_string);
        if !f.detail.is_object() {
            f.detail = json!({});
        }
        f.detail["sequence_case"] = json!(true);
    }
    Ok(findings)
}
