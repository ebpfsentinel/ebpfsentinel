use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::alert::mitre;
use serde::Serialize;
use utoipa::ToSchema;

use super::state::AppState;

/// MITRE ATT&CK coverage response.
#[derive(Serialize, ToSchema)]
pub struct MitreCoverageResponse {
    /// ATT&CK framework version.
    pub attack_version: String,
    /// Total number of covered techniques (for active components).
    pub total_techniques: usize,
    /// Covered techniques grouped by component.
    pub techniques: Vec<TechniqueEntry>,
    /// Coverage summary per tactic.
    pub by_tactic: Vec<TacticSummary>,
}

/// A single technique in the coverage matrix.
#[derive(Serialize, ToSchema)]
pub struct TechniqueEntry {
    pub component: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub description: String,
}

/// Per-tactic summary.
#[derive(Serialize, ToSchema)]
pub struct TacticSummary {
    pub tactic: String,
    pub covered_techniques: usize,
    pub components: Vec<String>,
}

/// `GET /api/v1/mitre/coverage` — MITRE ATT&CK coverage matrix.
#[utoipa::path(
    get, path = "/api/v1/mitre/coverage",
    tag = "MITRE ATT&CK",
    responses(
        (status = 200, description = "Coverage matrix of covered ATT&CK techniques", body = MitreCoverageResponse),
    )
)]
pub async fn mitre_coverage(State(state): State<Arc<AppState>>) -> Json<MitreCoverageResponse> {
    // Determine which components are active based on configured services.
    let mut active: Vec<&str> = Vec::new();

    // IDS is always available (core feature).
    if state.ids_service.is_some() {
        active.push("ids");
    }

    // ThreatIntel is always available (core service, not Option).
    active.push("threatintel");

    // DLP is optional.
    if state.dlp_service.is_some() {
        active.push("dlp");
    }

    // DDoS is optional.
    if state.ddos_service.is_some() {
        active.push("ddos");
    }

    let report = mitre::coverage_report(&active);

    let techniques = report
        .techniques
        .into_iter()
        .map(|t| TechniqueEntry {
            component: t.component,
            technique_id: t.technique_id,
            technique_name: t.technique_name,
            tactic: t.tactic,
            description: t.description,
        })
        .collect();

    let by_tactic = report
        .by_tactic
        .into_iter()
        .map(|t| TacticSummary {
            tactic: t.tactic,
            covered_techniques: t.covered_techniques,
            components: t.components,
        })
        .collect();

    Json(MitreCoverageResponse {
        attack_version: report.attack_version,
        total_techniques: report.total_techniques,
        techniques,
        by_tactic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_response_serialization() {
        let resp = MitreCoverageResponse {
            attack_version: "v18".to_string(),
            total_techniques: 2,
            techniques: vec![
                TechniqueEntry {
                    component: "ids".to_string(),
                    technique_id: "T1071".to_string(),
                    technique_name: "Application Layer Protocol".to_string(),
                    tactic: "command-and-control".to_string(),
                    description: "IDS signature match".to_string(),
                },
                TechniqueEntry {
                    component: "dlp".to_string(),
                    technique_id: "T1041".to_string(),
                    technique_name: "Exfiltration Over C2 Channel".to_string(),
                    tactic: "exfiltration".to_string(),
                    description: "DLP match: PCI or generic".to_string(),
                },
            ],
            by_tactic: vec![TacticSummary {
                tactic: "command-and-control".to_string(),
                covered_techniques: 1,
                components: vec!["ids".to_string()],
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["attack_version"], "v18");
        assert_eq!(json["total_techniques"], 2);
        assert_eq!(json["techniques"].as_array().unwrap().len(), 2);
        assert_eq!(json["techniques"][0]["technique_id"], "T1071");
        assert_eq!(json["by_tactic"][0]["tactic"], "command-and-control");
    }
}
