use super::entity::{AuditAction, AuditComponent, AuditEntry};

/// Filter parameters for querying stored audit entries.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Start of time range (inclusive, nanoseconds since epoch).
    pub from_ns: Option<u64>,
    /// End of time range (inclusive, nanoseconds since epoch).
    pub to_ns: Option<u64>,
    /// Filter by security component.
    pub component: Option<AuditComponent>,
    /// Filter by audit action.
    pub action: Option<AuditAction>,
    /// Filter by rule ID (exact match).
    pub rule_id: Option<String>,
    /// Maximum number of entries to return.
    pub limit: usize,
    /// Number of entries to skip.
    pub offset: usize,
}

impl AuditQuery {
    /// Check whether an `AuditEntry` matches all active filters.
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        if let Some(from) = self.from_ns
            && entry.timestamp_ns < from
        {
            return false;
        }
        if let Some(to) = self.to_ns
            && entry.timestamp_ns > to
        {
            return false;
        }
        if let Some(component) = self.component
            && entry.component != component
        {
            return false;
        }
        if let Some(action) = self.action
            && entry.action != action
        {
            return false;
        }
        if let Some(ref rule_id) = self.rule_id
            && entry.rule_id != *rule_id
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(component: AuditComponent, action: AuditAction, ts: u64) -> AuditEntry {
        AuditEntry::security_decision(
            component,
            action,
            ts,
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            false,
            80,
            443,
            6,
            "fw-001",
            "test",
        )
    }

    #[test]
    fn empty_query_matches_everything() {
        let q = AuditQuery::default();
        let e = make_entry(AuditComponent::Firewall, AuditAction::Drop, 1000);
        assert!(q.matches(&e));
    }

    #[test]
    fn from_ns_filters() {
        let q = AuditQuery {
            from_ns: Some(500),
            ..Default::default()
        };
        assert!(!q.matches(&make_entry(
            AuditComponent::Firewall,
            AuditAction::Drop,
            100
        )));
        assert!(q.matches(&make_entry(
            AuditComponent::Firewall,
            AuditAction::Drop,
            500
        )));
        assert!(q.matches(&make_entry(
            AuditComponent::Firewall,
            AuditAction::Drop,
            1000
        )));
    }

    #[test]
    fn to_ns_filters() {
        let q = AuditQuery {
            to_ns: Some(500),
            ..Default::default()
        };
        assert!(q.matches(&make_entry(
            AuditComponent::Firewall,
            AuditAction::Drop,
            100
        )));
        assert!(q.matches(&make_entry(
            AuditComponent::Firewall,
            AuditAction::Drop,
            500
        )));
        assert!(!q.matches(&make_entry(
            AuditComponent::Firewall,
            AuditAction::Drop,
            1000
        )));
    }

    #[test]
    fn component_filter() {
        let q = AuditQuery {
            component: Some(AuditComponent::Ids),
            ..Default::default()
        };
        assert!(!q.matches(&make_entry(AuditComponent::Firewall, AuditAction::Drop, 1)));
        assert!(q.matches(&make_entry(AuditComponent::Ids, AuditAction::Alert, 1)));
    }

    #[test]
    fn action_filter() {
        let q = AuditQuery {
            action: Some(AuditAction::Alert),
            ..Default::default()
        };
        assert!(!q.matches(&make_entry(AuditComponent::Firewall, AuditAction::Drop, 1)));
        assert!(q.matches(&make_entry(AuditComponent::Ids, AuditAction::Alert, 1)));
    }

    #[test]
    fn rule_id_filter() {
        let q = AuditQuery {
            rule_id: Some("fw-001".to_string()),
            ..Default::default()
        };
        assert!(q.matches(&make_entry(AuditComponent::Firewall, AuditAction::Drop, 1)));

        let other = AuditEntry::security_decision(
            AuditComponent::Ids,
            AuditAction::Alert,
            1,
            [0; 4],
            [0; 4],
            false,
            0,
            0,
            0,
            "ids-999",
            "",
        );
        assert!(!q.matches(&other));
    }

    #[test]
    fn combined_filters() {
        let q = AuditQuery {
            from_ns: Some(100),
            to_ns: Some(500),
            component: Some(AuditComponent::Firewall),
            action: Some(AuditAction::Drop),
            ..Default::default()
        };
        assert!(q.matches(&make_entry(
            AuditComponent::Firewall,
            AuditAction::Drop,
            300
        )));
        assert!(!q.matches(&make_entry(AuditComponent::Firewall, AuditAction::Drop, 50)));
        assert!(!q.matches(&make_entry(AuditComponent::Ids, AuditAction::Drop, 300)));
    }
}
