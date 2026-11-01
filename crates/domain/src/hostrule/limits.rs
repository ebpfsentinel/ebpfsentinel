//! What a host rule cannot say, and what to write instead.
//!
//! The syntax is closed on purpose: a limit is relieved by a typed field or a
//! new intent, never by grammar. A closed syntax that refuses without saying
//! why reads as a broken one, so every limit a rule can run into is a row
//! here, the refusal a rule gets is built from that row, and the
//! documentation page is generated from the same rows: a limit relieved in
//! code cannot stay stated in the documentation.

/// One limit of the syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRuleLimit {
    /// What cannot be said.
    pub limit: &'static str,
    /// What a rule writes to run into it.
    pub written: &'static str,
    /// Why, and what to write instead.
    pub instead: &'static str,
}

impl HostRuleLimit {
    /// The refusal a rule running into this limit gets.
    #[must_use]
    pub fn refusal(&self) -> String {
        format!("{}: {}", self.limit, self.instead)
    }
}

pub const NO_EXPRESSION: HostRuleLimit = HostRuleLimit {
    limit: "there is no expression language",
    written: "`when` or `followed_by` written as text, such as `exe = /bin/sh and uid = 0`, or a `condition`, `match`, `expression` or `filter` key beside them",
    instead: "write a map of matchers, every key holding at once, a list of values meaning any one of them, and one `any_of` at the top of `when` listing alternatives",
};

pub const NO_ABSENCE: HostRuleLimit = HostRuleLimit {
    limit: "a rule fires on an event, never on the absence of one",
    written: "`not_followed_by` or `unless_followed_by`",
    instead: "under the load an attacker creates every first step left unanswered would fire, so the alerts would grow with the attack; write the first step as a rule of its own and read what came after it in the process tree its alert carries",
};

pub const TWO_STEPS: HostRuleLimit = HostRuleLimit {
    limit: "a sequence is two steps",
    written: "`followed_by` inside `followed_by`",
    instead: "what came before the first step is in the ancestry the alert carries, so write the last two steps as the rule and a third step as a second rule",
};

pub const ANY_OF_DEPTH_ONE: HostRuleLimit = HostRuleLimit {
    limit: "`any_of` does not nest",
    written: "`any_of` inside an entry of `any_of`, or inside an intent",
    instead: "list every alternative, each an intent with its matchers, in the one `any_of` at the top of `when` or of `followed_by`",
};

pub const FIELDS_COMPARE_FOR_EQUALITY: HostRuleLimit = HostRuleLimit {
    limit: "two fields compare for equality only",
    written: "`<field>_gt_field` or `<field>_lt_field`",
    instead: "compare a field with a value through `_gt` or `_lt`, `_eq_field` and `_ne_field` comparing two fields, and open an issue naming the field an ordering would need, since ordering two fields is where arithmetic starts",
};

pub const SHIPPED_INTENTS: HostRuleLimit = HostRuleLimit {
    limit: "a rule names an intent of the catalogue",
    written: "an intent the agent does not ship",
    instead: "ask for one through an issue, or send the events through the OCSF export to an engine that holds the one you need",
};

pub const COUNT_IS_BOUNDED: HostRuleLimit = HostRuleLimit {
    limit: "a count has a window",
    written: "`count` without `within`",
    instead: "give it `within`, the window its events must fall in, such as `within: 60s` and at most an hour, since a counter with no window is a gauge and a gauge is a metric rather than a rule",
};

/// Every limit, in the order the documentation lists them.
pub const HOST_RULE_LIMITS: [HostRuleLimit; 7] = [
    NO_EXPRESSION,
    NO_ABSENCE,
    TWO_STEPS,
    ANY_OF_DEPTH_ONE,
    FIELDS_COMPARE_FOR_EQUALITY,
    SHIPPED_INTENTS,
    COUNT_IS_BOUNDED,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostrule::{HostRuleSet, HostRuleSpec};

    fn refusal(json: &str) -> String {
        let specs: Vec<HostRuleSpec> = serde_json::from_str(json).unwrap();
        HostRuleSet::compile(specs).unwrap_err().to_string()
    }

    fn assert_refused_by(limit: &HostRuleLimit, json: &str) {
        let err = refusal(json);
        assert!(err.contains(&limit.refusal()), "{}: {err}", limit.limit);
    }

    #[test]
    fn an_expression_is_refused_as_text_and_as_a_key() {
        assert_refused_by(
            &NO_EXPRESSION,
            r#"[{"id":"r","when":"exe = /bin/sh and uid = 0"}]"#,
        );
        assert_refused_by(
            &NO_EXPRESSION,
            r#"[{"id":"r","when":{"process.starts":{}},"followed_by":"curl after sh"}]"#,
        );
        assert_refused_by(
            &NO_EXPRESSION,
            r#"[{"id":"r","when":{"process.starts":{}},"condition":"a && b"}]"#,
        );
    }

    #[test]
    fn an_absence_is_refused_beside_when_and_inside_followed_by() {
        assert_refused_by(
            &NO_ABSENCE,
            r#"[{"id":"r","when":{"process.starts":{}},
                 "not_followed_by":{"within":"5s","process.ends":{}}}]"#,
        );
        assert_refused_by(
            &NO_ABSENCE,
            r#"[{"id":"r","when":{"process.starts":{}},
                 "followed_by":{"within":"5s","process.ends":{},"unless_followed_by":{}}}]"#,
        );
    }

    #[test]
    fn a_third_step_is_refused() {
        assert_refused_by(
            &TWO_STEPS,
            r#"[{"id":"r","when":{"process.starts":{}},
                 "followed_by":{"within":"5s","process.starts":{},
                                "followed_by":{"within":"5s","process.starts":{}}}}]"#,
        );
    }

    #[test]
    fn a_nested_any_of_is_refused_in_an_entry_and_in_an_intent() {
        assert_refused_by(
            &ANY_OF_DEPTH_ONE,
            r#"[{"id":"r","when":{"any_of":[
                 {"any_of":[{"process.starts":{}},{"process.ends":{}}]},
                 {"process.ends":{}}]}}]"#,
        );
        assert_refused_by(
            &ANY_OF_DEPTH_ONE,
            r#"[{"id":"r","when":{"process.starts":{"any_of":[]}}}]"#,
        );
    }

    #[test]
    fn ordering_two_fields_is_refused() {
        assert_refused_by(
            &FIELDS_COMPARE_FOR_EQUALITY,
            r#"[{"id":"r","when":{"process.starts":{"uid_lt_field":"parent_uid"}}}]"#,
        );
        assert_refused_by(
            &FIELDS_COMPARE_FOR_EQUALITY,
            r#"[{"id":"r","when":{"process.starts":{"uid_gt_field":"parent_uid"}}}]"#,
        );
    }

    #[test]
    fn an_intent_outside_the_catalogue_lists_the_catalogue_and_the_way_round() {
        let err = refusal(r#"[{"id":"r","when":{"process.mmaps":{}}}]"#);
        assert!(err.contains(&SHIPPED_INTENTS.refusal()), "{err}");
        assert!(
            err.contains("process.starts"),
            "the known intents are listed: {err}"
        );
    }

    #[test]
    fn a_count_without_a_window_is_refused() {
        assert_refused_by(
            &COUNT_IS_BOUNDED,
            r#"[{"id":"r","when":{"process.starts":{"count":{"min":5}}}}]"#,
        );
    }

    #[test]
    fn an_unknown_key_names_the_keys_a_rule_takes() {
        let err = refusal(r#"[{"id":"r","when":{"process.starts":{}},"priority":3}]"#);
        assert!(
            err.contains("`priority` is not a key of a host rule"),
            "{err}"
        );
        assert!(err.contains("`followed_by`"), "{err}");
    }

    #[test]
    fn every_limit_says_what_is_written_and_what_to_write_instead() {
        for limit in &HOST_RULE_LIMITS {
            assert!(!limit.limit.is_empty() && !limit.written.is_empty());
            assert!(!limit.instead.is_empty());
            assert!(
                !limit.limit.contains('|')
                    && !limit.written.contains('|')
                    && !limit.instead.contains('|'),
                "a row is a table row in the documentation"
            );
        }
    }
}
