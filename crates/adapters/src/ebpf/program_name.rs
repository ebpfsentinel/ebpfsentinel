//! The one spelling of a program name that leaves the agent.
//!
//! A program has two names and always has had. `xdp-firewall` is the artefact:
//! what the build produces, what the object file is called, what an operator
//! types and what every page of the documentation says. `xdp_firewall` is the
//! symbol inside that object, spelled with underscores because a C symbol has
//! to be, and it is the name the loader is asked for a program by.
//!
//! Internally the second is the right one to hold, since it is the key the
//! loader answers to. On the way out it is the wrong one: the Prometheus
//! `program` label, the ops endpoint and the anonymous heartbeat were each
//! publishing whichever of the two happened to be in the caller's hand, so the
//! same program appeared under two spellings depending on which surface was
//! read, and the fleet API translated one into the other on its way through.
//! Everything published goes through here instead.

/// The name a program is published under, from the name it is loaded under.
///
/// Idempotent: a name that is already the published one comes back unchanged,
/// so a caller holding either spelling is safe.
#[must_use]
pub fn published_program_name(program: &str) -> String {
    program.replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::published_program_name;

    #[test]
    fn a_symbol_name_becomes_the_artefact_name() {
        assert_eq!(published_program_name("xdp_firewall"), "xdp-firewall");
        assert_eq!(published_program_name("tc_nat_ingress"), "tc-nat-ingress");
    }

    #[test]
    fn a_name_that_is_already_published_is_left_alone() {
        // The callers are a mix: some hold the symbol they looked the program
        // up by, some hold a name that arrived already spelled the published
        // way, and neither can be made to care which.
        assert_eq!(published_program_name("xdp-firewall"), "xdp-firewall");
        assert_eq!(published_program_name(""), "");
    }
}
