pub mod brute_force;
pub mod credential_dumping;
pub mod dns_tunneling;
pub mod powershell_lateral;
pub mod registry_persistence;

use std::sync::Arc;
use crate::domain::rule::Rule;

/// Load all built-in rules into a `Vec<Arc<dyn Rule>>`.
///
/// Add new rules here to register them automatically with the engine.
pub fn load_all() -> Vec<Arc<dyn Rule>> {
    vec![
        Arc::new(powershell_lateral::PowerShellLateralRule),
        Arc::new(brute_force::BruteForceRule),
        Arc::new(dns_tunneling::DnsTunnelingRule),
        Arc::new(registry_persistence::RegistryPersistenceRule),
        Arc::new(credential_dumping::CredentialDumpingRule),
    ]
}
