pub mod account_creation;
pub mod archive_exfil;
pub mod av_tamper;
pub mod brute_force;
pub mod c2_beacon;
pub mod credential_dumping;
pub mod dns_tunneling;
pub mod download_cradle;
pub mod encoded_command;
pub mod file_dropper;
pub mod large_upload;
pub mod log_clear;
pub mod lolbin;
pub mod named_pipe;
pub mod office_macro;
pub mod pass_spray;
pub mod port_scan;
pub mod powershell_lateral;
pub mod psexec;
pub mod ransomware;
pub mod registry_persistence;
pub mod sched_task;
pub mod shadow_delete;
pub mod smb_lateral;
pub mod succ_after_fail;
pub mod sys_discovery;
pub mod uncommon_port;
pub mod wmi_abuse;

use std::sync::Arc;
use crate::domain::rule::Rule;

pub fn load_all() -> Vec<Arc<dyn Rule>> {
    vec![
        // Process / execution
        Arc::new(powershell_lateral::PowerShellLateralRule),
        Arc::new(credential_dumping::CredentialDumpingRule),
        Arc::new(lolbin::LolbinRule),
        Arc::new(encoded_command::EncodedCommandRule),
        Arc::new(wmi_abuse::WmiAbuseRule),
        Arc::new(sched_task::SchedTaskRule),
        Arc::new(account_creation::AccountCreationRule),
        Arc::new(shadow_delete::ShadowDeleteRule),
        Arc::new(av_tamper::AvTamperRule),
        Arc::new(log_clear::LogClearRule),
        Arc::new(sys_discovery::SysDiscoveryRule),
        Arc::new(office_macro::OfficeMacroRule),
        Arc::new(download_cradle::DownloadCradleRule),
        Arc::new(named_pipe::NamedPipeRule),
        Arc::new(psexec::PsexecRule),
        // File system
        Arc::new(file_dropper::FileDropperRule),
        Arc::new(ransomware::RansomwareRule),
        Arc::new(archive_exfil::ArchiveExfilRule),
        // Registry
        Arc::new(registry_persistence::RegistryPersistenceRule),
        // Network
        Arc::new(brute_force::BruteForceRule),
        Arc::new(dns_tunneling::DnsTunnelingRule),
        Arc::new(c2_beacon::C2BeaconRule),
        Arc::new(port_scan::PortScanRule),
        Arc::new(uncommon_port::UncommonPortRule),
        Arc::new(large_upload::LargeUploadRule),
        Arc::new(smb_lateral::SmbLateralRule),
        // Authentication
        Arc::new(succ_after_fail::SuccAfterFailRule),
        Arc::new(pass_spray::PassSprayRule),
    ]
}
