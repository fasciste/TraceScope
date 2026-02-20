/// Human-readable CLI report — no external crates, pure ANSI escapes.
use super::ForensicReport;

const SEP: &str  = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
const SEP2: &str = "────────────────────────────────────────────────────────────────";

pub fn print_report(report: &ForensicReport) {
    let level  = &report.score.threat_level;
    let score  = report.score.score;
    let colour = threat_colour(level);
    let s      = &report.summary;

    println!("\n{SEP}");
    println!("  \x1b[1;36mTRACESCOPE FORENSIC REPORT\x1b[0m");
    println!("{SEP}");
    println!("  Generated : {}", report.generated_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Duration  : {:.3}s", report.duration_secs);
    println!("  Events    : {}", report.events_processed);
    println!(
        "  Score     : \x1b[1m{score}/100\x1b[0m  [{colour}{level}\x1b[0m]"
    );

    // ── Detection summary bar ────────────────────────────────────────────────
    println!("{SEP2}");
    if s.total == 0 {
        println!("  Detections: \x1b[32m0  — no threats detected\x1b[0m");
    } else {
        print!("  Detections: {} total  ", s.total);
        if s.critical > 0 { print!("\x1b[1;31m●{}\x1b[0m CRIT  ", s.critical); }
        if s.high     > 0 { print!("\x1b[31m●{}\x1b[0m HIGH  ",   s.high);     }
        if s.medium   > 0 { print!("\x1b[33m●{}\x1b[0m MED  ",    s.medium);   }
        if s.low      > 0 { print!("\x1b[34m●{}\x1b[0m LOW  ",    s.low);      }
        if s.info     > 0 { print!("\x1b[0m●{}\x1b[0m INFO  ",    s.info);     }
        println!();
    }
    println!("{SEP}");

    if report.detections.is_empty() {
        println!("  \x1b[32mSystem appears clean.\x1b[0m");
    } else {
        println!();
        for (i, det) in report.detections.iter().enumerate() {
            let sev_col = sev_colour(&det.severity.to_string());
            println!(
                "  \x1b[2m[{}/{}]\x1b[0m  [{sev_col}{}\x1b[0m]  \x1b[1m{}\x1b[0m",
                i + 1, s.total, det.severity, det.rule_name
            );
            println!("    Rule    : {}", det.rule_id);
            println!("    Time    : {}", det.detected_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("    Score   : +{}", det.score_contribution);
            if !det.tags.is_empty() {
                println!("    Tags    : {}", det.tags.join(", "));
            }
            println!("    Evidence:");
            for ev in &det.evidence {
                println!("      • {ev}");
            }
            println!();
        }
    }

    println!("{SEP}\n");
}

fn threat_colour(level: &str) -> &'static str {
    match level {
        "CLEAN"             => "\x1b[32m",   // green
        "SUSPICIOUS"        => "\x1b[33m",   // yellow
        "LIKELY_COMPROMISE" => "\x1b[31m",   // red
        "CRITICAL_INCIDENT" => "\x1b[1;31m", // bold red
        _                   => "\x1b[0m",
    }
}

fn sev_colour(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => "\x1b[1;31m",
        "HIGH"     => "\x1b[31m",
        "MEDIUM"   => "\x1b[33m",
        "LOW"      => "\x1b[34m",
        _          => "\x1b[0m",
    }
}
