use anyhow::Result;
use axum::{Router, routing::get, response::Html};

use super::ForensicReport;

pub async fn serve(report: ForensicReport, port: u16) -> Result<()> {
    let html  = render(&report);
    let app   = Router::new().route("/", get(move || async move { Html(html) }));
    let addr  = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("\n  Dashboard → http://localhost:{port}   (Ctrl-C to stop)\n");
    axum::serve(listener, app).await?;
    Ok(())
}

fn render(r: &ForensicReport) -> String {
    let score       = r.score.score;
    let level       = &r.score.threat_level;
    let score_class = match level.as_str() {
        "CRITICAL_INCIDENT" => "crit",
        "LIKELY_COMPROMISE" => "high",
        "SUSPICIOUS"        => "med",
        _                   => "ok",
    };

    let det_cards: String = if r.detections.is_empty() {
        r#"<p class="clean">✓ No threats detected — system appears clean.</p>"#.into()
    } else {
        r.detections.iter().enumerate().map(|(i, d)| {
            let sev_lc   = d.severity.to_string().to_lowercase();
            let tags_html = d.tags.iter()
                .map(|t| format!("<span class=\"tag\">{t}</span>"))
                .collect::<Vec<_>>().join("");
            let evid_html = d.evidence.iter()
                .map(|e| format!("<li>{e}</li>"))
                .collect::<Vec<_>>().join("");
            format!(r#"
<div class="card {sev_lc}">
  <div class="card-head">
    <span class="idx">#{}</span>
    <span class="sev {sev_lc}">{}</span>
    <strong>{}</strong>
  </div>
  <div class="meta">
    <span>Rule: {}</span>
    <span>Score: +{}</span>
    <span>{}</span>
  </div>
  <div class="tags">{tags_html}</div>
  <ul class="evidence">{evid_html}</ul>
</div>"#,
                i + 1, d.severity, d.rule_name,
                d.rule_id, d.score_contribution,
                d.detected_at.format("%Y-%m-%d %H:%M:%S UTC")
            )
        }).collect()
    };

    let s = &r.summary;
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TraceScope — Forensic Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}}
header{{background:#161b22;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;align-items:center;gap:16px}}
header h1{{font-size:1.3rem;font-weight:700;color:#58a6ff;letter-spacing:.05em}}
header .sub{{color:#8b949e;font-size:.9rem}}
.container{{max-width:1100px;margin:0 auto;padding:24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px}}
.stat-val{{font-size:2rem;font-weight:700;line-height:1}}
.stat-lbl{{font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-top:6px}}
.ok{{color:#3fb950}}.med{{color:#d29922}}.high{{color:#f0883e}}.crit{{color:#f85149}}
.section-title{{font-size:1rem;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}}
.card{{background:#161b22;border:1px solid #30363d;border-left:4px solid;border-radius:8px;padding:18px;margin-bottom:14px}}
.card.critical{{border-left-color:#f85149}}.card.high{{border-left-color:#f0883e}}
.card.medium{{border-left-color:#d29922}}.card.low{{border-left-color:#388bfd}}
.card.info{{border-left-color:#8b949e}}
.card-head{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
.idx{{font-size:.75rem;color:#8b949e;font-weight:600}}
.sev{{font-size:.7rem;padding:2px 8px;border-radius:4px;font-weight:700;text-transform:uppercase}}
.sev.critical{{background:#4d1a1a;color:#f85149}}.sev.high{{background:#3d2600;color:#f0883e}}
.sev.medium{{background:#2d2200;color:#d29922}}.sev.low{{background:#0d1c3d;color:#388bfd}}
.card-head strong{{font-size:1rem}}
.meta{{display:flex;gap:20px;font-size:.8rem;color:#8b949e;margin-bottom:8px;flex-wrap:wrap}}
.tags{{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px}}
.tag{{font-size:.7rem;padding:1px 6px;border-radius:4px;background:#21262d;color:#58a6ff}}
.evidence{{list-style:none;padding-left:8px}}
.evidence li{{font-size:.85rem;color:#a8b1ba;padding:2px 0}}
.evidence li::before{{content:'▸ ';color:#30363d}}
.clean{{color:#3fb950;padding:24px;font-size:1.1rem}}
footer{{text-align:center;padding:24px;color:#30363d;font-size:.8rem;border-top:1px solid #21262d;margin-top:32px}}
</style>
</head>
<body>
<header>
  <h1>🔭 TraceScope</h1>
  <span class="sub">Forensic Correlation Report</span>
</header>
<div class="container">
  <div class="grid">
    <div class="stat">
      <div class="stat-val {score_class}">{score}</div>
      <div class="stat-lbl">Threat score / 100</div>
    </div>
    <div class="stat">
      <div class="stat-val {score_class}">{level}</div>
      <div class="stat-lbl">Threat level</div>
    </div>
    <div class="stat">
      <div class="stat-val">{evts}</div>
      <div class="stat-lbl">Events processed</div>
    </div>
    <div class="stat">
      <div class="stat-val">{total}</div>
      <div class="stat-lbl">Detections</div>
    </div>
    <div class="stat">
      <div class="stat-val crit">{crit}</div>
      <div class="stat-lbl">Critical</div>
    </div>
    <div class="stat">
      <div class="stat-val high">{high}</div>
      <div class="stat-lbl">High</div>
    </div>
    <div class="stat">
      <div class="stat-val med">{med}</div>
      <div class="stat-lbl">Medium</div>
    </div>
    <div class="stat">
      <div class="stat-val">{dur:.3}s</div>
      <div class="stat-lbl">Duration</div>
    </div>
  </div>
  <div class="section-title">Detections</div>
  {det_cards}
</div>
<footer>TraceScope v{ver} — {ts}</footer>
</body>
</html>"#,
        score_class = score_class,
        score  = score,
        level  = level,
        evts   = r.events_processed,
        total  = s.total,
        crit   = s.critical,
        high   = s.high,
        med    = s.medium,
        dur    = r.duration_secs,
        ver    = env!("CARGO_PKG_VERSION"),
        ts     = r.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        det_cards = det_cards,
    )
}
