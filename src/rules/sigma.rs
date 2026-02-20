use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use crate::domain::{
    detection::Detection,
    event::{Event, EventType, Severity},
    rule::{Rule, RuleContext},
};

pub fn load_from_path(path: &Path) -> Result<Arc<dyn Rule>> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read Sigma rule: {}", path.display()))?;
    load_from_str(&src)
        .with_context(|| format!("Invalid Sigma rule: {}", path.display()))
}

pub fn load_from_str(src: &str) -> Result<Arc<dyn Rule>> {
    let raw: SigmaRuleRaw = serde_yaml::from_str(src)
        .context("Sigma YAML parse error")?;
    Ok(Arc::new(SigmaRule::build(raw)?))
}

#[derive(Deserialize)]
struct SigmaRuleRaw {
    title:       String,
    id:          Option<String>,
    description: Option<String>,
    level:       Option<String>,
    tags:        Option<Vec<String>>,
    logsource:   SigmaLogsourceRaw,
    detection:   serde_yaml::Value,
}

#[derive(Deserialize)]
struct SigmaLogsourceRaw {
    category: Option<String>,
    #[allow(dead_code)]
    product:  Option<String>,
    service:  Option<String>,
}

struct SigmaRule {
    rule_id:     String,
    title:       String,
    description: String,
    severity:    Severity,
    tags:        Vec<String>,
    logsource:   Option<EventType>,
    detection:   Detection_,
}

struct Detection_ {
    sets:      HashMap<String, Vec<FieldMatcher>>,
    condition: Condition,
}

#[derive(Clone)]
enum Condition {
    Set(String),
    Not(Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    OneOf(String),
    AllOf(String),
}

struct FieldMatcher {
    field:    String,
    modifier: Modifier,
    values:   Vec<String>,
}

#[derive(Clone, Copy)]
enum Modifier { Exact, Contains, Startswith, Endswith }

impl SigmaRule {
    fn build(raw: SigmaRuleRaw) -> Result<Self> {
        let severity = level_to_severity(raw.level.as_deref());
        let logsource = raw.logsource.category.as_deref()
            .or(raw.logsource.service.as_deref())
            .and_then(category_to_event_type);

        let det_map = raw.detection.as_mapping()
            .context("Sigma detection must be a YAML mapping")?;

        let condition_str = det_map.get("condition")
            .and_then(|v| v.as_str())
            .context("Sigma rule missing 'condition' in detection")?;

        let mut sets = HashMap::new();
        for (k, v) in det_map {
            let key = k.as_str().unwrap_or_default();
            if key == "condition" || key == "timeframe" { continue; }
            sets.insert(key.to_owned(), parse_field_set(v)?);
        }

        Ok(Self {
            rule_id:     raw.id.unwrap_or_else(|| format!("SIGMA-{}", &raw.title[..raw.title.len().min(20)])),
            title:       raw.title,
            description: raw.description.unwrap_or_default(),
            severity,
            tags:        raw.tags.unwrap_or_default(),
            logsource,
            detection:   Detection_ {
                sets,
                condition: parse_condition(condition_str)?,
            },
        })
    }
}

#[async_trait]
impl Rule for SigmaRule {
    fn id(&self)          -> &str { &self.rule_id }
    fn name(&self)        -> &str { &self.title }
    fn description(&self) -> &str { &self.description }
    fn tags(&self)        -> &[&'static str] { &[] }

    async fn evaluate(&self, event: &Event, _ctx: &RuleContext) -> Result<Option<Detection>> {
        if let Some(expected) = &self.logsource {
            if &event.event_type != expected { return Ok(None); }
        }

        if !eval_condition(&self.detection.condition, event, &self.detection.sets) {
            return Ok(None);
        }

        let det = Detection::new(
            self.id(),
            self.name(),
            self.description(),
            self.severity,
            &[event],
            self.severity.weight(),
            self.tags.clone(),
            vec![format!("Sigma rule '{}' matched on {:?}", self.title, event.event_type)],
        );
        Ok(Some(det))
    }
}

fn eval_condition(
    cond:  &Condition,
    event: &Event,
    sets:  &HashMap<String, Vec<FieldMatcher>>,
) -> bool {
    match cond {
        Condition::Set(name)     => sets.get(name)
            .map(|m| matches_all(event, m))
            .unwrap_or(false),
        Condition::Not(inner)    => !eval_condition(inner, event, sets),
        Condition::And(a, b)     => eval_condition(a, event, sets) && eval_condition(b, event, sets),
        Condition::Or(a, b)      => eval_condition(a, event, sets) || eval_condition(b, event, sets),
        // "1 of X*" — any set whose name starts with the prefix matches
        Condition::OneOf(prefix) => sets.iter()
            .filter(|(k, _)| k.starts_with(prefix.as_str()))
            .any(|(_, m)| matches_all(event, m)),
        // "all of X*" — every matching set must pass
        Condition::AllOf(prefix) => {
            let relevant: Vec<_> = sets.iter()
                .filter(|(k, _)| k.starts_with(prefix.as_str()))
                .collect();
            !relevant.is_empty() && relevant.iter().all(|(_, m)| matches_all(event, m))
        }
    }
}

fn matches_all(event: &Event, matchers: &[FieldMatcher]) -> bool {
    matchers.iter().all(|m| {
        let hay = event.metadata.get(&m.field)
            .map(String::as_str)
            .unwrap_or("")
            .to_lowercase();
        // Within a set: OR logic (any value matches)
        m.values.iter().any(|v| {
            let v = v.to_lowercase();
            match m.modifier {
                Modifier::Exact      => hay == v,
                Modifier::Contains   => hay.contains(v.as_str()),
                Modifier::Startswith => hay.starts_with(v.as_str()),
                Modifier::Endswith   => hay.ends_with(v.as_str()),
            }
        })
    })
}

fn parse_field_set(v: &serde_yaml::Value) -> Result<Vec<FieldMatcher>> {
    let map = v.as_mapping().context("Sigma detection set must be a mapping")?;
    let mut out = Vec::new();
    for (fk, fv) in map {
        let key = fk.as_str().context("field key must be a string")?;
        let (field, modifier) = parse_modifier(key);
        let values = yaml_to_strings(fv);
        out.push(FieldMatcher { field, modifier, values });
    }
    Ok(out)
}

fn parse_modifier(key: &str) -> (String, Modifier) {
    let (field, mod_str) = key.split_once('|')
        .map(|(f, m)| (f, Some(m)))
        .unwrap_or((key, None));

    let modifier = match mod_str {
        Some("contains")   => Modifier::Contains,
        Some("startswith") => Modifier::Startswith,
        Some("endswith")   => Modifier::Endswith,
        _                  => Modifier::Exact,
    };
    (field.to_lowercase(), modifier)
}

fn yaml_to_strings(v: &serde_yaml::Value) -> Vec<String> {
    match v {
        serde_yaml::Value::String(s)   => vec![s.clone()],
        serde_yaml::Value::Number(n)   => vec![n.to_string()],
        serde_yaml::Value::Bool(b)     => vec![b.to_string()],
        serde_yaml::Value::Sequence(s) => s.iter().flat_map(yaml_to_strings).collect(),
        _                              => vec![],
    }
}

// Recursive-descent parser for Sigma condition strings.
// Supports: identifier, "not X", "X and Y", "X or Y", "1 of X*", "all of X*"
fn parse_condition(s: &str) -> Result<Condition> {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let (cond, _) = parse_or(&tokens, 0)?;
    Ok(cond)
}

fn parse_or(tokens: &[&str], pos: usize) -> Result<(Condition, usize)> {
    let (left, mut pos) = parse_and(tokens, pos)?;
    if tokens.get(pos).map(|t| t.eq_ignore_ascii_case("or")).unwrap_or(false) {
        let (right, pos2) = parse_or(tokens, pos + 1)?;
        pos = pos2;
        return Ok((Condition::Or(Box::new(left), Box::new(right)), pos));
    }
    Ok((left, pos))
}

fn parse_and(tokens: &[&str], pos: usize) -> Result<(Condition, usize)> {
    let (left, mut pos) = parse_unary(tokens, pos)?;
    if tokens.get(pos).map(|t| t.eq_ignore_ascii_case("and")).unwrap_or(false) {
        let (right, pos2) = parse_and(tokens, pos + 1)?;
        pos = pos2;
        return Ok((Condition::And(Box::new(left), Box::new(right)), pos));
    }
    Ok((left, pos))
}

fn parse_unary(tokens: &[&str], pos: usize) -> Result<(Condition, usize)> {
    if tokens.get(pos).map(|t| t.eq_ignore_ascii_case("not")).unwrap_or(false) {
        let (inner, pos2) = parse_primary(tokens, pos + 1)?;
        return Ok((Condition::Not(Box::new(inner)), pos2));
    }
    if tokens.get(pos).map(|t| t.eq_ignore_ascii_case("1")).unwrap_or(false)
        && tokens.get(pos + 1).map(|t| t.eq_ignore_ascii_case("of")).unwrap_or(false)
    {
        let prefix = tokens.get(pos + 2).context("expected name after '1 of'")?
            .trim_end_matches('*');
        return Ok((Condition::OneOf(prefix.to_owned()), pos + 3));
    }
    if tokens.get(pos).map(|t| t.eq_ignore_ascii_case("all")).unwrap_or(false)
        && tokens.get(pos + 1).map(|t| t.eq_ignore_ascii_case("of")).unwrap_or(false)
    {
        let prefix = tokens.get(pos + 2).context("expected name after 'all of'")?
            .trim_end_matches('*');
        return Ok((Condition::AllOf(prefix.to_owned()), pos + 3));
    }
    parse_primary(tokens, pos)
}

fn parse_primary(tokens: &[&str], pos: usize) -> Result<(Condition, usize)> {
    let tok = tokens.get(pos).context("unexpected end of condition")?;
    Ok((Condition::Set((*tok).to_owned()), pos + 1))
}

fn level_to_severity(level: Option<&str>) -> Severity {
    match level {
        Some("critical") => Severity::Critical,
        Some("high")     => Severity::High,
        Some("medium")   => Severity::Medium,
        Some("low")      => Severity::Low,
        _                => Severity::Info,
    }
}

fn category_to_event_type(cat: &str) -> Option<EventType> {
    Some(match cat {
        "process_creation" | "process_creation_windows" => EventType::ProcessCreation,
        "network_connection" | "network_traffic"        => EventType::NetworkConnection,
        "dns" | "dns_query"                             => EventType::DnsQuery,
        "file_event" | "file_creation"                  => EventType::FileCreation,
        "registry_event" | "registry_add"
        | "registry_set" | "registry_delete"            => EventType::RegistryModification,
        "logon_failed" | "login_failure"                => EventType::LoginFailure,
        "logon" | "login_success"                       => EventType::LoginSuccess,
        _                                               => return None,
    })
}
