use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    LikelyCompromise,
    CriticalIncident,
}

impl ThreatLevel {
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=29  => Self::Clean,
            30..=59 => Self::Suspicious,
            60..=84 => Self::LikelyCompromise,
            _       => Self::CriticalIncident,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean            => "CLEAN",
            Self::Suspicious       => "SUSPICIOUS",
            Self::LikelyCompromise => "LIKELY_COMPROMISE",
            Self::CriticalIncident => "CRITICAL_INCIDENT",
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// Lock-free atomic scoring — safe to increment from multiple concurrent rule tasks.
#[derive(Debug, Clone)]
pub struct ScoreEngine {
    score: Arc<AtomicU32>,
}

impl Default for ScoreEngine {
    fn default() -> Self {
        Self { score: Arc::new(AtomicU32::new(0)) }
    }
}

impl ScoreEngine {
    pub fn new() -> Self { Self::default() }

    #[inline]
    pub fn increment(&self, amount: u32) {
        self.score.fetch_add(amount, Ordering::Relaxed);
    }

    pub fn get(&self) -> u32 {
        self.score.load(Ordering::Relaxed)
    }

    pub fn threat_level(&self) -> ThreatLevel {
        ThreatLevel::from_score(self.get())
    }

    pub fn snapshot(&self) -> ScoreSnapshot {
        let score = self.get();
        ScoreSnapshot {
            score,
            threat_level: ThreatLevel::from_score(score).as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreSnapshot {
    pub score:        u32,
    pub threat_level: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds() {
        assert_eq!(ThreatLevel::from_score(0),  ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(29), ThreatLevel::Clean);
        assert_eq!(ThreatLevel::from_score(30), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(59), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(60), ThreatLevel::LikelyCompromise);
        assert_eq!(ThreatLevel::from_score(84), ThreatLevel::LikelyCompromise);
        assert_eq!(ThreatLevel::from_score(85), ThreatLevel::CriticalIncident);
    }

    #[test]
    fn concurrent_increment() {
        let engine = ScoreEngine::new();
        engine.increment(30);
        engine.increment(50);
        assert_eq!(engine.get(), 80);
        assert_eq!(engine.threat_level(), ThreatLevel::LikelyCompromise);
    }
}
