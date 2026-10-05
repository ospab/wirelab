use serde::Serialize;
use std::fmt;

/// A check either measured something and passed, measured something and
/// failed, or could not measure. The third outcome is never reported as a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    Pass,
    Fail,
    NoData,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Outcome::Pass => "PASS",
            Outcome::Fail => "FAIL",
            Outcome::NoData => "NO DATA",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub outcome: Outcome,
    /// What was measured, in numbers, or why nothing could be.
    pub evidence: String,
}

/// A measured quantity. `value: None` is NO DATA, with the reason in `note`.
#[derive(Debug, Clone, Serialize)]
pub struct Metric {
    pub id: String,
    pub value: Option<f64>,
    pub unit: &'static str,
    pub note: String,
}
