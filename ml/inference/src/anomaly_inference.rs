/// ONNX-based anomaly scorer stub.
/// In production this would load an ONNX model via the `ort` crate and run
/// the exported sklearn IsolationForest. Here we implement the same interface
/// using a deterministic heuristic so the rest of the system compiles and
/// runs without native ONNX runtime dependencies.
pub struct OnnxAnomalyScorer {
    model_path: String,
    contamination: f64,
}

impl OnnxAnomalyScorer {
    pub fn new(model_path: &str, contamination: f64) -> Self {
        Self {
            model_path: model_path.to_owned(),
            contamination: contamination.clamp(0.0, 0.5),
        }
    }

    /// Score a feature vector, returning a value in [0, 1] where higher = more anomalous.
    /// Stub: L2 norm normalized by a rough expected maximum, clipped to [0, 1].
    pub fn score(&self, feature_vector: &[f64]) -> f64 {
        if feature_vector.is_empty() {
            return 0.0;
        }
        let l2: f64 = feature_vector.iter().map(|x| x * x).sum::<f64>().sqrt();
        // Normalize: assume a "typical" vector has L2 ≈ 1.5; anomalous vectors score > 2.5
        (l2 / 3.0).min(1.0)
    }

    pub fn is_anomalous(&self, feature_vector: &[f64]) -> bool {
        self.score(feature_vector) > (1.0 - self.contamination)
    }

    pub fn model_path(&self) -> &str {
        &self.model_path
    }

    pub fn contamination(&self) -> f64 {
        self.contamination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_vector_scores_zero() {
        let scorer = OnnxAnomalyScorer::new("anomaly.onnx", 0.05);
        assert_eq!(scorer.score(&[0.0; 8]), 0.0);
    }

    #[test]
    fn high_magnitude_vector_is_anomalous() {
        let scorer = OnnxAnomalyScorer::new("anomaly.onnx", 0.05);
        let fv = vec![2.0; 8]; // very high values
        assert!(scorer.is_anomalous(&fv));
    }

    #[test]
    fn normal_vector_not_anomalous() {
        let scorer = OnnxAnomalyScorer::new("anomaly.onnx", 0.05);
        let fv = vec![0.1, 0.05, 0.2, 0.1, 0.3, 0.1, 0.05, 0.02];
        assert!(!scorer.is_anomalous(&fv));
    }

    #[test]
    fn score_capped_at_one() {
        let scorer = OnnxAnomalyScorer::new("anomaly.onnx", 0.05);
        let score = scorer.score(&[100.0; 8]);
        assert!(score <= 1.0);
    }

    #[test]
    fn empty_vector_scores_zero() {
        let scorer = OnnxAnomalyScorer::new("model.onnx", 0.1);
        assert_eq!(scorer.score(&[]), 0.0);
    }
}
