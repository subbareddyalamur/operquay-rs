#![forbid(unsafe_code)]

//! 47-parameter single-hidden-layer (`10 -> 3 -> 1`) `tanh` perceptron command ranker.

use serde::{Deserialize, Serialize};

pub const MLP_HIDDEN: usize = 3;
pub const MLP_FEATURES: usize = 10;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct MlpFeatures {
    pub age: f64,
    pub length: f64,
    pub exit_code: f64,
    pub frequency: f64,
    pub dir_match: f64,
    pub context_overlap: f64,
    pub selected_count: f64,
    pub env_match: f64,
    pub recent_failure: f64,
    pub occurrences: f64,
}

impl MlpFeatures {
    #[must_use]
    pub const fn to_array(self) -> [f64; MLP_FEATURES] {
        [
            self.age,
            self.length,
            self.exit_code,
            self.frequency,
            self.dir_match,
            self.context_overlap,
            self.selected_count,
            self.env_match,
            self.recent_failure,
            self.occurrences,
        ]
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MlpNode {
    pub w: [f64; MLP_FEATURES],
    pub b: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlpRanker {
    pub hidden: [MlpNode; MLP_HIDDEN],
    pub ow: [f64; MLP_HIDDEN],
    pub ob: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct TrainingSample {
    pub features: MlpFeatures,
    pub target: f64,
}

impl Default for MlpRanker {
    fn default() -> Self {
        Self::new()
    }
}

impl MlpRanker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hidden: [
                MlpNode {
                    w: [-0.5, 0.1, -0.8, 0.9, 0.6, 0.4, 0.7, 0.5, -0.3, 0.8],
                    b: 0.1,
                },
                MlpNode {
                    w: [-0.3, 0.05, -0.6, 0.7, 0.4, 0.6, 0.5, 0.3, -0.5, 0.6],
                    b: 0.05,
                },
                MlpNode {
                    w: [-0.4, 0.08, -0.7, 0.8, 0.5, 0.3, 0.6, 0.4, -0.4, 0.7],
                    b: 0.08,
                },
            ],
            ow: [0.6, 0.3, 0.4],
            ob: 0.05,
        }
    }

    #[must_use]
    pub fn forward(&self, features: MlpFeatures) -> f64 {
        let input = features.to_array();
        let mut h_out = [0.0_f64; MLP_HIDDEN];
        for (i, node) in self.hidden.iter().enumerate() {
            let mut sum = node.b;
            for (j, x) in input.iter().enumerate() {
                sum += node.w[j] * x;
            }
            h_out[i] = sum.tanh();
        }
        let mut out = self.ob;
        for (i, v) in h_out.iter().enumerate() {
            out += self.ow[i] * v;
        }
        f64::midpoint(out.tanh(), 1.0)
    }

    pub fn train(&mut self, samples: &[TrainingSample], lr: f64, epochs: usize) {
        if samples.is_empty() || epochs == 0 {
            return;
        }
        for _ in 0..epochs {
            for sample in samples {
                let input = sample.features.to_array();
                let mut h_out = [0.0_f64; MLP_HIDDEN];
                for (i, node) in self.hidden.iter().enumerate() {
                    let mut sum = node.b;
                    for (j, x) in input.iter().enumerate() {
                        sum += node.w[j] * x;
                    }
                    h_out[i] = sum.tanh();
                }
                let mut out_raw = self.ob;
                for (i, v) in h_out.iter().enumerate() {
                    out_raw += self.ow[i] * v;
                }
                let tanh_out = out_raw.tanh();
                let pred = f64::midpoint(tanh_out, 1.0);
                let err = sample.target.clamp(0.0, 1.0) - pred;
                let d_out = err * 0.5 * (1.0 - tanh_out * tanh_out);

                let prev_ow = self.ow;
                for i in 0..MLP_HIDDEN {
                    self.ow[i] += lr * d_out * h_out[i];
                }
                self.ob += lr * d_out;

                for (i, node) in self.hidden.iter_mut().enumerate() {
                    let d_h = d_out * prev_ow[i] * (1.0 - h_out[i] * h_out[i]);
                    for (j, x) in input.iter().enumerate() {
                        node.w[j] += lr * d_h * x;
                    }
                    node.b += lr * d_h;
                }
            }
        }
    }
}
