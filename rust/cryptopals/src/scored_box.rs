use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};

/// Combine a generic T with a score, so it is easy to sort or find min/max
pub struct ScoredBox<T> {
    score: f32,
    value: Box<T>,
}

impl<T> ScoredBox<T> {
    /// Constructor
    ///
    /// Note that `score` is first parameter, so it can be calculated with a
    /// borrowed reference of `value`. This would not be possible if it was the
    /// second parameter, since `value` would already be moved.
    pub fn new(score: f32, value: T) -> ScoredBox<T> {
        ScoredBox {
            value: Box::new(value),
            score,
        }
    }

    /// Get the value back out of the Box
    pub fn unbox(self) -> T {
        *self.value
    }
}

impl<T> PartialEq for ScoredBox<T> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl<T> Eq for ScoredBox<T> {}

impl<T> PartialOrd for ScoredBox<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for ScoredBox<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.total_cmp(&other.score)
    }
}
