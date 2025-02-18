use std::cmp::{Ordering, PartialEq, PartialOrd};

// A combination of a `Box<T>` with a number value, such that different
// instances can be compared and ordered.
//
// Currently numeric values of type `f32` or `u8` are supported.
pub struct ScoredItem<T> {
    score: f32,
    item: Box<T>,
}

impl<T> ScoredItem<T> {
    /// Constructor
    ///
    /// Note that `score` is first parameter, so it can be calculated with a
    /// borrowed reference of `item`. This would not be possible if it was
    /// the second parameter, since `item` would already be moved.
    pub fn new(score: f32, item: T) -> ScoredItem<T> {
        // Store item in a box
        let item = Box::new(item);

        // Return Box with score
        ScoredItem { score, item }
    }

    /// Get the value back out of the Box
    pub fn item(self) -> T {
        // Box::into_inner(self.item)
        *self.item
    }
}

// Use the `f32::total_cmp` function to implement `Ord`
impl<T> Ord for ScoredItem<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.total_cmp(&other.score)
    }
}

// Implementing `Eq` using the `Ord` implementation above
impl<T> Eq for ScoredItem<T> where ScoredItem<T>: Ord {}

// Implementing `PartialOrd` using the `Ord` implementation above
impl<T> PartialOrd for ScoredItem<T>
where
    ScoredItem<T>: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Implementing `PartialEq` using the `Ord` implementation above
impl<T> PartialEq for ScoredItem<T>
where
    ScoredItem<T>: Ord,
{
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example() {
        // List of strings in alphabetical order
        let mut list = Vec::from([
            ScoredItem::new(0.99, "one"),
            ScoredItem::new(3.14, "pi"),
            ScoredItem::new(6.28, "tau"),
            ScoredItem::new(2.72, "e"),
            ScoredItem::new(0.00, "zero"),
        ]);

        // Sort into numeric order
        list.sort();

        // Verify last element
        assert_eq!(list.pop().map(ScoredItem::item), Some("tau"));
    }
}
