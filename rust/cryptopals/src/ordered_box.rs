use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};

/// A combination of a `Box<T>` with a number value, such that different
/// instances can be compared and ordered.
///
/// ## Examples
/// ```
/// # use cryptopals::OrderedBox;
/// #
/// // List of strings in alphabetical order
/// let mut list = Vec::from([
///     OrderedBox::new(4.0, "four"),
///     OrderedBox::new(1.0, "one"),
///     OrderedBox::new(3.0, "three"),
///     OrderedBox::new(2.0, "two"),
///     OrderedBox::new(0.0, "zero"),
/// ]);
///
/// // Sort into numeric order
/// list.sort();
///
/// // Verify last element
/// assert_eq!(list.pop().map(OrderedBox::unbox), Some("four"));
/// ```
pub struct OrderedBox<T> {
    score: f32,
    content: Box<T>,
}

impl<T> OrderedBox<T> {
    /// Constructor
    ///
    /// Note that `score` is first parameter, so it can be calculated with a
    /// borrowed reference of `content`. This would not be possible if it was
    /// the second parameter, since `content` would already be moved.
    pub fn new(score: f32, content: T) -> OrderedBox<T> {
        // Store content in a box
        let content = Box::new(content);

        // Return Box with score
        OrderedBox { score, content }
    }

    /// Get the value back out of the Box
    pub fn unbox(self) -> T {
        *self.content
    }
}

impl<T> PartialEq for OrderedBox<T> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl<T> Eq for OrderedBox<T> {}

impl<T> PartialOrd for OrderedBox<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for OrderedBox<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.total_cmp(&other.score)
    }
}
