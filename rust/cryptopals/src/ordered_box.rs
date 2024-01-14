use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};

/// A combination of a `Box<T>` with a number value, such that different
/// instances can be compared and ordered.
///
/// Currently only numeric values of type `f32` or `u8` are supported.
///
/// ## Examples
/// ```
/// # use cryptopals::OrderedBox;
/// #
/// // List of strings in alphabetical order
/// let mut list = Vec::from([
///     OrderedBox::new(4, "four"),
///     OrderedBox::new(1, "one"),
///     OrderedBox::new(3, "three"),
///     OrderedBox::new(2, "two"),
///     OrderedBox::new(0, "zero"),
/// ]);
///
/// // Sort into numeric order
/// list.sort();
///
/// // Verify last element
/// assert_eq!(list.pop().map(OrderedBox::unbox), Some("four"));
/// ```
pub struct OrderedBox<S, T> {
    score: S,
    content: Box<T>,
}

impl<S, T> OrderedBox<S, T> {
    /// Constructor
    ///
    /// Note that `score` is first parameter, so it can be calculated with a
    /// borrowed reference of `content`. This would not be possible if it was
    /// the second parameter, since `content` would already be moved.
    pub fn new(score: S, content: T) -> OrderedBox<S, T> {
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

impl<S, T> PartialEq for OrderedBox<S, T>
where
    OrderedBox<S, T>: Ord,
{
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl<S, T> Eq for OrderedBox<S, T> where OrderedBox<S, T>: Ord {}

impl<S, T> PartialOrd for OrderedBox<S, T>
where
    OrderedBox<S, T>: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for OrderedBox<f32, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.total_cmp(&other.score)
    }
}

impl<T> Ord for OrderedBox<u8, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.cmp(&other.score)
    }
}
