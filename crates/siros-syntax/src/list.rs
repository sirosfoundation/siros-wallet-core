//! One or more values.

/// One or more values, in the order given: `new` refuses an empty list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllOf<T>(Vec<T>);

impl<T> AllOf<T> {
    /// The values, in their order; `None` for no value.
    #[must_use]
    pub fn new(items: Vec<T>) -> Option<Self> {
        (!items.is_empty()).then_some(Self(items))
    }

    /// One value.
    #[must_use]
    pub fn one(item: T) -> Self {
        Self(vec![item])
    }

    /// The values, in their order.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.0
    }

    /// The values, by value.
    #[must_use]
    pub fn into_items(self) -> Vec<T> {
        self.0
    }

    /// Each value mapped, in the same order.
    #[must_use]
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> AllOf<U> {
        AllOf(self.0.into_iter().map(f).collect())
    }

    /// Each value mapped, in the same order; the first error when a value fails.
    ///
    /// # Errors
    ///
    /// The first error `f` returns.
    pub fn try_map<U, E>(&self, f: impl FnMut(&T) -> Result<U, E>) -> Result<AllOf<U>, E> {
        self.0.iter().map(f).collect::<Result<_, _>>().map(AllOf)
    }

    /// These values, then `later`'s.
    #[must_use]
    pub fn and(mut self, later: Self) -> Self {
        self.0.extend(later.0);
        self
    }
}
