//! Values under distinct keys.

use siros_explain::Explain;

/// Values under distinct keys, in the order given. Each constructor holds the keys distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyed<K, V>(Vec<Entry<K, V>>);

/// A value under its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<K, V> {
    key: K,
    value: V,
}

impl<K, V> Entry<K, V> {
    /// The value under the key.
    #[must_use]
    pub const fn new(key: K, value: V) -> Self {
        Self { key, value }
    }

    /// The key.
    #[must_use]
    pub const fn key(&self) -> &K {
        &self.key
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> &V {
        &self.value
    }

    /// The value, by value.
    #[must_use]
    pub fn into_value(self) -> V {
        self.value
    }
}

/// A key given twice to [`Keyed::new`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[error("{key} is given twice")]
#[explain(id = "repeated")]
pub struct Repeated<K> {
    /// The key.
    pub key: K,
}

impl<K, V> Keyed<K, V> {
    /// No entry.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// The entries, in their order.
    #[must_use]
    pub fn entries(&self) -> &[Entry<K, V>] {
        &self.0
    }

    /// The entries, by value.
    #[must_use]
    pub fn into_entries(self) -> Vec<Entry<K, V>> {
        self.0
    }

    /// Each value mapped, under the same keys.
    #[must_use]
    pub fn map<U>(&self, mut f: impl FnMut(&V) -> U) -> Keyed<K, U>
    where
        K: Clone,
    {
        Keyed(
            self.0
                .iter()
                .map(|entry| Entry::new(entry.key.clone(), f(&entry.value)))
                .collect(),
        )
    }

    /// Each value mapped, under the same keys; the first error when a value fails.
    ///
    /// # Errors
    ///
    /// The first error `f` returns.
    pub fn try_map<U, E>(&self, mut f: impl FnMut(&V) -> Result<U, E>) -> Result<Keyed<K, U>, E>
    where
        K: Clone,
    {
        let mut entries = Vec::with_capacity(self.0.len());
        for entry in &self.0 {
            entries.push(Entry::new(entry.key.clone(), f(&entry.value)?));
        }
        Ok(Keyed(entries))
    }
}

impl<K: PartialEq, V> Keyed<K, V> {
    /// The entries, in their order; refused when a key repeats.
    ///
    /// # Errors
    ///
    /// The first key given a second time.
    pub fn new(entries: Vec<Entry<K, V>>) -> Result<Self, Repeated<K>> {
        let mut held: Vec<Entry<K, V>> = Vec::with_capacity(entries.len());
        for entry in entries {
            if held.iter().any(|earlier| earlier.key == entry.key) {
                return Err(Repeated { key: entry.key });
            }
            held.push(entry);
        }
        Ok(Self(held))
    }

    /// The entries, in their order, each key's first value alone.
    #[must_use]
    pub fn first_of(entries: impl IntoIterator<Item = Entry<K, V>>) -> Self {
        let mut held: Vec<Entry<K, V>> = Vec::new();
        for entry in entries {
            if held.iter().all(|earlier| earlier.key != entry.key) {
                held.push(entry);
            }
        }
        Self(held)
    }

    /// The value under a key.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.0
            .iter()
            .find(|entry| &entry.key == key)
            .map(|entry| &entry.value)
    }
}
