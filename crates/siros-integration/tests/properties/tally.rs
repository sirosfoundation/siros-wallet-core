//! How often each outcome and each checked branch was reached, by name in order of first reach.

/// The counts.
#[derive(Default)]
pub struct Tally(Vec<(String, usize)>);

impl Tally {
    /// Counts one reach of a branch.
    pub fn add(&mut self, name: impl Into<String>) {
        self.add_many(name, 1);
    }

    /// Counts `by` reaches of a branch.
    pub fn add_many(&mut self, name: impl Into<String>, by: usize) {
        let name = name.into();
        match self.0.iter_mut().find(|(known, _)| *known == name) {
            Some((_, count)) => *count += by,
            None => self.0.push((name, by)),
        }
    }

    /// How often a branch was reached.
    pub fn count(&self, name: &str) -> usize {
        self.0
            .iter()
            .find(|(known, _)| known == name)
            .map_or(0, |(_, count)| *count)
    }

    /// Every branch with its count.
    pub fn counts(&self) -> &[(String, usize)] {
        &self.0
    }
}
