//! The cartesian product of lists, the last list advancing fastest.

/// Each combination taking one item of every list, in odometer order. One empty combination
/// for no list; none when a list is empty.
pub(crate) fn product<T: Clone>(lists: &[Vec<T>]) -> Vec<Vec<T>> {
    lists.iter().fold(vec![Vec::new()], |combinations, list| {
        combinations
            .iter()
            .flat_map(|prefix| {
                list.iter().map(move |item| {
                    let mut combination = prefix.clone();
                    combination.push(item.clone());
                    combination
                })
            })
            .collect()
    })
}
