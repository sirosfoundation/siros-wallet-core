//! The instance of a batch a presentation uses (C5).

use rustc_hash::{FxHashMap, FxHashSet};

use crate::entry::CredentialEntry;
use crate::ids::{BatchId, CredentialId, InstanceId};
use crate::state::WalletState;

/// An instance of a batch: a value read from a credential entry, such as a wallet's usable
/// credential.
pub trait Instance {
    /// The entry the instance is read from.
    fn entry(&self) -> &CredentialEntry;
}

impl Instance for CredentialEntry {
    fn entry(&self) -> &CredentialEntry {
        self
    }
}

impl Instance for &CredentialEntry {
    fn entry(&self) -> &CredentialEntry {
        self
    }
}

impl WalletState {
    /// One instance per batch of `instances`: the one that the fewest of the state's presentation
    /// records name, the lowest `instanceId` on a tie. The batches keep the order of their first
    /// instance in `instances`.
    pub fn least_used<'i, T: Instance>(&self, instances: &'i [T]) -> Vec<&'i T> {
        let mut uses: FxHashMap<CredentialId, usize> = FxHashMap::default();
        for record in self.presentations() {
            let named: FxHashSet<CredentialId> =
                record.used_credential_ids().iter().copied().collect();
            for id in named {
                *uses.entry(id).or_insert(0) += 1;
            }
        }
        let rank = |instance: &T| -> (usize, InstanceId) {
            let entry = instance.entry();
            let named = uses.get(&entry.credential_id()).copied().unwrap_or(0);
            (named, entry.instance_id())
        };
        let mut chosen: Vec<(BatchId, &'i T)> = Vec::new();
        for instance in instances {
            let batch = instance.entry().batch_id();
            match chosen.iter_mut().find(|(earlier, _)| *earlier == batch) {
                Some((_, best)) => {
                    if rank(instance) < rank(best) {
                        *best = instance;
                    }
                }
                None => chosen.push((batch, instance)),
            }
        }
        chosen.into_iter().map(|(_, instance)| instance).collect()
    }
}
