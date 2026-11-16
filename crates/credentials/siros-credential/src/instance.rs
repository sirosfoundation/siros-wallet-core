//! The instance used for a batch (C5).

use rustc_hash::{FxHashMap, FxHashSet};
use siros_wallet_state::{BatchId, CredentialId, InstanceId, PresentationRecord};

use crate::credential::{Credential, EntryRef};
use crate::usable::UsableCredential;

/// An instance of a batch: a credential with the entry it is read from.
pub trait Instance {
    /// The entry the instance is read from.
    fn entry(&self) -> EntryRef;
}

impl Instance for Credential {
    fn entry(&self) -> EntryRef {
        Credential::entry(self)
    }
}

impl Instance for UsableCredential<'_> {
    fn entry(&self) -> EntryRef {
        self.credential().entry()
    }
}

/// One instance per batch of `instances`: the one that the fewest `records` name, the lowest
/// `instanceId` on a tie. The batches keep the order of their first instance in `instances`.
pub fn least_used<'i, T: Instance>(
    instances: &'i [T],
    records: &[PresentationRecord],
) -> Vec<&'i T> {
    let mut uses: FxHashMap<CredentialId, usize> = FxHashMap::default();
    for record in records {
        let named: FxHashSet<CredentialId> = record.used_credential_ids().iter().copied().collect();
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
        match chosen.iter_mut().find(|(b, _)| *b == batch) {
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
