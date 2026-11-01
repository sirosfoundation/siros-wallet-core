//! The identifiers and positions the plan, its view and the selection carry.

siros_codec::position!(
    /// The position of a Credential Query in the DCQL query's `credentials`.
    pub(crate) QueryIndex
);

siros_codec::position!(
    /// The position of a candidate among the candidates of its Credential Query.
    pub(crate) CandidateIndex
);

siros_codec::position!(
    /// The position of a credential set in the DCQL query's `credential_sets`.
    pub(crate) SetIndex
);

siros_codec::position!(
    /// The position of an option among the options of a `zkp_req` query.
    pub(crate) OptionIndex
);

siros_codec::position!(
    /// The position of an offer in the consent view.
    pub OfferIndex
);

siros_codec::position!(
    /// The position of an addition among the additions of an offer in the consent view.
    pub AdditionIndex
);
