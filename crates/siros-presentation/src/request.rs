//! The request as the matching reads it: the wallet's verified request, or the credential
//! picker's unverified one (P2).

use serde_json::Value;
use siros_dcql::DcqlQuery;
use siros_oid4vp::{RequestSignature, TransactionDataItem, UnverifiedRequest};
use siros_transaction_data::Channel;

/// What the matching reads of a request: its DCQL query, the Verifier metadata, its
/// `transaction_data` entries, whether it arrived signed, and how it reached the wallet.
pub trait MatchRequest {
    /// `dcql_query`.
    fn dcql_query(&self) -> &DcqlQuery;

    /// The Verifier metadata, which lists the systems a `zkp_req` query accepts.
    fn client_metadata(&self) -> Option<&Value>;

    /// The `transaction_data` strings as received; empty when the request has none.
    fn transaction_data(&self) -> &[TransactionDataItem];

    /// Whether the request arrived signed.
    fn signature(&self) -> RequestSignature;

    /// How the request reached the wallet, which sets the images transaction data admits.
    fn channel(&self) -> Channel;
}

/// The credential picker's request, whose signature intake verifies at selection.
impl MatchRequest for UnverifiedRequest {
    fn dcql_query(&self) -> &DcqlQuery {
        self.query()
    }

    fn client_metadata(&self) -> Option<&Value> {
        UnverifiedRequest::client_metadata(self)
    }

    fn transaction_data(&self) -> &[TransactionDataItem] {
        UnverifiedRequest::transaction_data(self)
    }

    fn signature(&self) -> RequestSignature {
        UnverifiedRequest::signature(self)
    }

    /// The credential picker reads a request of the Digital Credentials API alone.
    fn channel(&self) -> Channel {
        Channel::DcApi
    }
}

/// The wallet's request, which intake verified.
#[cfg(feature = "wallet")]
impl MatchRequest for siros_oid4vp::VerifiedRequest {
    fn dcql_query(&self) -> &DcqlQuery {
        siros_oid4vp::VerifiedRequest::dcql_query(self)
    }

    fn client_metadata(&self) -> Option<&Value> {
        siros_oid4vp::VerifiedRequest::client_metadata(self)
    }

    fn transaction_data(&self) -> &[TransactionDataItem] {
        siros_oid4vp::VerifiedRequest::transaction_data(self)
    }

    fn signature(&self) -> RequestSignature {
        siros_oid4vp::VerifiedRequest::signature(self)
    }

    fn channel(&self) -> Channel {
        match self.dc_api_protocol() {
            Some(_) => Channel::DcApi,
            None => Channel::Redirect,
        }
    }
}
