//! The https resources a test publishes, which answer the fetches phase 2 asks for.

use siros_openid4vp::effects::{Fetch, MediaType, Resource};
use siros_openid4vp::rows::HttpsUrl;

/// A resource a test publishes: what a GET of its URL returns.
#[derive(Debug, Clone)]
pub struct PublishedResource {
    /// The URL.
    pub url: HttpsUrl,
    /// The content.
    pub content: Vec<u8>,
    /// Its `Content-Type`.
    pub media: MediaType,
}

/// The resources a test publishes; a URL published twice answers with the first.
#[derive(Debug, Clone, Default)]
pub struct Published(Vec<PublishedResource>);

impl Published {
    /// These resources, in order.
    #[must_use]
    pub fn new(resources: Vec<PublishedResource>) -> Self {
        Self(resources)
    }

    /// The fetch of a resource phase 2 asks for: the first resource published at its URL, or a
    /// failed fetch when none is.
    #[must_use]
    pub fn answer(&self, resource: &Resource) -> Fetch {
        self.0
            .iter()
            .find(|published| published.url == *resource.url())
            .map_or(Fetch::Unfetched, |published| Fetch::Fetched {
                content: published.content.clone(),
                media: published.media.clone(),
            })
    }
}
