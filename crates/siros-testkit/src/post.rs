//! The doubles of the `request_uri` POST's contributions and of the Response URI answer's readers.

use siros_explain::Explained;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::uri::{AnswerMembers, AnswerReader};
use siros_openid4vp::wallet_metadata::{
    ParameterName, PostContent, PostContribution, PostContributionHost,
};

/// A POST contribution that declares the names given and writes the content given, which may
/// name what it did not declare.
#[derive(Debug, Clone)]
pub struct TestPostContribution {
    /// The `wallet_metadata` members it declares.
    pub members: &'static [ParameterName],
    /// The POST parameters it declares.
    pub parameters: &'static [ParameterName],
    /// What it writes into each POST.
    pub content: PostContent,
}

impl PostContribution for TestPostContribution {
    fn members(&self) -> &'static [ParameterName] {
        self.members
    }

    fn parameters(&self) -> &'static [ParameterName] {
        self.parameters
    }
}

impl<H> PostContributionHost<H> for TestPostContribution {
    fn write(&self, _host: &H) -> Result<PostContent, Fault> {
        Ok(self.content.clone())
    }
}

/// A reader of the Response URI's answer that declares the names given and reads no outcome.
#[derive(Debug, Clone, Copy)]
pub struct TestAnswerReader(pub &'static [ParameterName]);

impl AnswerReader for TestAnswerReader {
    fn names(&self) -> &'static [ParameterName] {
        self.0
    }

    fn read(
        &self,
        _members: &AnswerMembers<'_>,
    ) -> Result<Option<Box<dyn Explained>>, Box<dyn Explained>> {
        Ok(None)
    }
}
