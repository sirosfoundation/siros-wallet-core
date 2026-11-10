//! A type's metadata as MessageFormat 2 resource source: the wallet converts it at registration as
//! it does PaSO's, under TS12's label limits.

use siros_i18n::{Context, LocaleTag};
use siros_openid4vp::json::Node;
use siros_paso::render::Registered;
use siros_paso::view::ConvertError;

use crate::LIMITS;
use crate::document::BuiltInEntry;
use crate::translate::paso_metadata;

/// The type's display rules translated into PaSO's model and converted by
/// [`siros_paso::view::convert`]: a resource in the context's locale for the End-User's priority
/// list, checked to load into the context.
///
/// # Errors
///
/// [`ConvertError`]: the engine refuses the translation, the context holds no module, or the
/// source does not load into the context.
pub fn convert(
    entry: &BuiltInEntry<'_>,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<String, ConvertError> {
    let metadata = Node::Object(paso_metadata(entry));
    let registered = Registered::of(entry.kind().paso_type(), &metadata);
    siros_paso::view::convert(&registered, LIMITS, context, priority)
}
