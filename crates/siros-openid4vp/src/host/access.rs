//! How a plug-in reaches a host's modules, after axum's `State` and `FromRef`: [`Has`] for a
//! module the plug-in requires, [`MayHave`] for one it uses when the build holds it.

/// The host holds module `M`: a required provider (axum: `M: FromRef<S>`).
///
/// # Implementing
///
/// A build's host struct implements `Has<dyn M>` for each module it holds and [`MayHave<dyn M>`]
/// for each optional module, held or lacking; `siros_testkit::test_host!` writes both. A
/// registration bounds the modules it calls, so a host lacking a required module does not
/// compile with it. The presence of a module is the slot's type ([`Slot`]), sealed: no host
/// changes it while running. siros-integration's builds implement it.
pub trait Has<M: ?Sized> {
    /// The module.
    fn module(&self) -> &M;
}

/// Whether the build holds module `M`, settled by the slot's type: an optional provider.
pub trait MayHave<M: ?Sized> {
    /// [`Held`] or [`Empty`].
    type Slot: Slot<M>;
    /// The slot.
    fn slot(&self) -> &Self::Slot;
}

/// A module slot a build fills ([`Held`]) or leaves empty ([`Empty`]). Sealed: presence is a
/// property of the host's type, which no host changes while running. A host type cannot make a
/// slot of its own:
///
/// ```compile_fail,E0277
/// use siros_openid4vp::host::{Haip, Slot};
///
/// struct Forged;
///
/// impl Slot<dyn Haip> for Forged {
///     const HELD: bool = true;
///
///     fn filled(&self) -> Option<&(dyn Haip + 'static)> {
///         None
///     }
/// }
/// ```
pub trait Slot<M: ?Sized>: sealed::Sealed {
    /// Whether the slot holds the module.
    const HELD: bool;
    /// The module, when the slot holds it.
    fn filled(&self) -> Option<&M>;
}

/// A filled slot: the module, given as `&'static`.
pub struct Held<M: ?Sized + 'static>(&'static M);

impl<M: ?Sized + 'static> Held<M> {
    /// The slot holding the module.
    #[must_use]
    pub const fn new(module: &'static M) -> Self {
        Self(module)
    }
}

/// An empty slot.
pub struct Empty;

mod sealed {
    pub trait Sealed {}
    impl<M: ?Sized + 'static> Sealed for super::Held<M> {}
    impl Sealed for super::Empty {}
}

impl<M: ?Sized + 'static> Slot<M> for Held<M> {
    const HELD: bool = true;

    fn filled(&self) -> Option<&M> {
        Some(self.0)
    }
}

impl<M: ?Sized> Slot<M> for Empty {
    const HELD: bool = false;

    fn filled(&self) -> Option<&M> {
        None
    }
}

/// `host.get::<dyn Haip>()` for a required module, `host.maybe::<dyn RequestDecryption>()` for one
/// the build may hold.
pub trait Host {
    /// The module the host holds.
    fn get<M: ?Sized>(&self) -> &M
    where
        Self: Has<M>,
    {
        Has::<M>::module(self)
    }

    /// The module, when the build holds it.
    fn maybe<M: ?Sized>(&self) -> Option<&M>
    where
        Self: MayHave<M>,
    {
        MayHave::<M>::slot(self).filled()
    }
}

impl<H> Host for H {}
