// https://github.com/rust-lang/rust/issues/38219

// compile-flags:--test

/// ```
/// fail
/// ```
#[macro_export]
macro_rules! foo { () => {} }
