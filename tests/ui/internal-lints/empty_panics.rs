//@ compile-flags: -Z unstable-options

#![feature(rustc_private)]
#![forbid(rustc::empty_panics)]

fn main() {
    panic!()
    //~^ ERROR empty `panic!()`s do not provide any contextual information for debugging, please add some context or explanation
}

