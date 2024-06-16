use run_make_support::{cmd, rustc};

fn main() {
    rustc().opt_level("3").emit("obj").input("used.rs").run();
    cmd("nm").arg("used.o").run().assert_stdout_contains("FOO");
}
