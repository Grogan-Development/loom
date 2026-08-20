//! Fail-closed Git pre-receive hook that admits trees into Loom CAS.

fn main() {
    if let Err(error) = loom::git::run_pre_receive_hook() {
        eprintln!("loom: {error}");
        std::process::exit(1);
    }
}
