fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();

    if std::env::args_os().any(|argument| argument == "--self-test") {
        match password_manager::smoke::run_release_smoke() {
            Ok(()) => {
                println!("release_smoke=ok");
                return;
            }
            Err(error) => {
                eprintln!("release_smoke=failed: {error}");
                std::process::exit(1);
            }
        }
    }

    if let Err(error) = password_manager::app::run() {
        eprintln!("application_error={error}");
        std::process::exit(1);
    }
}
