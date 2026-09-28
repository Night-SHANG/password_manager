fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();

    password_manager::app::run()
}
