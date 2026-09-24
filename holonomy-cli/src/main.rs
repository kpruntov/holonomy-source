#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    holonomy_cli::cli::run_cli_with_args(std::env::args_os()).await;
}
