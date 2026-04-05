#[derive(clap::Parser)]
pub struct Args {
    pub host: Option<String>,
    pub service: Option<String>,
    #[arg(short, long)]
    pub username: Option<String>,
    #[arg(short, long)]
    pub password: Option<String>,
    #[arg(short, long)]
    pub token: Option<String>,
}
