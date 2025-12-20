#[derive(clap::Parser)]
pub struct Args {
  #[arg(short, long)]
  pub host_addr: String,
  #[arg(short_alias = 'P', long, default_value_t = 51000)]
  pub host_port: u16,
  #[arg(short, long)]
  pub service_addr: String,
  #[arg(short_alias = 'p', long)]
  pub service_port: u16,
}