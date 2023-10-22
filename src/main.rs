use std::fs::File;
use std::io::Write;

use anyhow::Result;
use clap::Parser;
use keepass::db::{Database, NodeRef};
use keepass::DatabaseKey;
use log::{debug, info, LevelFilter};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    kdbx: String,

    #[arg(short, long)]
    password: String,

    #[arg(short, long, default_value = ".env")]
    output: String,
}

fn main() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    let args = Args::parse();

    let mut db_file = File::open(args.kdbx)?;
    let mut output_file = File::create(args.output)?;
    let key = DatabaseKey::new().with_password(args.password.as_str());
    let db = Database::open(&mut db_file, key)?;

    for node in &db.root {
        match node {
            NodeRef::Group(g) => {
                info!("Ignoring group {}", g.name);
            }
            NodeRef::Entry(e) => {
                debug!("Writing {:?}", e.get_title());
                if let (Some(username), Some(password)) = (e.get_username(), e.get_password()) {
                    debug!("writing {}={} to file", username, password);
                    write!(output_file, "{}={}", username, password)?;
                } else {
                    info!("Username or password for {:?} not exist", e.get_title());
                }
            }
        }
    }

    Ok(())
}
