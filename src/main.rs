use std::fs::File;
use std::io::Write;

use anyhow::Result;
use clap::Parser;
use keepass::db::{Database, Node, NodeRef};
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

    info!("Converting items from {} to {}", args.kdbx, args.output);
    let mut db_file = File::open(args.kdbx)?;
    let mut output_file = File::create(args.output)?;
    let key = DatabaseKey::new().with_password(args.password.as_str());
    info!("Opening database");
    let db = Database::open(&mut db_file, key)?;
    info!("Database opened");

    let Some(NodeRef::Group(ref root_group)) = db.root.iter().next() else {
        info!("No root group found");
        return Ok(());
    };

    for node in root_group.children.iter() {
        match node {
            Node::Group(g) => {
                info!("Ignoring group {}", g.name);
            }
            Node::Entry(e) => {
                debug!("Writing {:?}", e.get_title());
                if let (Some(username), Some(password)) = (e.get_username(), e.get_password()) {
                    debug!("writing {}={} to file", username, password);
                    write!(output_file, "{}={}\n", username, password)?;
                } else {
                    info!("Username or password for {:?} not exist", e.get_title());
                }
            }
        }
    }

    info!("Finished");
    Ok(())
}
