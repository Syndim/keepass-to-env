use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::process::Command;

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

    #[arg(short, long)]
    output: Option<String>,
}

enum EnvTarget {
    File(File),
    Env(HashMap<String, String>),
}

fn write_env(target: &mut EnvTarget, key: &str, value: &str) -> Result<()> {
    match target {
        EnvTarget::File(ref mut file) => {
            write!(file, "{}={}\n", key, value)?;
        }
        EnvTarget::Env(ref mut map) => {
            map.insert(key.to_string(), value.to_string());
        }
    }

    Ok(())
}

fn save_env(target: EnvTarget) -> Result<()> {
    match target {
        EnvTarget::File(mut file) => {
            file.flush()?;
            drop(file);
        }
        EnvTarget::Env(map) => {
            let mut cmd = Command::new("fish");
            for (key, value) in map.into_iter() {
                cmd.env(key, value);
            }

            let mut child = cmd.spawn()?;
            let _ = child.wait()?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    let args = Args::parse();

    if let Some(ref output) = args.output {
        info!("Converting items from {} to {}", args.kdbx, output);
    } else {
        info!("Loading items from {} into shell env", args.kdbx);
    }

    let mut db_file = File::open(args.kdbx)?;
    let key = DatabaseKey::new().with_password(args.password.as_str());
    info!("Opening database");
    let db = Database::open(&mut db_file, key)?;
    info!("Database opened");

    let Some(NodeRef::Group(ref root_group)) = db.root.iter().next() else {
        info!("No root group found");
        return Ok(());
    };

    let mut env_target = if let Some(output) = args.output {
        EnvTarget::File(File::create(output)?)
    } else {
        EnvTarget::Env(HashMap::new())
    };

    for node in root_group.children.iter() {
        match node {
            Node::Group(g) => {
                info!("Ignoring group {}", g.name);
            }
            Node::Entry(e) => {
                debug!("Writing {:?}", e.get_title());
                if let (Some(username), Some(password)) = (e.get_username(), e.get_password()) {
                    debug!("writing {}={} to target", username, password);
                    write_env(&mut env_target, username, password)?;
                } else {
                    info!("Username or password for {:?} not exist", e.get_title());
                }
            }
        }
    }

    info!("Finished");
    save_env(env_target)?;

    Ok(())
}
