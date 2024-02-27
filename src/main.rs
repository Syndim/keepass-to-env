use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::process::Command;

use anyhow::{anyhow, Result};
use clap::Parser;
use keepass::db::{Database, Group, Node, NodeRef};
use keepass::DatabaseKey;
use log::{debug, info, LevelFilter};

#[derive(Parser)]
struct Args {
    #[arg(short, long, help = "Path to the Keepass database")]
    kdbx: String,

    #[arg(short, long, help = "Root path of the environment variables")]
    root: Option<String>,

    #[arg(short, long, help = "Password of the Keepass database")]
    password: Option<String>,

    #[arg(
        short,
        long,
        help = "Path to the output .env file, if not provided, a child shell will start with the environment variables"
    )]
    output: Option<String>,

    #[arg(short, long, help = "Shell to start")]
    shell: Option<String>,
}

struct ShellTarget {
    pub shell: String,
    pub env: HashMap<String, String>,
}

enum EnvTarget {
    File(File),
    Shell(ShellTarget),
}

fn write_env(target: &mut EnvTarget, key: &str, value: &str) -> Result<()> {
    match target {
        EnvTarget::File(ref mut file) => {
            write!(file, "{}={}\n", key, value)?;
        }
        EnvTarget::Shell(ref mut s) => {
            s.env.insert(key.to_string(), value.to_string());
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
        EnvTarget::Shell(s) => {
            let mut cmd = Command::new(s.shell);
            for (key, value) in s.env.into_iter() {
                cmd.env(key, value);
            }

            let mut child = cmd.spawn()?;
            let _ = child.wait()?;
        }
    }

    Ok(())
}

fn search_env<'a, T>(group: &Group, env_target: &mut EnvTarget, path: &mut T) -> Result<()>
where
    T: Iterator<Item = &'a String>,
{
    let next_group = path.next();
    for node in group.children.iter() {
        match node {
            Node::Group(g) => {
                if let Some(group) = next_group {
                    if group == &g.name {
                        search_env(g, env_target, path)?;
                    }
                } else {
                    info!("Ignoring group {}", g.name);
                }
            }
            Node::Entry(e) => {
                debug!("Writing {:?}", e.get_title());
                if let (Some(username), Some(password)) = (e.get_username(), e.get_password()) {
                    debug!("writing {}={} to target", username, password);
                    write_env(env_target, username, password)?;
                } else {
                    info!("Username or password for {:?} not exist", e.get_title());
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Warn).init();
    let args = Args::parse();

    if args.output.is_none() && args.shell.is_none() {
        const MSG: &str = "Either output file or shell should be specified";
        return Err(anyhow!(MSG));
    }

    if let Some(ref output) = args.output {
        info!("Converting items from {} to {}", args.kdbx, output);
    } else {
        info!("Loading items from {} into shell env", args.kdbx);
    }

    let mut db_file = File::open(args.kdbx)?;
    let password = if let Some(pwd) = args.password {
        pwd
    } else {
        let pwd = rpassword::prompt_password("Password:")?;
        pwd
    };

    let key = DatabaseKey::new().with_password(password.as_str());
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
        EnvTarget::Shell(ShellTarget {
            shell: args.shell.unwrap(),
            env: HashMap::new(),
        })
    };

    let path = if let Some(root) = args.root {
        root.split("/")
            .map(|s| s.to_string())
            .collect::<Vec<String>>()
    } else {
        vec![]
    };

    search_env(root_group, &mut env_target, &mut path.iter())?;

    info!("Finished");
    save_env(env_target)?;

    Ok(())
}
