use crate::{new_rpc_client, Command, Result};

pub struct Version;

impl Command for Version {
    fn name(&self) -> &'static str {
        "version"
    }

    fn clap_subcommand(&self) -> clap::App<'static, 'static> {
        clap::SubCommand::with_name(self.name())
            .about("Shows current version, and the currently supported versions")
    }

    fn run(&self, _: &clap::ArgMatches<'_>) -> Result<()> {
        let mut rpc = new_rpc_client()?;
        let current_version = rpc.get_current_version()?;
        println!("Current version: {}", current_version);
        let version_info = rpc.get_version_info()?;
        println!("\tIs supported: {}", version_info.current_is_supported);
        println!("\tIs up to date: {}", !version_info.current_is_outdated);
        if version_info.latest_stable != version_info.latest {
            println!(
                "Latest version: {} (latest stable: {})",
                version_info.latest, version_info.latest_stable
            );
        } else {
            println!("Latest version: {}", version_info.latest_stable);
        }
        Ok(())
    }
}
