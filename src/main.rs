use clap::Parser;

mod cli;
mod helpers;
mod test;

fn main() {
    let cli = cli::Cli::parse();

    match cli.commands {
        cli::Commands::Test(test) => test::handle_tests(test.sub_cmds),
    }
}
