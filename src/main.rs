use clap::Parser;

mod cli;
mod create_degree;
mod helpers;
mod test;

fn main() {
    let cli = cli::Cli::parse();

    match cli.commands {
        cli::Commands::Test(test) => test::handle_tests(test.sub_cmds),
        cli::Commands::CreateDegree {
            student_name,
            note,
            rsa_key,
            pem_file,
        } => create_degree::create_degree(&student_name, &note, &rsa_key, &pem_file).unwrap(),
        cli::Commands::ReadDegree {
            image,
            rsa_key,
            pem_file,
        } => create_degree::read_degree(&image, &rsa_key, &pem_file).unwrap(),
    }
}
