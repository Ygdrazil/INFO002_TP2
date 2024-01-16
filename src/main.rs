use std::io::Write;
use std::path::PathBuf;
use openssl::rsa::Rsa;

use std::fs::File;

use clap::{Parser, Subcommand, ValueHint, Args};
use image::io::Reader as ImageReader;
use image::ImageResult;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Test(TestCli),
}

#[derive(Args)]
struct TestCli {
    #[command(subcommand)]
    sub_cmds: TestSubCommands,
}

#[derive(Subcommand)]
enum TestSubCommands {
    StegWrite {
        #[clap(value_hint = ValueHint::FilePath, help = "The path to your source image", required = true)]
        source: PathBuf,

        #[clap(value_hint = ValueHint::FilePath, help = "The path to your target image", required = true)]
        target: PathBuf,

        #[clap(
            help = "The string you want to hide in your source image",
            required = true
        )]
        hidden_message: String,
    },
    StegRead {
        #[clap(value_hint = ValueHint::FilePath, help = "The path to the image you want to read", required = true)]
        source: PathBuf,

        #[clap(help = "The number of bytes the message", required = true)]
        nb_bytes: u16,
    },
    GenerateRSAKeys {
        #[clap(help = "The number of bytes your keys size will be", default_value = "256")]
        nb_bytes: u32,
    },
    EncryptMessage {
        #[clap(help = "The message to encrypt", required = true)]
        message_to_encrypt: String,

        #[clap(long, short='k', help = "The RSA key you want to use")]
        rsa_key: Option<String>,

        #[clap(long="file", short='f', value_hint = ValueHint::FilePath, help = "The .pem file of the RSA key you want to use")]
        pem_file: Option<PathBuf>,
    }
}

fn str_to_binary(string_to_convert: &String) -> Vec<u8> {
    let mut binary_string: Vec<u8> = Vec::new();
    for byte in string_to_convert.as_bytes() {
        for i in (0..8).rev() {
            binary_string.push((byte >> i) & 1);
        }
    }

    return binary_string;
}

fn hide_message_in_image(source: &PathBuf, target: &PathBuf, hidden_message: &String) -> ImageResult<()> {
    let mut img = ImageReader::open(source)?.decode()?.to_rgb8();

    let binary = str_to_binary(hidden_message);

    for i in 0..binary.len() {
        let x = i as u32 % img.width();
        let y = i as u32 / img.width();


        println!("Writing {} on x:{} y:{}", binary.get(i).unwrap(), x, y);
        let pixel = img.get_pixel_mut(x, y);
        pixel[0] = (pixel[0] & 0b1111_1110) | binary.get(i).unwrap();
    }

    img.save(target)?;

    return Ok(());
}

fn read_message_in_image(source: &PathBuf, nb_bytes: &u16) -> ImageResult<()> {
    let img = ImageReader::open(source)?.decode()?.to_rgb8();

    let mut binary_chain: Vec<u8> = Vec::new();

    for i in 0..(nb_bytes * 8) {
        let x = i as u32 % img.width();
        let y = i as u32 / img.width();
        binary_chain.push(img.get_pixel(x, y)[0] & 1);
    }

    for i in 0..binary_chain.len() {
        print!("{}", binary_chain.get(i).unwrap());
    }

    return Ok(());
}

fn generate_rsa_keys(nb_bytes: &u32) {
    let rsa = Rsa::generate(*nb_bytes * 8).unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();
    let private_key: Vec<u8> = rsa.private_key_to_pem().unwrap();

    print!("Public key :\n\n{}", String::from_utf8(public_key.clone()).unwrap());
    let mut file = File::create("public_key.pem").unwrap();
    file.write_all(&public_key).unwrap();
    drop(file);

    print!("\n\nPrivate key :\n\n{}", String::from_utf8(private_key.clone()).unwrap());
    let mut file = File::create(".private_key.pem").unwrap();
    file.write_all(&private_key).unwrap();
    drop(file);
}

fn encrypt_message(message_to_encrypt: &String, rsa_key: &Option<String>, pem_file: &Option<PathBuf>) {
    // TODO
}

fn main() {
    let cli = Cli::parse();

    match cli.commands {
        Commands::Test(test) => {
            let test_cmd = test.sub_cmds;

            match test_cmd {
                TestSubCommands::StegWrite { source, target, hidden_message } => {
                    hide_message_in_image(&source, &target, &hidden_message).unwrap_or_else(|e| {eprintln!("Error {}", e);});
                },
                TestSubCommands::StegRead { source, nb_bytes } => {
                    read_message_in_image(&source, &nb_bytes).unwrap_or_else(|e| {eprintln!("Error {}", e);});
                },
                TestSubCommands::GenerateRSAKeys { nb_bytes } => {
                    generate_rsa_keys(&nb_bytes);
                },
                TestSubCommands::EncryptMessage { message_to_encrypt, rsa_key, pem_file } => {
                    encrypt_message(&message_to_encrypt, &rsa_key, &pem_file);
                }
            }
        }
    }
}
