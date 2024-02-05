use clap::{ArgGroup, Args, Parser, Subcommand, ValueHint};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[clap(subcommand)]
    pub commands: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Test(TestCli),
    #[clap(group = ArgGroup::new("key").required(true).multiple(false))]
    CreateDegree {
        student_name: String,
        note: u32,
        #[clap(long, short = 'k', help = "The RSA key you want to use", group = "key")]
        rsa_key: Option<String>,

        #[clap(long="file", short='f', value_hint = ValueHint::FilePath, help = "The .pem file of the RSA key you want to use", group = "key")]
        pem_file: Option<PathBuf>,
    },
    #[clap(group = ArgGroup::new("key").required(true).multiple(false))]
    ReadDegree {
        image: PathBuf,
        #[clap(long, short = 'k', help = "The RSA key you want to use", group = "key")]
        rsa_key: Option<String>,

        #[clap(long="file", short='f', value_hint = ValueHint::FilePath, help = "The .pem file of the RSA key you want to use", group = "key")]
        pem_file: Option<PathBuf>,
    },
}

#[derive(Args)]
pub struct TestCli {
    #[command(subcommand)]
    pub sub_cmds: TestSubCommands,
}

#[derive(Subcommand)]
pub enum TestSubCommands {
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
    },
    GenerateRSAKeys {
        #[clap(
            help = "The number of bytes your keys size will be",
            default_value = "256"
        )]
        nb_bytes: u32,
    },
    #[clap(group = ArgGroup::new("key").required(true).multiple(false))]
    EncryptMessage {
        #[clap(help = "The message to encrypt", required = true)]
        message_to_encrypt: String,

        #[clap(long, short = 'k', help = "The RSA key you want to use", group = "key")]
        rsa_key: Option<String>,

        #[clap(long="file", short='f', value_hint = ValueHint::FilePath, help = "The .pem file of the RSA key you want to use", group = "key")]
        pem_file: Option<PathBuf>,
    },
    #[clap(group = ArgGroup::new("key").required(true).multiple(false))]
    DecryptMessage {
        #[clap(help = "The message to decrypt", required = true)]
        message_to_decrypt: String,

        #[clap(long, short = 'k', help = "The RSA key you want to use", group = "key")]
        rsa_key: Option<String>,

        #[clap(long="file", short='f', value_hint = ValueHint::FilePath, help = "The .pem file of the RSA key you want to use", group = "key")]
        pem_file: Option<PathBuf>,
    },
    #[clap(group = ArgGroup::new("key").required(true).multiple(false))]
    SignMessage {
        #[clap(help = "The message to sign", required = true)]
        message_to_sign: String,

        #[clap(long, short = 'k', help = "The RSA key you want to use", group = "key")]
        rsa_key: Option<String>,

        #[clap(long="file", short='f', value_hint = ValueHint::FilePath, help = "The .pem file of the RSA key you want to use", group = "key")]
        pem_file: Option<PathBuf>,
    },
    #[clap(group = ArgGroup::new("key").required(true).multiple(false))]
    VerifyMessage {
        #[clap(help = "The message to verify", required = true)]
        message_to_verify: String,

        #[clap(help = "The signature", required = true)]
        signature: String,

        #[clap(long, short = 'k', help = "The RSA key you want to use", group = "key")]
        rsa_key: Option<String>,

        #[clap(long="file", short='f', value_hint = ValueHint::FilePath, help = "The .pem file of the RSA key you want to use", group = "key")]
        pem_file: Option<PathBuf>,
    },
    WriteTextImage {
        #[clap(value_hint = ValueHint::FilePath, help = "The path to your source image", required = true)]
        source: PathBuf,

        #[clap(value_hint = ValueHint::FilePath, help = "The path to your target image", required = true)]
        target: PathBuf,

        #[clap(help = "The string you want to write on your image", required = true)]
        message: String,
    },
}
