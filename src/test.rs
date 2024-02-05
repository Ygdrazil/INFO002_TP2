use crate::helpers;

use crate::cli::*;

use std::path::PathBuf;

use anyhow::Result as AnyhowResult;
use image::io::Reader as ImageReader;

use base64::{engine::general_purpose, Engine as _};

pub fn handle_tests(sub_commads: TestSubCommands) {
    match sub_commads {
        TestSubCommands::StegWrite {
            source,
            target,
            hidden_message,
        } => {
            test_steg_write(&source, &target, &hidden_message).unwrap_or_else(|e| {
                eprintln!("Error {}", e);
            });
        }
        TestSubCommands::StegRead { source } => {
            test_steg_read(&source).unwrap_or_else(|e| {
                eprintln!("Error {}", e);
            });
        }
        TestSubCommands::GenerateRSAKeys { nb_bytes } => {
            test_rsa_generation(&nb_bytes).unwrap_or_else(|e| {
                eprintln!("Error {}", e);
            });
        }
        TestSubCommands::EncryptMessage {
            message_to_encrypt,
            rsa_key,
            pem_file,
        } => {
            test_encryption(&message_to_encrypt, &rsa_key, &pem_file).unwrap_or_else(|e| {
                eprintln!("Error {}", e);
            });
        }
        TestSubCommands::DecryptMessage {
            message_to_decrypt,
            rsa_key,
            pem_file,
        } => test_decryption(&message_to_decrypt, &rsa_key, &pem_file).unwrap_or_else(|e| {
            eprintln!("Error {}", e);
        }),
        TestSubCommands::SignMessage {
            message_to_sign,
            rsa_key,
            pem_file,
        } => test_sign(&message_to_sign, &rsa_key, &pem_file).unwrap_or_else(|e| {
            eprintln!("Error {}", e);
        }),
        TestSubCommands::VerifyMessage {
            message_to_verify,
            signature,
            rsa_key,
            pem_file,
        } => test_verify_message(&message_to_verify, &signature, &rsa_key, &pem_file)
            .unwrap_or_else(|e| {
                eprintln!("Error {}", e);
            }),
        TestSubCommands::WriteTextImage {
            source,
            target,
            message,
        } => test_write_text(&source, &target, &message).unwrap_or_else(|e| {
            eprintln!("Error {}", e);
        }),
    }
}

fn test_steg_write(source: &PathBuf, target: &PathBuf, hidden_message: &str) -> AnyhowResult<()> {
    let mut img = ImageReader::open(source)?.decode()?.to_rgba8();

    let binary = helpers::byte_to_binary(hidden_message.as_bytes());

    helpers::hide_message_in_image(&mut img, &binary)?;

    img.save(target)?;

    Ok(())
}

fn test_steg_read(source: &PathBuf) -> AnyhowResult<()> {
    let img = ImageReader::open(source)?.decode()?.to_rgba8();

    let decoded_data = helpers::read_message_in_image(&img)?;
    for word in decoded_data.iter() {
        print!("{}", *word as char);
    }

    Ok(())
}

fn test_rsa_generation(nb_bytes: &u32) -> AnyhowResult<()> {
    let rsa_keys = helpers::generate_rsa_keys(nb_bytes)?;

    print!("Public key : \n\n{}", String::from_utf8(rsa_keys.0)?);
    print!("Private key : \n\n{}", String::from_utf8(rsa_keys.1)?);

    Ok(())
}

fn test_sign(
    message_to_sign: &str,
    rsa_key: &Option<String>,
    pem_file: &Option<PathBuf>,
) -> AnyhowResult<()> {
    let b_rsa_key = match pem_file {
        None => rsa_key.as_ref().unwrap().clone().as_bytes().to_vec(),
        Some(path) => helpers::get_rsa_key_from_file(path)?,
    };

    let signature = helpers::sign_data(message_to_sign.as_bytes(), &b_rsa_key);

    match signature {
        Err(e) => eprintln!("Error {}", e),
        Ok(data) => {
            let base64_data = general_purpose::STANDARD.encode(data);
            println!("{}", base64_data);
        }
    }

    Ok(())
}

fn test_verify_message(
    message_to_verify: &str,
    signature: &str,
    rsa_key: &Option<String>,
    pem_file: &Option<PathBuf>,
) -> AnyhowResult<()> {
    let b_rsa_key = match pem_file {
        None => rsa_key.as_ref().unwrap().clone().as_bytes().to_vec(),
        Some(path) => helpers::get_rsa_key_from_file(path)?,
    };

    let signature = general_purpose::STANDARD.decode(signature)?;

    let verification = helpers::verify_data(message_to_verify.as_bytes(), &signature, &b_rsa_key);

    match verification {
        Err(e) => eprintln!("Error {}", e),
        Ok(data) => {
            println!("{}", data);
        }
    }

    Ok(())
}

fn test_encryption(
    message_to_encrypt: &str,
    rsa_key: &Option<String>,
    pem_file: &Option<PathBuf>,
) -> AnyhowResult<()> {
    let b_rsa_key = match pem_file {
        None => rsa_key.as_ref().unwrap().clone().as_bytes().to_vec(),
        Some(path) => helpers::get_rsa_key_from_file(path)?,
    };

    let encrypted_data = helpers::encrypt_message(message_to_encrypt.as_bytes(), &b_rsa_key);

    match encrypted_data {
        Err(e) => eprintln!("Error {}", e),
        Ok(data) => {
            let base64_data = general_purpose::STANDARD.encode(data);
            println!("{}", base64_data);
        }
    }

    Ok(())
}

fn test_decryption(
    message_to_decrypt: &str,
    rsa_key: &Option<String>,
    pem_file: &Option<PathBuf>,
) -> AnyhowResult<()> {
    let b_rsa_key = match pem_file {
        None => rsa_key.as_ref().unwrap().clone().as_bytes().to_vec(),
        Some(path) => helpers::get_rsa_key_from_file(path)?,
    };

    let encrypted_data = general_purpose::STANDARD.decode(message_to_decrypt)?;

    let decrypted_data = helpers::decrypt_message(&encrypted_data, &b_rsa_key);

    match decrypted_data {
        Err(e) => eprintln!("Error {}", e),
        Ok(data) => {
            println!("{}", String::from_utf8(data)?);
        }
    }

    Ok(())
}

fn test_write_text(source: &PathBuf, target: &PathBuf, message: &str) -> AnyhowResult<()> {
    let mut img = ImageReader::open(source)?.decode()?.to_rgba8();

    helpers::add_text(&mut img, message, 0, 0, 72.0);

    img.save(target)?;
    Ok(())
}
