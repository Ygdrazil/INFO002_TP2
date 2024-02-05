use std::path::PathBuf;

use std::fs::File;
use std::io::{Read, Write};

use ::openssl::sign::{Signer, Verifier};
use anyhow::Result as AnyhowResult;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};

use image::{ImageBuffer, Rgba};
use imageproc::drawing::draw_text_mut;
use rusttype::{Font, Scale};

pub fn byte_to_binary(bytes: &[u8]) -> Vec<u8> {
    let mut binary_string: Vec<u8> = Vec::new();
    for byte in bytes {
        for i in (0..8).rev() {
            binary_string.push((byte >> i) & 1);
        }
    }

    binary_string
}

pub fn binary_to_bytes(bits: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit == 1 {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }
    bytes
}

pub fn hide_message_in_image(
    img: &mut ImageBuffer<image::Rgba<u8>, Vec<u8>>,
    hidden_message: &[u8],
) -> AnyhowResult<()> {
    let mut i = 0;
    let mut padding_started = false;
    for pixel in img.pixels_mut() {
        if i < hidden_message.len() {
            let msg = hidden_message[i];
            pixel[0] = (pixel[0] & 0b1111_1110) | (msg & 0b0000_0001);
            i += 1;
        } else {
            // Padding with zeros for the rest of the image
            if !padding_started {
                pixel[0] = (pixel[0] & 0b1111_1110) | 0b0000_0001;
                padding_started = true;
            } else {
                pixel[0] &= 0b1111_1110
            }
        }
    }

    Ok(())
}

pub fn read_message_in_image(img: &ImageBuffer<image::Rgba<u8>, Vec<u8>>) -> AnyhowResult<Vec<u8>> {
    let mut binary_chain = Vec::new();
    let mut padding_started = false;

    for pixel in img.pixels().rev() {
        let bit = pixel[0] & 0b0000_0001;
        if bit == 1 && !padding_started {
            padding_started = true;
            continue;
        }
        if padding_started {
            binary_chain.push(bit);
        }
    }

    binary_chain.reverse();

    Ok(binary_to_bytes(binary_chain))
}

pub fn generate_rsa_keys(nb_bytes: &u32) -> AnyhowResult<(Vec<u8>, Vec<u8>)> {
    let rsa = Rsa::generate(*nb_bytes * 8)?;
    let public_key: Vec<u8> = rsa.public_key_to_pem()?;
    let private_key: Vec<u8> = rsa.private_key_to_pem()?;

    let mut file = File::create("public_key.pem")?;
    file.write_all(&public_key)?;
    drop(file);

    let mut file = File::create(".private_key.pem")?;
    file.write_all(&private_key)?;
    drop(file);

    Ok((public_key, private_key))
}

pub fn get_rsa_key_from_file(path: &PathBuf) -> AnyhowResult<Vec<u8>> {
    let mut file = File::open(path)?;

    let mut key: Vec<u8> = Vec::new();

    file.read_to_end(&mut key)?;

    Ok(key)
}

pub fn sign_data(data_to_sign: &[u8], rsa_key: &[u8]) -> AnyhowResult<Vec<u8>> {
    let key = Rsa::private_key_from_pem(rsa_key)?;

    println!("Correctly loaded public key !");
    let key = PKey::from_rsa(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;

    // Initialize the signature vector with the correct size
    let mut signature: Vec<u8> = vec![0; key.size()];

    signer.sign_oneshot(&mut signature, data_to_sign)?;

    Ok(signature)
}

pub fn verify_data(data: &[u8], signature: &[u8], rsa_key: &[u8]) -> AnyhowResult<bool> {
    let key = PKey::from_rsa(Rsa::public_key_from_pem(rsa_key)?)?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
    verifier.update(data)?;
    Ok(verifier.verify(signature)?)
}

pub fn encrypt_message(data_to_encrypt: &[u8], rsa_key: &[u8]) -> AnyhowResult<Vec<u8>> {
    let mut encrypted_data: Vec<u8>;

    let key = Rsa::private_key_from_pem(rsa_key);

    match key {
        Ok(key) => {
            println!("Correctly loaded private key !");
            encrypted_data = vec![0; key.size() as usize];
            let _ = key.private_encrypt(data_to_encrypt, &mut encrypted_data, Padding::PKCS1);
        }
        Err(_) => {
            let key = Rsa::public_key_from_pem(rsa_key);

            match key {
                Ok(key) => {
                    println!("Correctly loaded public key !");
                    encrypted_data = vec![0; key.size() as usize];
                    let _ =
                        key.public_encrypt(data_to_encrypt, &mut encrypted_data, Padding::PKCS1);
                }
                Err(e) => return Err(anyhow::Error::new(e)),
            }
        }
    }

    Ok(encrypted_data)
}

pub fn decrypt_message(message_to_decrypt: &[u8], rsa_key: &[u8]) -> AnyhowResult<Vec<u8>> {
    let mut decrypted_data: Vec<u8>;

    let key = Rsa::private_key_from_pem(rsa_key);

    match key {
        Ok(key) => {
            println!("Correctly loaded private key !");
            decrypted_data = vec![0; key.size() as usize];
            let _ = key.private_decrypt(message_to_decrypt, &mut decrypted_data, Padding::PKCS1);
        }
        Err(_) => {
            let key = Rsa::public_key_from_pem(rsa_key);

            match key {
                Ok(key) => {
                    println!("Correctly loaded public key !");
                    decrypted_data = vec![0; key.size() as usize];
                    let _ =
                        key.public_decrypt(message_to_decrypt, &mut decrypted_data, Padding::PKCS1);
                }
                Err(e) => return Err(anyhow::Error::new(e)),
            }
        }
    }

    Ok(decrypted_data)
}

pub fn add_text(img: &mut ImageBuffer<Rgba<u8>, Vec<u8>>, text: &str, x: i32, y: i32, size: f32) {
    let font_data = include_bytes!("../sans.ttf"); // replace with your font file path
    let font = Font::try_from_bytes(font_data as &[u8]).unwrap();

    let scale = Scale { x: size, y: size };
    let color = Rgba([0, 0, 0, 255u8]);

    draw_text_mut(img, color, x, y, scale, &font, text);
}
