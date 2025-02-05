use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};
use anyhow::Context;
use rand::RngCore;

// Password entry structure
#[derive(Serialize, Deserialize)]
struct PasswordEntry {
    name: String,
    username: String,
    password: String,
}

// Encrypted password store
#[derive(Serialize, Deserialize)]
struct PasswordStore {
    entries: Vec<PasswordEntry>,
}

// CLI Commands
#[derive(Subcommand)]
enum Commands {
    /// Add a new password entry
    Add {
        name: String,
        username: String,
        password: String,
    },
    /// Get a password entry
    Get { name: String },
    /// List all entries
    List,
    /// Initialize password store
    Init,
}

// CLI Arguments
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    /// Path to password store
    #[arg(short, long, default_value = "passwords.enc")]
    store: PathBuf,
}

// Main function
fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Init => init_store(&args.store),
        Commands::Add {
            name,
            username,
            password,
        } => add_entry(&args.store, &name, &username, &password),
        Commands::Get { name } => get_entry(&args.store, &name),
        Commands::List => list_entries(&args.store),
    }
}

// Initialize password store
fn init_store(store_path: &PathBuf) -> anyhow::Result<()> {
    let master_password = get_password("Set master password: ")?;
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(master_password.as_bytes(), &salt)?;
    
    let store = PasswordStore { entries: Vec::new() };
    let encrypted_data = encrypt_store(&store, hash.hash.unwrap().as_bytes())?;
    
    fs::write(store_path, encrypted_data)?;
    println!("Password store initialized!");
    Ok(())
}

// Add new entry
fn add_entry(store_path: &PathBuf, name: &str, username: &str, password: &str) -> anyhow::Result<()> {
    let mut store = decrypt_store(store_path)?;
    
    store.entries.push(PasswordEntry {
        name: name.to_string(),
        username: username.to_string(),
        password: password.to_string(),
    });
    
    let master_password = get_password("Master password: ")?;
    let encrypted_data = encrypt_store(&store, master_password.as_bytes())?;
    
    fs::write(store_path, encrypted_data)?;
    Ok(())
}

// Encryption/Decryption functions
fn encrypt_store(store: &PasswordStore, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).context("Invalid key length")?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);
    let serialized = bincode::serialize(store)?;
    let ciphertext = cipher
        .encrypt(nonce, serialized.as_ref())
        .context("Failed to encrypt data")?;
    Ok([nonce.to_vec(), ciphertext].concat())
}

fn decrypt_store(store_path: &PathBuf) -> anyhow::Result<PasswordStore> {
    let master_password = get_password("Master password: ")?;
    let encrypted_data = fs::read(store_path)?;
    
    let (nonce, ciphertext) = encrypted_data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(master_password.as_bytes())
        .context("Invalid key length")?;
    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .context("Failed to decrypt data")?;
    
    Ok(bincode::deserialize(&decrypted)?)
}

// Helper functions
fn get_password(prompt: &str) -> anyhow::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    Ok(password.trim().to_string())
}