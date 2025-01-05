use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use std::env;
use std::sync::Arc;
use tokio;
use dotenv::dotenv;

mod config;
mod ethereum;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    // Load Environment Variables
    let ws_url = env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");

    println!("🔗 Connecting to Ethereum WebSocket...");
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);

    println!("✅ Connected to Ethereum Node!");

    // Example: Fetch and print the latest block number
    match provider.get_block_number().await {
        Ok(block_number) => println!("📊 Latest Ethereum Block Number: {}", block_number),
        Err(err) => eprintln!("❌ Failed to fetch block number: {}", err),
    }

    Ok(())
}