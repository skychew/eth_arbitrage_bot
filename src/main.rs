use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
use std::env;
use std::sync::Arc;
use tokio;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    // Retrieve WebSocket URL from environment variables
    let ws_url = env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    println!("🔗 Connecting to Ethereum WebSocket: {}", ws_url);

    // Connect to Ethereum node via WebSocket
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);

    println!("✅ Connected to Ethereum Node!");

    // Listen for pending transactions
    println!("🕵️‍♂️ Listening for pending transactions...");

    let mut stream = provider.subscribe_pending_txs().await?;
    while let Some(tx_hash) = stream.next().await {
        println!("📝 Pending Transaction: {:?}", tx_hash);

        // Fetch transaction details
        if let Ok(tx) = provider.get_transaction(tx_hash).await {
            if let Some(transaction) = tx {
                println!("🔍 Transaction Details:");
                println!("From: {:?}", transaction.from);
                println!("To: {:?}", transaction.to);
                println!("Gas Price: {:?}", transaction.gas_price);
                println!("Value: {:?}", transaction.value);
            }
        }
    }

    Ok(())
}