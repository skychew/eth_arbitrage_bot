use ethers::prelude::*;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use dotenv::dotenv;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    let ws_url = std::env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    println!("================= Connecting to Eth WebSocket: {}", ws_url);
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);
    println!("✅ Eth Node Connected, listening...");

    // Create a channel for processing transactions
    let (tx, mut rx) = mpsc::channel(100); // Buffer size of 100

    // Spawn a task to listen for pending transactions
    let provider_clone = provider.clone();
    tokio::spawn(async move {
        let mut stream = provider_clone.subscribe_pending_txs().await.unwrap();
        while let Some(tx_hash) = stream.next().await {
            if let Err(_) = tx.send(tx_hash).await {
                println!("⚠️ Failed to send tx to the channel");
            }
        }
    });

    // Maintain a set of transactions being processed to avoid duplication
    let mut processed_tx_hashes = HashSet::new();

    // Process pending transactions
    while let Some(tx_hash) = rx.recv().await {
        if !processed_tx_hashes.contains(&tx_hash) {
            processed_tx_hashes.insert(tx_hash);

            let provider_clone = provider.clone();
            tokio::spawn(async move {
                monitor_transaction(tx_hash, provider_clone).await;
            });
        }
    }

    Ok(())
}

async fn monitor_transaction(tx_hash: TxHash, provider: Arc<Provider<Ws>>) {
    println!("🚀 Monitoring transaction {} for confirmation...", tx_hash);

    let mut retries = 0;
    let max_retries = 5;
    let mut delay = Duration::from_secs(5); // Start with a 5-second delay

    loop {
        if let Some(tx) = provider.get_transaction(tx_hash).await.unwrap_or(None) {
            match (tx.block_hash, tx.block_number) {
                (Some(block_hash), Some(block_number)) => {
                    println!("✅ Transaction {} mined in block number: {}", tx_hash, block_number);
                    println!("🔗 Block hash: {:?}", block_hash);
                    break;
                }
                _ => {
                    println!("⏳ Transaction {} is still pending...", tx_hash);
                }
            }
        } else {
            println!("⚠️ Transaction {} not found. Retrying...", tx_hash);
        }

        if retries >= max_retries {
            println!("🚫 Maximum retries reached for transaction {}. Skipping further checks.", tx_hash);
            break;
        }

        retries += 1;
        tokio::time::sleep(delay).await;

        // Exponential backoff to handle rate limits
        delay = Duration::from_secs(delay.as_secs() * 2);
    }
}