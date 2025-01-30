use ethers::prelude::*;
use std::{sync::Arc, time::Duration};
use dotenv::dotenv;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    // Connect to Ethereum provider
    let ws_url = std::env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    println!("================= Connecting to Eth WebSocket: {}", ws_url);
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);
    println!("✅ Eth Node Connected, listening...");
    let mut stream = provider.subscribe_pending_txs().await?;

    while let Some(tx_hash) = stream.next().await {
        println!("🚀 Monitoring transaction {} for confirmation...", tx_hash);

        let mut retries = 0;
        loop {
            if let Some(tx) = provider.get_transaction(tx_hash).await? {
                match tx.block_hash {
                    Some(block_hash) => {
                        println!("✅ Transaction {} mined!", tx_hash);
                        println!("🔗 Block hash: {:?}", block_hash);
                        break;
                    }
                    None => {
                        println!("⏳ Transaction {} is still pending...", tx_hash);
                    }
                }
            } else {
                println!("⚠️ Transaction {} not found. Retrying...", tx_hash);
            }

            // Retry up to 5 times and apply a delay
            retries += 1;
            if retries >= 5 {
                println!("🚫 Maximum retries reached for transaction {}. Skipping...", tx_hash);
                break;
            }

            // Delay of 10 seconds before the next check
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    Ok(())
}