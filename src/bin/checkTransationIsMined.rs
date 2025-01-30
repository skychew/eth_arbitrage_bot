use ethers::prelude::*;
use std::time::Duration;
use std::sync::Arc;
use dotenv::dotenv;

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
        loop {
            if let Some(tx) = provider.get_transaction(tx_hash).await? {
                match tx.block_hash {
                    Some(block_hash) => {
                        println!("🔗 Block hash: {:?}", block_hash);
                        break;
                    }
                    _ => {
                        println!("⏳ Transaction is still pending...");
                    }
                }
            } else {
                println!("⚠️ Transaction not found. Double-check the hash or wait a bit longer.");
            }

            // Check every 10 seconds
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    println!("🎉 Transaction is confirmed! You can now safely process any related events.");
    Ok(())
}