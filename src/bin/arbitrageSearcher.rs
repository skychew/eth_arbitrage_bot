use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
use ethers::types::{Transaction, Address, H256};
use std::sync::Arc;
use dotenv::dotenv;
use std::collections::HashSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    let infura_ws = std::env::var("ETH_WS_URL").expect("⚠️ ETH_WS_URL not set in .env");

    // Connect to Ethereum WebSocket
    let provider = Provider::<Ws>::connect(&infura_ws).await?;
    let provider = Arc::new(provider);

    println!("✅ Connected to Ethereum Node...");

    // Define known DEX router addresses
    let dex_routers: HashSet<Address> = vec![
        "0xE592427A0AEce92De3Edee1F18E0157C05861564".parse().unwrap(), // Uniswap V3 Router
        "0xd9e1CE17f2641F24AE83637ab66A2CCA9C378B9F".parse().unwrap(), // SushiSwap Router
    ].into_iter().collect();

    // Define function selectors for swap functions
    let swap_selectors: HashSet<String> = HashSet::from([
        "414bf389".to_string(), // exactInputSingle
        "c04b8d59".to_string(),
        "db3e2198".to_string(),
        "f28c0498".to_string(), // exactOutput
    ]);

    // Subscribe to pending transactions
    let mut pending_txs = provider.subscribe_pending_txs().await?;

    println!("📡 Listening for pending transactions...");

    // Process transactions as they appear
    while let Some(tx_hash) = pending_txs.next().await {
       // Correct handling of Result<Option<Transaction>>
        if let Ok(Some(tx)) = provider.get_transaction(tx_hash).await {
            // Check if the transaction is going to a known DEX router
            if let Some(to_address) = tx.to {
                if dex_routers.contains(&to_address) {
                    // Extract function selector (first 4 bytes of input data)
                    if let Some(input_data) = tx.input.get(0..4) {
                        let selector = H256::from_slice(input_data);  // Convert to H256
                    
                        if swap_selectors.contains(&selector) {
                            println!("🟢 Swap Detected on DEX!");
                            println!("🔗 Tx Hash: {:?}", tx.hash);
                            println!("📨 To: {:?}", to_address);
                            println!("🧩 Function Selector: {:?}", selector);
                            println!("💰 Value: {:?}", tx.value);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}