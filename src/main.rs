use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
use ethers::utils::format_ether;
use std::env;
use std::sync::Arc;
use tokio;
use dotenv::dotenv;
use log::{info, debug, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    env_logger::init();

    let ws_url = env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    debug!("🔗 Connecting to Ethereum WebSocket: {}", ws_url);

    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);

    info!("✅ Connected to Ethereum Node!");
    debug!("🕵️‍♂️ Debugging enabled: Listening for pending transactions...");

    let mut stream = provider.subscribe_pending_txs().await?;
    let dex_addresses = vec![
        // Uniswap V2 Router
        "0x7a250d5630b4cf539739df2c5dacab1e14a31957".parse::<Address>()?,
        // Uniswap V3 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564".parse::<Address>()?,
        // SushiSwap Router
        "0xd9e1ce17f2641f24aE83637ab66a2cca9C378B9F".parse::<Address>()?,
    ];

    while let Some(tx_hash) = stream.next().await {
        debug!("📝 Pending Transaction: {:?}", tx_hash);

        if let Ok(tx) = provider.get_transaction(tx_hash).await {
            if let Some(transaction) = tx {
                debug!("🔍 Checking transaction to: {:?}", transaction.to);
                if let Some(to) = transaction.to {
                    if dex_addresses.contains(&to) {
                        info!("🎯 DEX Transaction Detected!");
                        info!("From: {:?}", transaction.from);
                        info!("To: {:?}", transaction.to);
                        info!("Gas Price: {:?}", transaction.gas_price.map(|g| format_ether(g)));
                        info!("Value: {} ETH", format_ether(transaction.value));
                    }
                } else {
                    debug!("❌ Transaction `to` address is None.");
                }
            } else {
                debug!("❌ Could not fetch transaction details for {:?}", tx_hash);
            }
        } else {
            debug!("❌ Error fetching transaction details for {:?}", tx_hash);
        }
    }

    Ok(())
}