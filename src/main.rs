use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
//use ethers::utils::format_ether;
use ethers::utils::{format_ether, hex};
use std::env;
use std::sync::Arc;
use tokio;
use dotenv::dotenv;
use log::{info, debug, error};
use std::fs::OpenOptions;
use std::io::Write;
use env_logger::{Builder, Target};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    //env_logger::init();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
 

    // Configure env_logger to log to a file and stdout
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("bot_logs.log")
        .unwrap();

    Builder::new()
        .target(Target::Pipe(Box::new(log_file)))
        .filter(None, log::LevelFilter::Info)
        .init();

    info!("🔗 Connecting to Ethereum WebSocket: {}", ws_url);
    let ws_url = env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);

    info!("✅ Connected to Ethereum Node!");
    info!("🕵️‍♂️ Listening for pending transactions...");
    debug!("🕵️‍♂️ Debugging enabled: Listening for pending transactions...");

    let mut stream = provider.subscribe_pending_txs().await?;
    let dex_addresses = vec![
        "0x7a250d5630b4cf539739df2c5dacab1e14a31957".parse::<Address>()?, // Uniswap V2 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564".parse::<Address>()?, // Uniswap V3 Router       
        "0xd9e1ce17f2641f24aE83637ab66a2cca9C378B9F".parse::<Address>()?, // SushiSwap Router
    ];

    while let Some(tx_hash) = stream.next().await {
        debug!("📝 Pending Transaction: {:?}", tx_hash);

        if let Ok(tx) = provider.get_transaction(tx_hash).await {
            if let Some(transaction) = tx {
                debug!("🔍 Checking transaction to: {:?}", transaction.to);
                if let Some(to) = transaction.to {
                    if dex_addresses.contains(&to) {
                        info!("🎯 DEX Transaction Detected!");
                        info!("🔍 Transaction Hash: {:?}", tx_hash);
                        info!("From: {:?}", transaction.from);
                        info!("To: {:?}", transaction.to);
                        info!("Gas Price: {:?}", transaction.gas_price.map(|g| format_ether(g)));
                        info!("Value: {} ETH", format_ether(transaction.value));
                        
                        // Decode transaction input
                        decode_input_data(&transaction.input);
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

/// Decode DEX swap transaction input data
fn decode_input_data(input: &Bytes) {
    if input.is_empty() {
        error!("❌ Input data is empty, skipping...");
        return;
    }

    let selector = hex::encode(&input[0..4]);
    info!("🧩 Function Selector: 0x{}", selector);

    match selector.as_str() {
        "38ed1739" => info!("🛠️ Function: swapExactTokensForTokens"),
        "5c11d795" => info!("🛠️ Function: exactInputSingle (Uniswap V3)"),
        "18cbafe5" => info!("🛠️ Function: swapExactETHForTokens"),
        _ => info!("❓ Unknown Function Selector: 0x{}", selector),
    }

    // Print the full input data for debugging
    info!("🔑 Raw Input Data: {:?}", hex::encode(&input));
}