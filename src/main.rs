use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
//use ethers::utils::format_ether;
use ethers::utils::{format_ether, hex};
//use std::env;
use std::sync::Arc;
use tokio;
//use dotenv::dotenv;
use log::{info, error, debug};
use std::fs::OpenOptions;
//use std::io::Write;
use env_logger::{Builder, Target};
use ethers::abi::{AbiParser, Token};
use ethers::types::{Bytes, U256};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    //env_logger::init();
    //env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
   // Ensure the logger is initialized only once
    // Log to file and console using env_logger
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("bot_logs.log")
        .expect("Failed to open log file");

    Builder::new()
        .target(Target::Pipe(Box::new(log_file)))
        .filter(None, log::LevelFilter::Info)
        .init();

    let ws_url = std::env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    info!("🔗 Connecting to Eth WebSocket: {}", ws_url);
    
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);

    info!("✅ Eth Node Connected,listening...");
    //info!("🕵️‍♂️ Listening, pending transactions...");
    debug!("🕵️‍♂️ Debugging : Listening for pending transactions...");

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
                        info!("🎯 DEX Transac Detected!");
                       // info!("🔍 Transac Hash: {:?}", tx_hash);
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
// Updated decode_input_data function
fn decode_input_data(input: &Bytes) {
    if input.is_empty() {
        error!("❌ Input data is empty, skipping...");
        return;
    }

    let selector = hex::encode(&input[0..4]);
    info!("🧩 Function Selector: 0x{}", selector);

    let abi = AbiParser::default()
        .parse(&[
            "function exactInputSingle(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)",
            "function exactInput(bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum)",
            "function exactOutputSingle(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum, uint160 sqrtPriceLimitX96)",
            "function exactOutput(bytes path, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum)"
        ])
        .expect("Failed to parse ABI");

    match selector.as_str() {
        "414bf389" => {
            info!("🛠️ Decoding: exactOutput");
            if let Ok(decoded) = abi
                .function("exactOutput")
                .unwrap()
                .decode_input(&input[4..])
            {
                if let (Token::Bytes(path), Token::Address(recipient), Token::Uint(deadline), Token::Uint(amount_out), Token::Uint(amount_in_max)) =
                    (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                {
                    info!("🔄 Path: {:?}", hex::encode(path));
                    info!("👤 Recipient: {:?}", recipient);
                    info!("⏳ Deadline: {:?}", deadline);
                    info!("💰 Amount Out: {:?}", amount_out);
                    info!("💸 Amount In Max: {:?}", amount_in_max);
                }
            }
        }
        "f28c0498" => {
            info!("🛠️ Decoding: exactInput");
            if let Ok(decoded) = abi
                .function("exactInput")
                .unwrap()
                .decode_input(&input[4..])
            {
                if let (Token::Bytes(path), Token::Address(recipient), Token::Uint(deadline), Token::Uint(amount_in), Token::Uint(amount_out_min)) =
                    (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                {
                    info!("🔄 Path: {:?}", hex::encode(path));
                    info!("👤 Recipient: {:?}", recipient);
                    info!("⏳ Deadline: {:?}", deadline);
                    info!("💰 Amount In: {:?}", amount_in);
                    info!("💸 Amount Out Min: {:?}", amount_out_min);
                }
            }
        }
        "db3e2198" => {
            info!("🛠️ Decoding: exactOutputSingle");
            if let Ok(decoded) = abi
                .function("exactOutputSingle")
                .unwrap()
                .decode_input(&input[4..])
            {
                if let (Token::Address(token_in), Token::Address(token_out), Token::Uint(fee), Token::Address(recipient), Token::Uint(deadline), Token::Uint(amount_out), Token::Uint(amount_in_max), Token::Uint(sqrt_price_limit)) =
                    (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4], &decoded[5], &decoded[6], &decoded[7])
                {
                    info!("🔄 Token In: {:?}", token_in);
                    info!("🔄 Token Out: {:?}", token_out);
                    info!("💹 Fee: {:?}", fee);
                    info!("👤 Recipient: {:?}", recipient);
                    info!("⏳ Deadline: {:?}", deadline);
                    info!("💰 Amount Out: {:?}", amount_out);
                    info!("💸 Amount In Max: {:?}", amount_in_max);
                }
            }
        }
        _ => {
            info!("❓ Unknown Function Selector: 0x{}", selector);
            info!("🔑 Raw Input Data: {:?}", hex::encode(&input));
        }
    }
}