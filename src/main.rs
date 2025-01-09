use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
use ethers::utils::format_ether;
use std::sync::Arc;
use tokio;
use log::{info, warn, error, debug};
use std::fs::OpenOptions;
use env_logger::{Builder, Target};
use ethers::abi::{AbiParser, Abi, Token};
use ethers::types::{Bytes, U256};

//use retry::{retry_async, delay::Exponential};
use retry::OperationResult;
use ethers::types::{Transaction, H256};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv::dotenv().ok();

    // Initialize logging
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("bot_logs.log")
        .expect("Failed to open log file");
    Builder::new()
        .target(Target::Pipe(Box::new(log_file)))
        .filter(None, log::LevelFilter::Info)
        .init();

    // Connect to Ethereum provider
    let ws_url = std::env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    info!("Connecting to Eth WebSocket: {}", ws_url);
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);
    info!("✅ Eth Node Connected, listening...");

    // Define the ABI
    let abi = AbiParser::default()
        .parse(&[
            "function exactInputSingle(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)",
            "function exactInput(bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum)",
            "function exactOutputSingle(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum, uint160 sqrtPriceLimitX96)",
            "function exactOutput(bytes path, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum)",
        ])
        .expect("Failed to parse ABI");

    // Subscribe to pending transactions
    let mut stream = provider.subscribe_pending_txs().await?;
    let dex_addresses = vec![
        "0x7a250d5630b4cf539739df2c5dacab1e14a31957".parse()?, // Uniswap V2 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564".parse()?, // Uniswap V3 Router
        "0xd9e1ce17f2641f24aE83637ab66a2cca9C378B9F".parse()?, // SushiSwap Router
    ];

    while let Some(tx_hash) = stream.next().await {
        debug!("Pending Transaction: {:?}", tx_hash);

        if let Some(transaction) = fetch_transaction(provider.clone(), tx_hash).await {
            if let Some(to) = transaction.to {
                if dex_addresses.contains(&to) {
                    info!("DEX Transaction Detected!");
                    info!("From: {:?}", transaction.from);
                    info!("To: {:?}", transaction.to);
                    info!("Gas Price: {:?}", transaction.gas_price.map(|g| format_ether(g)));
                    info!("Value: {} ETH", format_ether(transaction.value));

                    // Decode transaction input
                    if let Some((token_in, token_out, amount_in, recipient)) = decode_input_data(&transaction.input, &abi) {
                        info!("🔄 Starting Arbitrage Simulation...");
                        info!("🪙 Token In: {:?}", token_in);
                        info!("🪙 Token Out: {:?}", token_out);
                        info!("💰 Amount In: {:?}", amount_in);
                        info!("👤 Recipient: {:?}", recipient);

                        // Call simulate_arbitrage
                        match simulate_arbitrage(token_in, token_out, amount_in, Arc::clone(&provider)).await {
                            Ok(_) => { /* Simulation successful */ }
                            Err(e) => { error!("Error in simulate_arbitrage: {:?}", e); }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Decode DEX swap transaction input data
fn decode_input_data(input: &Bytes, abi: &Abi) -> Option<(Address, Address, U256, Address)> {
    // Check for empty input
    if input.is_empty() {
        error!("❌ Input data is empty, skipping...");
        return None;
    }

    // Extract function selector
    let selector = hex::encode(&input[0..4]);
    info!("🧩 Function Selector: 0x{}", selector);

    // Match the selector against known function signatures
    match selector.as_str() {
        // Match for "exactOutput" function
        "414bf389" => {
            info!("🛠️ Decoding: exactOutput");
            // Use the provided ABI to decode the function input
            match abi.function("exactOutput").and_then(|func| func.decode_input(&input[4..])) {
                Ok(decoded) => {
                    if decoded.len() == 5 {
                        if let (
                            Token::Bytes(path),
                            Token::Address(recipient),
                            Token::Uint(_deadline),
                            Token::Uint(amount_out),
                            Token::Uint(amount_in_maximum),
                        ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                        {
                            info!("🛠️ Decoded exactOutput successfully!");
                            // Example return value with extracted data
                            return Some((*recipient, *recipient, *amount_out, *recipient));
                        }
                    } else {
                        error!(
                            "❌ Unexpected number of parameters for exactOutput: expected 5, got {}",
                            decoded.len()
                        );
                    }
                }
                Err(e) => {
                    error!("❌ Failed to decode exactOutput: {:?}", e);
                }
            }
        }
        // Match for "exactInput" function
        "f28c0498" => {
            info!("🛠️ Decoding: exactInput");
            // Use the provided ABI to decode the function input
            match abi.function("exactInput").and_then(|func| func.decode_input(&input[4..])) {
                Ok(decoded) => {
                    if decoded.len() == 5 {
                        if let (
                            Token::Bytes(path),
                            Token::Address(recipient),
                            Token::Uint(_deadline),
                            Token::Uint(amount_in),
                            Token::Uint(_amount_out_minimum),
                        ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                        {
                            info!("🛠️ Decoded exactInput successfully!");
                            // Example return value with extracted data
                            return Some((*recipient, *recipient, *amount_in, *recipient));
                        }
                    } else {
                        error!(
                            "❌ Unexpected number of parameters for exactInput: expected 5, got {}",
                            decoded.len()
                        );
                    }
                }
                Err(e) => {
                    error!("❌ Failed to decode exactInput: {:?}", e);
                }
            }
        }
        // Handle unknown selectors
        _ => {
            info!("❓ Unknown Function Selector: 0x{}", selector);
            info!("🔑 Raw Input Data: {:?}", hex::encode(&input));
        }
    }

    // Return None if no valid decoding occurred
    None
}

/// Simulate arbitrage opportunity based on detected DEX transaction
use std::collections::HashMap;

async fn simulate_arbitrage(
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    provider: Arc<Provider<Ws>>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("🔄 Starting Arbitrage Simulation...");
    info!("🪙 Token In: {:?}", token_in);
    info!("🪙 Token Out: {:?}", token_out);
    info!("💰 Amount In: {:?}", amount_in);

    // Example DEX router addresses for price fetching
    let dex_addresses: HashMap<&str, Address> = HashMap::from([
        ("UniswapV2", "0x7a250d5630b4cf539739df2c5dacab1e14a31957".parse().unwrap()),
        ("SushiSwap", "0xd9e1ce17f2641f24aE83637ab66a2cca9C378B9F".parse().unwrap()),
    ]);

    let mut buy_price: Option<U256> = None;
    let mut sell_price: Option<U256> = None;

    // Fetch prices from each DEX
    for (dex, address) in dex_addresses.iter() {
        let call_data = ethers::abi::encode(&[
            ethers::abi::Token::Address(token_in),
            ethers::abi::Token::Address(token_out),
            ethers::abi::Token::Uint(amount_in),
        ]);

        let result = provider
        .call(
            &ethers::types::TransactionRequest::default()
                .to(*address)
                .data(call_data)
                .into(), 
            None
        )
        .await?;
        info!("💾 Call result: {:?}", result);
        {
            let price = U256::from_big_endian(&result[0..32]);
            info!("💱 {} Price: {}", dex, price);

            if buy_price.is_none() {
                buy_price = Some(price);
            } else {
                sell_price = Some(price);
            }
        }
    }

    if let (Some(buy), Some(sell)) = (buy_price, sell_price) {
        let gas_cost = U256::from(1_000_000_000_000_000u64); // Example gas fee

        let profit = sell.checked_sub(buy).unwrap_or_default().checked_sub(gas_cost).unwrap_or_default();

        if profit > U256::from(0) {
            info!("💰 Arbitrage Opportunity Detected!");
            info!("🔹 Buy Price: {}", buy);
            info!("🔸 Sell Price: {}", sell);
            info!("⛽ Gas Cost: {}", gas_cost);
            info!("💵 Profit: {}", profit);
        } else {
            info!("❌ No profitable arbitrage found.");
        }
    } else {
        error!("❌ Failed to fetch prices from DEXs.");
    }
    Ok(())
}

async fn fetch_transaction(provider: Arc<Provider<Ws>>, tx_hash: H256) -> Option<Transaction> {
    let max_retries = 5; // Maximum number of retries
    let mut attempt = 0;
    let mut delay = Duration::from_millis(4000); // Initial delay

    while attempt < max_retries {
        attempt += 1;

        match provider.get_transaction(tx_hash).await {
            Ok(Some(tx)) => {
                info!("Transaction fetched successfully on attempt {}", attempt);
                return Some(tx);
            }
            Ok(None) => {
                warn!(
                    "Transaction not found (attempt {}). Retrying in {:?}...",
                    attempt, delay
                );
            }
            Err(e) => {
                error!(
                    "Error fetching transaction on attempt {}: {}. Retrying in {:?}...",
                    attempt, e, delay
                );
            }
        }

        // Wait before retrying
        sleep(delay).await;
        delay *= 2; // Exponential backoff
    }

    error!("Failed to fetch transaction after {} attempts", max_retries);
    None
}

fn is_fatal_error(error: &ProviderError) -> bool {
    match error {
        ProviderError::JsonRpcClientError(_) => true,
        _ => false,
    }
}