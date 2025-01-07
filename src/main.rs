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
                        
                        if let Some((token_in, token_out, amount_in, recipient)) = decode_input_data(&transaction.input) {
                            info!("🔄 Token In: {:?}", token_in);
                            info!("🔄 Token Out: {:?}", token_out);
                            info!("💰 Amount In: {:?}", amount_in);
                            info!("👤 Recipient: {:?}", recipient);
                        
                            // Call simulate_arbitrage
                            simulate_arbitrage(token_in, token_out, amount_in, Arc::clone(&provider)).await;
                        }
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
fn decode_input_data(input: &Bytes) -> Option<(Address, Address, U256, Address)> {
    if input.is_empty() {
        error!("❌ Input data is empty, skipping...");
        return None;
    }

    let selector = hex::encode(&input[0..4]);
    info!("🧩 Function Selector: 0x{}", selector);

    let abi = AbiParser::default()
        .parse(&[
            "function exactInputSingle(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)",
            "function exactInput(bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum)",
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
                if let (Token::Bytes(_), Token::Address(recipient), Token::Uint(_), Token::Uint(amount_out), Token::Uint(_)) =
                    (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                {
                    return Some((
                        Address::default(),
                        Address::default(),
                        *amount_out,
                        *recipient,
                    ));
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
                if let (Token::Bytes(_), Token::Address(recipient), Token::Uint(_), Token::Uint(amount_in), Token::Uint(_)) =
                    (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                {
                    return Some((
                        Address::default(),
                        Address::default(),
                        *amount_in,
                        *recipient,
                    ));
                }
            }
        }
        _ => {
            info!("❓ Unknown Function Selector: 0x{}", selector);
            info!("🔑 Raw Input Data: {:?}", hex::encode(&input));
        }
    }

    None
}

/// Simulate arbitrage opportunity based on detected DEX transaction
use ethers::types::U256;
use std::collections::HashMap;


async fn simulate_arbitrage(
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    provider: Arc<Provider<Ws>>,
) {
    info!("🔄 Simulating arbitrage for Token In: {:?}, Token Out: {:?}", token_in, token_out);

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

        if let Ok(result) = provider
            .call(
                &ethers::types::TransactionRequest::default()
                    .to(*address)
                    .data(call_data),
                None,
            )
            .await
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
}