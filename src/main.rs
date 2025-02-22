///Read Me in footer
use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
use ethers::utils::format_ether;
use ethers::types::{Transaction, H256};
use ethers::abi::{AbiParser, Abi, Token};
use ethers::types::{Bytes, U256};
use ethers::types::H160;

use std::sync::{Arc, Mutex};
use std::error::Error;
use std::collections::HashSet;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::fs::OpenOptions;
use std::io::{self, Write}; // Required for flushing stdout

use tokio;
use tokio::sync::Semaphore; //use semaphore to limit the number of concurrent requests 500 per second for Infura
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{sleep, Duration};

use log::{info, warn, error, debug};
use log::LevelFilter; //declare here so that we can overwrite in command line
use env_logger::{Builder, Target};

use reqwest;
use serde_json::Value;

// Global counters
static API_TX_COUNT: AtomicUsize = AtomicUsize::new(0);
static REVIEW_COUNT: AtomicUsize = AtomicUsize::new(0);
static ADDRESS_COUNT: AtomicUsize = AtomicUsize::new(0);
static ARBITRAGE_COUNT: AtomicUsize = AtomicUsize::new(0);
static TODEX_COUNT: AtomicUsize = AtomicUsize::new(0);
static API_TX_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);
static SUCCESS_COUNT: AtomicUsize = AtomicUsize::new(0);
static RETRY_COUNT: AtomicUsize = AtomicUsize::new(0);
static RETRY_ERR_COUNT: AtomicUsize = AtomicUsize::new(0);
static MINED_COUNT: AtomicUsize = AtomicUsize::new(0);

const DEFAULT: Option<u32> = None;

//allow multiple infura keys
struct InfuraManager {
    urls: Vec<String>,
    current_index: Mutex<usize>,
}
impl InfuraManager {
    fn new() -> Self {
        let urls = vec![
            env::var("INFURA_WS_URL_1").expect("INFURA_WS_URL_1 must be set"),
            env::var("INFURA_WS_URL_2").expect("INFURA_WS_URL_2 must be set"),
            env::var("INFURA_WS_URL_3").expect("INFURA_WS_URL_3 must be set"),
        ];
        InfuraManager {
            urls,
            current_index: Mutex::new(0),
        }
    }
    fn get_current_url(&self) -> String {
        let index = *self.current_index.lock().unwrap();
        self.urls[index].clone()
    }

    fn switch_url(&self) {
        let mut index = self.current_index.lock().unwrap();
        *index = (*index + 1) % self.urls.len();
        info!("🔄 Switching to Infura URL: {}", self.urls[*index]);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv::dotenv().ok();

    // Maximum 500 requests per second for Infura
    let rate_limiter = Arc::new(Semaphore::new(498)); 

    // Initialize logging
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("bot_logs.log")
        .expect("Failed to open log file");
    Builder::new()
        .target(Target::Pipe(Box::new(log_file)))
        .filter(None, LevelFilter::Info)
        .init();

    // Define the ABI signatures
    let abi = AbiParser::default()
        .parse(&[
            "function exactInputSingle(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)",
            "function exactInput(bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum)",
            "function exactOutputSingle(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum, uint160 sqrtPriceLimitX96)",
            "function exactOutput(bytes path, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum)",
            "function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)",
            "function swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)",
            "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)",
            "function addLiquidity(address tokenA, address tokenB, uint amountADesired, uint amountBDesired, uint amountAMin, uint amountBMin, address to, uint deadline)",
            "function removeLiquidity(address tokenA, address tokenB, uint liquidity, uint amountAMin, uint amountBMin, address to, uint deadline)"

        ])
        .expect("Failed to parse ABI");
    
    // Define the list of allowed token addresses
    let allowed_tokens: HashSet<Address> = HashSet::from([
        "0x2eaa73bd0db20c64f53febea7b5f5e5bccc7fb8b".parse().unwrap(), // ETH
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse().unwrap(), // WETH
        "0x514910771AF9Ca656af840dff83E8264EcF986CA".parse().unwrap(), // LINK
        "0x163f8C2467924be0ae7B5347228CABF260318753".parse().unwrap(), // WLD
        "0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3".parse().unwrap(), // ONDO
        "0x57e114B691Db790C35207b2e685D4A43181e6061".parse().unwrap(), // ENA
        "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE".parse().unwrap(), // SHIB
        "0x6982508145454Ce325dDbE47a25d4ec3d2311933".parse().unwrap(), // PEPE
        "0x4C1746A800D224393fE2470C70A35717eD4eA5F1".parse().unwrap(), // PLUME
        "0xE0f63A424a4439cBE457D80E4f4b51aD25b2c56C".parse().unwrap(), // SPX
        "0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a".parse().unwrap(), // MOG
        "0xA2cd3D43c775978A96BdBf12d733D5A1ED94fb18".parse().unwrap(), // XCN
        "0xdac17f958d2ee523a2206206994597c13d831ec7".parse().unwrap(), // USDT
        "0x6b3595068778dd592e39a122f4f5a5cf09c90fe2".parse().unwrap(), // SUSHI
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599".parse().unwrap(), // WBTC
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".parse().unwrap(), // USDC
        "0x6b175474e89094c44da98b954eedeac495271d0f".parse().unwrap(), // DAI
    ]);

    // Define the list of DEX router addresses
    let dex_groups = vec![
        ("Uniswap", vec![
            ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".parse::<H160>().unwrap(), "Uniswap V2"),
            ("0xe592427a0aece92de3edee1f18e0157c05861564".parse::<H160>().unwrap(), "Uniswap V3"),
        ]),
        ("SushiSwap", vec![
            ("0xd9e1ce17f2641f24aE83637ab66a2cca9c378b9f".parse::<H160>().unwrap(), "SushiSwap"),
        ]),
    ];
    // Uniswap V3 Quoter contract address
    const UNISWAP_V3_QUOTER: &str = "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6";

    /* ======== Subscribe to pending transactions
    •	What It Does: This connects to the Ethereum mempool and listens for all pending transactions (those broadcast but not yet mined into a block).
    •	Key Points:
    •	The subscription provides transaction hashes, not full transaction details.
    •	The subscription stream should continue indefinitely, feeding new transaction hashes as they appear.
    =========== */
    // Initialize InfuraManager
    let manager = Arc::new(InfuraManager::new());
    // Attempt to connect to Infura
    let provider = connect_to_infura(manager.clone()).await?;
    let provider = Arc::new(provider);
    /* 
    // Connect to Ethereum provider
    let ws_url = std::env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    info!("================= Connecting to Eth WebSocket: {}", ws_url);
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);
    */
    info!("✅ Eth Node Connected, listening...");
    let mut stream = provider.subscribe_pending_txs().await?;
    // Initialize the number of hash processsed
    let mut hash_count = 0;       

    debug!("📡 Fetching valid trading pairs from Binance...");
    let valid_pairs = fetch_valid_pairs().await?;

    while let Some(tx_hash) = stream.next().await {
        //check if we run out of infura credits
        match tx_hash_result {
            Ok(tx_hash) => {
                debug!("Tx Hash: {:?}",tx_hash); 
                hash_count += 1; 
                //Tx only counts fetch_transaction and fetch_price
                print!("\rHash#: {} | Review#: {} | ADD#: {} | ToDeX#: {} | Abtrg#: {} | Tx#: {} | Fail#: {} | 1stTry#: {} | Retry#: {} | RtryErr#: {} | isMined#: {}", 
                    hash_count, 
                    REVIEW_COUNT.load(Ordering::SeqCst), 
                    ADDRESS_COUNT.fetch_add(1, Ordering::SeqCst),
                    TODEX_COUNT.load(Ordering::SeqCst), 
                    ARBITRAGE_COUNT.load(Ordering::SeqCst),
                    API_TX_COUNT.load(Ordering::SeqCst), 
                    API_TX_FAIL_COUNT.load(Ordering::SeqCst),
                    SUCCESS_COUNT.load(Ordering::SeqCst),
                    RETRY_COUNT.load(Ordering::SeqCst),
                    RETRY_ERR_COUNT.load(Ordering::SeqCst),
                    MINED_COUNT.load(Ordering::SeqCst), 
                ); 
                // Flush the output to ensure it appears immediately
                io::stdout().flush().unwrap();
                
                if let Some(transaction) = fetch_transaction(provider.clone(), tx_hash, rate_limiter.clone()).await {
                    REVIEW_COUNT.fetch_add(1, Ordering::SeqCst);

                    if let Some(to) = transaction.to {
                        ADDRESS_COUNT.fetch_add(1, Ordering::SeqCst);
                        if let Some((detected_dex_name, matching_address)) = dex_groups.iter().find(|(_, addresses)| {
                            addresses.iter().any(|(address, _)| address == &to)
                        }) {
                            TODEX_COUNT.fetch_add(1, Ordering::SeqCst);
                            info!("++Listed DEX Router found!: {} (Address: {:?})", detected_dex_name, matching_address);
                            info!("Hash : {:?}", tx_hash);
                            info!("From : {:?}", transaction.from);
                            info!("To   : {:?}", transaction.to);
                            let gas_price = transaction.gas_price.map(|g| ethers::utils::format_units(g, "gwei").unwrap());
                            info!("Gas Price: {} Gwei", gas_price.unwrap_or_else(|| "unknown".to_string()));
                            info!("AMT ETH: {} ETH", format_ether(transaction.value));

                            // Decode transaction input
                            //_amount_in is probably too large so we overide it
                            if let Some((token_in, token_out, _amount_in, recipient)) = decode_input_data(&transaction.input, &abi) {
                                let (token_in_name, _) = get_token_info(&token_in);
                                let (token_out_name, _) = get_token_info(&token_out);
                            
                                // Check if token is listed
                                if !allowed_tokens.contains(&token_in) {
                                    warn!("❌ TokenInUnListed: {:?}", token_in);
                                }else{
                                    info!("TokenInListed: {:?}", token_in_name);
                                }
                                
                                if !allowed_tokens.contains(&token_out) {
                                    warn!("❌ TokenOutUnListed: {:?}", token_out);
                                }else{
                                    info!("TokenOutListed: {:?}", token_out_name);
                                }
                            
                                if allowed_tokens.contains(&token_in) && allowed_tokens.contains(&token_out) {
                                    let (_, token_in_decimals) = get_token_info(&token_in);
                                    //override amount_in to 2 tokens
                                    let amount_in = U256::from(2) * U256::exp10(token_in_decimals as usize);

                                    info!("✅ Listed Tokens. Starting Arbitrage Sim!");
                                    info!("🪙 Token In: {:?}", token_in_name);
                                    info!("🪙 Token Out: {:?}", token_out_name);
                                    info!("💰 Amount In: {:?}", amount_in);
                                    info!("👤 Recipient: {:?}", recipient);

                                    let mut prices = vec![];

                                    for (_group_name, dexes) in &dex_groups {
                                        for (dex_address, dex_name) in dexes {
                                            if let Some(price) = fetch_price(&provider, *dex_address, dex_name, token_in, token_out, amount_in, DEFAULT).await {
                                                prices.push((dex_name.to_string(), price));
                                            }
                                        }
                                    }
                                    // Check Binance price.
                                    let symbol = format!("{}{}", token_in_name, token_out_name);
                                    
                                    if valid_pairs.contains(&symbol) {
                                        match fetch_binance_price(&symbol).await {
                                            Ok(price) => {
                                                info!("💱 Current Price for {}: ${:.2}", symbol, price);
                                            }
                                            Err(e) => {
                                                error!("❌ Error fetching price for {}: {}", symbol, e);
                                            }
                                        }
                                    } else {
                                        error!("❌ Pair {} is not valid on Binance.", symbol);
                                    }

                                    // Perform arbitrage simulation if we have at least two prices
                                    if prices.len() >= 2 {
                                        let mut prices_iter = prices.iter();
                                        let first_price = prices_iter.next().unwrap();
                                        let second_price = prices_iter.next().unwrap();
                                        ARBITRAGE_COUNT.fetch_add(1, Ordering::SeqCst);
                                        simulate_arbitrage(Some(first_price.1), Some(second_price.1), amount_in)?;
                                    } else {
                                        warn!("❌ Not enough price data for arbitrage simulation.");
                                    }
                                }else {
                                    warn!("❌ Skipping...");
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("❌ Stream error detected: {}. Switching to new Infura key...", e);
                
                // Switch to the next Infura URL if transaction is of credits.
                manager.switch_url();

                // Reconnect using the new URL
                provider = Arc::new(connect_to_infura(manager.clone()).await?);

                // Resubscribe to pending transactions
                stream = provider.subscribe_pending_txs().await?;
            }
        }//end match
        Ok(())
    }//end subscription stream
}//end main

/* ======== Decode DEX swap transaction input data
    Confirmed using https://www.4byte.directory/
    Paste selector to get function signature

    Function (selector)
    exactInputSingle (0x414bf389)
    exactOutput (0xf28c0498)
    exactOutputSingle (0xdb3e2198)
    exactInput (0xc04b8d59)
    ========*/ 
fn decode_input_data(input: &Bytes, abi: &Abi) -> Option<(Address, Address, U256, Address)> {
    // Check for empty input
    if input.is_empty() {
        error!("❌ Input data is empty, skipping...");
        return None;
    }

    // Extract function selector
    let selector = hex::encode(&input[0..4]);
    //This will print the raw input data of the transaction, which you can manually decode later
    info!("Start Decode");
    info!("🔑 Raw Input Data: {:?}", hex::encode(&input));
    info!("🧩 Raw Function Selector: 0x{}", selector);

    // Match the selector against known function signatures
    match selector.as_str() {
         // Decode exactOutput
        "f28c0498" => {
            info!("🛠️ Decoding: exactOutput");
            match abi.function("exactOutput").and_then(|func| func.decode_input(&input[4..])) {
                Ok(decoded) => {
                    info!("🔍 Decoded Parameters: {:?}", decoded);
                    if decoded.len() == 5 {
                        if let (
                            Token::Bytes(path),
                            Token::Address(recipient),
                            Token::Uint(_deadline),
                            Token::Uint(amount_out),
                            Token::Uint(_amount_in_maximum),
                        ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                        {
                            if path.len() >= 40 {
                                info!("🛠️ Decoded exactOutput successfully!");
                                let token_in = Address::from_slice(&path[0..20]);
                                let token_out = Address::from_slice(&path[path.len() - 20..]);
                                return Some((token_in, token_out, *amount_out, *recipient));
                            } else {
                                error!("❌ Invalid path length for exactOutput: {:?}", path.len());
                            }
                        } else {
                            error!("❌ Decoding failed: Unexpected parameter structure.");
                        }
                    } else {
                        error!(
                            "❌ Unexpected number of parameters for exactOutput: expected 5, got {}",
                            decoded.len()
                        );
                    }   
                }Err(e) => {
                    error!("❌ Failed to decode exactOutput: {:?}", e);
                }
            }
        }

         // Decode exactInput
        "c04b8d59" => {
            info!("🛠️ Decoding: exactInput");
            if let Ok(decoded) = abi.function("exactInput").and_then(|func| func.decode_input(&input[4..])) {
                if decoded.len() == 5 {
                    if let (
                        Token::Bytes(path),
                        Token::Address(recipient),
                        Token::Uint(_deadline),
                        Token::Uint(amount_in),
                        Token::Uint(_amount_out_minimum),
                    ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4])
                    {
                        if path.len() >= 40 {
                            let token_in = Address::from_slice(&path[0..20]);
                            let token_out = Address::from_slice(&path[path.len() - 20..]);
                            return Some((token_in, token_out, *amount_in, *recipient));
                        } else {
                            error!("❌ Invalid path length for exactInput: {:?}", path.len());
                        }
                    }
                } else {
                    error!(
                        "❌ Unexpected number of parameters for exactInput: expected 5, got {}",
                        decoded.len()
                    );
                }
            } else {
                error!("❌ Failed to decode exactInput");
            }
        }

        // Decode exactInputSingle
        "414bf389" => {
            info!("🛠️ Decoding: exactInputSingle");
            if let Ok(decoded) = abi.function("exactInputSingle").and_then(|func| func.decode_input(&input[4..])) {
                if decoded.len() == 8 {
                    if let (
                        Token::Address(token_in),
                        Token::Address(token_out),
                        Token::Uint(_fee),
                        Token::Address(recipient),
                        Token::Uint(_deadline),
                        Token::Uint(amount_in),
                        Token::Uint(_amount_out_minimum),
                        Token::Uint(_sqrt_price_limit_x96),
                    ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4], &decoded[5], &decoded[6], &decoded[7])
                    {
                        info!("🛠️ Decoded exactInputSingle successfully!");
                        return Some((*token_in, *token_out, *amount_in, *recipient));
                    }
                } else {
                    error!("❌ Unexpected number of parameters for exactInputSingle: expected 8, got {}", decoded.len());
                }
            } else {
                error!("❌ Failed to decode exactInputSingle");
            }
        }

        // Decode exactOutputSingle
        "db3e2198" => {
            info!("🛠️ Decoding: exactOutputSingle");
            if let Ok(decoded) = abi.function("exactOutputSingle").and_then(|func| func.decode_input(&input[4..])) {
                if decoded.len() == 8 {
                    if let (
                        Token::Address(token_in),
                        Token::Address(token_out),
                        Token::Uint(_fee),
                        Token::Address(recipient),
                        Token::Uint(_deadline),
                        Token::Uint(amount_out),
                        Token::Uint(_amount_in_maximum),
                        Token::Uint(_sqrt_price_limit_x96),
                    ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4], &decoded[5], &decoded[6], &decoded[7])
                    {
                        info!("🛠️ Decoded exactOutputSingle successfully!");
                        return Some((*token_in, *token_out, *amount_out, *recipient));
                    }
                } else {
                    error!("❌ Unexpected number of parameters for exactOutputSingle: expected 8, got {}", decoded.len());
                }
            } else {
                error!("❌ Failed to decode exactOutputSingle");
            }
        }
        "ac9650d8" => {
            info!("🛠️ Ignoring: multicall");
            return None;
        }

        // New handlers for swap functions
        "38ed1739" => {  // swapExactTokensForTokens
            info!("🛠️ Decoding: swapExactTokensForTokens");
            if let Ok(decoded) = abi.function("swapExactTokensForTokens").and_then(|func| func.decode_input(&input[4..])) {
                if decoded.len() == 5 {
                    if let (
                        Token::Uint(amount_in),
                        Token::Uint(_amount_out_min),
                        Token::Array(path),
                        Token::Address(recipient),
                        Token::Uint(_deadline)
                    ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4]) {
                        let token_in = path[0].clone().into_address().unwrap();
                        let token_out = path[path.len() - 1].clone().into_address().unwrap();
                        return Some((token_in, token_out, *amount_in, *recipient));
                    }
                }
            }
        }

        "18cbafe5" => {  // swapExactETHForTokens
            info!("🛠️ Decoding: swapExactETHForTokens");
            if let Ok(decoded) = abi.function("swapExactETHForTokens").and_then(|func| func.decode_input(&input[4..])) {
                if decoded.len() == 4 {
                    if let (
                        Token::Uint(_amount_out_min),
                        Token::Array(path),
                        Token::Address(recipient),
                        Token::Uint(_deadline)
                    ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3]) {
                        let token_in = Address::zero(); // ETH
                        let token_out = path[path.len() - 1].clone().into_address().unwrap();
                        let amount_in = U256::from(0);  // Dynamic
                        return Some((token_in, token_out, amount_in, *recipient));
                    }
                }
            }
        }

        "e8e33700" => {  // addLiquidity
            info!("🛠️ Decoding: addLiquidity");
            if let Ok(decoded) = abi.function("addLiquidity").and_then(|func| func.decode_input(&input[4..])) {
                if decoded.len() == 8 {
                    if let (
                        Token::Address(token_a),
                        Token::Address(token_b),
                        Token::Uint(amount_a),
                        Token::Uint(amount_b),
                        Token::Uint(_amount_a_min),
                        Token::Uint(_amount_b_min),
                        Token::Address(recipient),
                        Token::Uint(_deadline)
                    ) = (&decoded[0], &decoded[1], &decoded[2], &decoded[3], &decoded[4], &decoded[5], &decoded[6], &decoded[7]) {
                        return Some((*token_a, *token_b, *amount_a + *amount_b, *recipient));
                    }
                }
            }
        }
        // Unknown function selector
        _ => {
            info!("❓ Unknown Function Selector: 0x{}", selector);
            info!("🔑 Raw Input Data: {:?}", hex::encode(&input));
        }
    }
    // Return None if no valid decoding occurred
    None
}

/// 💰 Simulate arbitrage opportunity based on detected DEX transaction
fn simulate_arbitrage(sushi_price: Option<U256>, uniswap_price: Option<U256>, amount_in: U256) -> Result<(), Box<dyn std::error::Error>> {
    //let gas_fee_eth = U256::from(1_000_000_u64); // Example gas fee in wei (0.000001 ETH)
    let gas_fee_eth = U256::from(0_u64); // assume 0 first
    if let (Some(sushi), Some(uni)) = (sushi_price, uniswap_price) {
        info!("Starting Simulate Arbitrage. GasEth: {}, Sushi: {}, Uni: {}", gas_fee_eth, sushi, uni);
        if sushi > uni {
            let profit = sushi.checked_sub(uni).unwrap_or_default().checked_sub(gas_fee_eth).unwrap_or_default();
            if profit > U256::zero() {
                println!("🚀 Arbitrage Opportunity Detected!");
                println!("🔹 Buy on Uniswap: {}", uni);
                println!("🔸 Sell on SushiSwap: {}", sushi);
                println!("💵 Profit (before gas): {}", profit);
            } else {
                error!("❌ No profitable arbitrage (before gas).");
            }
        } else if uni > sushi {
            let profit = uni.checked_sub(sushi).unwrap_or_default().checked_sub(gas_fee_eth).unwrap_or_default();
            if profit > U256::zero() {
                info!("🚀 Arbitrage Opportunity Detected!");
                info!("🔹 Buy on SushiSwap: {}", sushi);
                info!("🔸 Sell on Uniswap: {}", uni);
                info!("💵 Profit (before gas): {}", profit);
                info!("💵 Amount in: {}", amount_in);
            } else {
                error!("❌ No profitable arbitrage (before gas).");
            }
        } else {
            info!("⚖️ Prices are equal. No arbitrage.");
        }
    } else {
        error!("❌ Failed to fetch prices from one or both DEXs.");
    }

    Ok(())
}
/* ======== Fetch Full Transaction Details
    What It Does: 
    For every pending transaction hash received from the mempool or blockchain, the bot tries to fetch the full transaction details using get_transaction. Get transaction returns:

    When you fetch transaction data using get_transaction(hash) from an Ethereum node or using libraries like ethers-rs, web3.py, or other JSON-RPC clients, the returned transaction object (tx) typically includes the following fields:

    General Format of an Ethereum Transaction (eth_getTransactionByHash)
    Field	    Description
    -blockHash	    Hash of the block containing this transaction (null if pending).
    -blockNumber	Block number where this transaction was included (null if pending).
    -from	        Address of the sender.
    -to	            Address of the receiver or contract (null for contract creation).
    -gas	        Gas limit provided by the sender.
    -gasPrice	    Gas price in wei.
    -hash	        Hash of the transaction.
    -input	        The data payload (used for contract calls or empty for ETH transfers).
    -nonce	        Transaction count of the sender before this transaction.
    -r	            Signature part R (used in transaction signing).
    -s	            Signature part S (used in transaction signing).
    -v	            Recovery id for the signature.
    -transactionIndex	Index of the transaction within the block (null if pending).
    -value	        Amount of ETH transferred in wei (0 for contract calls).

	•	Issue Observed:
	•	Sometimes the fetched transaction is missing (Ok(None)), likely due to one of the following:
	•	Propagation Delay: The transaction hasn’t fully propagated to the node you’re connected to.
	•	Dropped Transactions: The transaction was dropped due to low gas fees or replacement.
	•	Rate Limiting/Provider Issues: The provider (e.g., Infura) may throttle requests if you’re exceeding its rate limits.
    •	Network Congestion: The Ethereum network is congested, and the transaction is stuck in the mempool.
    •	Transaction changed nonce stays the same but the transaction is replaced so the hash has changed.
    •	To handle these issues, the bot retries fetching the transaction up to five times with exponential backoff.

    ===========
    Recommended: 4 max_retries, 2000ms initial delay 
    4 retries with exponential backoff (2,4,6,8) because if the transaction is not found after 3 retries, it’s likely not going to be mined. 
    Average time for a block to processed in Ethereum is 13 seconds.
    ===========
    Future if we want to ensure we dont miss any transaction, we can use higher retry count 
    and lower delay time if we want to compete for arbitrage opportunities but we will need more transaction credits.
 */
async fn fetch_transaction(provider: Arc<Provider<Ws>>, tx_hash: H256,rate_limiter: Arc<Semaphore>) -> Option<Transaction> {
    let max_retries = 6; // Maximum number of retries 
    let mut attempt = 0;
    let mut delay = Duration::from_millis(40); // Initial delay is small so we dont miss transaction and it goes out of the pending block.
    let mut eror = 0;
    let permit: OwnedSemaphorePermit = rate_limiter.clone().acquire_owned().await.unwrap();
    // Enforce spacing (2ms per request for 500 requests/sec)
    sleep(Duration::from_millis(2)).await;

    while attempt < max_retries {
        API_TX_COUNT.fetch_add(1, Ordering::SeqCst);

        match provider.get_transaction(tx_hash).await {
            Ok(Some(tx)) => {
                if attempt == 0 {
                    //success on first attempt
                    SUCCESS_COUNT.fetch_add(1, Ordering::SeqCst);
                }else{
                    if eror == 0{
                        //see if retry actually works.
                        RETRY_COUNT.fetch_add(1, Ordering::SeqCst);
                    } else {
                        //see if after error there was a success
                        RETRY_ERR_COUNT.fetch_add(1, Ordering::SeqCst);
                    }
                }
                // Check if the transaction is mined
                if tx.block_hash.is_some() {
                    MINED_COUNT.fetch_add(1, Ordering::SeqCst);
                }
                debug!("Transaction fetched successfully on attempt {}", attempt);
                return Some(tx);
            }
            Ok(None) => {
                debug!(
                    "Transaction not found (attempt {}). Retrying in {:?}...",
                    attempt, delay
                );
            }
            Err(e) => {
                debug!(
                    "Error fetching transaction on attempt {}: {}. Retrying in {:?}...",
                    attempt, e, delay
                );
                eror+=1;
            }

        }
        sleep(delay).await;
        delay *= 6;
        attempt += 1;
    }
    debug!("Failed to fetch transaction after {} attempts", max_retries);

    drop(permit);
    API_TX_FAIL_COUNT.fetch_add(1, Ordering::SeqCst);

    None
}
/// 🔍 Fetch DEX Prices
async fn fetch_price(
    provider: &Arc<Provider<Ws>>,
    router: Address,
    dex_name: &str,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    fee_tier: Option<u32>,  // Only relevant for Uniswap V3
) -> Option<U256> {
    info!("==== 📞 Fetching price from {} ====", dex_name);
    API_TX_COUNT.fetch_add(1, Ordering::SeqCst);

    //set default value if None
    let fee_tier = fee_tier.unwrap_or(3000);

    // Setup Call Data
    let call_data = if dex_name == "Uniswap V3" {
        // Encode call for Uniswap V3 Quoter contract
        let function_selector = hex::decode("f7729d43").unwrap(); //quoteExactInputSingle
        let encoded_params = ethers::abi::encode(&[
            Token::Address(token_in),
            Token::Address(token_out),
            Token::Uint(U256::from(fee_tier)),
            Token::Uint(amount_in),  //amount_in
            Token::Uint(U256::zero()),  // sqrtPriceLimitx96 :No price limit
        ]);
        [function_selector, encoded_params].concat()
    // println!("-UniswapV3 Calldata-");
    } else {
        // Use Uniswap V2/SushiSwap logic with `getAmountsOut`
        let function_selector = hex::decode("d06ca61f").unwrap(); // `getAmountsOut`
        let path = vec![Token::Address(token_in), Token::Address(token_out)];
        let encoded_params = ethers::abi::encode(&[
            Token::Uint(amount_in),
            Token::Array(path),
        ]);
        [function_selector, encoded_params].concat()
        //println!("-UniswapV2 Calldata-");
    };

    // Replace quoter address instead of router address for uniswap v3
    let router = if dex_name == "Uniswap V3" {
        UNISWAP_V3_QUOTER.parse::<H160>().unwrap()
    } else {
        router
    };

    // Print the complete transaction request for debugging
    /*
    Here’s a breakdown of the key components:
	1.	Gas: This represents the amount of computational work required to execute the transaction. It depends on the complexity of the operation (e.g., calling a smart contract, swapping tokens).
	2.	Gas Price: This indicates the price per unit of gas in Gwei. It determines how much ETH you’re willing to pay for each unit of gas.
	3.	From = None: Since this is a read-only call (simulation) to fetch price (using .call()), you don’t need to specify a from address. This is fine in this context.
	4.	Value = Some(0): This refers to the amount of ETH sent along with the transaction. Since you are only fetching data (not making a swap or sending ETH), 0 ETH is correct.

    If this were a live transaction, specifying from, gas, and gas price would be mandatory. But for a simulation (call()), the current setup is valid.
    */

    debug!("fee_tier: {}", fee_tier);
    debug!("amount_in: {}", amount_in);
    debug!("No price limit:  0");
    debug!("router: {:?}", router);
    debug!("Call Data (Hex): {:?}", hex::encode(&call_data));

    let tx = TransactionRequest::new()
        .to(router)
        .data(call_data)
        .gas(U256::from(1_000_000))
        .value(U256::zero());

    debug!("Provider: {:?}", tx);

    let (token_out_name, token_out_decimals) = get_token_info(&token_out);

    match provider.call(&tx.into(), None).await {
        Ok(res) => {
            debug!("🔍 Raw Response: {:?}", res); // Inspect the raw response

            let price = if res.len() >= 128 {
                // Uniswap V2 (dynamic array)
                info!("🔍 Decoding Uniswap V2 response...");
                U256::from_big_endian(&res[96..128])
            } else if res.len() >= 32 {
                // Uniswap V3 (direct output)
                info!("🔍 Decoding Uniswap V3 response...");
                U256::from_big_endian(&res[0..32])
            } else {
                error!("❌ Response too short or unexpected format: {:?}", res);
                return None;
            };
    
            info!("token_out_decimals: {:?}", token_out_decimals);
    
            let normalized_price = price.checked_div(U256::exp10(token_out_decimals as usize))
                .unwrap_or(U256::zero());
    
            debug!("💱 {}, Price {}: {} | Raw Price: {:?}", dex_name, token_out_name, normalized_price, price);
    
            Some(normalized_price)
        }
        Err(e) => {
            error!("❌ {} call failed: {:?}", dex_name, e);
            None
        }
    }
}

/// Mapping token addresses to their token name and decimals
fn get_token_info(address: &Address) -> (String, u8) {
    let token_map: HashMap<Address, (&str, u8)> = HashMap::from([
        ("0x2eaa73bd0db20c64f53febea7b5f5e5bccc7fb8b".parse().unwrap(), ("ETH", 18)),
        ("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse().unwrap(), ("WETH", 18)),
        ("0x514910771AF9Ca656af840dff83E8264EcF986CA".parse().unwrap(), ("LINK", 18)),
        ("0x163f8C2467924be0ae7B5347228CABF260318753".parse().unwrap(), ("WLD", 18)),
        ("0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3".parse().unwrap(), ("ONDO", 18)),
        ("0x57e114B691Db790C35207b2e685D4A43181e6061".parse().unwrap(), ("ENA", 18)),
        ("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE".parse().unwrap(), ("SHIB", 18)),
        ("0x6982508145454Ce325dDbE47a25d4ec3d2311933".parse().unwrap(), ("PEPE", 18)),
        ("0x4C1746A800D224393fE2470C70A35717eD4eA5F1".parse().unwrap(), ("PLUME", 18)),
        ("0xE0f63A424a4439cBE457D80E4f4b51aD25b2c56C".parse().unwrap(), ("SPX", 8)),
        ("0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a".parse().unwrap(), ("MOG", 18)),
        ("0xA2cd3D43c775978A96BdBf12d733D5A1ED94fb18".parse().unwrap(), ("XCN", 18)),
        ("0xdac17f958d2ee523a2206206994597c13d831ec7".parse().unwrap(), ("USDT", 6)),
        ("0x6b3595068778dd592e39a122f4f5a5cf09c90fe2".parse().unwrap(), ("SUSHI", 18)),
        ("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599".parse().unwrap(), ("WBTC", 8)),
        ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".parse().unwrap(), ("USDC", 6)),
        ("0x6b175474e89094c44da98b954eedeac495271d0f".parse().unwrap(), ("DAI", 18)),
    ]);

    match token_map.get(address) {
        Some(&(name, decimals)) => (name.to_string(), decimals),
        None => ("NotListed".to_string(), 18), // Default to 18 decimals for unknown tokens
    }
}

/// Connect to Multiple Infura URLs (3)
async fn connect_to_infura(manager: Arc<InfuraManager>) -> Result<Provider<Ws>, Box<dyn std::error::Error>> {
    loop {
        let ws_url = manager.get_current_url();
        match Ws::connect(&ws_url).await {
            Ok(ws) => {
                info!("🔗 Connected to Infura: {}", ws_url);
                return Ok(Provider::new(ws));
            }
            Err(e) => {
                error!("❌ Failed to connect: {}. Retrying with a different API key...", e);
                manager.switch_url();
                sleep(Duration::from_secs(2)).await; // Wait before retrying
            }
        }
    }
}

/// Fetch the real-time price of a trading pair from Binance
///
/// # Arguments:
/// - `symbol`: The trading pair symbol (e.g., "BTCUSDT").
///
/// # Returns:
/// - `Ok(f64)`: The current price as a floating-point number if successful.
/// - `Err(Box<dyn Error>)`: An error message if the request fails.
async fn fetch_binance_price(symbol: &str) -> Result<f64, Box<dyn Error>> {
    let binance_url = "https://api.binance.com/api/v3/ticker/price";
    let request_url = format!("{}?symbol={}", binance_url, symbol);

    let response = reqwest::get(&request_url).await?;
    if response.status().is_success() {
        let data: Value = response.json().await?;
        let price: f64 = data["price"].as_str().unwrap().parse()?;
        Ok(price)
    } else {
        Err(format!(
            "Failed to fetch price for {}: {}",
            symbol,
            response.status()
        )
        .into())
    }
}

/// Fetch all valid trading pairs from Binance
///
/// # Returns:
/// - `Ok<HashSet<String>>`: A set of valid trading pairs if successful.
/// - `Err<Box<dyn Error>>`: An error message if the request fails.
async fn fetch_valid_pairs() -> Result<HashSet<String>, Box<dyn Error>> {
    let binance_url = "https://api.binance.com/api/v3/exchangeInfo";
    let response = reqwest::get(binance_url).await?;

    if response.status().is_success() {
        let data: Value = response.json().await?;
        let empty_vec = vec![]; // Create a persistent empty vector
        let symbols = data["symbols"].as_array().unwrap_or(&empty_vec); // Use a reference to the variable
        let valid_pairs: HashSet<String> = symbols
            .iter()
            .filter_map(|symbol| symbol["symbol"].as_str().map(|s| s.to_string()))
            .collect();
        Ok(valid_pairs)
    } else {
        Err(format!(
            "Failed to fetch valid pairs from Binance: {}",
            response.status()
        )
        .into())
    }
}

/* ========== 📚 Ethereum Arbitrage Detection Bot v1.0 ===========
📚 Ethereum Arbitrage Detection Bot v1.0

🎯 Purpose:
This bot connects to the Ethereum network in real-time and listens for pending transactions. It identifies transactions related to decentralized exchanges (DEXs) like Uniswap and SushiSwap, decodes them, and simulates potential arbitrage opportunities by comparing token prices between different DEXs.

🔍 Key Features:
- Connects to Ethereum via WebSocket using Infura.
- Monitors pending transactions and checks if they interact with known DEX router addresses.
- Decodes swap transactions to identify tokens being traded and the involved amounts.
- Simulates the potential arbitrage by comparing prices from Uniswap V2/V3 and SushiSwap.
- Logs any profitable opportunities.

🔧 Current Limitations:
- Works only on Ethereum Mainnet for ETH-based tokens.
- Scans transactions directly interacting with DEX routers (simple arbitrage).
- No multi-hop or advanced contract-level interaction detection (planned for future versions).

🌱 Future Enhancements:
- Support for multi-hop and internal contract call detection.
- Integration with centralized exchanges (CEXs) to find CEX-DEX arbitrage.
- Price simulation across multiple networks and tokens beyond ETH-based assets.
- Improved profit calculations, factoring in gas costs and slippage.

🚀 Version Progress:
- V1: Ethereum Mainnet, ETH-based tokens only.
- V2: Basic to-address detection for simple DEX arbitrage.
- V3: CEX and DEX interaction.
- V4: Multi-network arbitrage opportunities.
- V5: Enhanced profit calculation (gas fees, slippage, etc.).

============ */
// Spawn a task to periodically print the counter - this was overlapping the hashcount print.
/* 
    tokio::spawn(async move {
        loop {
            print!("\r| API Tx: {}", API_TX_COUNT.load(Ordering::SeqCst));
            io::stdout().flush().unwrap(); // Ensure the line updates immediately
            sleep(Duration::from_secs(300)).await;
        }
    });
*/