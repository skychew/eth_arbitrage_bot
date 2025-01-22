/*
Understanding the Current Arbitrage Strategy

The bot is designed to simulate arbitrage opportunities by monitoring pending Ethereum transactions and analyzing swaps on decentralized exchanges (DEXs) like Uniswap and SushiSwap.

Step-by-Step Breakdown of the Strategy

    1.	Subscribe to Pending Transactions
	    •	The bot connects to the Ethereum mempool using a WebSocket provider (Infura) and listens for pending transactions.
	    •	Every pending transaction hash is fetched and examined.
    2.	Filter Transactions by DEX Router Addresses
	    •	It checks if the transaction’s to address matches known DEX router addresses (e.g., Uniswap V2/V3 or SushiSwap routers).
	    •	If a transaction is sent to these routers, it’s likely a swap.
	3.	Decode Swap Transactions
	    •	The bot decodes the transaction input data to extract:
        •	    Token In (token_in)
        •	    Token Out (token_out)
        •	    Amount In (amount_in)
        •	    Recipient (recipient)
        •	It handles functions like:
            •	exactInput
            •	exactOutput
            •	exactInputSingle
            •	exactOutputSingle
	4.	Simulate Arbitrage
	    •	For detected swaps, the bot tries to simulate a trade on multiple DEXs (Uniswap and SushiSwap) by calling the call method (which doesn’t execute transactions but simulates them).
	    •	It encodes the swap call to fetch the expected output price on each DEX.
	    •	It compares the simulated buy price and sell price across the DEXs.
	5.	Profit Calculation
	    •	Profit is calculated as:

\text{Profit} = (\text{Sell Price} - \text{Buy Price}) - \text{Gas Cost}

	•	If the profit is positive, the bot logs that a profitable arbitrage opportunity exists.
    NEXTTODO:
*/
use ethers::prelude::*;
use ethers::providers::{Provider, Ws, StreamExt};
use ethers::utils::format_ether;
use std::sync::Arc;
use tokio::sync::Semaphore; //use semaphore to limit the number of concurrent requests 500 per second for Infura
use tokio;
use log::{info, warn, error, debug};
use log::LevelFilter; //declare here so that we can overwrite in command line
use std::fs::OpenOptions;
use env_logger::{Builder, Target};
use ethers::abi::{AbiParser, Abi, Token};
use ethers::types::{Bytes, U256};
//use std::collections::HashMap;

//use retry::{retry_async, delay::Exponential};
//use retry::OperationResult;
use ethers::types::{Transaction, H256};
use tokio::time::{sleep, Duration};

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

    // Connect to Ethereum provider
    let ws_url = std::env::var("ETH_WS_URL").expect("ETH_WS_URL must be set");
    info!("Connecting to Eth WebSocket: {}", ws_url);
    let provider = Provider::<Ws>::connect(ws_url).await?;
    let provider = Arc::new(provider);
    info!("✅ Eth Node Connected, listening...");

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

    /* ======== Subscribe to pending transactions
	•	What It Does: This connects to the Ethereum mempool and listens for all pending transactions (those broadcast but not yet mined into a block).
	•	Key Points:
	•	The subscription provides transaction hashes, not full transaction details.
	•	The subscription stream should continue indefinitely, feeding new transaction hashes as they appear.
    =========== */
    let mut stream = provider.subscribe_pending_txs().await?;
    let dex_addresses = vec![
        "0x7a250d5630b4cf539739df2c5dacab1e14a31957".parse()?, // Uniswap V2 Router
        "0xe592427a0aece92de3edee1f18e0157c05861564".parse()?, // Uniswap V3 Router
        "0xd9e1ce17f2641f24aE83637ab66a2cca9C378B9F".parse()?, // SushiSwap Router
    ];

    while let Some(tx_hash) = stream.next().await {
        debug!("Rcvd Pending Transaction: {:?}", tx_hash);
        /* ========
            •	What It Does:
                For every pending transaction hash received from the mempool, the bot tries to fetch the full transaction details using get_transaction.
            •	Key Points:
            •	The get_transaction function is a blocking call that waits for the transaction to be mined.
            •	The function retries up to five times with exponential backoff.
            •	Once the transaction is fetched, the bot checks if the transaction is a DEX swap by comparing the to address with known DEX router addresses.
            •	If the transaction is a DEX swap, the bot decodes the input data to extract the token addresses, amounts, and recipient.
            •	Finally, the bot calls simulate_arbitrage to check for profitable arbitrage opportunities.
            ===========
        */
        if let Some(transaction) = fetch_transaction(provider.clone(), tx_hash, rate_limiter.clone()).await {
            if let Some(to) = transaction.to {
                if dex_addresses.contains(&to) {
                    info!("DEX Transaction Detected!: {:?}", tx_hash);
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

                        // Router Addresses
                        let sushi_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F".parse()?;
                        let uniswap_router: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".parse()?;

                        // Define token pair: WETH -> USDT
                        //let amount_in = U256::from_dec_str("1000000000000000000")?; 
                        let path = vec![
                            Token::Address(token_in), 
                            Token::Address(token_out),
                        ];

                        // Function selector for getAmountsOut
                        let function_selector = hex::decode("d06ca61f")?;
                        let encoded_params = ethers::abi::encode(&[
                            Token::Uint(amount_in),
                            Token::Array(path.clone()),
                        ]);

                        // SushiSwap call data
                        let mut sushi_call_data = function_selector.clone();
                        sushi_call_data.extend(encoded_params.clone());

                        // Uniswap call data
                        let mut uniswap_call_data = function_selector.clone();
                        uniswap_call_data.extend(encoded_params);

                        // === SushiSwap Call ===
                        let sushi_price = fetch_price(&provider, sushi_router, sushi_call_data, "SushiSwap").await;

                        // === Uniswap Call ===
                        let uniswap_price = fetch_price(&provider, uniswap_router, uniswap_call_data, "Uniswap").await;

                        // === Simulate Arbitrage ===
                        simulate_arbitrage(sushi_price, uniswap_price, amount_in)?;
                    }
                }
            }
        }
    }

    Ok(())
}

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
    let gas_fee_eth = U256::from(1_000_000_000_000_000u64); // Example gas fee in wei (0.001 ETH)

    if let (Some(sushi), Some(uni)) = (sushi_price, uniswap_price) {
        info!("Starting Simulate Arbitrage...");
        if sushi > uni {
            let profit = sushi.checked_sub(uni).unwrap_or_default().checked_sub(gas_fee_eth).unwrap_or_default();
            if profit > U256::zero() {
                info!("🚀 Arbitrage Opportunity Detected!");
                info!("🔹 Buy on Uniswap: {}", uni);
                info!("🔸 Sell on SushiSwap: {}", sushi);
                info!("💵 Profit (after gas): {}", profit);
            } else {
                println!("❌ No profitable arbitrage (after gas).");
            }
        } else if uni > sushi {
            let profit = uni.checked_sub(sushi).unwrap_or_default().checked_sub(gas_fee_eth).unwrap_or_default();
            if profit > U256::zero() {
                info!("🚀 Arbitrage Opportunity Detected!");
                info!("🔹 Buy on SushiSwap: {}", sushi);
                info!("🔸 Sell on Uniswap: {}", uni);
                info!("💵 Profit (after gas): {}", profit);
                info!("💵 Amount in: {}", amount_in);
            } else {
                info!("❌ No profitable arbitrage (after gas).");
            }
        } else {
            info!("⚖️ Prices are equal. No arbitrage.");
        }
    } else {
        info!("❌ Failed to fetch prices from one or both DEXs.");
    }

    Ok(())
}
/* ======== Fetch Full Transaction Details
	•	What It Does: 
        For every pending transaction hash received from the mempool, the bot tries to fetch the full transaction details using get_transaction.
	•	Issue Observed:
	•	Sometimes the fetched transaction is missing (Ok(None)), likely due to one of the following:
	•	Propagation Delay: The transaction hasn’t fully propagated to the node you’re connected to.
	•	Dropped Transactions: The transaction was dropped due to low gas fees or replacement.
	•	Rate Limiting/Provider Issues: The provider (e.g., Infura) may throttle requests if you’re exceeding its rate limits.
    •	Network Congestion: The Ethereum network is congested, and the transaction is stuck in the mempool.
    •	To handle these issues, the bot retries fetching the transaction up to five times with exponential backoff.
    ===========
    Recommended: 4 max_retries, 5000ms initial delay (5 second)
    4 retries with exponential backoff (5s, 10s, 20s, 40s) because if the transaction is not found after 3 retries, it’s likely not going to be mined. 
    Average time for a block to processed in Ethereum is 13 seconds.
    ===========
    Future if we want to ensure we dont miss any transaction, we can use higher retry count 
    and lower delay time if we want to compete for arbitrage opportunities but we will need more transaction credits.
 */
async fn fetch_transaction(provider: Arc<Provider<Ws>>, tx_hash: H256,rate_limiter: Arc<Semaphore>) -> Option<Transaction> {
    let max_retries = 4; // Maximum number of retries 
    let mut attempt = 0;
    let mut delay = Duration::from_millis(50); // Initial delay

    // Acquire a permit from the rate limiter
    let _permit = rate_limiter.acquire().await.unwrap();

    while attempt < max_retries {
        attempt += 1;

        match provider.get_transaction(tx_hash).await {
            Ok(Some(tx)) => {
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
            }
        }

        // Wait before retrying
        sleep(delay).await;
        delay *= 2; // Exponential backoff
    }

    debug!("Failed to fetch transaction after {} attempts", max_retries);
    None
}

// 🔍 Fetch DEX Prices
async fn fetch_price(
    provider: &Arc<Provider<Ws>>,
    router: Address,

    call_data: Vec<u8>,
    dex_name: &str,
) -> Option<U256> {
    println!("📞 Fetching price from {}...", dex_name);

    let tx = TransactionRequest::new()
        .to(router)
        .data(call_data)
        .gas(U256::from(1_000_000))
        .value(U256::zero());

    match provider.call(&tx.into(), None).await {
        Ok(res) => {
            if res.len() >= 32 {
                let price = U256::from_big_endian(&res[0..32]);
                info!("💱 {} Price: {}", dex_name, price);
                Some(price)
            } else {
                warn!("❌ {} response too short: {:?}", dex_name, res);
                None
            }
        }
        Err(e) => {
            error!("❌ {} call failed: {:?}", dex_name, e);
            None
        }
    }
}