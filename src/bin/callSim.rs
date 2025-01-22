use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{TransactionRequest, Address, U256};
use std::sync::Arc;
use dotenv::dotenv;
use ethers::abi::Token;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    let infura_ws = std::env::var("ETH_WS_URL").expect("⚠️ ETH_WS_URL not set in .env");

    // Connect to Ethereum Node
    let provider = Provider::<Ws>::connect(&infura_ws).await?;
    let provider = Arc::new(provider);

    println!("✅ Connected to Ethereum Node...");

    // Router Addresses
    let sushi_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F".parse()?;
    let uniswap_router: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".parse()?;

    // Define token pair: WETH -> USDT
    let amount_in = U256::from_dec_str("1000000000000000000")?; // 1 WETH
    let path = vec![
        Token::Address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse()?), // WETH
        //Token::Address("0xdac17f958d2ee523a2206206994597c13d831ec7".parse()?), // USDT
        Token::Address("0xbbbb2d4d765c1e455e4896a64ba3883e914abbbb".parse()?),
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

    Ok(())
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
                println!("💱 {} Price: {}", dex_name, price);
                Some(price)
            } else {
                println!("❌ {} response too short: {:?}", dex_name, res);
                None
            }
        }
        Err(e) => {
            println!("❌ {} call failed: {:?}", dex_name, e);
            None
        }
    }
}

// 💰 Simulate Arbitrage
fn simulate_arbitrage(sushi_price: Option<U256>, uniswap_price: Option<U256>, amount_in: U256) -> Result<(), Box<dyn std::error::Error>> {
    let gas_fee_eth = U256::from(1_000_000_000_000_000u64); // Example gas fee in wei (0.001 ETH)

    if let (Some(sushi), Some(uni)) = (sushi_price, uniswap_price) {
        println!("🔍 Comparing prices...");
        if sushi > uni {
            let profit = sushi.checked_sub(uni).unwrap_or_default().checked_sub(gas_fee_eth).unwrap_or_default();
            if profit > U256::zero() {
                println!("🚀 Arbitrage Opportunity Detected!");
                println!("🔹 Buy on Uniswap: {}", uni);
                println!("🔸 Sell on SushiSwap: {}", sushi);
                println!("💵 Profit (after gas): {}", profit);
                println!("💵 Amount in: {}", amount_in);
            } else {
                println!("❌ No profitable arbitrage (after gas).");
            }
        } else if uni > sushi {
            let profit = uni.checked_sub(sushi).unwrap_or_default().checked_sub(gas_fee_eth).unwrap_or_default();
            if profit > U256::zero() {
                println!("🚀 Arbitrage Opportunity Detected!");
                println!("🔹 Buy on SushiSwap: {}", sushi);
                println!("🔸 Sell on Uniswap: {}", uni);
                println!("💵 Profit (after gas): {}", profit);
                println!("💵 Amount in: {}", amount_in);
            } else {
                println!("❌ No profitable arbitrage (after gas).");
            }
        } else {
            println!("⚖️ Prices are equal. No arbitrage.");
        }
    } else {
        println!("❌ Failed to fetch prices from one or both DEXs.");
    }

    Ok(())
}