use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{TransactionRequest, Address, U256};
use std::sync::Arc;
use dotenv::dotenv;
use ethers::abi::Token;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let infura_ws = std::env::var("ETH_WS_URL").expect("⚠️ ETH_WS_URL not set in .env");

    let provider = Provider::<Ws>::connect(&infura_ws).await?;
    let provider = Arc::new(provider);

    println!("✅ Connected to Ethereum Node...");

    // Router Addresses
    let sushi_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F".parse()?;
    let uniswap_router: Address = "0x7a250d5630b4cf539739df2c5dacab1e14a31957".parse()?;

    // Token Pair: WETH -> USDT
    let weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse()?;
    let usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7".parse()?;

    let amount_in = U256::from_dec_str("1000000000000000000")?; // 1 WETH

    // Simulate price fetch from both DEXs
    let sushi_price = get_price(&provider, sushi_router, weth, usdt, amount_in).await?;
    let uni_price = get_price(&provider, uniswap_router, weth, usdt, amount_in).await?;

    println!("🍣 SushiSwap Price: {}", sushi_price);
    println!("🦄 Uniswap Price: {}", uni_price);

    // Estimate gas cost (approx. 200,000 gas used for swaps)
    let gas_price = provider.get_gas_price().await?;
    let gas_limit = U256::from(200_000);
    let gas_cost = gas_price * gas_limit;

    println!("⛽ Estimated Gas Cost: {}", gas_cost);

    // Simulate Arbitrage
    if sushi_price > uni_price + gas_cost {
        let profit = sushi_price - uni_price - gas_cost;
        println!("💰 Arbitrage Opportunity: Buy on Uniswap 🦄, Sell on SushiSwap 🍣");
        println!("💵 Estimated Profit: {}", profit);
    } else if uni_price > sushi_price + gas_cost {
        let profit = uni_price - sushi_price - gas_cost;
        println!("💰 Arbitrage Opportunity: Buy on SushiSwap 🍣, Sell on Uniswap 🦄");
        println!("💵 Estimated Profit: {}", profit);
    } else {
        println!("❌ No Arbitrage Opportunity Found.");
    }

    Ok(())
}

// 🔍 Fetch Price from DEX
async fn get_price(
    provider: &Arc<Provider<Ws>>,
    dex_router: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
) -> Result<U256, Box<dyn std::error::Error>> {
    let function_selector = hex::decode("d06ca61f")?; // getAmountsOut
    let path = vec![
        Token::Address(token_in),
        Token::Address(token_out),
    ];

    let encoded_params = ethers::abi::encode(&[
        Token::Uint(amount_in),
        Token::Array(path),
    ]);

    let mut call_data = function_selector;
    call_data.extend(encoded_params);

    let tx = TransactionRequest::new()
        .to(dex_router)
        .data(call_data)
        .gas(U256::from(1_000_000))
        .value(U256::zero());

    let result = provider.call(&tx.into(), None).await?;

    if result.len() >= 64 {
        let price = U256::from_big_endian(&result[32..64]); // Last item in the array is the output token amount
        Ok(price)
    } else {
        Err("❌ Response too short".into())
    }
}