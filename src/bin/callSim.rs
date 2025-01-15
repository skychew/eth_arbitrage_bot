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

    // Define Router Addresses
    let sushi_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F"
        .parse()
        .expect("Invalid SushiSwap Router address");

    let uniswap_router: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        .parse()
        .expect("Invalid Uniswap Router address");

    // Define the token pair WETH -> USDT
    let amount_in = U256::from_dec_str("1000000000000000000")?; // 1 WETH
    
    let path = vec![
        Token::Address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse()?), // WETH
        Token::Address("0xdac17f958d2ee523a2206206994597c13d831ec7".parse()?), // USDT
    ];
    
    // Function selector for getAmountsOut
    let function_selector = hex::decode("d06ca61f")?;
    let encoded_params = ethers::abi::encode(&[
        Token::Uint(amount_in),
        Token::Array(path.clone()),  // Clone path for Uniswap reuse
    ]);
    
    // SushiSwap call data
    let mut sushi_call_data = function_selector.clone();
    sushi_call_data.extend(encoded_params.clone());

    // Uniswap call data
    let mut uniswap_call_data = function_selector.clone();
    uniswap_call_data.extend(encoded_params);

    // === SushiSwap Call ===
    println!("📞 Sending call to SushiSwap...");
    let sushi_tx = TransactionRequest::new()
        .to(sushi_router)
        .data(sushi_call_data)
        .gas(U256::from(1_000_000))
        .value(U256::zero());

    let sushi_result = provider.call(&sushi_tx.into(), None).await;

    match sushi_result {
        Ok(res) => {
            if res.len() >= 32 {
                let price = U256::from_big_endian(&res[0..32]);
                println!("💱 SushiSwap Price: {}", price);
            } else {
                println!("❌ SushiSwap response too short: {:?}", res);
            }
        }
        Err(e) => {
            println!("❌ SushiSwap call failed: {:?}", e);
        }
    }

    // === Uniswap Call ===
    println!("📞 Sending call to Uniswap...");
    let uniswap_tx = TransactionRequest::new()
        .to(uniswap_router)
        .data(uniswap_call_data)
        .gas(U256::from(1_000_000))
        .value(U256::zero());

    let uniswap_result = provider.call(&uniswap_tx.into(), None).await;

    match uniswap_result {
        Ok(res) => {
            if res.len() >= 32 {
                let price = U256::from_big_endian(&res[0..32]);
                println!("💱 Uniswap Price: {}", price);
            } else {
                println!("❌ Uniswap response too short: {:?}", res);
            }
        }
        Err(e) => {
            println!("❌ Uniswap call failed: {:?}", e);
        }
    }

    Ok(())
}