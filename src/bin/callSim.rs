use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{Address, U256, TransactionRequest};
use ethers::abi::Token;
use std::sync::Arc;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let infura_ws = std::env::var("ETH_WS_URL").expect("⚠️ ETH_WS_URL not set in .env");

    let provider = Provider::<Ws>::connect(&infura_ws).await?;
    let provider = Arc::new(provider);

    println!("✅ Connected to Ethereum Node...");

    // SushiSwap Router Address
    let sushi_router: Address = "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f".parse()?;

    // Define token addresses (WETH → USDT)
    let weth: Address = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse()?;
    let usdt: Address = "0xdac17f958d2ee523a2206206994597c13d831ec7".parse()?;

    let amount_in = U256::exp10(18); // 1 WETH (10^18 wei)

    // Correct encoding for getAmountsOut(uint256 amountIn, address[] path)
    let call_data = ethers::abi::encode(&[
        Token::Uint(amount_in),
        Token::Array(vec![Token::Address(weth), Token::Address(usdt)]),
    ]);

    // Construct the transaction
    let tx = TransactionRequest::new()
        .to(sushi_router)
        .data(call_data)
        .gas(U256::from(1_000_000))  // High gas for simulation
        .value(U256::zero());        // No ETH sent

    println!("📞 Sending call to SushiSwap...");

    // Perform the call
    let result = provider.call(&tx.into(), None).await;

    match result {
        Ok(res) => {
            if res.len() >= 32 {
                let price = U256::from_big_endian(&res[0..32]);
                println!("💱 SushiSwap Price: {}", price);
            } else {
                println!("❌ Response too short: {:?}", res);
            }
        }
        Err(e) => {
            println!("❌ Call failed: {:?}", e);
        }
    }

    Ok(())
}