use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{TransactionRequest, Address, U256};
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use dotenv::dotenv;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    let infura_ws = env::var("INFURA_WS")?;
    
    // Connect to Ethereum Node
    let provider = Provider::<Ws>::connect(&infura_ws).await?;
    let provider = Arc::new(provider);

    println!("✅ Connected to Ethereum Node...");

    // SushiSwap Router Address
    let sushi_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F"
        .parse()
        .expect("Invalid SushiSwap Router address");

    // Sample call data from logs (verify if correct)
    let call_data = hex::decode("d06ca61f0000000000000000000000000000000000000000000000000000000067853b5900000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000f82d4fdf85f9da750000000000000000000000000000000000000000000000000000000000000042")
        .expect("Invalid call data");

    println!("📞 Sending call to SushiSwap...");

    // Construct the transaction
    let tx = TransactionRequest::new()
        .to(sushi_router)
        .data(call_data)
        .gas(U256::from(1_000_000)) // High gas for simulation
        .value(U256::zero());       // No ETH sent

    // Perform the call
    let result = provider.call(&tx, None).await;

    // Log the result
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