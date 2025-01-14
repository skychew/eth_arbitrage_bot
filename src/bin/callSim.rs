/*Working version
✅ Connected to Ethereum Node...
📞 Sending call to SushiSwap...
💱 SushiSwap Price: 32
*/

use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{TransactionRequest, Address, U256};
//use std::convert::TryFrom;
use std::sync::Arc;
//use tokio::time::{sleep, Duration};
use dotenv::dotenv;
//use std::env;
//use crate::abi::Token;
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

    // SushiSwap Router Address
    let sushi_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F"
        .parse()
        .expect("Invalid SushiSwap Router address");

    let amount_in = U256::from_dec_str("1000000000000000000")?; // 1 WETH
    
    let path = vec![
        Token::Address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".parse()?), // WETH
        Token::Address("0xdac17f958d2ee523a2206206994597c13d831ec7".parse()?), // USDT
    ];
    
    // Correct function selector for `getAmountsOut`
    let function_selector = hex::decode("d06ca61f")?;
    
    // ABI-encode the parameters
    let encoded_params = ethers::abi::encode(&[
        Token::Uint(amount_in),
        Token::Array(path),
    ]);
        
        // Combine selector and parameters
        let mut call_data = function_selector.clone();
        call_data.extend(encoded_params);

    println!("📞 Sending call to SushiSwap...");

    // Construct the transaction
    let tx = TransactionRequest::new()
        .to(sushi_router)
        .data(call_data)
        .gas(U256::from(1_000_000)) // High gas for simulation
        .value(U256::zero());       // No ETH sent

    // Perform the call
   // let result = provider.call(&tx, None).await;
   let result = provider.call(&tx.into(), None).await;

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