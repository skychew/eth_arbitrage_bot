static ERC20_ABI: &[u8] = include_bytes!("../../abi/erc20abi.json");

use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{TransactionRequest, Address, U256};
use std::sync::Arc;
use dotenv::dotenv;
use ethers::abi::{Abi,Token};
use std::io::Cursor;
use std::collections::HashSet;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    let infura_ws = std::env::var("ETH_WS_URL").expect("⚠️ ETH_WS_URL not set in .env");
    // Load the ABI from the embedded bytes
    let erc20_abi = Abi::load(Cursor::new(ERC20_ABI))?;
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

    // Connect to Ethereum Node
    let provider = Arc::new(Arc::new(Provider::<Ws>::connect(&infura_ws).await?));

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

    let token_out: Address = path.last().unwrap().clone().into_address().unwrap();
    let token_in: Address = path.first().unwrap().clone().into_address().unwrap();

    if !allowed_tokens.contains(&token_in) {
        println!("❌ Token In is not allowed: {:?}", token_in);
    }else{
        println!("TokenInListed: {:?}", token_in);
    }
    
    if !allowed_tokens.contains(&token_out) {
        println!("❌ Token Out is not allowed: {:?}", token_out);
    }else{
        println!("TokenOutListed: {:?}", token_out);
    }

    if allowed_tokens.contains(&token_in) && allowed_tokens.contains(&token_out) {
        println!("✅ Allowed Tokens Detected!");

        // Contract instances
        let contract_out = Contract::new(token_out, erc20_abi.clone(), provider.clone());
        let contract_in = Contract::new(token_in, erc20_abi.clone(), provider.clone());

        // Check if `token_out` is a valid ERC-20 token
        match check_erc20(&contract_out).await {
            Ok((name, symbol, decimals)) => {
                println!(
                    "✅ Valid ERC-20 Token Out: {} ({}) with {} decimals",
                    name, symbol, decimals
                );
            }
            Err(e) => {
                println!("⚠️ Invalid or Non-ERC-20 Token Detected: {:?}, Error: {}", token_out, e);
                return Ok(()); // Skip further processing
            }
        }
        
        // Check if `token_out` is a valid ERC-20 token
        match check_erc20(&contract_in).await {
            Ok((name, symbol, decimals)) => {
                println!(
                    "✅ Valid ERC-20 Token Out: {} ({}) with {} decimals",
                    name, symbol, decimals
                );
            }
            Err(e) => {
                println!("⚠️ Invalid or Non-ERC-20 Token Detected: {:?}, Error: {}", token_out, e);
                return Ok(()); // Skip further processing
            }
        }

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
        } else {
            println!("❌ Token pair not listed.Skipping...");
            return Ok(()); // Skip further processing
        }

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

/// Check if token is ERC-20
async fn check_erc20<P>(
    contract: &Contract<Arc<Provider<P>>>,
) -> Result<(String, String, u8), Box<dyn std::error::Error>>
where
    P: ethers::providers::JsonRpcClient + 'static,
{
    // Query `name`
    let name: String = contract.method::<(), String>("name", ())?.call().await?;

    // Query `symbol`
    let symbol: String = contract.method::<(), String>("symbol", ())?.call().await?;

    // Query `decimals`
    let decimals: u8 = contract.method::<(), u8>("decimals", ())?.call().await?;

    Ok((name, symbol, decimals))
}