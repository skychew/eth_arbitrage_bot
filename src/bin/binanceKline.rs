use reqwest;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Token symbols and their addresses
    let tokens: HashMap<&str, &str> = HashMap::from([
        ("0x2eaa73bd0db20c64f53febea7b5f5e5bccc7fb8b", "ETH"),
        ("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "WETH"),
        ("0x514910771AF9Ca656af840dff83E8264EcF986CA", "LINK"),
        ("0x163f8C2467924be0ae7B5347228CABF260318753", "WLD"),
        ("0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3", "ONDO"),
        ("0x57e114B691Db790C35207b2e685D4A43181e6061", "ENA"),
        ("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", "SHIB"),
        ("0x6982508145454Ce325dDbE47a25d4ec3d2311933", "PEPE"),
        ("0x4C1746A800D224393fE2470C70A35717eD4eA5F1", "PLUME"),
        ("0xE0f63A424a4439cBE457D80E4f4b51aD25b2c56C", "SPX"),
        ("0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a", "MOG"),
        ("0xA2cd3D43c775978A96BdBf12d733D5A1ED94fb18", "XCN"),
        ("0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT"),
        ("0x6b3595068778dd592e39a122f4f5a5cf09c90fe2", "SUSHI"),
        ("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", "WBTC"),
        ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC"),
        ("0x6b175474e89094c44da98b954eedeac495271d0f", "DAI"),
    ]);

    println!("📡 Fetching valid trading pairs from Binance...");
    let valid_pairs = fetch_valid_pairs().await?;

    println!("📡 Fetching current prices for all valid trading pairs...");
    let symbols: Vec<&str> = tokens.values().cloned().collect();
    let request_interval = Duration::from_millis(100); // Throttle requests to 10 per second

    for i in 0..symbols.len() {
        for j in 0..symbols.len() {
            if i != j {
                let symbol = format!("{}{}", symbols[i], symbols[j]);
                if valid_pairs.contains(&symbol) {
                    match fetch_binance_price(&symbol).await {
                        Ok(price) => {
                            println!("💱 Current Price for {}: ${:.2}", symbol, price);
                        }
                        Err(e) => {
                            eprintln!("❌ Error fetching price for {}: {}", symbol, e);
                        }
                    }
                    // Add a delay to throttle requests
                    sleep(request_interval).await;
                } else {
                    println!("❌ Pair {} is not valid on Binance.", symbol);
                }
            }
        }
    }

    Ok(())
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