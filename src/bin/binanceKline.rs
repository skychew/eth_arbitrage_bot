
use reqwest;
use serde_json::Value;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let symbol = "BTCUSDT"; // Example trading pair

    println!("📡 Fetching current price for {}...", symbol);

    match fetch_binance_price(symbol).await {
        Ok(price) => {
            println!("💱 Current Price for {}: ${:.2}", symbol, price);
        }
        Err(e) => {
            eprintln!("❌ Error fetching price: {}", e);
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
    // Binance API endpoint for Ticker Price
    let binance_url = "https://api.binance.com/api/v3/ticker/price";

    // Construct the request URL
    let request_url = format!("{}?symbol={}", binance_url, symbol);

    // Make the API request
    let response = reqwest::get(&request_url).await?;
    if response.status().is_success() {
        // Parse the JSON response
        let data: Value = response.json().await?;
        // Extract the price as a floating-point number
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