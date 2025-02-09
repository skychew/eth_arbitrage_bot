use ethers::types::{H160, U256, Transaction};
use std::str::FromStr;
use std::collections::HashSet;
use ethers::utils::format_ether;
use std::sync::atomic::AtomicUsize;
use ethers::abi::Address;
use ethers::types::Address;
use std::cmp::Ordering;
use std::sync::atomic::Ordering;

static REVIEW_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOGIC1: AtomicUsize = AtomicUsize::new(0);
static LOGIC2: AtomicUsize = AtomicUsize::new(0);
static ARBITRAGE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv::dotenv().ok();

       
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
    // Define the list of DEX router addresses
    let dex_groups = vec![
        ("Uniswap", vec![
            ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".parse::<H160>().unwrap(), "Uniswap V2"),
            ("0xe592427a0aece92de3edee1f18e0157c05861564".parse::<H160>().unwrap(), "Uniswap V3"),
        ]),
        ("SushiSwap", vec![
            ("0xd9e1ce17f2641f24aE83637ab66a2cca9c378b9f".parse::<H160>().unwrap(), "SushiSwap"),
        ]),
    ];
        //hardcode transaction to check
    let transaction = Transaction {
        to: Some("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".parse::<H160>().unwrap()), // Uniswap V2
        from: "0x6b175474e89094c44da98b954eedeac495271d0f".parse::<H160>().unwrap(),
        value: U256::from(1000),
        gas_price: Some(U256::from(10)),
        ..Default::default()
    };

    let mut arbitrage_detected = false;
    let mut detected_dex_name = String::new();
    let mut matching_address = None;
    if let Some(transaction) = transaction {
        REVIEW_COUNT.fetch_add(1, Ordering::SeqCst);

        // Check both `to` and `from` addresses for the router address.
        if let Some((detected_dex_name_inner, m_address)) = [transaction.to, Some(transaction.from)]
            .into_iter()
            .flatten() // Filter out `None` values
            .find_map(|address| {
                dex_groups.iter().find_map(|(dex_name, addresses)| {
                    //Closure a type of mini function
                    if addresses.iter().any(|(dex_address, _)| dex_address == &address) {
                        Some(((*dex_name).to_string(), address)) // Return both dex_name and address
                        LOGIC1.fetch_add(1, Ordering::SeqCst);
                    } else {
                            None
                    }
                })
            })
        {
            arbitrage_detected = true;
            detected_dex_name = detected_dex_name_inner.to_string();
            matching_address =Some(m_address);
        }
        if let Some(to) = transaction.to {
            
            if let Some((dex_name, _)) = dex_groups.iter().find(|(_, addresses)| {
                addresses.iter().any(|(address, _)| address == &to)
            }) {
                arbitrage_detected = true;
                detected_dex_name = dex_name.to_string();
                matching_address = Some(to);
                LOGIC2.fetch_add(1, Ordering::SeqCst);
            }
        }
        if arbitrage_detected {
            ARBITRAGE_COUNT.fetch_add(1, Ordering::SeqCst);
            println!("++Listed DEX Router found!: {} (Address: {:?})", detected_dex_name, matching_address);
            println!("Hash : {:?}", tx_hash);
            println!("From : {:?}", transaction.from);
            println!("To   : {:?}", transaction.to);
            let gas_price = transaction.gas_price.map(|g| ethers::utils::format_units(g, "gwei").unwrap());
            println!("Gas Price: {} Gwei", gas_price.unwrap_or_else(|| "unknown".to_string()));
            println!("AMT ETH: {} ETH", format_ether(transaction.value));
            println!("Review Count: {} | Logic1: {} | Logic2: {} | Arbitrage: {}",
             REVIEW_COUNT.load(Ordering::SeqCst), 
             LOGIC1.load(Ordering::SeqCst), 
             LOGIC2.load(Ordering::SeqCst), 
             ARBITRAGE_COUNT.load(Ordering::SeqCst)
            );
        }
    }

    Ok(())
}
    