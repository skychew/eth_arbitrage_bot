# 🚀 Ethereum Arbitrage Bot

This is a Rust-based Ethereum arbitrage bot that connects to an Ethereum node using WebSockets (Infura/Alchemy), monitors mempool transactions, and interacts with decentralized exchanges (DEXs) like Uniswap CEXs like Binance.

/*
📚 Ethereum Arbitrage Detection Bot v1.0

🎯 Purpose:
This bot connects to the Ethereum network in real-time and listens for pending transactions. It identifies transactions related to decentralized exchanges (DEXs) like Uniswap and SushiSwap, decodes them, and simulates potential arbitrage opportunities by comparing token prices between different DEXs.

🔍 Key Features:
- Connects to Ethereum via WebSocket using Infura.
- Monitors pending transactions and checks if they interact with known DEX router addresses.
- Decodes swap transactions to identify tokens being traded and the involved amounts.
- Simulates the potential arbitrage by comparing prices from Uniswap V2/V3 and SushiSwap.
- Logs any profitable opportunities.

🔧 Current Limitations:
- Works only on Ethereum Mainnet for ETH-based tokens.
- Scans transactions directly interacting with DEX routers (simple arbitrage).
- No multi-hop or advanced contract-level interaction detection (planned for future versions).

🌱 Future Enhancements:
- Support for multi-hop and internal contract call detection.
- Integration with centralized exchanges (CEXs) to find CEX-DEX arbitrage.
- Price simulation across multiple networks and tokens beyond ETH-based assets.
- Improved profit calculations, factoring in gas costs and slippage.

🚀 Version Progress:
- V1: Ethereum Mainnet, ETH-based tokens only.
- V2: Basic to-address detection for simple DEX arbitrage.
- V3: CEX and DEX interaction.
- V4: Multi-network arbitrage opportunities.
- V5: Enhanced profit calculation (gas fees, slippage, etc.).

*/



## 📦 Requirements

- Rust (`1.65+`)
- Ethereum RPC Node (Infura)
- Hetzner Cloud Server
