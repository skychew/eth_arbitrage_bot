# 🚀 Ethereum Arbitrage Bot

This is a Rust-based Ethereum arbitrage bot that connects to an Ethereum node using WebSockets (Infura/Alchemy), monitors mempool transactions, and interacts with decentralized exchanges (DEXs) like Uniswap.

## 📦 Requirements

- Rust (`1.65+`)
- Ethereum RPC Node (e.g., Infura, Alchemy)
- Hetzner Cloud Server (Recommended for deployment)

## 🔑 Environment Variables

Create a `.env` file with the following variables:

```env
ETH_RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
ETH_WS_URL=wss://mainnet.infura.io/ws/v3/YOUR_PROJECT_ID
PRIVATE_KEY=your_wallet_private_key