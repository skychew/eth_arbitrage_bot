use std::env;

pub struct Config {
    pub eth_rpc_url: String,
    pub eth_ws_url: String,
    pub private_key: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            eth_rpc_url: env::var("ETH_RPC_URL").expect("ETH_RPC_URL must be set"),
            eth_ws_url: env::var("ETH_WS_URL").expect("ETH_WS_URL must be set"),
            private_key: env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set"),
        }
    }
}