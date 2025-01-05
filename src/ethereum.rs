use ethers::prelude::*;
use std::sync::Arc;

pub async fn fetch_latest_block(provider: Arc<Provider<Ws>>) -> Result<U64, ProviderError> {
    provider.get_block_number().await
}