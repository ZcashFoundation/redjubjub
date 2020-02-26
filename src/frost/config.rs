/// Configuration data for FROST shares.
pub struct Config {
    /// The total number of shares for threshold signatures.
    pub num_shares: usize,
    /// The number of shares required for signing.
    pub threshold: usize,
    /// The identifier for this specific share.
    pub share_id: usize,
}
