pub mod constants;
pub mod dto;
pub mod extra;
pub mod storage;

pub use constants::*;
pub use dto::*;
pub use extra::{LockedExtra, LockedExtraV1, MeltedExtra, MeltedExtraV1};
use serde::{Deserialize, Serialize};
use std::string::String;

// Common
// Mainnet
pub const ETHEREUM_MAINNET: u32 = 1;
pub const OPTIMISM_MAINNET: u32 = 10;
pub const POLYGON_MAINNET: u32 = 137;
pub const BINANCE_MAINNET: u32 = 56;
pub const FILECOIN_EVM_MAINNET: u32 = 314;
pub const ARBITRUM_MAINNET: u32 = 42161;
pub const ZKSYNC_ERA_MAINNET: u32 = 324;
pub const AVALANCHE_C_MAINNET: u32 = 43114;
pub const BASE_MAINNET: u32 = 8453;
pub const LINEA_MAINNET: u32 = 59144;
pub const PEGO_MAINNET: u32 = 20201022;
pub const QSZL_MAINNET: u32 = 7181;
pub const BEVM_MAINNET: u32 = 1501;
pub const OPBNB_MAINNET: u32 = 204;
pub const NAUTILUS_MAINNET: u32 = 22222;
pub const HECO_MAINNET: u32 = 128;
pub const METER_MAINNET: u32 = 82;
pub const SCROLL_MAINNET: u32 = 534352;
pub const TRON_MAINNET: u32 = 0x2b6653dc;
pub const COREDAO_MAINNET: u32 = 1116;
pub const X1_MAINNET: u32 = 196;
pub const SATOSHIVM_MAINNET: u32 = 3109;
pub const OLD_AINN_MAINNET: u32 = 2639;
pub const AINN_MAINNET: u32 = 2649;
pub const B2_MAINNET: u32 = 223;
pub const BITLAYER_MAINNET: u32 = 200901;
pub const ZKLINK_MAINNET: u32 = 810180;


// Testnet
pub const ETHEREUM_GOERLI: u32 = 5;
pub const OPTIMISM_GOERLI: u32 = 420;
pub const POLYGON_MUMBAI: u32 = 80001;
pub const BINANCE_TESTNET: u32 = 97;
pub const FILECOIN_EVM_TESTNET: u32 = 3141;
pub const FILECOIN_EVM_CALIBRATION: u32 = 314159;
pub const ARBITRUM_GOERLI: u32 = 421613;
pub const ETHEREUM_SEPOLIA: u32 = 11155111;
pub const ZKSYNC_GOERLI: u32 = 280;
pub const AVALANCHE_FUJI: u32 = 43113;
pub const BASE_GOERLI: u32 = 84531;
pub const LINEA_TESTNET: u32 = 59140;
pub const PEGO_TESTNET: u32 = 123456;
pub const BEVM_TESTNET: u32 = 1502;
pub const OPBNB_TESTNET: u32 = 5611;
pub const SCROLL_SEPOLIA: u32 = 534351;
pub const NAUTILUS_PROTEUS: u32 = 88002;
pub const METER_TESTNET: u32 = 83;
pub const TRON_SHASTA: u32 = 0x94a9059e;
pub const TRON_LOCAL: u32 = 0xc845df2f;
pub const COREDAO_TESTNET: u32 = 1115;
pub const X1_TESTNET: u32 = 195;
pub const SATOSHIVM_TESTNET: u32 = 3110;
pub const SATOSHIVM_DEVNET: u32 = 42420;
pub const OPTIMISM_SEPOLIA: u32 = 11155420;
pub const BASE_SEPOLIA: u32 = 84532;
pub const ENDURANCE_DEVNET: u32 = 6482;
pub const OLD_AINN_TESTNET: u32 = 2638;
pub const AINN_TESTNET: u32 = 2648;
pub const AINN_DEVNET: u32 = 2647;
pub const B2_HABITAT_TESTNET: u32 = 1123;
pub const TAKER_TESTNET: u32 = 2748;
pub const BITLAYER_TESTNET: u32 = 200810;
pub const ZKLINK_TESTNET: u32 = 810181;
pub const BOOL_EVM_BETA_TESTNET: u32 = 481;

pub const LOCAL_CHAIN: u32 = 31337;

// Defined by BOOL
// ChainId = sha2.hash256(chain_name)[..4] as u32
// Mainnet
// "Bitcoin-Mainnet"
pub const BITCOIN_MAINNET: u32 = 0xa0898816;
// "Solana-Mainnet"
pub const SOLANA_MAINNET: u32 = 0xfb99f4e7;
// "Aptos-Mainnet"
pub const APTOS_MAINNET: u32 = 0x1fcb566a;
// "Filecoin-Mainnet"
pub const FILECOIN_MAINNET: u32 = 0x4d25d7c9;
// "Dogecoin-Mainnet"
pub const DOGECOIN_MAINNET: u32 = 0xad6c4d97;
// "Starknet-Mainnet"
pub const STARKNET_MAINNET: u32 = 0x1cdfd9d0;
// "Sui-Mainnet"
pub const SUI_MAINNET: u32 = 0x098e30e0;
// "Bool-Alpha-Mainnet"
pub const BOOL_ALPHA_MAINNET: u32 = 0x678f3716;
// "Bifrost-Polkadot"
pub const BIFROST_POLKADOT: u32 = 0xaa9f7ce3;
// "Bifrost-Kusama"
pub const BIFROST_KUSAMA: u32 = 0x013f3768;
// "Crust-Mainnet"
pub const CRUST_MAINNET: u32 = 0x39003bef;
// "Ton-Mainnet"
pub const TON_MAINNET: u32 = 0xfbaee342;
// "Near-Mainnet"
pub const NEAR_MAINNET: u32 = 0x175c9227;

// Testnet
// "Bitcoin-Testnet"
pub const BITCOIN_TESTNET: u32 = 0x10340fc0;
// "Solana-Testnet"
pub const SOLANA_TESTNET: u32 = 0x43997816;
// "Solana-Devnet"
pub const SOLANA_DEVNET: u32 = 0x93cde8db;
// "Aptos_Testnet"
pub const APTOS_TESTNET: u32 = 0xf2b44907;
// "Filecoin-Testnet"
pub const FILECOIN_TESTNET: u32 = 0xc529e6ea;
// "Dogecoin-Testnet"
pub const DOGECOIN_TESTNET: u32 = 0x343b2383;
// "Starknet-Testnet"
pub const STARKNET_TESTNET: u32 = 0x6bac76ab;
// "Starknet-Testnet2"
pub const STARKNET_TESTNET2: u32 = 0xe86205aa;
// "Sui-Testnet"
pub const SUI_TESTNET: u32 = 0x7257a51b;
// "Sui-Devnet"
pub const SUI_DEVNET: u32 = 0x8ae3775b;
// "Bool-Local"
pub const BOOL_LOCAL: u32 = 0xe070ccdf;
// "Bool-Devnet"
pub const BOOL_DEVNET: u32 = 0x50ab69e2;
// "Bool-Testnet"
pub const BOOL_TESTNET: u32 = 0x87a87a5e;
// "Bifrost-Testnet"
pub const BIFROST_TESTNET: u32 = 0x1a046484;
// "Crust-Testnet"
pub const CRUST_TESTNET: u32 = 0x3a0476d5;
// "Ton-Testnet"
pub const TON_TESTNET: u32 = 0x9a7e9bdc;
// "Near-Testnet"
pub const NEAR_TESTNET: u32 = 0x15497ae7;

pub const CHAIN_IDS: [u32; 93] = [
    ETHEREUM_MAINNET,
    OPTIMISM_MAINNET,
    POLYGON_MAINNET,
    BINANCE_MAINNET,
    ETHEREUM_GOERLI,
    OPTIMISM_GOERLI,
    POLYGON_MUMBAI,
    BINANCE_TESTNET,
    FILECOIN_MAINNET,
    BITCOIN_MAINNET,
    BITCOIN_TESTNET,
    SOLANA_MAINNET,
    SOLANA_TESTNET,
    SOLANA_DEVNET,
    APTOS_MAINNET,
    APTOS_TESTNET,
    FILECOIN_TESTNET,
    FILECOIN_EVM_MAINNET,
    FILECOIN_EVM_TESTNET,
    ARBITRUM_GOERLI,
    ARBITRUM_MAINNET,
    ETHEREUM_SEPOLIA,
    DOGECOIN_MAINNET,
    DOGECOIN_TESTNET,
    ZKSYNC_ERA_MAINNET,
    ZKSYNC_GOERLI,
    LOCAL_CHAIN,
    STARKNET_MAINNET,
    STARKNET_TESTNET,
    STARKNET_TESTNET2,
    SUI_MAINNET,
    SUI_DEVNET,
    SUI_TESTNET,
    BOOL_LOCAL,
    BOOL_DEVNET,
    BOOL_TESTNET,
    BOOL_ALPHA_MAINNET,
    AVALANCHE_C_MAINNET,
    AVALANCHE_FUJI,
    BASE_MAINNET,
    BASE_GOERLI,
    LINEA_MAINNET,
    LINEA_TESTNET,
    PEGO_MAINNET,
    PEGO_TESTNET,
    QSZL_MAINNET,
    BEVM_MAINNET,
    BEVM_TESTNET,
    FILECOIN_EVM_CALIBRATION,
    BIFROST_POLKADOT,
    BIFROST_KUSAMA,
    BIFROST_TESTNET,
    CRUST_MAINNET,
    CRUST_TESTNET,
    OPBNB_MAINNET,
    OPBNB_TESTNET,
    SCROLL_SEPOLIA,
    SCROLL_MAINNET,
    NAUTILUS_MAINNET,
    NAUTILUS_PROTEUS,
    HECO_MAINNET,
    TON_MAINNET,
    TON_TESTNET,
    METER_MAINNET,
    METER_TESTNET,
    NEAR_MAINNET,
    NEAR_TESTNET,
    TRON_MAINNET,
    TRON_SHASTA,
    TRON_LOCAL,
    COREDAO_MAINNET,
    COREDAO_TESTNET,
    X1_MAINNET,
    X1_TESTNET,
    SATOSHIVM_MAINNET,
    SATOSHIVM_TESTNET,
    SATOSHIVM_DEVNET,
    OPTIMISM_SEPOLIA,
    BASE_SEPOLIA,
    ENDURANCE_DEVNET,
    OLD_AINN_MAINNET,
    OLD_AINN_TESTNET,
    AINN_MAINNET,
    AINN_TESTNET,
    AINN_DEVNET,
    B2_HABITAT_TESTNET,
    TAKER_TESTNET,
    B2_MAINNET,
    BITLAYER_MAINNET,
    BITLAYER_TESTNET,
    ZKLINK_MAINNET,
    ZKLINK_TESTNET,
    BOOL_EVM_BETA_TESTNET,
];

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[repr(u16)]
pub enum ChainType {
    #[default]
    Raw = 0,
    Fil = 1,
    Bsc = 2,
    Btc = 3,
    Eth = 4,
    Solana = 5,
    Aptos = 6,
    Starknet = 7,
    Sui = 8,
    Substrate = 9,
    Ton = 10,
    Near = 11,
    Tron = 12,
}

impl ChainType {
    pub fn from_chain_id(num: u32) -> Self {
        match num {
            ETHEREUM_MAINNET
            | OPTIMISM_MAINNET
            | POLYGON_MAINNET
            | BINANCE_MAINNET
            | ETHEREUM_GOERLI
            | OPTIMISM_GOERLI
            | POLYGON_MUMBAI
            | BINANCE_TESTNET
            | LOCAL_CHAIN
            | FILECOIN_EVM_MAINNET
            | FILECOIN_EVM_TESTNET
            | ARBITRUM_MAINNET
            | ARBITRUM_GOERLI
            | ETHEREUM_SEPOLIA
            | ZKSYNC_GOERLI
            | ZKSYNC_ERA_MAINNET
            | AVALANCHE_FUJI
            | AVALANCHE_C_MAINNET
            | BASE_MAINNET
            | BASE_GOERLI
            | LINEA_MAINNET
            | LINEA_TESTNET
            | PEGO_MAINNET
            | PEGO_TESTNET
            | QSZL_MAINNET
            | FILECOIN_EVM_CALIBRATION
            | BEVM_MAINNET
            | BEVM_TESTNET
            | OPBNB_MAINNET
            | OPBNB_TESTNET
            | SCROLL_SEPOLIA
            | SCROLL_MAINNET
            | NAUTILUS_MAINNET
            | NAUTILUS_PROTEUS
            | HECO_MAINNET
            | METER_MAINNET
            | METER_TESTNET
            | COREDAO_MAINNET
            | COREDAO_TESTNET
            | X1_MAINNET
            | X1_TESTNET
            | SATOSHIVM_DEVNET
            | SATOSHIVM_MAINNET
            | SATOSHIVM_TESTNET
            | OPTIMISM_SEPOLIA
            | BASE_SEPOLIA
            | ENDURANCE_DEVNET
            | OLD_AINN_MAINNET
            | OLD_AINN_TESTNET
            | AINN_MAINNET
            | AINN_TESTNET
            | AINN_DEVNET
            | B2_HABITAT_TESTNET
            | TAKER_TESTNET
            | B2_MAINNET
            | BITLAYER_MAINNET
            | BITLAYER_TESTNET
            | ZKLINK_MAINNET | ZKLINK_TESTNET
            | BOOL_EVM_BETA_TESTNET  => Self::Eth,
            BITCOIN_MAINNET | BITCOIN_TESTNET | DOGECOIN_MAINNET | DOGECOIN_TESTNET => Self::Btc,
            SOLANA_MAINNET | SOLANA_TESTNET | SOLANA_DEVNET => Self::Solana,
            FILECOIN_TESTNET | FILECOIN_MAINNET => Self::Fil,
            APTOS_MAINNET | APTOS_TESTNET => Self::Aptos,
            STARKNET_MAINNET | STARKNET_TESTNET | STARKNET_TESTNET2 => Self::Starknet,
            SUI_MAINNET | SUI_DEVNET | SUI_TESTNET => Self::Sui,
            BOOL_LOCAL | BOOL_DEVNET | BOOL_TESTNET | BOOL_ALPHA_MAINNET | BIFROST_POLKADOT
            | BIFROST_TESTNET | BIFROST_KUSAMA | CRUST_MAINNET | CRUST_TESTNET => Self::Substrate,
            TON_MAINNET | TON_TESTNET => Self::Ton,
            NEAR_MAINNET | NEAR_TESTNET => Self::Near,
            TRON_MAINNET | TRON_SHASTA | TRON_LOCAL => Self::Tron,
            _ => Self::Raw,
        }
    }
}

impl From<u16> for ChainType {
    fn from(num: u16) -> ChainType {
        match num {
            0 => ChainType::Raw,
            1 => ChainType::Fil,
            2 => ChainType::Bsc,
            3 => ChainType::Btc,
            4 => ChainType::Eth,
            5 => ChainType::Solana,
            6 => ChainType::Aptos,
            7 => ChainType::Starknet,
            8 => ChainType::Sui,
            9 => ChainType::Substrate,
            10 => ChainType::Ton,
            11 => ChainType::Near,
            12 => ChainType::Tron,
            _ => ChainType::Raw,
        }
    }
}

impl From<ChainType> for u16 {
    fn from(val: ChainType) -> u16 {
        val as u16
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub enum EngineType {
    #[default]
    ECDSA,
    EDDSA,
    BLS,
    SCHNORR,
    STARKNET,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
pub enum CmtTypeEx {
    #[default]
    Raw,
    Token,
    Rune,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TaprootData {
    #[default]
    None,
    // (tap_tweak_hash, tweaked_pk)
    Escape(Vec<u8>, Vec<u8>),
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    pub cid: u32,
    pub anchor: String,
    pub channel_id: u32,
    pub chain_id: u32,
    pub public_key: String,
    pub create_time: u32,
    pub engine: EngineType,
    pub cmt_type: CmtTypeEx,
    pub taproot_data: TaprootData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerReceiveParams {
    pub message: Vec<u8>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomNumberSendParams {
    pub message: Vec<u8>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncodeAbiParams {
    ReceiveMsg(MessengerReceiveParams),
    RandomNumber(RandomNumberSendParams),
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UpdateStatusParams {
    // btc committee list with (pubkey, chain_id, create_time, engine)
    pub btc_cmts: Vec<(String, u32, u32, EngineType, CmtTypeEx)>,
    // filecoin committee list with (pubkey, chain_id, engine)
    pub fil_cmts: Vec<(String, u32, EngineType)>,
    pub is_new_connect: bool,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SyncStatus {
    #[serde(rename = "startingBlock")]
    pub starting_block: i64,
    #[serde(rename = "currentBlock")]
    pub current_block: i64,
    #[serde(rename = "highestBlock")]
    pub highest_block: Option<i64>,
}

pub fn no_prefix<T: AsRef<str>>(data: T) -> String {
    data.as_ref()
        .strip_prefix("0x")
        .unwrap_or(data.as_ref())
        .to_string()
}
