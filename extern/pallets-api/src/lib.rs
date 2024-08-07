pub mod client;
pub mod event_watcher;
pub mod query_committee;
pub mod query_facility;
pub mod query_mining;
pub mod query_channel;
pub mod query_oracle;
pub mod query_timestamp;
pub mod query_system;
pub mod query_rpc;
pub mod submit_committee;
pub mod submit_facility;
pub mod submit_mining;
pub mod submit_channel;
pub mod submit_oracle;
pub mod submit_ethereum;
pub mod submit_rpc;

pub use query_committee::*;
pub use query_facility::*;
pub use query_mining::*;
pub use query_channel::*;
pub use query_oracle::*;
pub use query_rpc::*;
pub use submit_committee::*;
pub use submit_facility::*;
pub use submit_mining::*;
pub use submit_channel::*;
pub use submit_oracle::*;
pub use submit_ethereum::*;
pub use submit_rpc::*;
pub use subxt::constants::Address;
pub use subxt::{error::RpcError, Error, events::EventDetails, subxt, JsonRpseeError};
pub use subxt::tx::{BoolSigner, SecretKey};
pub use crate::client::BoolConfig;
pub use subxt::events::StaticEvent;
use node_primitives::CustomError;

/// use subxt cli to update metadata 'subxt metadata --url http://127.0.0.1:9933 --version 14 -f bytes > metadata.scale'
#[subxt::subxt(
    runtime_metadata_path = "./metadata.scale.reg",
    derive_for_all_types = "Eq, PartialEq, Clone, Debug",
)]
pub mod bool {}

pub type BoolSubClient = client::SubClient<BoolConfig, BoolSigner<BoolConfig>>;

#[derive(Debug, PartialEq)]
pub enum CommitteeEvent {
    StartCommittee,
    InitialCommittee,
    AllowFork,
    StartFork,
    CommitteeCreateFinished,
    ApplyEpochChange,
    NewEpochCandidate,
    RecoverFork,
    CommitteeStartWork,
    StopCommittee,
    RefreshAssets,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum ChannelEvent {
    NewTransaction,
    SubmitTransaction,
    Connection,
    NewSourceHash,
    CreateNewTx,
    RefreshInscription,
    SignRefresh,
    SubmitRefresh,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum MinningEvent {
    NewChallenge,
    Heartbeat,
    DeviceJoinService,
    DeviceTryExitService,
    DeviceExitService,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum OracleEvent {
    TriggerSign,
    NewRandomNumber,
    NewBrc20IndexData,
    SubmitBrc20ConsensusResult,
    ReEmitBrc20ConsensusResult,
    Brc20OracleRequest,
    Brc20OracleSignResult,
    Unknown,
}


impl std::str::FromStr for CommitteeEvent {
    type Err = ();
    fn from_str(input: &str) -> Result<CommitteeEvent, Self::Err> {
        match input {
            "StartCommittee" => Ok(CommitteeEvent::StartCommittee),
            "InitialCommittee" => Ok(CommitteeEvent::InitialCommittee),
            "AllowFork" => Ok(CommitteeEvent::AllowFork),
            "StartFork" => Ok(CommitteeEvent::StartFork),
            "CommitteeCreateFinished" => Ok(CommitteeEvent::CommitteeCreateFinished),
            "ApplyEpochChange" => Ok(CommitteeEvent::ApplyEpochChange),
            "NewEpochCandidate" => Ok(CommitteeEvent::NewEpochCandidate),
            "RecoverFork" => Ok(CommitteeEvent::RecoverFork),
            "CommitteeStartWork" => Ok(CommitteeEvent::CommitteeStartWork),
            "StopCommittee" => Ok(CommitteeEvent::StopCommittee),
            "RefreshAssets" => Ok(CommitteeEvent::RefreshAssets),
            _ => Ok(CommitteeEvent::Unknown),
        }
    }
}

impl std::str::FromStr for ChannelEvent {
    type Err = ();
    fn from_str(input: &str) -> Result<ChannelEvent, Self::Err> {
        match input {
            "NewTransaction" => Ok(ChannelEvent::NewTransaction),
            "SubmitTransaction" => Ok(ChannelEvent::SubmitTransaction),
            "Connection" => Ok(ChannelEvent::Connection),
            "NewSourceHash" => Ok(ChannelEvent::NewSourceHash),
            "CreateNewTx" => Ok(ChannelEvent::CreateNewTx),
            "RefreshInscription" => Ok(ChannelEvent::RefreshInscription),
            "SignRefresh" => Ok(ChannelEvent::SignRefresh),
            "SubmitRefresh" => Ok(ChannelEvent::SubmitRefresh),
            _ => Ok(ChannelEvent::Unknown),
        }
    }
}

impl std::str::FromStr for MinningEvent {
    type Err = ();
    fn from_str(input: &str) -> Result<MinningEvent, Self::Err> {
        match input {
            "NewChallenge" => Ok(MinningEvent::NewChallenge),
            "Heartbeat" => Ok(MinningEvent::Heartbeat),
            "DeviceJoinService" => Ok(MinningEvent::DeviceJoinService),
            "DeviceTryExitService" => Ok(MinningEvent::DeviceTryExitService),
            "DeviceExitService" => Ok(MinningEvent::DeviceExitService),
            _ => Ok(MinningEvent::Unknown),
        }
    }
}

impl std::str::FromStr for OracleEvent {
    type Err = ();
    fn from_str(input: &str) -> Result<OracleEvent, Self::Err> {
        match input {
            "TriggerSign" => Ok(OracleEvent::TriggerSign),
            "NewRandomNumber" => Ok(OracleEvent::NewRandomNumber),
            "NewBrc20IndexData" => Ok(OracleEvent::NewBrc20IndexData),
            "SubmitBrc20ConsensusResult" => Ok(OracleEvent::SubmitBrc20ConsensusResult),
            "ReEmitBrc20ConsensusResult" => Ok(OracleEvent::ReEmitBrc20ConsensusResult),
            "Brc20OracleRequest" => Ok(OracleEvent::Brc20OracleRequest),
            "Brc20OracleSignResult" => Ok(OracleEvent::Brc20OracleSignResult),
            _ => Ok(OracleEvent::Unknown),
        }
    }
}

pub(crate) fn convert_to_custom_error(custom: u8) -> String {
    let err = CustomError::from_num(custom);
    err.to_string()
}

pub(crate) fn handle_custom_error(error: Error) -> String {
    if let Error::Rpc(RpcError::ClientError(e)) = error {
        let err = e.to_string();
        parse_custom_err_from_string_err(err)
    } else {
        error.to_string()
    }
}

fn parse_custom_err_from_string_err(err: String) -> String {
    // only try to extract 'custom number', will return input if parse error
    let v: Vec<&str> = err.split("Custom error: ").collect();
    if v.len() == 2 {
        let vv: Vec<&str> = v[1].split('\"').collect();
        if vv.len() == 2 {
            if let Ok(num) = vv[0].parse::<u8>() {
                return convert_to_custom_error(num)
            }
        }
    }
    err
}
