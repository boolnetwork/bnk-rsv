//! EventWatcher for Bool node witch BoolSubClient.
use tokio::sync::mpsc::Sender;
use subxt::Config;
use subxt::events::EventDetails;
use std::cmp::Ordering;
use crate::{BoolConfig, BoolSubClient as SubClient};

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub enum WatcherMode {
    #[default]
    Both,
    Latest,
    Finalized,
}

#[derive(Clone)]
pub struct EventWatcher {
    log_target: String,
    client: SubClient,
    finalize_delay: u32,
    handler: Sender<(WatcherMode, Vec<EventDetails<BoolConfig>>)>,
    latest: u32,
    finalized: u32,
}

impl EventWatcher {
    pub fn new(
        log_target: &str,
        client: SubClient,
        finalize_delay: u32,
        handler: Sender<(WatcherMode, Vec<EventDetails<BoolConfig>>)>,
    ) -> Self {
        EventWatcher {
            log_target: log_target.to_string(),
            client,
            finalize_delay,
            handler,
            latest: 0,
            finalized: 0,
        }
    }

    pub fn run(mut self, mode: WatcherMode) {
        tokio::spawn(async move {
            log::info!(target: &self.log_target, "start event watcher with finalize_delay {}", self.finalize_delay);
            // initialize latest block number
            loop {
                match get_block_number(self.client.clone(), None).await {
                    Ok(block_number) => {
                        self.latest = block_number.checked_sub(1).unwrap_or(0);
                        break;
                    }
                    Err(e) => log::error!(target: &self.log_target, "initialize latest block: {e:?}"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            // initialize finalized block number
            loop {
                match get_block_hash(self.client.clone(), WatcherMode::Finalized).await {
                    Ok(hash) => match get_block_number(self.client.clone(), Some(hash)).await {
                        Ok(block_number) => {
                            let block_number = block_number.checked_sub(1).unwrap_or(0);
                            self.finalized = block_number.max(self.latest.checked_sub(self.finalize_delay).unwrap_or(0) );
                            break;
                        }
                        Err(e) => log::error!(target: &self.log_target, "initialize finalized block: {e:?}"),
                    }
                    Err(e) => log::error!(target: &self.log_target, "initialize finalized block: {e:?}"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }

            loop {
                if matches!(mode, WatcherMode::Latest | WatcherMode::Both) {
                    match get_block_number(self.client.clone(), None).await {
                        Ok(current_number) => {
                            match self.latest.cmp(&current_number) {
                                Ordering::Less => {
                                    log::trace!(target: &self.log_target, "handle latest block from {:?} to {current_number}", self.latest);
                                    self.handle_blocks_events(self.latest + 1, current_number, WatcherMode::Latest).await;
                                    self.latest = current_number;
                                    // we need to update finalized block to "latest - finalize_delay"
                                    self.finalized = (self.finalized).max(self.latest.checked_sub(self.finalize_delay).unwrap_or(0));
                                }
                                Ordering::Equal => log::debug!(target: &self.log_target, "caught up with the best latest block height: {current_number:?}"),
                                Ordering::Greater => log::debug!(target: &self.log_target, "latest block height is rolled back, from {:?} to {current_number:?}", self.latest),
                            }
                        },
                        Err(e) => log::error!(target: &self.log_target, "get latest block: {e:?}"),
                    };
                }

                if matches!(mode, WatcherMode::Finalized | WatcherMode::Both) {
                    // for Finalized mode, we need to update latest block number
                    if matches!(mode, WatcherMode::Finalized) {
                        match get_block_number(self.client.clone(), None).await {
                            Ok(latest_bumber) => {
                                self.latest = latest_bumber;
                                // we need to update finalized block to "latest - finalize_delay"
                                self.finalized = (self.finalized).max(self.latest.checked_sub(self.finalize_delay).unwrap_or(0));
                            },
                            Err(e) => log::error!(target: &self.log_target, "get latest block: {e:?}"),
                        };
                    }

                    match get_block_hash(self.client.clone(), WatcherMode::Finalized).await {
                        Ok(hash) => match get_block_number(self.client.clone(), Some(hash)).await {
                            Ok(current_number) => {
                                match self.finalized.cmp(&current_number) {
                                    Ordering::Less => {
                                        log::trace!(target: &self.log_target, "handle finalized block from {:?} to {current_number}", self.finalized);
                                        self.handle_blocks_events(self.finalized + 1, current_number, WatcherMode::Finalized).await;
                                        self.finalized = current_number;
                                    }
                                    Ordering::Equal => log::debug!(target: &self.log_target, "caught up with the best finalized block height: {current_number:?}"),
                                    Ordering::Greater => log::warn!(target: &self.log_target, "finalized block height is rolled back, local: {:?}, chain: {current_number:?}", self.finalized),
                                }
                            },
                            Err(e) => log::error!(target: &self.log_target, "get finalized block number err: {e:?}"),
                        },
                        Err(e) => log::error!(target: &self.log_target, "get finalized block hash err: {e:?}"),
                    };
                }

                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    /// handle blocks between [from, to]
    async fn handle_blocks_events(&self, from: u32, to: u32, mode: WatcherMode) {
        // handle block one by one
        for block in from..=to {
            match self.client.client.read().await.rpc().block_hash(Some(block.into())).await {
                Ok(hash) => {
                    match hash {
                        Some(hash) => {
                            let events = match self.client.client.read().await.events().at(hash).await {
                                Ok(events) => events,
                                Err(e) => {
                                    log::error!(target: &self.log_target, "event watcher get events by block hash: {hash:?} failed for: {e:?}");
                                    continue;
                                }
                            };
                            let events: Vec<_> = events
                                .iter()
                                .into_iter()
                                .filter_map(|event| match event {
                                    Ok(event) => Some(event),
                                    Err(e) => {
                                        log::error!(target: &self.log_target, "event decode from metadata failed for: {e:?}");
                                        None
                                    }
                                })
                                .collect();
                            if !events.is_empty() {
                                if let Err(e) = self.handler.send((mode, events)).await {
                                    log::error!(target: &self.log_target, "handle_blocks_events(send events to handler err: {e:?})");
                                }
                            }
                        }
                        None => {
                            log::error!(target: &self.log_target, "handle_blocks_events(get empty block hash by number: {block:?})");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    log::error!(target: &self.log_target, "handle_blocks_events(get block hash by number: {block:?} failed for: {e:?})");
                    continue;
                }
            }
        }
    }
}

pub async fn get_block_hash(client: SubClient, mode: WatcherMode) -> Result<<BoolConfig as Config>::Hash, String> {
    let guard_client = client.client.read().await;
    match mode {
        WatcherMode::Latest => {
            match guard_client.rpc().block_hash(None).await {
                Ok(Some(hash)) => return Ok(hash),
                Ok(None) => return Err("get empty lastet block".to_string()),
                Err(e) => {
                    drop(guard_client);
                    log::error!("get latest block failed for : {e:?}, try to rebuild client");
                    let err_str = e.to_string();
                    if let Err(e) = client.handle_error(e).await {
                        return Err(e.to_string());
                    }
                    return Err(err_str);
                }
            }
        },
        WatcherMode::Finalized => {
            match guard_client.rpc().finalized_head().await {
                Ok(hash) => return Ok(hash),
                Err(e) => {
                    drop(guard_client);
                    log::error!("event watcher get finalized block failed for : {e:?}, try to rebuild client");
                    let err_str = e.to_string();
                    if let Err(e) = client.handle_error(e).await {
                        return Err(e.to_string());
                    }
                    return Err(err_str);
                }
            }
        },
        WatcherMode::Both => Err("function get_block_hash doesn't support mode: WatcherMode::Both".to_string()),
    }
}

pub async fn get_block_number(client: SubClient, hash: Option<<BoolConfig as Config>::Hash>) -> Result<u32, String> {
    use subxt::config::Header;

    let guard_client = client.client.read().await;
    match guard_client.rpc().block(hash).await {
        Ok(Some(info)) => return Ok({
            let block: u64 = info.block.header.number().into();
            block as u32
        }),
        Ok(None) => return Err(format!("subxt client get empty block by hash: {hash:?}")),
        Err(e) => {
            drop(guard_client);
            log::error!("event watcher get block by hash: {hash:?} failed for: {e:?}, try to rebuild client");
            let err_str = e.to_string();
            if let Err(e) = client.handle_error(e).await {
                return Err(e.to_string());
            }
            return Err(err_str);
        },
    }
}
