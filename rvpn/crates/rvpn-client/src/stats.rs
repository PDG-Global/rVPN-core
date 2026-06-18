//! Stats Manager for R-VPN Client
//!
//! Provides historical stats storage and retrieval for the `stats` CLI command.
//! Uses a ring buffer to store stats snapshots efficiently without unbounded growth.

use crate::metrics::{MetricsSnapshot, global_metrics};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Default number of stats snapshots to keep in memory (ring buffer size)
/// At 3 minute intervals, this keeps ~6 hours of history
const DEFAULT_RING_BUFFER_SIZE: usize = 120;

/// Default stats collection interval in seconds
const DEFAULT_COLLECTION_INTERVAL_SECS: u64 = 180; // 3 minutes

/// Stats file name for persistence
const STATS_FILE_NAME: &str = "rvpn_stats.json";

/// A single stats entry with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsEntry {
    /// Unix timestamp when stats were collected
    pub timestamp_secs: u64,
    /// The metrics snapshot
    pub snapshot: MetricsSnapshot,
}

impl StatsEntry {
    /// Create a new stats entry from a snapshot
    pub fn new(snapshot: MetricsSnapshot) -> Self {
        Self {
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            snapshot,
        }
    }

    /// Format timestamp as human-readable string
    #[allow(dead_code)]
    pub fn formatted_time(&self) -> String {
        let datetime = chrono::DateTime::from_timestamp(self.timestamp_secs as i64, 0)
            .unwrap_or_default();
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

/// Historical stats storage with ring buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsHistory {
    /// Ring buffer of stats entries
    entries: VecDeque<StatsEntry>,
    /// Maximum number of entries to keep
    max_size: usize,
    /// Collection interval in seconds
    collection_interval_secs: u64,
}

impl StatsHistory {
    /// Create a new stats history with default size
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_RING_BUFFER_SIZE)
    }

    /// Create a new stats history with specific capacity
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_size),
            max_size,
            collection_interval_secs: DEFAULT_COLLECTION_INTERVAL_SECS,
        }
    }

    /// Add a new entry to the ring buffer
    pub fn push(&mut self, entry: StatsEntry) {
        if self.entries.len() >= self.max_size {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Get all entries
    #[allow(dead_code)]
    pub fn entries(&self) -> &VecDeque<StatsEntry> {
        &self.entries
    }

    /// Get the latest entry
    #[allow(dead_code)]
    pub fn latest(&self) -> Option<&StatsEntry> {
        self.entries.back()
    }

    /// Get the oldest entry
    #[allow(dead_code)]
    pub fn oldest(&self) -> Option<&StatsEntry> {
        self.entries.front()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get entries from the last N seconds
    #[allow(dead_code)]
    pub fn entries_since(&self, seconds: u64) -> Vec<&StatsEntry> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(seconds);
        
        self.entries
            .iter()
            .filter(|e| e.timestamp_secs >= cutoff)
            .collect()
    }

    /// Calculate average messages per second over all history
    pub fn avg_messages_per_second(&self) -> f64 {
        if self.entries.len() < 2 {
            return 0.0;
        }
        
        let total_msgs: u64 = self.entries.iter()
            .map(|e| e.snapshot.messages_received_total)
            .sum();
        
        let duration_secs = self.entries.len() as u64 * self.collection_interval_secs;
        
        if duration_secs > 0 {
            total_msgs as f64 / duration_secs as f64
        } else {
            0.0
        }
    }

    /// Get total reconnections detected
    /// This is detected by looking for uptime resets in consecutive entries
    pub fn detect_reconnections(&self) -> u32 {
        let mut reconnections = 0u32;
        let mut prev_uptime: Option<u64> = None;
        
        for entry in &self.entries {
            let uptime = entry.snapshot.connection_uptime_secs;
            
            // If uptime decreased, there was a reconnection
            if let Some(prev) = prev_uptime {
                if uptime < prev {
                    reconnections += 1;
                }
            }
            
            prev_uptime = Some(uptime);
        }
        
        reconnections
    }

    /// Get stats file path in given data directory
    fn stats_file_path_in(data_dir: &PathBuf) -> PathBuf {
        data_dir.join(STATS_FILE_NAME)
    }

    /// Save stats to disk in given data directory
    pub async fn save_to(&self, data_dir: &PathBuf) -> anyhow::Result<()> {
        let path = Self::stats_file_path_in(data_dir);
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        
        let json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(&path, json).await?;
        
        debug!("Stats saved to {:?}", path);
        Ok(())
    }

    /// Load stats from disk in given data directory
    pub async fn load_from(data_dir: &PathBuf) -> anyhow::Result<Self> {
        let path = Self::stats_file_path_in(data_dir);
        
        if !path.exists() {
            return Ok(Self::new());
        }
        
        let json = tokio::fs::read_to_string(&path).await?;
        let history: Self = serde_json::from_str(&json)?;
        
        info!("Loaded {} stats entries from {:?}", history.len(), path);
        Ok(history)
    }

    /// Save stats to default location (for backward compatibility)
    #[allow(dead_code)]
    pub async fn save(&self) -> anyhow::Result<()> {
        let data_dir = dirs::data_dir()
            .map(|d| d.join("rvpn"))
            .unwrap_or_else(|| PathBuf::from("."));
        self.save_to(&data_dir).await
    }

    /// Load stats from default location (for backward compatibility)
    #[allow(dead_code)]
    pub async fn load() -> anyhow::Result<Self> {
        let data_dir = dirs::data_dir()
            .map(|d| d.join("rvpn"))
            .unwrap_or_else(|| PathBuf::from("."));
        Self::load_from(&data_dir).await
    }
}

impl Default for StatsHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// Stats Manager that handles collection and storage
pub struct StatsManager {
    /// Historical stats storage
    history: Arc<RwLock<StatsHistory>>,
    /// Collection interval
    interval_secs: u64,
    /// Whether to persist to disk
    persist: bool,
    /// Data directory for stats file
    data_dir: PathBuf,
}

impl StatsManager {
    /// Create a new stats manager
    #[allow(dead_code)]
    pub async fn new() -> Self {
        Self::with_config(DEFAULT_COLLECTION_INTERVAL_SECS, true, None).await
    }

    /// Create a new stats manager with custom config
    /// 
    /// # Arguments
    /// * `interval_secs` - Collection interval in seconds
    /// * `persist` - Whether to persist stats to disk
    /// * `data_dir` - Optional data directory (defaults to platform data dir)
    pub async fn with_config(
        interval_secs: u64, 
        persist: bool,
        data_dir: Option<PathBuf>
    ) -> Self {
        let data_dir = data_dir.unwrap_or_else(Self::default_data_dir);
        
        // Try to load existing history
        let history = match StatsHistory::load_from(&data_dir).await {
            Ok(h) => {
                info!("Loaded {} historical stats entries", h.len());
                h
            }
            Err(e) => {
                debug!("Could not load stats history: {}", e);
                StatsHistory::new()
            }
        };

        Self {
            history: Arc::new(RwLock::new(history)),
            interval_secs,
            persist,
            data_dir,
        }
    }

    /// Get default data directory
    fn default_data_dir() -> PathBuf {
        dirs::data_dir()
            .map(|d| d.join("rvpn"))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// Start the stats collection task
    pub fn start_collection(&self) -> tokio::task::JoinHandle<()> {
        let history = self.history.clone();
        let interval_secs = self.interval_secs;
        let persist = self.persist;
        let data_dir = self.data_dir.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                
                // Collect stats
                if let Some(metrics) = global_metrics() {
                    let snapshot = metrics.snapshot().await;
                    let entry = StatsEntry::new(snapshot);
                    
                    // Add to history
                    {
                        let mut h = history.write().await;
                        h.push(entry);
                        
                        // Persist if enabled
                        if persist {
                            if let Err(e) = h.save_to(&data_dir).await {
                                warn!("Failed to save stats: {}", e);
                            }
                        }
                    }
                    
                    debug!("Stats collected and stored");
                }
            }
        })
    }

    /// Get a snapshot of current history
    #[allow(dead_code)]
    pub async fn get_history(&self) -> StatsHistory {
        self.history.read().await.clone()
    }

    /// Get the latest stats entry
    #[allow(dead_code)]
    pub async fn get_latest(&self) -> Option<StatsEntry> {
        self.history.read().await.latest().cloned()
    }

    /// Get current stats formatted for display
    #[allow(dead_code)]
    pub async fn get_current_stats(&self) -> anyhow::Result<String> {
        let mut output = String::new();
        
        // Get latest historical entry as fallback
        let latest_entry = self.get_latest().await;
        
        // Try to get current metrics directly for real-time data
        let current = if let Some(metrics) = global_metrics() {
            Some(metrics.snapshot().await)
        } else {
            None
        };

        output.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                    R-VPN Connection Stats                    ║\n");
        output.push_str("╠══════════════════════════════════════════════════════════════╣\n");

        // Use current metrics if available, otherwise fall back to latest historical entry
        let is_historical = current.is_none();
        let snapshot = current.or_else(|| latest_entry.as_ref().map(|e| e.snapshot.clone()));

        if let Some(snapshot) = snapshot {
            let health = format!("{:?}", snapshot.connection_health);
            let health_display = match snapshot.connection_health {
                crate::metrics::ConnectionHealth::Connected => format!("\x1b[32m{}\x1b[0m", health), // Green
                crate::metrics::ConnectionHealth::Connecting => format!("\x1b[33m{}\x1b[0m", health), // Yellow
                crate::metrics::ConnectionHealth::Reconnecting => format!("\x1b[33m{}\x1b[0m", health), // Yellow
                crate::metrics::ConnectionHealth::Disconnected => format!("\x1b[31m{}\x1b[0m", health), // Red
            };

            if is_historical {
                output.push_str(&format!("║  Connection Status: {:<43} ║\n", 
                    format!("{} (from history)", health_display)));
            } else {
                output.push_str(&format!("║  Connection Status: {:<43} ║\n", health_display));
            }
            output.push_str(&format!("║  Uptime: {:>50} ║\n", format_duration(snapshot.connection_uptime_secs)));
            output.push_str("╠══════════════════════════════════════════════════════════════╣\n");
            output.push_str("║  Traffic Statistics                                          ║\n");
            output.push_str(&format!("║    Messages Sent:     {:>38} ║\n", format_number(snapshot.messages_sent_total)));
            output.push_str(&format!("║    Messages Received: {:>38} ║\n", format_number(snapshot.messages_received_total)));
            output.push_str(&format!("║    Messages/sec:      {:>38.1} ║\n", snapshot.messages_received_per_sec));
            output.push_str(&format!("║    Data Sent:         {:>38} ║\n", format_bytes(snapshot.bytes_sent_total)));
            output.push_str(&format!("║    Data Received:     {:>38} ║\n", format_bytes(snapshot.bytes_received_total)));
            output.push_str("╠══════════════════════════════════════════════════════════════╣\n");
            output.push_str("║  Performance                                                 ║\n");
            output.push_str(&format!("║    Decrypt Latency (p50): {:>33} ║\n", format_micros(snapshot.decryption_p50_us)));
            output.push_str(&format!("║    Decrypt Latency (p99): {:>33} ║\n", format_micros(snapshot.decryption_p99_us)));
            output.push_str(&format!("║    Decrypt Latency (avg): {:>33} ║\n", format_micros(snapshot.avg_decrypt_time_us as u64)));
            output.push_str(&format!("║    Reorder Buffer Depth:  {:>33} ║\n", snapshot.reorder_buffer_depth));
            output.push_str("╠══════════════════════════════════════════════════════════════╣\n");
            output.push_str("║  Quality Metrics                                             ║\n");
            output.push_str(&format!("║    Reorder Events:    {:>38} ║\n", snapshot.messages_skipped));
            output.push_str(&format!("║    Dropped Messages:  {:>38} ║\n", 0u64));
        } else {
            output.push_str("║  No active connection or metrics history available          ║\n");
        }

        // Historical stats
        let history = self.get_history().await;
        if !history.is_empty() {
            output.push_str("╠══════════════════════════════════════════════════════════════╣\n");
            output.push_str("║  Historical Summary                                          ║\n");
            output.push_str(&format!("║    History Entries:   {:>38} ║\n", history.len()));
            output.push_str(&format!("║    Collection Period: {:>38} ║\n", 
                format_duration(history.len() as u64 * DEFAULT_COLLECTION_INTERVAL_SECS)));
            output.push_str(&format!("║    Detected Reconnections: {:>32} ║\n", history.detect_reconnections()));
            output.push_str(&format!("║    Avg Messages/sec:  {:>38.2} ║\n", history.avg_messages_per_second()));
            
            if let Some(oldest) = history.oldest() {
                output.push_str(&format!("║    Oldest Entry:      {:>38} ║\n", oldest.formatted_time()));
            }
            if let Some(latest) = history.latest() {
                output.push_str(&format!("║    Latest Entry:      {:>38} ║\n", latest.formatted_time()));
            }
        }

        output.push_str("╚══════════════════════════════════════════════════════════════╝\n");
        
        Ok(output)
    }

    /// Print stats history in a table format
    #[allow(dead_code)]
    pub async fn print_history(&self, entries: usize) -> anyhow::Result<String> {
        let history = self.get_history().await;
        let entries_to_show = entries.min(history.len());
        
        let mut output = String::new();
        output.push_str("Recent Stats History (last {} entries):\n\n");
        output.push_str("Timestamp            | Health     | Uptime | Msgs Recv | Msgs/sec | Latency(p50)\n");
        output.push_str("---------------------|------------|--------|-----------|----------|-------------\n");
        
        for entry in history.entries().iter().rev().take(entries_to_show) {
            let s = &entry.snapshot;
            output.push_str(&format!(
                "{} | {:10} | {:6} | {:9} | {:8.1} | {:11}\n",
                entry.formatted_time(),
                format!("{:?}", s.connection_health),
                format_duration_short(s.connection_uptime_secs),
                s.messages_received_total,
                s.messages_received_per_sec,
                format_micros(s.decryption_p50_us),
            ));
        }
        
        Ok(output)
    }

    /// Clear all historical stats
    #[allow(dead_code)]
    pub async fn clear_history(&self) {
        let mut h = self.history.write().await;
        *h = StatsHistory::with_capacity(h.max_size);
        
        // Also delete the file
        let path = StatsHistory::stats_file_path_in(&self.data_dir);
        let _ = tokio::fs::remove_file(path).await;
        
        info!("Stats history cleared");
    }
}

/// Format duration in human-readable format
#[allow(dead_code)]
fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if days > 0 {
        format!("{}d {:02}h {:02}m {:02}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{:02}h {:02}m {:02}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{:02}m {:02}s", minutes, seconds)
    } else {
        format!("{:02}s", seconds)
    }
}

/// Format duration in short format
#[allow(dead_code)]
fn format_duration_short(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    
    if hours > 0 {
        format!("{}h{:02}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

/// Format number with commas
fn format_number(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap_or_default()
        .join(",")
}

/// Format bytes in human-readable format
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let exp = (bytes as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let value = bytes as f64 / 1024f64.powi(exp as i32);
    
    if exp == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", value, UNITS[exp])
    }
}

/// Format microseconds in human-readable format
fn format_micros(micros: u64) -> String {
    if micros < 1000 {
        format!("{} μs", micros)
    } else if micros < 1_000_000 {
        format!("{:.2} ms", micros as f64 / 1000.0)
    } else {
        format!("{:.2} s", micros as f64 / 1_000_000.0)
    }
}

/// Global stats manager instance
use std::sync::OnceLock;
static GLOBAL_STATS_MANAGER: OnceLock<Arc<StatsManager>> = OnceLock::new();

/// Initialize the global stats manager
#[allow(dead_code)]
pub async fn init_global_stats_manager() -> Arc<StatsManager> {
    let manager = Arc::new(StatsManager::new().await);
    GLOBAL_STATS_MANAGER.set(manager.clone()).ok();
    manager
}

/// Initialize the global stats manager with custom data directory
pub async fn init_global_stats_manager_with_dir(data_dir: PathBuf) -> Arc<StatsManager> {
    let manager = Arc::new(StatsManager::with_config(
        DEFAULT_COLLECTION_INTERVAL_SECS, 
        true,
        Some(data_dir)
    ).await);
    GLOBAL_STATS_MANAGER.set(manager.clone()).ok();
    manager
}

/// Get the global stats manager
#[allow(dead_code)]
pub fn global_stats_manager() -> Option<Arc<StatsManager>> {
    GLOBAL_STATS_MANAGER.get().cloned()
}

/// Start stats collection with the global manager
#[allow(dead_code)]
pub async fn start_global_stats_collection() -> Option<tokio::task::JoinHandle<()>> {
    if let Some(manager) = global_stats_manager() {
        Some(manager.start_collection())
    } else {
        None
    }
}
