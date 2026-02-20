/// Plugin system — enabled with `--features plugins`.
///
/// Plugins implement the `Plugin` trait and are registered in a
/// `PluginRegistry`.  The runner broadcasts events and detections to all
/// registered plugins after normal pipeline processing.
///
/// Future: dynamic loading via `libloading` behind an additional feature flag.
#[cfg(feature = "plugins")]
mod implementation {
    use std::sync::Arc;

    use anyhow::Result;
    use async_trait::async_trait;

    use crate::domain::detection::Detection;
    use crate::domain::event::Event;

    // ─── Plugin trait ─────────────────────────────────────────────────────────

    #[async_trait]
    pub trait Plugin: Send + Sync + 'static {
        fn name(&self)    -> &str;
        fn version(&self) -> &str { "0.1.0" }

        /// Called for every normalised event that passes through the pipeline.
        async fn process(&self, event: &Event) -> Result<()>;

        /// Called whenever a detection is produced.
        async fn on_detection(&self, _detection: &Detection) -> Result<()> { Ok(()) }
    }

    // ─── Registry ────────────────────────────────────────────────────────────

    #[derive(Default)]
    pub struct PluginRegistry {
        plugins: Vec<Arc<dyn Plugin>>,
    }

    impl PluginRegistry {
        pub fn new() -> Self { Self::default() }

        pub fn register(&mut self, plugin: Arc<dyn Plugin>) {
            tracing::info!(name = plugin.name(), "Plugin registered");
            self.plugins.push(plugin);
        }

        pub async fn broadcast_event(&self, event: &Event) {
            for p in &self.plugins {
                if let Err(e) = p.process(event).await {
                    tracing::warn!(plugin = p.name(), error = %e, "Plugin event error");
                }
            }
        }

        pub async fn broadcast_detection(&self, detection: &Detection) {
            for p in &self.plugins {
                if let Err(e) = p.on_detection(detection).await {
                    tracing::warn!(plugin = p.name(), error = %e, "Plugin detection error");
                }
            }
        }
    }
}

#[cfg(feature = "plugins")]
pub use implementation::*;
