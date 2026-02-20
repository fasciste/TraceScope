// Live network capture — requires the `live-capture` feature and libpcap.
// Build with:  cargo build --features live-capture
// Run as root or with:  sudo setcap cap_net_raw+eip ./tracescope

#[cfg(feature = "live-capture")]
pub mod live {
    use anyhow::{Context, Result};
    use tokio::sync::mpsc;
    use tracing::{debug, info, warn};

    use crate::domain::event::{EventSource, RawEvent};
    use crate::ingestion::pcap::packet_to_json;

    pub async fn capture(interface: &str, tx: mpsc::Sender<RawEvent>) -> Result<()> {
        info!(interface, "Live capture starting");

        let iface  = interface.to_owned();
        let source = EventSource::Pcap { interface: iface.clone() };

        // pcap is a synchronous C library — keep it off the async executor.
        tokio::task::spawn_blocking(move || {
            let mut cap = pcap::Capture::from_device(iface.as_str())
                .context("Device not found")?
                .promisc(true)
                .snaplen(65535)
                .open()
                .context("Cannot open capture (need root or CAP_NET_RAW)")?;

            loop {
                match cap.next_packet() {
                    Ok(pkt) => {
                        let json = packet_to_json(pkt.data);
                        if tx.blocking_send(RawEvent::new(source.clone(), json)).is_err() {
                            debug!("Live capture: downstream closed");
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        warn!(error = %e, "Live capture error");
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }).await??;

        Ok(())
    }
}
