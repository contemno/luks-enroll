//! zbus interface implementation (stub — full version in progress).

pub struct LuksEnrollService {
    idle_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

impl LuksEnrollService {
    pub fn new(idle_tx: tokio::sync::mpsc::UnboundedSender<()>) -> Self {
        LuksEnrollService { idle_tx }
    }
}

#[zbus::interface(name = "net.contemno.LuksEnroll1")]
impl LuksEnrollService {
    #[zbus(name = "GetSystemdVersion")]
    async fn get_systemd_version(&self) -> i32 {
        let _ = &self.idle_tx;
        999
    }
}
