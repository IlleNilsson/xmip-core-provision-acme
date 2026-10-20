//! A listener answered on a thread of its own until it is dropped: the
//! http-01 answer here, and the ACME server `internal-ca` runs, each a
//! connection at a time.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use provision::{ProvisionError, Result};

/// How long the wake-up connection a stop makes may take.
const WAKE: Duration = Duration::from_secs(1);

/// A listener being answered, until dropped.
pub struct Listening {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Listening {
    /// Listen on `listen` and hand every connection to `answer` on a thread
    /// called `name`.
    ///
    /// # Errors
    ///
    /// Where `listen` cannot be bound — a port another program holds, or
    /// one below 1024 an unprivileged account may not take — naming it.
    pub fn start(
        listen: &str,
        name: &str,
        answer: impl Fn(TcpStream) + Send + 'static,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen).map_err(|failure| {
            ProvisionError::new(format!("{name} cannot listen on {listen}: {failure}"))
        })?;
        Self::on(listener, name, answer)
    }

    /// As [`Listening::start`], on a listener already bound — where what
    /// answers needs to know the port before the first connection.
    ///
    /// # Errors
    ///
    /// Where the thread cannot be started.
    pub fn on(
        listener: TcpListener,
        name: &str,
        answer: impl Fn(TcpStream) + Send + 'static,
    ) -> Result<Self> {
        let address = listener
            .local_addr()
            .map_err(|failure| ProvisionError::new(format!("the bound address: {failure}")))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                for connection in listener.incoming() {
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    if let Ok(connection) = connection {
                        let _ = connection.set_nodelay(true);
                        answer(connection);
                    }
                }
            })
            .map_err(|failure| ProvisionError::new(format!("starting {name}: {failure}")))?;
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }

    /// The address it listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for Listening {
    /// Stop: the flag set, the waiting accept woken by a connection of its
    /// own, the thread joined.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Knocked until it has heard (`net::accepting`).
        if let Some(thread) = self.thread.take() {
            let address = self.address;
            let _ = net::accepting::woken(thread, WAKE, || net::accepting::knock(address, WAKE));
        }
    }
}
