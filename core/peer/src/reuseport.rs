//! `EXTENSION-SIGNALING` §7.3 — the TCP simultaneous-open substrate's socket
//! requirement.
//!
//! # Why this file exists at all
//!
//! `EXTENSION-NETWORK.md` §6.7.3 requires a peer to punch from the **same local
//! endpoint whose mapping was observed** by the reflector. A NAT allocates a
//! mapping per local socket, so an `srflx` candidate is meaningful *only* for
//! the socket that produced it — punch from a fresh ephemeral socket and the
//! address you advertised is, in §6.7.3's words, a hole that will never open.
//!
//! On UDP and QUIC that is one socket reused and effectively free. §7.3 states
//! the TCP case bluntly:
//!
//! > **The socket requirement is substrate-dependent and is not satisfiable by
//! > discipline.** On TCP it requires `SO_REUSEADDR` / `SO_REUSEPORT` plus an
//! > explicit bind on both the reflector dial and the punch dial — no amount of
//! > careful code substitutes for the socket options.
//!
//! `tokio::net::TcpStream::connect` binds an OS-assigned ephemeral port and
//! exposes no way to say otherwise, which is why this goes through `socket2`.
//! That crate is already in `Cargo.lock` transitively via tokio, so depending
//! on it directly promotes an existing edge rather than adding one.
//!
//! # Unsupported is a fall-through, never a failure
//!
//! On a platform without the sockopt the §7.3 same-socket punch cannot be
//! honored, so [`dial_reuseport`] fails and the §10.3 seam reports *no live
//! path* — the ladder then takes the ordinary store-and-forward route.
//! Degrading rather than erroring is deliberate: §10.3 makes a failed traversal
//! a fall-through, and "this OS lacks a sockopt" must present to the ladder
//! exactly as "that peer is unreachable" does.
//!
//! # Local, not interoperable
//!
//! §7.2 lists socket options among what "stays local and MAY diverge." The
//! interoperable requirement is only the *shared local port*; the spelling is
//! platform-local. Go reaches the same behavior through `net.Dialer.Control`
//! plus `golang.org/x/sys/unix` (`ext/signaling/reuseport.go`).

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

/// Build a TCP socket with `SO_REUSEADDR` + `SO_REUSEPORT` bound to `local`.
///
/// Both options are needed and they are not the same thing: `SO_REUSEADDR`
/// permits rebinding a port in `TIME_WAIT`, while `SO_REUSEPORT` is what
/// permits a *concurrent* second bind — which is the whole point here, since
/// the punch dial and the punch listener share one port at the same instant.
fn bound_reuse_socket(local: SocketAddr) -> io::Result<Socket> {
    let domain = match local {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    // Not available on every target; `socket2` gates the method itself, so the
    // cfg here mirrors the crate's own support matrix rather than guessing.
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&local.into())?;
    Ok(socket)
}

/// Dial `remote` from the exact local endpoint `local`, with the §7.3 socket
/// options set.
///
/// `local` is the address whose NAT mapping the reflector observed. The punch
/// MUST reuse it — that is §6.7.3's rule, and it is the reason this function
/// takes a local address at all rather than letting the OS choose.
///
/// `on_connect_issued` fires **exactly when the `connect` syscall has gone out**
/// and not before — after the bind, after a hard failure has been ruled out, and
/// regardless of whether the connect then succeeds, is refused, or times out.
/// That instant is the one §7.1 step 4 legislates ("each peer MUST issue an
/// outbound connection attempt at `fire_at`"), and it is not observable from
/// outside this function: a caller that counts before calling counts sockets it
/// never managed to bind, and one that counts after awaiting misses every dial
/// that was refused — which opens a NAT mapping exactly as an accepted one does.
/// See `PeerPunchEstablisher::outbound_attempts`.
pub async fn dial_reuseport(
    local: SocketAddr,
    remote: SocketAddr,
    on_connect_issued: impl FnOnce(),
) -> io::Result<TcpStream> {
    let socket = bound_reuse_socket(local)?;
    // `connect` on a non-blocking socket returns EINPROGRESS; hand the fd to
    // tokio and let it drive readiness rather than spinning here.
    match socket.connect(&remote.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc_einprogress()) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        // Nothing left the host — not an outbound attempt.
        Err(e) => return Err(e),
    }
    on_connect_issued();
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    // Wait for the connect to resolve. A simultaneous open reports writable
    // once the handshake completes in either direction.
    stream.writable().await?;
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    // Disable Nagle, matching TcpConnector — a punch carries small coordination
    // frames where a 40 ms delayed-ACK stall is the whole budget.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Listen on `local` with the same options, so the port that dials the peer can
/// also **accept** the peer's dial.
///
/// Pure simultaneous-open — both sides only dialing — connects only when both
/// sockets sit in `SYN_SENT` at the crossing instant, which is a narrow and
/// fragile window. Listening as well means a counterpart's SYN lands rather
/// than being refused in the gap between our own dial attempts. Both sides
/// dialing is still what opens both NAT holes (§7.1 step 4); the listener only
/// catches whichever direction survives.
///
/// Go does the same (`listenReusePort`). **Ruled 2026-08-01** (arch `b3ff6ad`,
/// §7.1 step 4): listening alongside is fine, and listening *instead* is not —
/// "listening alone opens no hole, because only an outbound packet creates the
/// local NAT mapping." So this is a catcher, never a substitute; the dial that
/// runs beside it is the MUST. See `punch::cross`.
pub fn listen_reuseport(local: SocketAddr) -> io::Result<TcpListener> {
    let socket = bound_reuse_socket(local)?;
    // A small backlog: this listener exists to catch one counterpart's dial,
    // not to serve a peer's general inbound traffic.
    socket.listen(8)?;
    TcpListener::from_std(socket.into())
}

/// `EINPROGRESS` without pulling in a `libc` dependency for one constant.
/// Same value across the Unix targets this path is compiled for.
fn libc_einprogress() -> i32 {
    115
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sockopts actually take: two sockets bind the *same* port at the same
    /// time. Without `SO_REUSEPORT` the second bind fails with `EADDRINUSE`, so
    /// this asserts the one property §7.3 says cannot be had by discipline.
    #[tokio::test]
    async fn two_sockets_share_one_local_port() {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let first = listen_reuseport(addr).expect("first bind");
        let second = listen_reuseport(addr).expect(
            "second bind on the same port — this is exactly what SO_REUSEPORT buys, \
             and the §7.3 punch is unbuildable without it",
        );
        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
    }

    /// **The substrate, end to end** (§7.1 step 4): two peers each bind one
    /// port, each listen on it, and each dial the other at the same instant.
    /// After the crossfire a direct path exists.
    ///
    /// This is loopback, so it proves the *socket* choreography and not NAT
    /// traversal — no mapping is created and none is crossed. It is the
    /// same ceiling Go's punch tests have, and no report out of this should
    /// claim two NAT'd peers connected.
    #[tokio::test]
    async fn simultaneous_open_crosses() {
        // Two ports nobody holds, obtained the usual way: bind, read, release.
        let (a_addr, b_addr) = {
            let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
            (a.local_addr().unwrap(), b.local_addr().unwrap())
        };

        // Each side listens on its own punch port *and* dials the other. §7.1
        // step 4 is the two dials — they are what open both (notional) NAT
        // mappings — so the dials are what this asserts on. The listeners are
        // held open for the whole test because they are what makes a dial land
        // when the two SYNs do not cross in flight; they are deliberately never
        // accepted from, since which of dial-vs-accept completes is a kernel
        // race and awaiting the loser is an unbounded hang (it hung here before
        // this was restructured).
        let _a_listen = listen_reuseport(a_addr).expect("a listen");
        let _b_listen = listen_reuseport(b_addr).expect("b listen");

        let d = std::time::Duration::from_secs(2);
        let a_dial = tokio::spawn(async move {
            tokio::time::timeout(d, dial_reuseport(a_addr, b_addr, || {})).await
        });
        let b_dial = tokio::spawn(async move {
            tokio::time::timeout(d, dial_reuseport(b_addr, a_addr, || {})).await
        });

        // At least one direction must come up. Asserting "some direction
        // connected" rather than a specific one keeps this a reachability test
        // instead of a timing test.
        let landed = [
            matches!(a_dial.await.unwrap(), Ok(Ok(_))),
            matches!(b_dial.await.unwrap(), Ok(Ok(_))),
        ];
        assert!(
            landed.iter().any(|ok| *ok),
            "a simultaneous open from two reuseport sockets must produce a path"
        );
    }

    /// A dial from a bound local port reports that exact port to the peer — the
    /// §6.7.3 property the whole substrate rests on. If the dial silently used
    /// a fresh ephemeral port, the `srflx` candidate advertised from the
    /// reflector socket would describe a mapping this connection never uses.
    #[tokio::test]
    async fn dial_leaves_from_the_bound_local_port() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = probe.local_addr().unwrap();
        drop(probe);

        let accept = tokio::spawn(async move { server.accept().await.map(|(_, peer)| peer) });
        let stream = dial_reuseport(local, server_addr, || {})
            .await
            .expect("dial");

        assert_eq!(stream.local_addr().unwrap(), local);
        let observed = accept.await.unwrap().expect("accept");
        assert_eq!(
            observed, local,
            "the peer must observe the bound port — otherwise the advertised \
             srflx candidate is a hole that will never open (§6.7.3)"
        );
    }
}
