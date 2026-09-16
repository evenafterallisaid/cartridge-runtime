use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use cartridge_engine::{DaemonRequest, DaemonResponse, daemon_request_with_timeout};
use cartridge_network::{HttpMethod, MAX_SERVICE_REQUEST_BYTES, ServiceRequest, ServiceResponse};

const MAX_HEAD: usize = 16 * 1024;
const IO_DEADLINE: Duration = Duration::from_secs(3);
const MAX_CLIENTS: usize = 4;

pub fn serve(
    root: &Path,
    stack: &str,
    instance: &str,
    token_file: &Path,
    port: u16,
    timeout_ms: u64,
) -> Result<()> {
    let token = read_token(token_file)?;
    daemon_request_with_timeout(root, DaemonRequest::Ping, Duration::from_secs(3))
        .map_err(anyhow::Error::msg)
        .context("engine is not reachable")?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let authority = listener.local_addr()?.to_string();
    let stopping = Arc::new(AtomicBool::new(false));
    let signal = stopping.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    println!("http://{authority}");
    thread::scope(|scope| -> Result<()> {
        let mut clients = Vec::new();
        while !stopping.load(Ordering::Acquire) {
            let mut index = 0;
            while index < clients.len() {
                let client: &thread::ScopedJoinHandle<'_, ()> = &clients[index];
                if client.is_finished() {
                    let _ = clients.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    if !peer.ip().is_loopback() || clients.len() >= MAX_CLIENTS {
                        continue;
                    }
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    let token = &token;
                    let authority = &authority;
                    clients.push(scope.spawn(move || {
                        let result = read_request(&mut stream, authority, token);
                        let (response, head) = match result {
                            Ok(request) => {
                                let head = request.method == HttpMethod::Head;
                                let result = daemon_request_with_timeout(
                                    root,
                                    DaemonRequest::Invoke {
                                        stack: stack.into(),
                                        instance: instance.into(),
                                        request,
                                        timeout_ms,
                                    },
                                    Duration::from_millis(timeout_ms + 2_000),
                                );
                                let response = match result {
                                    Ok(DaemonResponse::Invoked(response))
                                        if response.validate().is_ok() =>
                                    {
                                        response
                                    }
                                    _ => error_response(503),
                                };
                                (response, head)
                            }
                            Err(status) => (error_response(status), false),
                        };
                        let _ = write_response(&mut stream, response, head);
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    })
}

fn read_token(path: &Path) -> Result<String> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        bail!("ingress token must be a regular file");
    }
    let file = File::open(path).context("could not open ingress token file")?;
    let mut token = String::new();
    file.take(129).read_to_string(&mut token)?;
    if token.len() > 128 {
        bail!("ingress token file is too large");
    }
    let token = token.trim_end_matches(['\r', '\n']);
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("ingress token must be 64 lowercase hexadecimal characters");
    }
    Ok(token.into())
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "ingress deadline expired")
        })
}

fn read_request(
    stream: &mut TcpStream,
    authority: &str,
    token: &str,
) -> Result<ServiceRequest, u16> {
    let deadline = Instant::now() + IO_DEADLINE;
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() >= MAX_HEAD {
            return Err(431);
        }
        let mut chunk = [0; 1024];
        stream
            .set_read_timeout(Some(remaining(deadline).map_err(|_| 408u16)?))
            .map_err(|_| 400u16)?;
        let count = stream.read(&mut chunk).map_err(|_| 408u16)?;
        if count == 0 {
            return Err(400);
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    if header_end > MAX_HEAD {
        return Err(431);
    }
    let (mut request, length) = parse_head(&bytes[..header_end], authority, token)?;
    if bytes.len() - header_end > length {
        return Err(400);
    }
    request.body.extend_from_slice(&bytes[header_end..]);
    while request.body.len() < length {
        let mut chunk = [0; 8192];
        let limit = chunk.len().min(length - request.body.len());
        stream
            .set_read_timeout(Some(remaining(deadline).map_err(|_| 408u16)?))
            .map_err(|_| 400u16)?;
        let count = stream.read(&mut chunk[..limit]).map_err(|_| 408u16)?;
        if count == 0 {
            return Err(400);
        }
        request.body.extend_from_slice(&chunk[..count]);
    }
    Ok(request)
}

fn parse_head(bytes: &[u8], authority: &str, token: &str) -> Result<(ServiceRequest, usize), u16> {
    let text = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    if !text.ends_with("\r\n\r\n") {
        return Err(400);
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut parts = lines.next().ok_or(400u16)?.split(' ');
    let method = match parts.next() {
        Some("GET") => HttpMethod::Get,
        Some("HEAD") => HttpMethod::Head,
        Some("POST") => HttpMethod::Post,
        Some("PUT") => HttpMethod::Put,
        Some("PATCH") => HttpMethod::Patch,
        Some("DELETE") => HttpMethod::Delete,
        _ => return Err(405),
    };
    let path = parts.next().ok_or(400u16)?.to_owned();
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(400);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !value.bytes().all(|b| (32..=126).contains(&b))
        {
            return Err(400);
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
            || headers.len() > 128
        {
            return Err(400);
        }
    }
    if headers.remove("host").as_deref() != Some(authority) {
        return Err(421);
    }
    if headers.contains_key("origin") || headers.get("sec-fetch-site").is_some_and(|v| v != "none")
    {
        return Err(403);
    }
    let expected = format!("Bearer {token}");
    let actual = headers.remove("authorization").ok_or(401u16)?;
    if actual.len() != expected.len()
        || actual
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return Err(401);
    }
    for name in [
        "transfer-encoding",
        "expect",
        "upgrade",
        "trailer",
        "te",
        "proxy-authorization",
        "proxy-connection",
    ] {
        if headers.contains_key(name) {
            return Err(400);
        }
    }
    if headers
        .remove("connection")
        .is_some_and(|v| !v.eq_ignore_ascii_case("close") && !v.eq_ignore_ascii_case("keep-alive"))
    {
        return Err(400);
    }
    let length = match headers.remove("content-length") {
        None => 0,
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
            value.parse::<usize>().map_err(|_| 413u16)?
        }
        _ => return Err(400),
    };
    if length > MAX_SERVICE_REQUEST_BYTES {
        return Err(413);
    }
    let request = ServiceRequest {
        id: hex::encode(rand::random::<[u8; 32]>()),
        method,
        path,
        headers,
        body: Vec::new(),
    };
    request.validate().map_err(|_| 400u16)?;
    Ok((request, length))
}

fn error_response(status: u16) -> ServiceResponse {
    ServiceResponse {
        status,
        headers: BTreeMap::new(),
        body: format!("request failed ({status})\n").into_bytes(),
    }
}

fn encode_response(response: ServiceResponse, head: bool) -> Vec<u8> {
    let response = if response.validate().is_ok() && response.status >= 200 {
        response
    } else {
        error_response(502)
    };
    let no_body = matches!(response.status, 204 | 205 | 304);
    let length = if no_body { 0 } else { response.body.len() };
    let mut encoded = format!(
        "HTTP/1.1 {} Response\r\nConnection: close\r\n",
        response.status
    );
    if !matches!(response.status, 204 | 304) {
        let _ = write!(encoded, "Content-Length: {length}\r\n");
    }
    encoded.push_str("Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n");
    for (name, value) in response.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "cache-control"
                | "x-content-type-options"
                | "trailer"
                | "te"
                | "keep-alive"
                | "proxy-connection"
        ) || lower.starts_with("access-control-")
            || !value.bytes().all(|b| (32..=126).contains(&b))
        {
            continue;
        }
        let _ = write!(encoded, "{name}: {value}\r\n");
    }
    encoded.push_str("\r\n");
    let mut bytes = encoded.into_bytes();
    if !head && !no_body {
        bytes.extend_from_slice(&response.body);
    }
    bytes
}

fn write_response(
    stream: &mut TcpStream,
    response: ServiceResponse,
    head: bool,
) -> std::io::Result<()> {
    let bytes = encode_response(response, head);
    let deadline = Instant::now() + IO_DEADLINE;
    let mut written = 0;
    while written < bytes.len() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let count = stream.write(&bytes[written..])?;
        if count == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        written += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const AUTHORITY: &str = "127.0.0.1:8080";
    fn wire(extra: &str) -> String {
        format!(
            "POST /health HTTP/1.1\r\nHost: {AUTHORITY}\r\nAuthorization: Bearer {}\r\n{extra}\r\n",
            "a".repeat(64)
        )
    }
    #[test]
    fn authentication_and_framing_fail_closed() {
        let token = "a".repeat(64);
        let valid = wire("Content-Length: 4\r\nContent-Type: text/plain\r\n");
        let (request, length) = parse_head(valid.as_bytes(), AUTHORITY, &token).unwrap();
        assert_eq!(length, 4);
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request.headers.contains_key("host"));
        for extra in [
            "Content-Length: 1\r\ncontent-length: 2\r\n",
            "Content-Length: +1\r\n",
            "Content-Length: 262145\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Origin: http://evil.example\r\n",
            "Sec-Fetch-Site: cross-site\r\n",
            "Connection: authorization\r\n",
            "Expect: 100-continue\r\n",
            "X-Test: ok\nInjected: value\r\n",
            " Host: duplicate\r\n",
        ] {
            assert!(
                parse_head(wire(extra).as_bytes(), AUTHORITY, &token).is_err(),
                "{extra}"
            );
        }
        assert_eq!(
            parse_head(valid.as_bytes(), "localhost:8080", &token).unwrap_err(),
            421
        );
        assert_eq!(
            parse_head(valid.as_bytes(), AUTHORITY, &"b".repeat(64)).unwrap_err(),
            401
        );
        for path in [
            "//evil.example",
            "/../secret",
            "/%2e%2e/secret",
            "http://evil.example/",
        ] {
            assert!(
                parse_head(valid.replace("/health", path).as_bytes(), AUTHORITY, &token).is_err()
            );
        }
    }
    #[test]
    fn real_socket_reads_fragmented_body_and_strips_credentials() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let request = wire("Content-Length: 4\r\n").replace(AUTHORITY, &address.to_string());
            stream.write_all(request.as_bytes()).unwrap();
            stream.write_all(b"ping").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.ends_with("pong"));
        });
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream, &address.to_string(), &"a".repeat(64)).unwrap();
        assert_eq!(request.body, b"ping");
        write_response(
            &mut stream,
            ServiceResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: b"pong".to_vec(),
            },
            false,
        )
        .unwrap();
        drop(stream);
        client.join().unwrap();
    }
    #[test]
    fn response_framing_is_host_owned() {
        let mut response = ServiceResponse {
            status: 200,
            headers: BTreeMap::from([("access-control-allow-origin".into(), "*".into())]),
            body: b"payload".to_vec(),
        };
        let encoded = String::from_utf8(encode_response(response.clone(), true)).unwrap();
        assert!(encoded.contains("Content-Length: 7\r\n"));
        assert!(!encoded.contains("payload"));
        assert!(!encoded.contains("access-control"));
        response.status = 204;
        let encoded = String::from_utf8(encode_response(response.clone(), false)).unwrap();
        assert!(!encoded.contains("Content-Length"));
        assert!(!encoded.contains("payload"));
        response.status = 101;
        assert!(
            String::from_utf8(encode_response(response, false))
                .unwrap()
                .starts_with("HTTP/1.1 502")
        );
    }

    #[test]
    fn token_file_rejects_truncation_and_invalid_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        let token = "a".repeat(64);
        std::fs::write(&path, format!("{token}\n")).unwrap();
        assert_eq!(read_token(&path).unwrap(), token);
        for invalid in [
            "b".repeat(63),
            "A".repeat(64),
            format!("{token}{}hidden", "\n".repeat(100)),
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(read_token(&path).is_err());
        }
    }

    #[test]
    fn incomplete_socket_request_has_absolute_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"GET /").unwrap();
        let started = Instant::now();
        assert_eq!(
            read_request(&mut server, AUTHORITY, &"a".repeat(64)).unwrap_err(),
            408
        );
        assert!(started.elapsed() < Duration::from_secs(6));
    }
}
