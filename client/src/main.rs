use getrandom::getrandom;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const VERSION: &str = "0.1.0";
const MAGIC: &[u8; 4] = b"PHP1";
const EMBEDDED_CONFIG: &str = include_str!("../config/default_client.json");
const AUTOSTART_TASK_NAME: &str = "PortHoneypotClient";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClientConfig {
    server_host: String,
    server_port: u16,
    shared_key_hex: String,
    node_id: String,
    listen_ports: Vec<u16>,
    stealth_mode: bool,
    stealth_fallback_to_tcp: bool,
    autostart: bool,
    hidden: bool,
    heartbeat_interval_secs: u64,
    flush_interval_secs: u64,
    max_payload_bytes: usize,
    spool_path: String,
    log_path: String,
    #[serde(default = "default_log_max_bytes")]
    log_max_bytes: u64,
    #[serde(default = "default_log_backup_count")]
    log_backup_count: usize,
    #[serde(default = "default_update_enabled")]
    update_enabled: bool,
    #[serde(default = "default_update_interval_secs")]
    update_interval_secs: u64,
    #[serde(default)]
    update_base_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AttackEvent {
    ts: u64,
    source_ip: String,
    source_port: Option<u16>,
    target_port: u16,
    mode: String,
    content: String,
}

#[derive(Clone)]
struct Crypto {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

struct ListenerManager {
    config: Arc<Mutex<ClientConfig>>,
    running: Arc<AtomicBool>,
    spool_lock: Arc<Mutex<()>>,
    enabled: AtomicBool,
    listeners: Mutex<HashMap<u16, Arc<AtomicBool>>>,
}

impl ListenerManager {
    fn new(config: Arc<Mutex<ClientConfig>>, running: Arc<AtomicBool>, spool_lock: Arc<Mutex<()>>) -> Self {
        Self {
            config,
            running,
            spool_lock,
            enabled: AtomicBool::new(false),
            listeners: Mutex::new(HashMap::new()),
        }
    }

    fn start_all(&self) {
        self.enabled.store(true, Ordering::SeqCst);
        for port in self.desired_ports() {
            self.start_port(port);
        }
    }

    fn stop_all(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.stop_all_listeners();
        let cfg = self.config.lock().unwrap().clone();
        log_line(&cfg, "INFO", "all listeners stopped by control command");
    }

    fn set_ports(&self, ports: Vec<u16>) {
        let mut ports = ports;
        ports.sort_unstable();
        ports.dedup();
        {
            let mut cfg = self.config.lock().unwrap();
            cfg.listen_ports = ports.clone();
            log_line(&cfg, "INFO", &format!("listen ports updated to {:?}", cfg.listen_ports));
        }
        if !self.enabled.load(Ordering::SeqCst) {
            return;
        }
        let active = self.active_ports();
        for port in active {
            if !ports.contains(&port) {
                self.stop_port(port);
            }
        }
        for port in ports {
            self.start_port(port);
        }
    }

    fn desired_ports(&self) -> Vec<u16> {
        self.config.lock().unwrap().listen_ports.clone()
    }

    fn active_ports(&self) -> Vec<u16> {
        self.listeners.lock().unwrap().keys().copied().collect()
    }

    fn start_port(&self, port: u16) {
        if self.listeners.lock().unwrap().contains_key(&port) {
            return;
        }
        let cfg = self.config.lock().unwrap().clone();
        match TcpListener::bind(("0.0.0.0", port)) {
            Ok(listener) => {
                if let Err(err) = listener.set_nonblocking(true) {
                    log_line(&cfg, "ERROR", &format!("listener on port {} failed: {}", port, err));
                    return;
                }
                let stop = Arc::new(AtomicBool::new(false));
                self.listeners.lock().unwrap().insert(port, stop.clone());
                let running = self.running.clone();
                let spool_lock = self.spool_lock.clone();
                thread::spawn(move || {
                    if let Err(err) = listener_loop(cfg.clone(), port, listener, running, stop, spool_lock) {
                        log_line(&cfg, "ERROR", &format!("listener on port {} stopped: {}", port, err));
                    }
                });
            }
            Err(err) => {
                log_line(&cfg, "ERROR", &format!("port {} is unavailable: {}", port, err));
            }
        }
    }

    fn stop_port(&self, port: u16) {
        if let Some(stop) = self.listeners.lock().unwrap().remove(&port) {
            stop.store(true, Ordering::SeqCst);
        }
    }

    fn stop_all_listeners(&self) {
        let stops: Vec<Arc<AtomicBool>> = self.listeners.lock().unwrap().drain().map(|(_, stop)| stop).collect();
        for stop in stops {
            stop.store(true, Ordering::SeqCst);
        }
    }
}

impl Crypto {
    fn new(key_hex: &str) -> io::Result<Self> {
        let mut key = decode_hex(key_hex).unwrap_or_else(|| hmac_digest(key_hex.as_bytes(), b"fallback"));
        if key.len() < 32 {
            key = hmac_digest(&key, b"short-key");
        }
        key.truncate(32);
        let enc = hmac_digest(&key, b"enc");
        let mac = hmac_digest(&key, b"mac");
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&enc[..32]);
        mac_key.copy_from_slice(&mac[..32]);
        Ok(Self { enc_key, mac_key })
    }

    fn keystream(&self, nonce: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut counter: u32 = 0;
        while out.len() < len {
            let mut msg = Vec::with_capacity(nonce.len() + 4);
            msg.extend_from_slice(nonce);
            msg.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&hmac_digest(&self.enc_key, &msg));
            counter = counter.wrapping_add(1);
        }
        out.truncate(len);
        out
    }

    fn encrypt(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce = [0u8; 16];
        getrandom(&mut nonce)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("getrandom failed: {:?}", err)))?;
        let stream = self.keystream(&nonce, plaintext.len());
        let ciphertext: Vec<u8> = plaintext.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
        let mut body = Vec::with_capacity(4 + 16 + ciphertext.len() + 32);
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&ciphertext);
        let tag = hmac_digest(&self.mac_key, &body);
        body.extend_from_slice(&tag);
        Ok(body)
    }

    fn decrypt(&self, frame: &[u8]) -> io::Result<Vec<u8>> {
        if frame.len() < 4 + 16 + 32 || &frame[..4] != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad encrypted frame"));
        }
        let tag_start = frame.len() - 32;
        let expected = hmac_digest(&self.mac_key, &frame[..tag_start]);
        if !constant_time_eq(&expected, &frame[tag_start..]) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame authentication failed"));
        }
        let nonce = &frame[4..20];
        let ciphertext = &frame[20..tag_start];
        let stream = self.keystream(nonce, ciphertext.len());
        Ok(ciphertext.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect())
    }
}

fn main() -> io::Result<()> {
    let mut config = load_config()?;
    config.node_id = ensure_node_id(&config)?;
    ensure_parent(&config.log_path)?;
    ensure_parent(&config.spool_path)?;
    if handle_cli_command(&config)? {
        return Ok(());
    }
    log_line(&config, "INFO", &format!("client starting, node_id={}", config.node_id));
    configure_autostart(&config);

    let crypto = Crypto::new(&config.shared_key_hex)?;
    let running = Arc::new(AtomicBool::new(true));
    let spool_lock = Arc::new(Mutex::new(()));
    let shared_config = Arc::new(Mutex::new(config.clone()));
    let listener_manager = Arc::new(ListenerManager::new(
        shared_config.clone(),
        running.clone(),
        spool_lock.clone(),
    ));

    if config.stealth_mode {
        let ok = start_stealth_backend(shared_config.clone(), running.clone(), spool_lock.clone());
        if !ok && config.stealth_fallback_to_tcp {
            log_line(&config, "WARN", "stealth backend unavailable, falling back to general TCP honeypot mode");
            listener_manager.start_all();
        }
    } else {
        listener_manager.start_all();
    }

    let upload_crypto = crypto.clone();
    let upload_running = running.clone();
    let upload_lock = spool_lock.clone();
    let upload_config = shared_config.clone();
    let upload_manager = listener_manager.clone();
    thread::spawn(move || upload_loop(upload_config, upload_crypto, upload_running, upload_lock, upload_manager));

    if config.update_enabled {
        let update_config = shared_config.clone();
        let update_running = running.clone();
        thread::spawn(move || update_loop(update_config, update_running));
    }

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn handle_cli_command(config: &ClientConfig) -> io::Result<bool> {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("run");
    match command {
        "run" => Ok(false),
        "--help" | "-h" | "help" => {
            print_help();
            Ok(true)
        }
        "--version" | "-V" | "version" => {
            println!("porthoneypot-client {}", VERSION);
            Ok(true)
        }
        "status" => {
            println!("node_id={}", config.node_id);
            println!("server={}:{}", config.server_host, config.server_port);
            println!("listen_ports={:?}", config.listen_ports);
            println!("stealth_mode={}", config.stealth_mode);
            println!("update_enabled={}", config.update_enabled);
            println!("update_base_url={}", config.update_base_url);
            Ok(true)
        }
        "check-update" => {
            let applied = check_update_once(config, false)?;
            println!("update_available={}", applied);
            Ok(true)
        }
        "install-autostart" | "install" => {
            install_autostart()?;
            Ok(true)
        }
        "uninstall-autostart" | "uninstall" => {
            uninstall_autostart()?;
            Ok(true)
        }
        other => {
            eprintln!("unknown command: {}", other);
            print_help();
            Ok(true)
        }
    }
}

fn print_help() {
    println!("Port Honeypot Client {}", VERSION);
    println!("usage: porthoneypot-client [run|status|check-update|install-autostart|uninstall-autostart]");
}

fn load_config() -> io::Result<ClientConfig> {
    let mut candidates: Vec<PathBuf> = vec![PathBuf::from("client_config.json")];
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("client_config.json"));
        }
    }
    for path in candidates {
        if path.exists() {
            let raw = fs::read_to_string(path)?;
            return serde_json::from_str(&raw).map_err(invalid_data);
        }
    }
    serde_json::from_str(EMBEDDED_CONFIG).map_err(invalid_data)
}

fn default_update_enabled() -> bool {
    false
}

fn default_update_interval_secs() -> u64 {
    300
}

fn default_log_max_bytes() -> u64 {
    2 * 1024 * 1024
}

fn default_log_backup_count() -> usize {
    5
}

fn ensure_node_id(config: &ClientConfig) -> io::Result<String> {
    if !config.node_id.trim().is_empty() {
        return Ok(config.node_id.clone());
    }
    let path = Path::new("data/node_id");
    if path.exists() {
        return Ok(fs::read_to_string(path)?.trim().to_string());
    }
    ensure_parent(path)?;
    let hostname = hostname();
    let now = now_ts();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hostname.hash(&mut hasher);
    now.hash(&mut hasher);
    let node_id = format!("{}-{:016x}", hostname, hasher.finish());
    fs::write(path, &node_id)?;
    Ok(node_id)
}

fn listener_loop(
    config: ClientConfig,
    port: u16,
    listener: TcpListener,
    running: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    spool_lock: Arc<Mutex<()>>,
) -> io::Result<()> {
    log_line(&config, "INFO", &format!("listening on 0.0.0.0:{}", port));
    while running.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(900)));
                let mut buf = vec![0u8; config.max_payload_bytes.max(1).min(1024)];
                let size = stream.read(&mut buf).unwrap_or(0);
                buf.truncate(size);
                let content = String::from_utf8_lossy(&buf).to_string();
                let event = AttackEvent {
                    ts: now_ts(),
                    source_ip: addr.ip().to_string(),
                    source_port: Some(addr.port()),
                    target_port: port,
                    mode: "general".to_string(),
                    content,
                };
                append_event(&config, &spool_lock, &event)?;
                local_attack_notice(&config, &event);
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(err),
        }
    }
    log_line(&config, "INFO", &format!("listener on port {} stopped", port));
    Ok(())
}

fn upload_loop(
    config: Arc<Mutex<ClientConfig>>,
    crypto: Crypto,
    running: Arc<AtomicBool>,
    spool_lock: Arc<Mutex<()>>,
    listener_manager: Arc<ListenerManager>,
) {
    while running.load(Ordering::SeqCst) {
        let cfg = config.lock().unwrap().clone();
        match TcpStream::connect((cfg.server_host.as_str(), cfg.server_port)) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));
                if let Err(err) = register(&cfg, &crypto, &mut stream) {
                    log_line(&cfg, "WARN", &format!("register failed: {}", err));
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
                log_line(&cfg, "INFO", "connected to server");
                loop {
                    let loop_cfg = config.lock().unwrap().clone();
                    match send_heartbeat(&loop_cfg, &crypto, &mut stream) {
                        Ok(ack) => apply_server_commands(&listener_manager, &ack),
                        Err(err) => {
                            log_line(&loop_cfg, "WARN", &format!("heartbeat failed: {}", err));
                            break;
                        }
                    }
                    if let Err(err) = flush_spool(&loop_cfg, &crypto, &mut stream, &spool_lock) {
                        log_line(&loop_cfg, "WARN", &format!("event upload failed: {}", err));
                        break;
                    }
                    thread::sleep(Duration::from_secs(loop_cfg.flush_interval_secs.max(1)));
                }
            }
            Err(err) => {
                log_line(&cfg, "WARN", &format!("server connection failed: {}", err));
                local_disconnect_notice(&cfg);
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

fn register(config: &ClientConfig, crypto: &Crypto, stream: &mut TcpStream) -> io::Result<()> {
    let msg = json!({
        "type": "register",
        "node_id": config.node_id,
        "hostname": hostname(),
        "os": env::consts::OS,
        "arch": env::consts::ARCH,
        "version": VERSION,
        "listen_ports": config.listen_ports,
        "stealth_mode": config.stealth_mode
    });
    send_json(stream, crypto, &msg)?;
    let _ = read_json(stream, crypto)?;
    Ok(())
}

fn send_heartbeat(config: &ClientConfig, crypto: &Crypto, stream: &mut TcpStream) -> io::Result<Value> {
    let msg = json!({
        "type": "heartbeat",
        "node_id": config.node_id,
        "ts": now_ts(),
        "listen_ports": config.listen_ports
    });
    send_json(stream, crypto, &msg)?;
    read_json(stream, crypto)
}

fn apply_server_commands(listener_manager: &ListenerManager, ack: &Value) {
    let Some(commands) = ack.get("commands").and_then(Value::as_array) else {
        return;
    };
    for command in commands {
        let name = command.get("command").and_then(Value::as_str).unwrap_or("");
        match name {
            "start_all" => listener_manager.start_all(),
            "stop_all" => listener_manager.stop_all(),
            "set_ports" => {
                let ports = command
                    .get("payload")
                    .and_then(|p| p.get("listen_ports"))
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_u64)
                            .filter(|port| *port > 0 && *port < 65536)
                            .map(|port| port as u16)
                            .collect::<Vec<u16>>()
                    })
                    .unwrap_or_default();
                listener_manager.set_ports(ports);
            }
            _ => {
                let cfg = listener_manager.config.lock().unwrap().clone();
                log_line(&cfg, "WARN", &format!("unsupported server command ignored: {}", name));
            }
        }
    }
}

fn flush_spool(
    config: &ClientConfig,
    crypto: &Crypto,
    stream: &mut TcpStream,
    spool_lock: &Mutex<()>,
) -> io::Result<()> {
    let _guard = spool_lock.lock().unwrap();
    let events = read_spooled_events(&config.spool_path)?;
    if events.is_empty() {
        return Ok(());
    }
    let msg = json!({"type": "events", "node_id": config.node_id, "events": events});
    send_json(stream, crypto, &msg)?;
    let ack = read_json(stream, crypto)?;
    if ack.get("type").and_then(Value::as_str) == Some("ack") {
        clear_spool(&config.spool_path)?;
    }
    Ok(())
}

fn send_json(stream: &mut TcpStream, crypto: &Crypto, value: &Value) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(invalid_data)?;
    let encrypted = crypto.encrypt(&payload)?;
    if encrypted.len() > u32::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
    stream.write_all(&encrypted)?;
    Ok(())
}

fn read_json(stream: &mut TcpStream, crypto: &Crypto) -> io::Result<Value> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > 8 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame size"));
    }
    let mut encrypted = vec![0u8; size];
    stream.read_exact(&mut encrypted)?;
    let plaintext = crypto.decrypt(&encrypted)?;
    serde_json::from_slice(&plaintext).map_err(invalid_data)
}

fn append_event(config: &ClientConfig, spool_lock: &Mutex<()>, event: &AttackEvent) -> io::Result<()> {
    let _guard = spool_lock.lock().unwrap();
    ensure_parent(&config.spool_path)?;
    let mut file = OpenOptions::new().create(true).append(true).open(&config.spool_path)?;
    let line = serde_json::to_string(event).map_err(invalid_data)?;
    writeln!(file, "{}", line)?;
    log_line(
        config,
        "ALERT",
        &format!(
            "port {} accessed by {}:{}",
            event.target_port,
            event.source_ip,
            event.source_port.unwrap_or_default()
        ),
    );
    Ok(())
}

fn read_spooled_events(path: &str) -> io::Result<Vec<AttackEvent>> {
    let p = Path::new(path);
    if !p.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(p)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<AttackEvent>(&line) {
            out.push(event);
        }
    }
    Ok(out)
}

fn clear_spool(path: &str) -> io::Result<()> {
    ensure_parent(path)?;
    File::create(path)?;
    Ok(())
}

fn start_stealth_backend(
    config: Arc<Mutex<ClientConfig>>,
    running: Arc<AtomicBool>,
    spool_lock: Arc<Mutex<()>>,
) -> bool {
    #[cfg(target_os = "windows")]
    {
        windows_stealth::start(config, running, spool_lock)
    }
    #[cfg(target_os = "linux")]
    {
        linux_stealth::start(config, running, spool_lock)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let cfg = config.lock().unwrap().clone();
        log_line(
            &cfg,
            "WARN",
            "stealth SYN backend is not implemented for this platform; falling back if enabled",
        );
        let _ = (running, spool_lock);
        false
    }
}

#[cfg(any(test, target_os = "windows", target_os = "linux"))]
fn parse_ipv4_syn_packet(packet: &[u8], listen_ports: &[u16]) -> Option<AttackEvent> {
    if packet.len() < 40 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if version != 4 || ihl < 20 || packet.len() < ihl + 20 {
        return None;
    }
    if packet[9] != 6 {
        return None;
    }
    let source_ip =
        std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string();
    let dest_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    let tcp = &packet[ihl..];
    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let target_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if !listen_ports.contains(&target_port) {
        return None;
    }
    let flags = tcp[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    if !syn || ack {
        return None;
    }
    let ttl = packet[8];
    Some(AttackEvent {
        ts: now_ts(),
        source_ip,
        source_port: Some(source_port),
        target_port,
        mode: "stealth".to_string(),
        content: format!(
            "SYN probe to {}:{} ttl={} flags=0x{:02x}",
            dest_ip, target_port, ttl, flags
        ),
    })
}

fn configure_autostart(config: &ClientConfig) {
    if config.autostart {
        log_line(
            config,
            "INFO",
            "autostart requested; run install-autostart to register this client on the host",
        );
    }
}

fn install_autostart() -> io::Result<()> {
    let exe = env::current_exe()?;
    #[cfg(windows)]
    {
        let action = format!("\"{}\" run", exe.display());
        let status = Command::new("schtasks")
            .args(["/Create", "/SC", "ONLOGON", "/TN", AUTOSTART_TASK_NAME, "/TR", &action, "/F"])
            .status()?;
        if !status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "schtasks /Create failed"));
        }
        println!("installed Windows logon autostart task: {}", AUTOSTART_TASK_NAME);
    }
    #[cfg(not(windows))]
    {
        println!("create a systemd service with ExecStart={} run", exe.display());
    }
    Ok(())
}

fn uninstall_autostart() -> io::Result<()> {
    #[cfg(windows)]
    {
        let status = Command::new("schtasks")
            .args(["/Delete", "/TN", AUTOSTART_TASK_NAME, "/F"])
            .status()?;
        if !status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "schtasks /Delete failed"));
        }
        println!("removed Windows autostart task: {}", AUTOSTART_TASK_NAME);
    }
    #[cfg(not(windows))]
    {
        println!("remove the systemd service created for porthoneypot-client");
    }
    Ok(())
}

fn update_loop(config: Arc<Mutex<ClientConfig>>, running: Arc<AtomicBool>) {
    while running.load(Ordering::SeqCst) {
        let cfg = config.lock().unwrap().clone();
        if cfg.update_enabled {
            if let Err(err) = check_update_once(&cfg, true) {
                log_line(&cfg, "WARN", &format!("update check failed: {}", err));
            }
        }
        let wait_secs = cfg.update_interval_secs.max(30);
        for _ in 0..wait_secs {
            if !running.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}

fn check_update_once(config: &ClientConfig, apply: bool) -> io::Result<bool> {
    if config.update_base_url.trim().is_empty() {
        return Ok(false);
    }
    let base = config.update_base_url.trim().trim_end_matches('/');
    let platform = platform_id();
    let manifest_url = format!("{}/api/client-updates/{}/manifest", base, platform);
    let manifest_bytes = http_get_bytes(&manifest_url)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(invalid_data)?;
    if manifest.get("available").and_then(Value::as_bool) != Some(true) {
        return Ok(false);
    }
    let remote_version = manifest.get("version").and_then(Value::as_str).unwrap_or("");
    if !version_gt(remote_version, VERSION) {
        return Ok(false);
    }
    log_line(
        config,
        "INFO",
        &format!("update available: current={}, remote={}", VERSION, remote_version),
    );
    if !apply {
        return Ok(true);
    }

    let download_path = manifest
        .get("download_path")
        .and_then(Value::as_str)
        .unwrap_or("");
    if download_path.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "manifest missing download_path"));
    }
    let download_url = if download_path.starts_with("http://") {
        download_path.to_string()
    } else {
        format!("{}{}", base, download_path)
    };
    let binary = http_get_bytes(&download_url)?;
    if let Some(size) = manifest.get("size").and_then(Value::as_u64) {
        if binary.len() as u64 != size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "download size mismatch"));
        }
    }
    if let Some(expected) = manifest.get("sha256").and_then(Value::as_str) {
        let actual = sha256_hex(&binary);
        if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "download sha256 mismatch"));
        }
    }
    let update_dir = Path::new("updates");
    fs::create_dir_all(update_dir)?;
    let staged_name = if env::consts::OS == "windows" {
        "porthoneypot-client-new.exe"
    } else {
        "porthoneypot-client-new"
    };
    let staged = update_dir.join(staged_name);
    fs::write(&staged, binary)?;
    log_line(config, "INFO", &format!("update staged at {}", staged.display()));
    schedule_update_apply(config, &staged)?;
    Ok(true)
}

fn schedule_update_apply(config: &ClientConfig, staged: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        let exe = env::current_exe()?;
        let workdir = env::current_dir()?;
        let script = Path::new("updates").join("apply_update.ps1");
        let content = format!(
            "$ErrorActionPreference = 'Stop'\n\
             Wait-Process -Id {} -ErrorAction SilentlyContinue\n\
             Start-Sleep -Milliseconds 800\n\
             Copy-Item -LiteralPath {} -Destination {} -Force\n\
             Start-Process -FilePath {} -ArgumentList 'run' -WorkingDirectory {} -WindowStyle Hidden\n",
            process::id(),
            ps_quote(staged),
            ps_quote(&exe),
            ps_quote(&exe),
            ps_quote(&workdir),
        );
        fs::write(&script, content)?;
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-File",
                script.to_string_lossy().as_ref(),
            ])
            .spawn()?;
        log_line(config, "INFO", "update apply script started; exiting current process");
        process::exit(0)
    }
    #[cfg(not(windows))]
    {
        log_line(
            config,
            "INFO",
            &format!("update downloaded to {}; replace the running binary during maintenance", staged.display()),
        );
        Ok(())
    }
}

fn http_get_bytes(url: &str) -> io::Result<Vec<u8>> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = TcpStream::connect((host.as_str(), port))?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: porthoneypot-client/{}\r\nConnection: close\r\n\r\n",
        path, host, VERSION
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = find_subsequence(&response, b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP response missing header"))?;
    let header = String::from_utf8_lossy(&response[..header_end]);
    let status_line = header.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Err(io::Error::new(io::ErrorKind::Other, format!("HTTP request failed: {}", status_line)));
    }
    Ok(response[header_end + 4..].to_vec())
}

fn parse_http_url(url: &str) -> io::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "only http:// update URLs are supported"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "update URL missing host"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(invalid_data)?),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let out = digest.finalize();
    let mut text = String::with_capacity(out.len() * 2);
    for byte in out {
        text.push_str(&format!("{:02x}", byte));
    }
    text
}

fn version_gt(remote: &str, current: &str) -> bool {
    let parse = |value: &str| {
        value
            .split(|ch: char| !ch.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .take(4)
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect::<Vec<u64>>()
    };
    let mut left = parse(remote);
    let mut right = parse(current);
    while left.len() < 4 {
        left.push(0);
    }
    while right.len() < 4 {
        right.push(0);
    }
    left > right
}

fn platform_id() -> String {
    let os = match env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        other => other,
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{}-{}", os, arch)
}

#[cfg(windows)]
fn ps_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

fn local_attack_notice(config: &ClientConfig, _event: &AttackEvent) {
    let message = format!(
        "{}:{} accessed local honeypot port {}",
        _event.source_ip,
        _event.source_port.unwrap_or_default(),
        _event.target_port
    );
    windows_local_alert(config, "Port Honeypot Attack", &message, true);
    log_line(config, "INFO", "local attack notification emitted");
}

fn local_disconnect_notice(config: &ClientConfig) {
    windows_local_alert(config, "Port Honeypot", "Server connection lost", true);
    log_line(config, "WARN", "server connection lost");
}

fn windows_local_alert(config: &ClientConfig, title: &str, message: &str, sound: bool) {
    #[cfg(windows)]
    {
        let title = ps_string(title);
        let message = ps_string(message);
        let beep = if sound {
            "[Console]::Beep(1800,180); [Console]::Beep(1200,180);"
        } else {
            ""
        };
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; \
             $n=New-Object System.Windows.Forms.NotifyIcon; \
             $n.Icon=[System.Drawing.SystemIcons]::Warning; \
             $n.Visible=$true; \
             $n.ShowBalloonTip(5000,{},{},[System.Windows.Forms.ToolTipIcon]::Warning); \
             {} Start-Sleep -Milliseconds 5500; $n.Dispose()",
            title, message, beep
        );
        if let Err(err) = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
            .current_dir(env::temp_dir())
            .spawn()
        {
            log_line(config, "WARN", &format!("windows local alert failed: {}", err));
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (config, title, message, sound);
    }
}

#[cfg(windows)]
fn ps_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn log_line(config: &ClientConfig, level: &str, message: &str) {
    let ts = now_ts();
    let line = format!("{} [{}] {}\n", ts, level, message);
    let path = Path::new(&config.log_path);
    if ensure_parent(path).is_ok() {
        let _ = rotate_log_if_needed(path, config.log_max_bytes, config.log_backup_count);
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

fn rotate_log_if_needed(path: &Path, max_bytes: u64, backup_count: usize) -> io::Result<()> {
    let max_bytes = max_bytes.max(64 * 1024);
    let backup_count = backup_count.max(1);
    if !path.exists() || path.metadata()?.len() < max_bytes {
        return Ok(());
    }

    let oldest = backup_path(path, backup_count);
    if oldest.exists() {
        fs::remove_file(&oldest)?;
    }
    for index in (1..backup_count).rev() {
        let src = backup_path(path, index);
        if src.exists() {
            fs::rename(&src, backup_path(path, index + 1))?;
        }
    }
    fs::rename(path, backup_path(path, 1))?;
    Ok(())
}

fn backup_path(path: &Path, index: usize) -> PathBuf {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "client.log".to_string());
    path.with_file_name(format!("{}.{}", name, index))
}

fn hostname() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn ensure_parent<P: AsRef<Path>>(path: P) -> io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn invalid_data<E: std::fmt::Display>(err: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

fn hmac_digest(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(target_os = "windows")]
mod windows_stealth {
    use super::*;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};

    type Handle = *mut c_void;
    type WinDivertOpenFn = unsafe extern "system" fn(*const c_char, u32, i16, u64) -> Handle;
    type WinDivertRecvFn = unsafe extern "system" fn(Handle, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
    type WinDivertSendFn =
        unsafe extern "system" fn(Handle, *const c_void, u32, *mut u32, *const WinDivertAddress) -> i32;
    type WinDivertCloseFn = unsafe extern "system" fn(Handle) -> i32;

    const WINDIVERT_LAYER_NETWORK: u32 = 0;
    const FILTER: &str = "inbound and !impostor and ip and tcp.Syn and !tcp.Ack";

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct WinDivertAddress {
        timestamp: i64,
        flags: u32,
        reserved2: u32,
        data: [u8; 64],
    }

    struct WinDivert {
        module: Handle,
        open: WinDivertOpenFn,
        recv: WinDivertRecvFn,
        send: WinDivertSendFn,
        close: WinDivertCloseFn,
    }

    struct WinDivertHandle(Handle);

    unsafe impl Send for WinDivert {}
    unsafe impl Send for WinDivertHandle {}

    unsafe extern "system" {
        fn LoadLibraryA(name: *const c_char) -> Handle;
        fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
        fn FreeLibrary(module: Handle) -> i32;
    }

    impl Drop for WinDivert {
        fn drop(&mut self) {
            if !self.module.is_null() {
                unsafe {
                    FreeLibrary(self.module);
                }
            }
        }
    }

    pub fn start(
        config: Arc<Mutex<ClientConfig>>,
        running: Arc<AtomicBool>,
        spool_lock: Arc<Mutex<()>>,
    ) -> bool {
        let cfg = config.lock().unwrap().clone();
        let api = match WinDivert::load() {
            Ok(api) => api,
            Err(err) => {
                log_line(
                    &cfg,
                    "ERROR",
                    &format!(
                        "failed to load WinDivert.dll: {}; place WinDivert.dll and WinDivert64.sys beside the client exe and run as Administrator",
                        err
                    ),
                );
                return false;
            }
        };

        let filter = CString::new(FILTER).expect("static WinDivert filter is valid");
        let handle = unsafe { (api.open)(filter.as_ptr(), WINDIVERT_LAYER_NETWORK, 0, 0) };
        if is_invalid_handle(handle) {
            log_line(
                &cfg,
                "ERROR",
                &format!(
                    "failed to open WinDivert handle: {}; run as Administrator and verify WinDivert64.sys is available",
                    io::Error::last_os_error()
                ),
            );
            return false;
        }

        log_line(
            &cfg,
            "INFO",
            "Windows WinDivert stealth SYN backend started; inbound SYN packets for configured ports will be dropped",
        );
        let divert_handle = WinDivertHandle(handle);
        thread::spawn(move || capture_loop(api, divert_handle, config, running, spool_lock));
        true
    }

    impl WinDivert {
        fn load() -> io::Result<Self> {
            let name = CString::new("WinDivert.dll").unwrap();
            let module = unsafe { LoadLibraryA(name.as_ptr()) };
            if module.is_null() {
                return Err(io::Error::last_os_error());
            }
            let api = unsafe {
                let open = load_symbol::<WinDivertOpenFn>(module, b"WinDivertOpen\0")?;
                let recv = load_symbol::<WinDivertRecvFn>(module, b"WinDivertRecv\0")?;
                let send = load_symbol::<WinDivertSendFn>(module, b"WinDivertSend\0")?;
                let close = load_symbol::<WinDivertCloseFn>(module, b"WinDivertClose\0")?;
                WinDivert {
                    module,
                    open,
                    recv,
                    send,
                    close,
                }
            };
            Ok(api)
        }
    }

    unsafe fn load_symbol<T: Copy>(module: Handle, name: &[u8]) -> io::Result<T> {
        let ptr = GetProcAddress(module, name.as_ptr() as *const c_char);
        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(std::mem::transmute_copy(&ptr))
    }

    fn capture_loop(
        api: WinDivert,
        handle: WinDivertHandle,
        config: Arc<Mutex<ClientConfig>>,
        running: Arc<AtomicBool>,
        spool_lock: Arc<Mutex<()>>,
    ) {
        debug_assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);
        let mut packet = [0u8; 65535];
        let mut recent: HashMap<(String, u16, u16), u64> = HashMap::new();
        while running.load(Ordering::SeqCst) {
            let mut packet_len = 0u32;
            let mut addr = unsafe { std::mem::zeroed::<WinDivertAddress>() };
            let ok = unsafe {
                (api.recv)(
                    handle.0,
                    packet.as_mut_ptr() as *mut c_void,
                    packet.len() as u32,
                    &mut packet_len,
                    &mut addr,
                )
            };
            if ok == 0 {
                let cfg = config.lock().unwrap().clone();
                log_line(&cfg, "WARN", &format!("WinDivertRecv failed: {}", io::Error::last_os_error()));
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            let cfg = config.lock().unwrap().clone();
            let bytes = &packet[..packet_len as usize];
            let Some(event) = parse_ipv4_syn_packet(bytes, &cfg.listen_ports) else {
                reinject_packet(&api, handle.0, bytes, &addr, &cfg);
                continue;
            };

            let key = (
                event.source_ip.clone(),
                event.source_port.unwrap_or_default(),
                event.target_port,
            );
            let now = now_ts();
            if recent.get(&key).is_some_and(|last| now.saturating_sub(*last) < 2) {
                continue;
            }
            recent.insert(key, now);
            if recent.len() > 4096 {
                recent.retain(|_, last| now.saturating_sub(*last) < 30);
            }

            if let Err(err) = append_event(&cfg, &spool_lock, &event) {
                log_line(&cfg, "ERROR", &format!("failed to spool WinDivert stealth event: {}", err));
            } else {
                local_attack_notice(&cfg, &event);
            }
        }
        unsafe {
            (api.close)(handle.0);
        }
    }

    fn reinject_packet(api: &WinDivert, handle: Handle, packet: &[u8], addr: &WinDivertAddress, cfg: &ClientConfig) {
        let mut send_len = 0u32;
        let ok = unsafe {
            (api.send)(
                handle,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                &mut send_len,
                addr,
            )
        };
        if ok == 0 {
            log_line(
                cfg,
                "WARN",
                &format!("WinDivertSend passthrough failed: {}", io::Error::last_os_error()),
            );
        }
    }

    fn is_invalid_handle(handle: Handle) -> bool {
        handle.is_null() || handle == (-1isize) as Handle
    }
}

#[cfg(target_os = "linux")]
mod linux_stealth {
    use super::*;
    use std::collections::HashMap;
    use std::os::raw::{c_int, c_void};

    const AF_INET: c_int = 2;
    const SOCK_RAW: c_int = 3;
    const IPPROTO_TCP: c_int = 6;

    unsafe extern "C" {
        fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
        fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        fn close(fd: c_int) -> c_int;
    }

    pub fn start(
        config: Arc<Mutex<ClientConfig>>,
        running: Arc<AtomicBool>,
        spool_lock: Arc<Mutex<()>>,
    ) -> bool {
        let cfg = config.lock().unwrap().clone();
        let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_TCP) };
        if fd < 0 {
            log_line(
                &cfg,
                "ERROR",
                &format!(
                    "failed to open Linux raw TCP socket: {}; run as root or grant CAP_NET_RAW",
                    io::Error::last_os_error()
                ),
            );
            return false;
        }
        log_line(
            &cfg,
            "INFO",
            "Linux stealth SYN backend started; RST blocking must be configured with scripts/linux_stealth_setup.sh",
        );
        thread::spawn(move || capture_loop(fd, config, running, spool_lock));
        true
    }

    fn capture_loop(
        fd: c_int,
        config: Arc<Mutex<ClientConfig>>,
        running: Arc<AtomicBool>,
        spool_lock: Arc<Mutex<()>>,
    ) {
        let mut buf = [0u8; 65535];
        let mut recent: HashMap<(String, u16, u16), u64> = HashMap::new();
        while running.load(Ordering::SeqCst) {
            let size = unsafe { recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if size < 0 {
                let cfg = config.lock().unwrap().clone();
                log_line(&cfg, "WARN", &format!("raw socket recv failed: {}", io::Error::last_os_error()));
                thread::sleep(Duration::from_millis(200));
                continue;
            }
            let cfg = config.lock().unwrap().clone();
            let Some(event) = parse_ipv4_syn_packet(&buf[..size as usize], &cfg.listen_ports) else {
                continue;
            };

            let key = (
                event.source_ip.clone(),
                event.source_port.unwrap_or_default(),
                event.target_port,
            );
            let now = now_ts();
            if recent.get(&key).is_some_and(|last| now.saturating_sub(*last) < 2) {
                continue;
            }
            recent.insert(key, now);
            if recent.len() > 4096 {
                recent.retain(|_, last| now.saturating_sub(*last) < 30);
            }

            if let Err(err) = append_event(&cfg, &spool_lock, &event) {
                log_line(&cfg, "ERROR", &format!("failed to spool stealth event: {}", err));
            } else {
                local_attack_notice(&cfg, &event);
            }
        }
        unsafe {
            close(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(target_port: u16, flags: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
        packet[20..22].copy_from_slice(&49152u16.to_be_bytes());
        packet[22..24].copy_from_slice(&target_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet
    }

    #[test]
    fn parses_configured_stealth_syn() {
        let event = parse_ipv4_syn_packet(&tcp_packet(3389, 0x02), &[22, 80, 3389])
            .expect("configured SYN should be captured");
        assert_eq!(event.source_ip, "192.0.2.10");
        assert_eq!(event.source_port, Some(49152));
        assert_eq!(event.target_port, 3389);
        assert_eq!(event.mode, "stealth");
        assert!(event.content.contains("SYN probe"));
    }

    #[test]
    fn ignores_syn_ack_and_unconfigured_ports() {
        assert!(parse_ipv4_syn_packet(&tcp_packet(3389, 0x12), &[3389]).is_none());
        assert!(parse_ipv4_syn_packet(&tcp_packet(443, 0x02), &[3389]).is_none());
    }
}
