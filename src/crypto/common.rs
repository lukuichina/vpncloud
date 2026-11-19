use super::{
    core::{test_speed, CryptoCore},
    init::{self, InitResult, InitState, CLOSING},
    rotate::RotationState,
};
use crate::{
    error::Error,
    types::NodeId,
    util::{from_base62, to_base62, MsgBuffer, get_machine_id},
};
use ring::{
    aead::{self, Algorithm, LessSafeKey, UnboundKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey},
    digest,
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair, ED25519_PUBLIC_KEY_LEN},
};
use smallvec::{smallvec, SmallVec};
use std::{fmt::Debug, io::Read, num::NonZeroU32, sync::Arc, time::Duration};

const SALT: &[u8; 32] = b"vpncloudVPNCLOUDvpncl0udVpnCloud";
const INIT_MESSAGE_FIRST_BYTE: u8 = 0xff;
const MESSAGE_TYPE_ROTATION: u8 = 0x10;

pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_LEN];
pub type EcdhPublicKey = UnparsedPublicKey<SmallVec<[u8; 96]>>;
pub type EcdhPrivateKey = EphemeralPrivateKey;
pub type Key = SmallVec<[u8; 32]>;

const DEFAULT_ALGORITHMS: [&str; 3] = ["AES128", "AES256", "CHACHA20"];

#[cfg(test)]
const SPEED_TEST_TIME: f32 = 0.02;
#[cfg(not(test))]
const SPEED_TEST_TIME: f32 = 0.1;

// Periodic key rotation interval, in ticks (ticks == seconds here, since
// every_second() is driven once per housekeep). Rotation was previously
// disabled (usize::MAX) because a lost/reordered rotation frame could desync
// the peers' key slots and cause "Failed to decrypt". Two changes make it
// safe again: (1) the NodeId-primary refactor no longer rebuilds peer.crypto
// on address change, so rotation state survives roaming; (2) the CryptoCore
// key ring was widened 4->8 slots so an in-flight key cannot be evicted by a
// single lost/retransmitted rotation within its recovery window.
// The rotation period is set at runtime via --rotate-interval (0 = disabled).

pub trait Payload: Debug + PartialEq + Sized {
    fn write_to(&self, buffer: &mut MsgBuffer);
    fn read_from<R: Read>(r: R) -> Result<Self, Error>;
    /// Returns a default/empty payload. Used when completing a handshake
    /// without a crypto core (peer already completed init as initiator).
    /// Default implementation tries to read from empty data.
    fn default_payload() -> Self {
        use std::io::Cursor;
        Self::read_from(Cursor::new(&[])).unwrap_or_else(|_| {
            panic!("Payload::default_payload() not implemented for this type")
        })
    }
}

#[derive(Clone)]
pub struct Algorithms {
    pub algorithm_speeds: SmallVec<[(&'static Algorithm, f32); 3]>,
    pub allow_unencrypted: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct Config {
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub trusted_keys: Vec<String>,
    pub algorithms: Vec<String>,
    /// Periodic key rotation interval in seconds (0 = disabled). Driven once
    /// per second from the housekeep loop. Configurable at runtime via
    /// `--rotate-interval` so rotation can be toggled without recompiling.
    pub rotate_interval: usize,
}

pub struct Crypto {
    pub node_id: NodeId,
    key_pair: Arc<Ed25519KeyPair>,
    trusted_keys: Arc<[Ed25519PublicKey]>,
    algorithms: Algorithms,
    rotate_interval: usize,
}

impl Crypto {
    pub fn parse_algorithms(algos: &[String]) -> Result<(bool, Vec<&'static aead::Algorithm>), Error> {
        let algorithms = algos.iter().map(|a| a as &str).collect::<Vec<_>>();
        let allowed = if algorithms.is_empty() { &DEFAULT_ALGORITHMS } else { &algorithms as &[&str] };
        let mut algos = vec![];
        let mut unencrypted = false;
        for name in allowed {
            let algo = match &name.to_uppercase() as &str {
                "UNENCRYPTED" | "NONE" | "PLAIN" => {
                    unencrypted = true;
                    continue;
                }
                "AES128" | "AES128_GCM" | "AES_128" | "AES_128_GCM" => &aead::AES_128_GCM,
                "AES256" | "AES256_GCM" | "AES_256" | "AES_256_GCM" => &aead::AES_256_GCM,
                "CHACHA" | "CHACHA20" | "CHACHA20_POLY1305" => &aead::CHACHA20_POLY1305,
                _ => return Err(Error::InvalidConfig("Unknown crypto method")),
            };
            algos.push(algo)
        }
        Ok((unencrypted, algos))
    }

    pub fn new(config: &Config) -> Result<Self, Error> {
        let key_pair = if let Some(priv_key) = &config.private_key {
            if let Some(pub_key) = &config.public_key {
                Self::parse_keypair(priv_key, pub_key)?
            } else {
                Self::parse_private_key(priv_key)?
            }
        } else if let Some(password) = &config.password {
            Self::keypair_from_password(password)
        } else {
            return Err(Error::InvalidConfig("Either private_key or password must be set"));
        };
        // Derive deterministic node_id:
        // - If private_key configured: use its public key (user ensures uniqueness)
        // - If only password: include machine_id to avoid collisions across nodes sharing password
        let node_id = if config.private_key.is_some() {
            Self::derive_node_id(key_pair.public_key().as_ref())
        } else {
            let machine_id = get_machine_id();
            Self::derive_node_id_with_salt(key_pair.public_key().as_ref(), Some(&machine_id))
        };
        let mut trusted_keys = vec![];
        for tn in &config.trusted_keys {
            trusted_keys.push(Self::parse_public_key(tn)?);
        }
        if trusted_keys.is_empty() {
            info!("Trusted keys not set, trusting only own public key");
            let mut key = [0; ED25519_PUBLIC_KEY_LEN];
            key.clone_from_slice(key_pair.public_key().as_ref());
            trusted_keys.push(key);
        }
        let (unencrypted, allowed_algos) = Self::parse_algorithms(&config.algorithms)?;
        if unencrypted {
            warn!("Crypto settings allow unencrypted connections")
        }
        let mut algos = Algorithms { algorithm_speeds: smallvec![], allow_unencrypted: unencrypted };
        let duration = Duration::from_secs_f32(SPEED_TEST_TIME);
        let mut speeds = Vec::new();
        for algo in allowed_algos {
            let speed = test_speed(algo, &duration);
            algos.algorithm_speeds.push((algo, speed as f32));
            speeds.push((format!("{:?}", algo), speed as f32));
        }
        if !speeds.is_empty() {
            info!(
                "Crypto speeds: {}",
                speeds.into_iter().map(|(a, s)| format!("{}: {:.1} MiB/s", a, s)).collect::<Vec<_>>().join(", ")
            );
        }
        info!("Key rotation interval: {}s (0 = disabled)", config.rotate_interval);
        Ok(Self {
            node_id,
            key_pair: Arc::new(key_pair),
            trusted_keys: trusted_keys.into_boxed_slice().into(),
            algorithms: algos,
            rotate_interval: config.rotate_interval,
        })
    }

    pub fn generate_keypair(password: Option<&str>) -> (String, String) {
        let mut bytes = [0; 32];
        match password {
            None => {
                let rng = SystemRandom::new();
                rng.fill(&mut bytes).unwrap();
            }
            Some(password) => {
                pbkdf2::derive(
                    pbkdf2::PBKDF2_HMAC_SHA256,
                    NonZeroU32::new(4096).unwrap(),
                    SALT,
                    password.as_bytes(),
                    &mut bytes,
                );
            }
        }
        let keypair = Ed25519KeyPair::from_seed_unchecked(&bytes).unwrap();
        let privkey = to_base62(&bytes);
        let pubkey = to_base62(keypair.public_key().as_ref());
        (privkey, pubkey)
    }

    fn keypair_from_password(password: &str) -> Ed25519KeyPair {
        let mut key = [0; 32];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(4096).unwrap(), SALT, password.as_bytes(), &mut key);
        Ed25519KeyPair::from_seed_unchecked(&key).unwrap()
    }

    /// Derive deterministic node_id from Ed25519 public key (SHA256, first 16 bytes)
    fn derive_node_id(public_key: &[u8]) -> NodeId {
        assert_eq!(public_key.len(), ED25519_PUBLIC_KEY_LEN);
        let hash = digest::digest(&digest::SHA256, public_key);
        let mut node_id = [0u8; 16];
        node_id.clone_from_slice(&hash.as_ref()[..16]);
        node_id
    }

    /// Derive node_id from public key + unique salt (for password-only configs to avoid collisions)
    fn derive_node_id_with_salt(public_key: &[u8], salt: Option<&str>) -> NodeId {
        assert_eq!(public_key.len(), ED25519_PUBLIC_KEY_LEN);
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(public_key);
        if let Some(s) = salt {
            ctx.update(s.as_bytes());
        }
        let hash = ctx.finish();
        let mut node_id = [0u8; 16];
        node_id.clone_from_slice(&hash.as_ref()[..16]);
        node_id
    }

    fn parse_keypair(privkey: &str, pubkey: &str) -> Result<Ed25519KeyPair, Error> {
        let privkey = from_base62(privkey).map_err(|_| Error::InvalidConfig("Failed to parse private key"))?;
        let pubkey = from_base62(pubkey).map_err(|_| Error::InvalidConfig("Failed to parse public key"))?;
        let keypair = Ed25519KeyPair::from_seed_and_public_key(&privkey, &pubkey)
            .map_err(|_| Error::InvalidConfig("Keys rejected by crypto library"))?;
        Ok(keypair)
    }

    fn parse_private_key(privkey: &str) -> Result<Ed25519KeyPair, Error> {
        let privkey = from_base62(privkey).map_err(|_| Error::InvalidConfig("Failed to parse private key"))?;
        let keypair = Ed25519KeyPair::from_seed_unchecked(&privkey)
            .map_err(|_| Error::InvalidConfig("Key rejected by crypto library"))?;
        Ok(keypair)
    }

    fn parse_public_key(pubkey: &str) -> Result<Ed25519PublicKey, Error> {
        let pubkey = from_base62(pubkey).map_err(|_| Error::InvalidConfig("Failed to parse public key"))?;
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(Error::InvalidConfig("Failed to parse public key"));
        }
        let mut result = [0; ED25519_PUBLIC_KEY_LEN];
        result.clone_from_slice(&pubkey);
        Ok(result)
    }

    pub fn public_key_from_private_key(privkey: &str) -> Result<String, Error> {
        let keypair = Self::parse_private_key(privkey)?;
        Ok(to_base62(keypair.public_key().as_ref()))
    }

    pub fn peer_instance<P: Payload>(&self, payload: P) -> PeerCrypto<P> {
        PeerCrypto::new(
            self.node_id,
            payload,
            self.key_pair.clone(),
            self.trusted_keys.clone(),
            self.algorithms.clone(),
            self.rotate_interval,
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum MessageResult<P: Payload> {
    Message(u8),
    Initialized(P),
    InitializedWithReply(P),
    Reply,
    None,
}

pub struct PeerCrypto<P: Payload> {
    #[allow(dead_code)]
    node_id: NodeId,
    init: Option<InitState<P>>,
    rotation: Option<RotationState>,
    unencrypted: bool,
    core: Option<CryptoCore>,
    rotate_counter: usize,
    /// Rotation period in ticks (~seconds); 0 disables rotation.
    rotate_interval: usize,
    /// Role we played in the completed handshake: Some(true) if we were the
    /// initiator (we sent PING), Some(false) if responder. Used for
    /// deterministic simultaneous-open tie-breaking. None until init succeeds.
    initiator: Option<bool>,
}

impl<P: Payload> PeerCrypto<P> {
    pub fn new(
        node_id: NodeId, init_payload: P, key_pair: Arc<Ed25519KeyPair>, trusted_keys: Arc<[Ed25519PublicKey]>,
        algorithms: Algorithms, rotate_interval: usize,
    ) -> Self {
        Self {
            node_id,
            init: Some(InitState::new(node_id, init_payload, key_pair, trusted_keys, algorithms)),
            rotation: None,
            unencrypted: false,
            core: None,
            rotate_counter: 0,
            rotate_interval,
            initiator: None,
        }
    }

    fn get_init(&mut self) -> Result<&mut InitState<P>, Error> {
        if let Some(init) = &mut self.init {
            Ok(init)
        } else {
            Err(Error::InvalidCryptoState("Initialization already finished"))
        }
    }

    fn get_core(&mut self) -> Result<&mut CryptoCore, Error> {
        if let Some(core) = &mut self.core {
            Ok(core)
        } else {
            Err(Error::InvalidCryptoState("Crypto core not ready yet"))
        }
    }

    fn get_rotation(&mut self) -> Result<&mut RotationState, Error> {
        if let Some(rotation) = &mut self.rotation {
            Ok(rotation)
        } else {
            Err(Error::InvalidCryptoState("Key rotation not initialized"))
        }
    }

    pub fn initialize(&mut self, out: &mut MsgBuffer) -> Result<(), Error> {
        let init = self.get_init()?;
        if init.stage() != init::STAGE_PING {
            Err(Error::InvalidCryptoState("Initialization already ongoing"))
        } else {
            init.send_ping(out);
            out.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            Ok(())
        }
    }

    pub fn has_init(&self) -> bool {
        self.init.is_some()
    }

    pub fn is_ready(&self) -> bool {
        self.core.is_some()
    }

    /// Role in the completed handshake: Some(true) = we were initiator,
    /// Some(false) = we were responder, None = not negotiated yet.
    pub fn is_initiator(&self) -> Option<bool> {
        self.initiator
    }

    pub fn algorithm_name(&self) -> &'static str {
        if let Some(ref core) = self.core {
            let algo = core.algorithm();
            if algo == &aead::CHACHA20_POLY1305 {
                "CHACHA20"
            } else if algo == &aead::AES_128_GCM {
                "AES128"
            } else if algo == &aead::AES_256_GCM {
                "AES256"
            } else {
                unreachable!()
            }
        } else {
            "PLAIN"
        }
    }

    fn handle_init_message(&mut self, buffer: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        let result = self.get_init()?.handle_init(buffer)?;
        if !buffer.is_empty() {
            buffer.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
        }
        match result {
            InitResult::Continue => Ok(MessageResult::Reply),
            InitResult::Success { peer_payload, is_initiator } => {
                let unencrypted_planned = self.get_init()?.selected_algorithm().is_none();
                self.initiator = Some(is_initiator);
                debug!(
                    "Crypto init success: is_initiator={}, unencrypted_planned={}",
                    is_initiator, unencrypted_planned
                );
                self.core = self.get_init()?.take_core();
                if self.core.is_none() {
                    self.unencrypted = true;
                }
                let stage_after = self.get_init()?.stage();
                if stage_after == init::CLOSING {
                    debug!("Crypto init: stage CLOSING after success, clearing init state (is_initiator={})", is_initiator);
                    self.init = None
                } else {
                    debug!("Crypto init: keeping init state at stage={} (is_initiator={})", stage_after, is_initiator);
                }
                if self.core.is_some() {
                    self.rotation = Some(RotationState::new(!is_initiator, buffer));
                    debug!("Initialized rotation state: is_initiator={}, reply_len={}", is_initiator, buffer.len());
                }
                if !is_initiator {
                    if self.unencrypted {
                        return Ok(MessageResult::Initialized(peer_payload));
                    }
                    assert!(!buffer.is_empty());
                    buffer.prepend_byte(MESSAGE_TYPE_ROTATION);
                    self.encrypt_message(buffer)?;
                }
                Ok(MessageResult::InitializedWithReply(peer_payload))
            }
        }
    }

    fn handle_rotate_message(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.unencrypted {
            return Ok(());
        }
        debug!("Handling rotation payload: {} bytes", data.len());
        if let Some(rot) = self.get_rotation()?.handle_message(data)? {
            let core = self.get_core()?;
            let algo = core.algorithm();
            let key = LessSafeKey::new(UnboundKey::new(algo, &rot.key[..algo.key_len()]).unwrap());
            debug!("Applying rotated key: id={}, use_for_sending={}", rot.id, rot.use_for_sending);
            core.rotate_key(key, rot.id, rot.use_for_sending);
        } else {
            debug!("Rotation payload processed: no key ready/applied");
        }
        Ok(())
    }

    fn encrypt_message(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        if self.unencrypted {
            return Ok(());
        }
        self.get_core()?.encrypt(buffer);
        Ok(())
    }

    fn decrypt_message(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        if self.unencrypted {
            return Ok(());
        }
        self.get_core()?.decrypt(buffer)
    }

    pub fn handle_message(&mut self, buffer: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        // HOT PATH
        if buffer.is_empty() {
            return Err(Error::InvalidCryptoState("No message in buffer"));
        }
        if is_init_message(buffer.buffer()) {
            // COLD PATH
            debug!("Received init message");
            buffer.take_prefix();
            self.handle_init_message(buffer)
        } else {
            // HOT PATH
            debug!("Received encrypted message: {} bytes", buffer.len());
            self.decrypt_message(buffer)?;
            let msg_type = buffer.take_prefix();
            debug!("Decrypted message type={}", msg_type);
            if msg_type == MESSAGE_TYPE_ROTATION {
                // COLD PATH
                debug!("Received rotation message (decrypted)");
                self.handle_rotate_message(buffer.buffer())?;
                buffer.clear();
                Ok(MessageResult::None)
            } else {
                Ok(MessageResult::Message(msg_type))
            }
        }
    }

    pub fn send_message(&mut self, type_: u8, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        assert_ne!(type_, MESSAGE_TYPE_ROTATION);
        buffer.prepend_byte(type_);
        self.encrypt_message(buffer)
    }

    pub fn every_second(&mut self, out: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        out.clear();
        if let Some(ref mut core) = self.core {
            core.every_second()
        }
        if let Some(ref mut init) = self.init {
            init.every_second(out)?;
        }
        if self.init.as_ref().map(|i| i.stage()).unwrap_or(CLOSING) == CLOSING {
            self.init = None
        }
        if !out.is_empty() {
            out.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            return Ok(MessageResult::Reply);
        }
        if let Some(ref mut rotate) = self.rotation {
            // rotate_interval == 0 disables periodic rekeying (configurable via --rotate-interval).
            if self.rotate_interval == 0 {
                return Ok(MessageResult::None);
            }
            self.rotate_counter += 1;
            if self.rotate_counter >= self.rotate_interval {
                self.rotate_counter = 0;
                if let Some(rot) = rotate.cycle(out) {
                    let core = self.get_core()?;
                    let algo = core.algorithm();
                    let key = LessSafeKey::new(UnboundKey::new(algo, &rot.key[..algo.key_len()]).unwrap());
                    core.rotate_key(key, rot.id, rot.use_for_sending);
                }
                if !out.is_empty() {
                    out.prepend_byte(MESSAGE_TYPE_ROTATION);
                    self.encrypt_message(out)?;
                    return Ok(MessageResult::Reply);
                }
            }
        }
        Ok(MessageResult::None)
    }
}

pub fn is_init_message(msg: &[u8]) -> bool {
    // HOT PATH
    !msg.is_empty() && msg[0] == INIT_MESSAGE_FIRST_BYTE
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::NODE_ID_BYTES;

    fn create_node(config: &Config) -> PeerCrypto<Vec<u8>> {
        let crypto = Crypto::new(config).unwrap();
        crypto.peer_instance(vec![])
    }

    #[test]
    fn normal() {
        let config = Config { password: Some("test".to_string()), ..Default::default() };
        let mut node1 = create_node(&config);
        let mut node2 = create_node(&config);
        let mut msg = MsgBuffer::new(16);

        node1.initialize(&mut msg).unwrap();
        assert!(!msg.is_empty());

        debug!("Node1 -> Node2");
        let res = node2.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::Reply);
        assert!(!msg.is_empty());

        debug!("Node1 <- Node2");
        let res = node1.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::InitializedWithReply(vec![]));
        assert!(!msg.is_empty());

        debug!("Node1 -> Node2");
        let res = node2.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::InitializedWithReply(vec![]));
        assert!(!msg.is_empty());

        debug!("Node1 <- Node2");
        let res = node1.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::None);
        assert!(msg.is_empty());

        let mut buffer = MsgBuffer::new(16);
        let rng = SystemRandom::new();
        buffer.set_length(1000);
        rng.fill(buffer.message_mut()).unwrap();
        for _ in 0..1000 {
            node1.send_message(1, &mut buffer).unwrap();
            let res = node2.handle_message(&mut buffer).unwrap();
            assert_eq!(res, MessageResult::Message(1));

            match node1.every_second(&mut msg).unwrap() {
                MessageResult::None => (),
                MessageResult::Reply => {
                    let res = node2.handle_message(&mut msg).unwrap();
                    assert_eq!(res, MessageResult::None);
                }
                other => assert_eq!(other, MessageResult::None),
            }
            match node2.every_second(&mut msg).unwrap() {
                MessageResult::None => (),
                MessageResult::Reply => {
                    let res = node1.handle_message(&mut msg).unwrap();
                    assert_eq!(res, MessageResult::None);
                }
                other => assert_eq!(other, MessageResult::None),
            }
        }
    }
}
