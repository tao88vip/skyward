use crate::token::Token;
use anyhow::{bail, Context, Result};
use skyward_binder::driver::{Binder, Handle};
use skyward_binder::hidl::{self, Answer, EmbeddedStruct, Message};
use skyward_binder::parcel::Parcel;
use skyward_binder::{service, status};

/// The phone's own key service, the only thing that can use a key the
/// hardware wrapped.
pub const SERVICE: &str = "android.hardware.security.keymint.IKeyMintDevice/default";

const DEVICE: &str = "android.hardware.security.keymint.IKeyMintDevice";
const OPERATION: &str = "android.hardware.security.keymint.IKeyMintOperation";

/// The older key service Android 11 and earlier register with hwbinder.
const KEYMASTER: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const KEYMASTER_INSTANCE: &str = "default";

const KM_GET_HARDWARE_INFO: u32 = 1;
const KM_GET_KEY_CHARACTERISTICS: u32 = 9;
const KM_EXPORT_KEY: u32 = 10;
const KM_UPGRADE_KEY: u32 = 12;
const KM_BEGIN: u32 = 16;
const KM_UPDATE: u32 = 17;
const KM_FINISH: u32 = 18;
const KM_ABORT: u32 = 19;

/// How large HIDL lays out the values begin() carries.
const KEY_PARAMETER_BYTES: usize = 32;
const AUTH_TOKEN_BYTES: usize = 56;
const VERIFICATION_TOKEN_BYTES: usize = 56;

/// Where the union and blob sit inside a HIDL KeyParameter.
const PARAM_UNION: usize = 4;
const PARAM_UNION_VALUE: usize = 8;
const PARAM_BLOB: usize = 16;

/// The arm of a KeyParameter union for each value written here.
const UNION_BLOCK_MODE: u32 = 1;
const UNION_PADDING: u32 = 2;
const UNION_INTEGER: u32 = 12;
const UNION_NONE: u32 = 0;

const GET_HARDWARE_INFO: u32 = 1;
const UPGRADE_KEY: u32 = 6;
const CONVERT_STORAGE_KEY: u32 = 13;
const GET_KEY_CHARACTERISTICS: u32 = 14;
const BEGIN: u32 = 10;

/// The top of a tag says what kind of value it carries.
const TAG_KIND: i32 = -268_435_456;
const KIND_ULONG: i32 = 1_342_177_280;
const KIND_ULONG_REP: i32 = -1_610_612_736;
const KIND_DATE: i32 = 1_610_612_736;
const KIND_BYTES: i32 = -1_879_048_192;
const KIND_BIGNUM: i32 = -2_147_483_648;
const UPDATE: u32 = 2;
const FINISH: u32 = 3;
const ABORT: u32 = 4;

/// How long the nonce of an AES-GCM key is here.
const NONCE_BYTES: usize = 12;

/// The key service's way of saying the key was made under an older build of
/// the phone's own firmware and has to be renewed before it will be used.
const KEY_REQUIRES_UPGRADE: i32 = -62;

const PURPOSE_DECRYPT: i32 = 1;
const BLOCK_MODE_GCM: i32 = 32;
const PADDING_NONE: i32 = 1;
const KEY_FORMAT_RAW: u32 = 3;

/// What a key parameter is tagged with. The high bits say which kind of
/// value follows, which is why the numbers look arbitrary.
const TAG_PURPOSE: i32 = 536_870_913;
const TAG_BLOCK_MODE: i32 = 536_870_916;
const TAG_PADDING: i32 = 536_870_918;
const TAG_MAC_LENGTH: i32 = 805_307_371;
const TAG_APPLICATION_ID: i32 = -1_879_047_591;
const TAG_NONCE: i32 = -1_879_047_191;

/// Which arm of a parameter's value is used.
const VALUE_PADDING_MODE: i32 = 3;
const VALUE_KEY_PURPOSE: i32 = 7;
const VALUE_INTEGER: i32 = 11;
const VALUE_BLOB: i32 = 14;
const VALUE_BLOCK_MODE: i32 = 2;

/// The tag's value and which arm it is written as.
enum Value<'a> {
    Enum(i32, i32),
    Integer(i32),
    Blob(&'a [u8]),
}

fn parameter(p: &mut Parcel, tag: i32, value: Value) {
    // Each parameter is a structure of its own: it says it is there, then
    // how long it is, so the far side can step over what it does not know.
    p.i32(1);
    let start = p.here();
    p.i32(0);
    p.i32(tag);
    // The value is a structure of its own too, and says so the same way,
    // though it carries no length because only one arm of it is ever set.
    p.i32(1);
    match value {
        Value::Enum(arm, v) => {
            p.i32(arm);
            p.i32(v);
        }
        Value::Integer(v) => {
            p.i32(VALUE_INTEGER);
            p.i32(v);
        }
        Value::Blob(v) => {
            p.i32(VALUE_BLOB);
            p.blob(v);
        }
    }
    let size = (p.here() - start) as i32;
    p.fill(start, size);
}

/// Hand over the note the secure world wrote when the user answered their
/// screen lock. A key guarded by the screen lock is refused without it.
fn vouched(p: &mut Parcel, note: &Token) {
    p.i32(1);
    let start = p.here();
    p.i32(0);
    p.i64(note.challenge);
    p.i64(note.user);
    p.i64(note.authenticator);
    p.i32(note.kind);
    // The time it was written is a structure of its own.
    p.i32(1);
    let when = p.here();
    p.i32(0);
    p.i64(note.when);
    let size = (p.here() - when) as i32;
    p.fill(when, size);
    p.blob(&note.mac);
    let size = (p.here() - start) as i32;
    p.fill(start, size);
}

/// One HIDL KeyParameter.
fn hardware_parameter(tag: i32, arm: u32, value: u64, blob: &[u8]) -> EmbeddedStruct {
    let mut bytes = vec![0u8; KEY_PARAMETER_BYTES];
    bytes[0..4].copy_from_slice(&(tag as u32).to_le_bytes());
    bytes[PARAM_UNION..PARAM_UNION + 4].copy_from_slice(&arm.to_le_bytes());
    bytes[PARAM_UNION_VALUE..PARAM_UNION_VALUE + 8].copy_from_slice(&value.to_le_bytes());
    bytes[PARAM_BLOB + 8..PARAM_BLOB + 12].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    EmbeddedStruct {
        bytes,
        children: vec![(PARAM_BLOB, blob.to_vec())],
    }
}

fn hardware_integer(tag: i32, arm: u32, value: u64) -> EmbeddedStruct {
    hardware_parameter(tag, arm, value, &[])
}

fn hardware_blob(tag: i32, blob: &[u8]) -> EmbeddedStruct {
    hardware_parameter(tag, UNION_NONE, 0, blob)
}

/// The parameters Vold gives before it decrypts a wrapped key.
fn hardware_parameters(app_id: &[u8], nonce: Option<&[u8]>) -> Vec<EmbeddedStruct> {
    let mut params = vec![
        hardware_integer(TAG_BLOCK_MODE, UNION_BLOCK_MODE, BLOCK_MODE_GCM as u64),
        hardware_integer(TAG_PADDING, UNION_PADDING, PADDING_NONE as u64),
        hardware_integer(TAG_MAC_LENGTH, UNION_INTEGER, 128),
    ];
    if !app_id.is_empty() {
        params.push(hardware_blob(TAG_APPLICATION_ID, app_id));
    }
    if let Some(nonce) = nonce {
        params.push(hardware_blob(TAG_NONCE, nonce));
    }
    params
}

/// A HardwareAuthToken, or the empty one a key with no screen lock takes.
fn hardware_note(note: Option<&Token>) -> EmbeddedStruct {
    let mut bytes = vec![0u8; AUTH_TOKEN_BYTES];
    let mac = match note {
        Some(note) => {
            bytes[0..8].copy_from_slice(&note.challenge.to_le_bytes());
            bytes[8..16].copy_from_slice(&note.user.to_le_bytes());
            bytes[16..24].copy_from_slice(&note.authenticator.to_le_bytes());
            bytes[24..28].copy_from_slice(&(note.kind as u32).to_le_bytes());
            bytes[32..40].copy_from_slice(&note.when.to_le_bytes());
            &note.mac[..]
        }
        None => &[],
    };
    bytes[48..52].copy_from_slice(&(mac.len() as u32).to_le_bytes());
    EmbeddedStruct {
        bytes,
        children: vec![(40, mac.to_vec())],
    }
}

fn empty_verification() -> EmbeddedStruct {
    EmbeddedStruct {
        bytes: vec![0u8; VERIFICATION_TOKEN_BYTES],
        children: vec![(16, Vec::new()), (40, Vec::new())],
    }
}

/// What the phone says about its key hardware.
pub struct Hardware {
    pub version: i32,
    pub security_level: i32,
    pub name: String,
    pub author: String,
}

enum Backend<'a> {
    KeyMint(Handle<'a>),
    Keymaster(Handle<'a>),
}

/// The phone's key service, as this program talks to it.
pub struct KeyMint<'a> {
    backend: Backend<'a>,
}

impl<'a> KeyMint<'a> {
    /// Reach the running key service, preferring the newer AIDL KeyMint and
    /// taking Android 11's HIDL Keymaster 4.0 where that is what the phone
    /// has.
    pub fn open(binder: &'a Binder, hardware: &'a Binder) -> Result<KeyMint<'a>> {
        // The running Android system may number its service directory
        // differently from the recovery's. A failed AIDL look-up therefore
        // falls through to the HIDL service this phone actually has.
        if let Ok(Some(device)) = service::find(binder, SERVICE) {
            return Ok(KeyMint {
                backend: Backend::KeyMint(device),
            });
        }
        if let Some(device) = hidl::find(hardware, KEYMASTER, KEYMASTER_INSTANCE)? {
            return Ok(KeyMint {
                backend: Backend::Keymaster(device),
            });
        }
        bail!(
            "neither {SERVICE} nor {KEYMASTER}/{KEYMASTER_INSTANCE} is running; the phone's key service has to be started first"
        )
    }

    fn keymint(&self) -> Option<&Handle<'a>> {
        match &self.backend {
            Backend::KeyMint(device) => Some(device),
            Backend::Keymaster(_) => None,
        }
    }

    fn keymaster(&self) -> Option<&Handle<'a>> {
        match &self.backend {
            Backend::Keymaster(device) => Some(device),
            Backend::KeyMint(_) => None,
        }
    }

    fn aidl(&self) -> Result<&Handle<'a>> {
        self.keymint()
            .context("this operation is only available on AIDL KeyMint")
    }

    fn legacy(&self) -> Result<&Handle<'a>> {
        self.keymaster()
            .context("this operation needs the older Keymaster service")
    }

    /// Reach the running key service, or say that none is.
    pub fn open_aidl(binder: &'a Binder) -> Result<KeyMint<'a>> {
        let device = service::find(binder, SERVICE)?.with_context(|| {
            format!("{SERVICE} is not running; the phone's key service has to be started first")
        })?;
        Ok(KeyMint {
            backend: Backend::KeyMint(device),
        })
    }

    pub fn hardware(&self) -> Result<Hardware> {
        if let Some(device) = self.keymaster() {
            let reply = device
                .transact(KM_GET_HARDWARE_INFO, &Message::call(KEYMASTER))
                .context("ask the key service about itself")?;
            let mut read = Answer::new(reply.bytes());
            read.status().context("ask the key service about itself")?;
            let level = read
                .i32()
                .context("read the key hardware's security level")?;
            let name = read.text().with_context(|| {
                format!("read the key hardware's name from {:02x?}", reply.bytes())
            })?;
            let author = read.text().context("read the key hardware's author")?;
            return Ok(Hardware {
                version: 4,
                security_level: level,
                name,
                author,
            });
        }
        let device = self.aidl()?;
        let reply = device
            .transact(GET_HARDWARE_INFO, &Parcel::call(DEVICE))
            .context("ask the key service about itself")?;
        let mut read = reply.read();
        status::ok(&mut read).context("ask the key service about itself")?;
        let end = read.structure()?;
        let info = Hardware {
            version: read.i32()?,
            security_level: read.i32()?,
            name: read.string()?,
            author: read.string()?,
        };
        read.go(end)?;
        Ok(info)
    }

    /// Turn a key that only the storage hardware can use into the form it
    /// takes for this start of the phone. The key itself never leaves the
    /// secure world: what comes back is wrapped again, for the hardware to
    /// unwrap as it reads and writes.
    pub fn ephemeral_storage_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        if self.keymaster().is_some() {
            return match self.keymaster_export(key) {
                Err(e) if keymaster_refused_with(&e) == Some(KEY_REQUIRES_UPGRADE) => {
                    let renewed = self
                        .keymaster_upgrade(key, Vec::new())
                        .context("renew the storage key for the firmware running now")?;
                    self.keymaster_export(&renewed)
                }
                exported => exported,
            };
        }
        match self.convert(key) {
            Err(e) if status::refused_with(&e) == Some(KEY_REQUIRES_UPGRADE) => {
                // As with a key that decrypts, the key is renewed for the
                // firmware running now, as Android's keystore2 renews one
                // for vold, and the one on disk is left as it is. A storage
                // key is bound to nothing that has to be given again.
                let renewed = self
                    .upgrade(key, |call| call.i32(0))
                    .context("renew the storage key for the firmware running now")?;
                self.convert(&renewed)
            }
            converted => converted,
        }
    }

    fn convert(&self, key: &[u8]) -> Result<Vec<u8>> {
        let mut call = Parcel::call(DEVICE);
        call.blob(key);
        let reply = self
            .aidl()?
            .transact(CONVERT_STORAGE_KEY, &call)
            .context("make a storage key for this start")?;
        let mut read = reply.read();
        status::ok(&mut read).context("make a storage key for this start")?;
        read.blob().context("read the storage key")
    }

    /// What the key service says a key may be used for: each entry is a tag
    /// and the number or length that came with it.
    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        if self.keymaster().is_some() {
            return self.keymaster_authorizations(key_blob, app_id);
        }
        let mut call = Parcel::call(DEVICE);
        call.blob(key_blob);
        call.blob(app_id);
        call.blob(&[]);
        let reply = self
            .aidl()?
            .transact(GET_KEY_CHARACTERISTICS, &call)
            .context("ask what the key may be used for")?;
        let mut read = reply.read();
        status::ok(&mut read).context("ask what the key may be used for")?;
        let mut out = Vec::new();
        for _ in 0..read.i32()?.max(0) {
            let end = read.structure()?;
            read.i32()
                .context("read which part of the phone holds the key")?;
            for _ in 0..read.i32()?.max(0) {
                let next = read.structure()?;
                let tag = read.i32()?;
                read.i32().context("read whether the tag has a value")?;
                read.i32().context("read which arm of the value is set")?;
                let value = match tag & TAG_KIND {
                    KIND_ULONG | KIND_ULONG_REP | KIND_DATE => read.i64()?,
                    KIND_BYTES | KIND_BIGNUM => read.blob()?.len() as i64,
                    _ => read.i32()? as i64,
                };
                out.push((tag, value));
                read.go(next)?;
            }
            read.go(end)?;
        }
        Ok(out)
    }

    /// Undo an AES-GCM encryption the key service did with `key_blob`. The
    /// service only hands back the plaintext when `app_id` is the one the
    /// key was made for, so a wrong secret fails here rather than yielding
    /// something that looks like a key. A key guarded by a screen lock
    /// takes the note the secure world wrote when it was answered.
    pub fn gcm_decrypt(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
        note: Option<&Token>,
    ) -> Result<Vec<u8>> {
        if self.keymaster().is_some() {
            return self.keymaster_gcm_decrypt(key_blob, app_id, nonce, body, note);
        }
        let operation = match self.begin(key_blob, app_id, nonce, note) {
            Ok(operation) => operation,
            Err(e) if status::refused_with(&e) == Some(KEY_REQUIRES_UPGRADE) => {
                // The phone's firmware has moved on since this key was
                // made. Renewing it gives a key for the firmware running
                // now; the one on disk is left as it is, so nothing of the
                // phone's own is changed by reading it here.
                let renewed = self
                    .upgrade(key_blob, |call| Self::gcm_params(call, app_id, nonce))
                    .context("renew the key for the firmware running now")?;
                self.begin(&renewed, app_id, nonce, note)?
            }
            Err(e) => return Err(e),
        };
        let mut out = self.update(&operation, body)?;
        out.extend_from_slice(&self.finish(&operation)?);
        Ok(out)
    }

    fn keymaster_gcm_decrypt(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
        note: Option<&Token>,
    ) -> Result<Vec<u8>> {
        let operation = match self.keymaster_begin(key_blob, app_id, nonce, note) {
            Ok(operation) => operation,
            Err(e) if keymaster_refused_with(&e) == Some(KEY_REQUIRES_UPGRADE) => {
                let renewed = self
                    .keymaster_upgrade(key_blob, hardware_parameters(app_id, None))
                    .context("renew the key for the firmware running now")?;
                self.keymaster_begin(&renewed, app_id, nonce, note)?
            }
            Err(e) => return Err(e),
        };
        let mut out = self.keymaster_update(operation, body)?;
        out.extend_from_slice(&self.keymaster_finish(operation)?);
        Ok(out)
    }

    fn keymaster_begin(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        note: Option<&Token>,
    ) -> Result<u64> {
        let mut call = Message::call(KEYMASTER);
        call.u32(PURPOSE_DECRYPT as u32);
        call.bytes(key_blob);
        call.structures(
            KEY_PARAMETER_BYTES,
            hardware_parameters(app_id, Some(nonce)),
        );
        call.structure(hardware_note(note));
        let reply = self
            .legacy()?
            .transact(KM_BEGIN, &call)
            .context("start a decryption")?;
        let mut read = Answer::new(reply.bytes());
        keymaster_ok(&mut read).context("start a decryption")?;
        read.skip_empty_struct_vector()
            .context("read the parameters the decryption came back with")?;
        read.u64().context("read the decryption's handle")
    }

    fn keymaster_update(&self, operation: u64, input: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(KEYMASTER);
        call.u64(operation);
        call.structures(KEY_PARAMETER_BYTES, Vec::new());
        call.bytes(input);
        call.structure(hardware_note(None));
        call.structure(empty_verification());
        let reply = self
            .legacy()?
            .transact(KM_UPDATE, &call)
            .context("feed the decryption")?;
        let mut read = Answer::new(reply.bytes());
        keymaster_ok(&mut read).context("feed the decryption")?;
        read.u32().context("read how much the decryption took")?;
        read.skip_empty_struct_vector()
            .context("read the parameters the decryption came back with")?;
        read.vector()
            .map(<[u8]>::to_vec)
            .context("read what the decryption gave back")
    }

    fn keymaster_finish(&self, operation: u64) -> Result<Vec<u8>> {
        let mut call = Message::call(KEYMASTER);
        call.u64(operation);
        call.structures(KEY_PARAMETER_BYTES, Vec::new());
        call.bytes(&[]);
        call.bytes(&[]);
        call.structure(hardware_note(None));
        call.structure(empty_verification());
        let reply = self
            .legacy()?
            .transact(KM_FINISH, &call)
            .context("close the decryption")?;
        let mut read = Answer::new(reply.bytes());
        keymaster_ok(&mut read)
            .context("close the decryption, which is where a wrong key is refused")?;
        read.skip_empty_struct_vector()
            .context("read the parameters the decryption came back with")?;
        read.vector()
            .map(<[u8]>::to_vec)
            .context("read what the decryption ended with")
    }

    fn keymaster_export(&self, key_blob: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(KEYMASTER);
        call.u32(KEY_FORMAT_RAW);
        call.bytes(key_blob);
        call.bytes(&[]);
        call.bytes(&[]);
        let reply = self
            .legacy()?
            .transact(KM_EXPORT_KEY, &call)
            .context("export the storage key")?;
        let mut read = Answer::new(reply.bytes());
        keymaster_ok(&mut read).context("export the storage key")?;
        read.vector()
            .map(<[u8]>::to_vec)
            .context("read the exported storage key")
    }

    fn keymaster_authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        let mut call = Message::call(KEYMASTER);
        call.bytes(key_blob);
        call.bytes(app_id);
        call.bytes(&[]);
        let reply = self
            .legacy()?
            .transact(KM_GET_KEY_CHARACTERISTICS, &call)
            .context("ask what the key may be used for")?;
        let mut read = Answer::new(reply.bytes());
        keymaster_ok(&mut read).context("ask what the key may be used for")?;
        let characteristics = read.pointed().context("read the key's characteristics")?;
        if characteristics.len() != 32 {
            bail!(
                "the key service answered {} bytes of characteristics, and one record is 32",
                characteristics.len()
            );
        }
        let mut out = Vec::new();
        for _ in 0..2 {
            let parameters = read
                .pointed()
                .context("read one list of the key's characteristics")?;
            if parameters.len() % KEY_PARAMETER_BYTES != 0 {
                bail!(
                    "a list of {} bytes does not hold whole {KEY_PARAMETER_BYTES}-byte key parameters",
                    parameters.len()
                );
            }
            for parameter in parameters.as_chunks::<KEY_PARAMETER_BYTES>().0 {
                let tag = i32::from_le_bytes(parameter[0..4].try_into().expect("four bytes"));
                let value = match tag & TAG_KIND {
                    KIND_ULONG | KIND_ULONG_REP | KIND_DATE => {
                        i64::from_le_bytes(parameter[8..16].try_into().expect("eight bytes"))
                    }
                    KIND_BYTES | KIND_BIGNUM => {
                        u32::from_le_bytes(parameter[24..28].try_into().expect("four bytes")) as i64
                    }
                    _ => {
                        u32::from_le_bytes(parameter[8..12].try_into().expect("four bytes")) as i64
                    }
                };
                out.push((tag, value));
                // Every KeyParameter carries an embedded blob object, even
                // when the blob is empty.
                read.skip_address()
                    .context("step over a key parameter's value")?;
            }
        }
        Ok(out)
    }

    fn keymaster_upgrade(&self, key_blob: &[u8], params: Vec<EmbeddedStruct>) -> Result<Vec<u8>> {
        let mut call = Message::call(KEYMASTER);
        call.bytes(key_blob);
        call.structures(KEY_PARAMETER_BYTES, params);
        let reply = self
            .legacy()?
            .transact(KM_UPGRADE_KEY, &call)
            .context("renew the key")?;
        let mut read = Answer::new(reply.bytes());
        keymaster_ok(&mut read).context("renew the key")?;
        read.vector()
            .map(<[u8]>::to_vec)
            .context("read the renewed key")
    }

    fn keymaster_abort(&self, operation: u64) -> Result<()> {
        let mut call = Message::call(KEYMASTER);
        call.u64(operation);
        let reply = self
            .legacy()?
            .transact(KM_ABORT, &call)
            .context("drop the decryption")?;
        keymaster_ok(&mut Answer::new(reply.bytes())).context("drop the decryption")
    }

    /// What the key service has to be told to use an AES-GCM key: how it is
    /// used, how long its tag is, what it is bound to, and the nonce it was
    /// encrypted under.
    ///
    /// What a key is bound to is named only where there is something: the
    /// secure world folds the binding into the key it unwraps the key blob
    /// with, and a binding to nothing named is not the same to it as none
    /// named at all, so naming an empty one leaves it unable to unwrap a
    /// key that was made bound to nothing.
    fn gcm_params(call: &mut Parcel, app_id: &[u8], nonce: &[u8]) {
        call.i32(if app_id.is_empty() { 5 } else { 6 });
        parameter(
            call,
            TAG_BLOCK_MODE,
            Value::Enum(VALUE_BLOCK_MODE, BLOCK_MODE_GCM),
        );
        parameter(
            call,
            TAG_PADDING,
            Value::Enum(VALUE_PADDING_MODE, PADDING_NONE),
        );
        parameter(call, TAG_MAC_LENGTH, Value::Integer(128));
        if !app_id.is_empty() {
            parameter(call, TAG_APPLICATION_ID, Value::Blob(app_id));
        }
        parameter(call, TAG_NONCE, Value::Blob(nonce));
        parameter(
            call,
            TAG_PURPOSE,
            Value::Enum(VALUE_KEY_PURPOSE, PURPOSE_DECRYPT),
        );
    }

    /// Open a decryption with the key service and keep hold of it.
    fn begin(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        note: Option<&Token>,
    ) -> Result<Handle<'a>> {
        let mut call = Parcel::call(DEVICE);
        call.i32(PURPOSE_DECRYPT);
        call.blob(key_blob);
        Self::gcm_params(&mut call, app_id, nonce);
        // A key guarded by the screen lock takes the note the secure world
        // wrote when the user answered it; one that is not guarded takes
        // nothing, and is refused nothing for carrying a note either.
        match note {
            Some(note) => vouched(&mut call, note),
            None => call.none(),
        }

        // The decryption the service opens outlives the reply that named
        // it, so take a share of it before the reply's room goes back.
        let reply = self
            .aidl()?
            .transact(BEGIN, &call)
            .context("start a decryption")?;
        let mut read = reply.read();
        status::ok(&mut read).context("start a decryption")?;
        read.structure()
            .context("read what the key service answered")?;
        read.i64().context("read the decryption's challenge")?;
        let params = read
            .i32()
            .context("read how many parameters the decryption came back with")?;
        for _ in 0..params.max(0) {
            let end = read
                .structure()
                .context("read a parameter the decryption came back with")?;
            read.go(end)?;
        }
        match read
            .object()
            .context("read the decryption the key service opened")?
        {
            Some(h) => Handle::hold(reply.binder(), h),
            None => anyhow::bail!("the key service opened no decryption"),
        }
    }

    /// A key for the firmware running now, from one made under an older
    /// build. What it is bound to has to be given again, as `params` write
    /// it, or the service cannot tell it is the right key.
    fn upgrade(&self, key_blob: &[u8], params: impl FnOnce(&mut Parcel)) -> Result<Vec<u8>> {
        let mut call = Parcel::call(DEVICE);
        call.blob(key_blob);
        params(&mut call);
        let reply = self
            .aidl()?
            .transact(UPGRADE_KEY, &call)
            .context("renew the key")?;
        let mut read = reply.read();
        status::ok(&mut read).context("renew the key")?;
        read.blob().context("read the renewed key")
    }

    fn update(&self, operation: &Handle, input: &[u8]) -> Result<Vec<u8>> {
        let mut call = Parcel::call(OPERATION);
        call.blob(input);
        call.none();
        call.none();
        let reply = operation
            .transact(UPDATE, &call)
            .context("feed the decryption")?;
        let mut read = reply.read();
        status::ok(&mut read).context("feed the decryption")?;
        read.blob().context("read what the decryption gave back")
    }

    fn finish(&self, operation: &Handle) -> Result<Vec<u8>> {
        let mut call = Parcel::call(OPERATION);
        call.opt_blob(None);
        call.opt_blob(None);
        call.none();
        call.none();
        call.opt_blob(None);
        let reply = operation
            .transact(FINISH, &call)
            .context("close the decryption")?;
        let mut read = reply.read();
        status::ok(&mut read)
            .context("close the decryption, which is where a wrong key is refused")?;
        read.blob().context("read what the decryption ended with")
    }

    fn abort(&self, operation: &Handle) -> Result<()> {
        let reply = operation
            .transact(ABORT, &Parcel::call(OPERATION))
            .context("drop the decryption")?;
        status::ok(&mut reply.read()).context("drop the decryption")
    }

    /// Whether the secure world will unwrap the key at all: a decryption is
    /// opened on it under a nonce of nothing and dropped again, which reads
    /// nothing and changes nothing. It tells a key the secure world cannot
    /// unwrap, as one made under another build or bound to something not
    /// given back to it is, apart from one that merely decrypts to nothing.
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        if self.keymaster().is_some() {
            let operation = self.keymaster_begin(key_blob, app_id, &[0; NONCE_BYTES], None)?;
            return self.keymaster_abort(operation);
        }
        let operation = self.begin(key_blob, app_id, &[0; NONCE_BYTES], None)?;
        self.abort(&operation)
    }
}

/// Keymaster's ErrorCode leads a reply. Zero means it took the call.
fn keymaster_ok(read: &mut Answer<'_>) -> Result<()> {
    // A HIDL reply carries the transport status before the method's own
    // generated return values.
    read.status()?;
    let code = read.i32().context("read the key service's answer")?;
    if code == 0 {
        Ok(())
    } else {
        bail!("the key service refused the call with its code {code}")
    }
}

fn keymaster_refused_with(error: &anyhow::Error) -> Option<i32> {
    let said = format!("{error:#}");
    said.rsplit("code ")
        .next()
        .and_then(|value| value.parse().ok())
}
