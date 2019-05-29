//!
//! Doughnut V0 codec
//!
use bit_reverse::ParallelReverse;
use core::ptr;
use hashbrown::HashMap;

use crate::error::DoughnutErr;

const VERSION: u16 = 0;
const VERSION_MASK: u16 = 0x7FF;
const WITHOUT_NOT_BEFORE_OFFSET: u8 = 71;
const WITH_NOT_BEFORE_OFFSET: u8 = 75;
const SIGNATURE_MASK: u8 = 0x1F;
const NOT_BEFORE_MASK: u8 = 0b1000_0000;
// const PERMISSION_DOMAIN_COUNT_MASK: u8 = 0b1111_1110;

#[derive(Debug)]
pub struct DoughnutV0<'a>(&'a [u8]);

/// Return the payload version from the given byte slice
fn payload_version(buf: &[u8]) -> u16 {
    let payload_version = u16::from_le_bytes([buf[0].swap_bits(), buf[0].swap_bits()]);
    payload_version & VERSION_MASK
}

/// Returns the doughnut "permission domain count"
fn permission_domain_count(buf: &[u8]) -> u8 {
    (buf[2] << 1).swap_bits() + 1
}

/// Whether the doughnut has "not before" bit set
fn has_not_before(buf: &[u8]) -> bool {
    buf[2] & NOT_BEFORE_MASK == 1
}

impl<'a> DoughnutV0<'a> {
    /// Create a new v0 Doughnut from encoded bytes verifying it's correctness.
    /// Returns an error if encoding is invalid
    pub fn new(encoded: &'a [u8]) -> Result<Self, DoughnutErr<'a>> {
        if encoded.len() < 2 {
            return Err(DoughnutErr::BadEncoding(&"Missing header"));
        }
        if payload_version(encoded) != VERSION {
            return Err(DoughnutErr::UnsupportedVersion);
        }

        let offset = u16::from(if has_not_before(encoded) {
            WITH_NOT_BEFORE_OFFSET
        } else {
            WITHOUT_NOT_BEFORE_OFFSET
        });
        let permission_domain_length = permission_domain_count(encoded) as u16 * (18 + 1); // + 1 byte per domain expected in payload

        println!("domain count: {:?}", permission_domain_count(encoded));
        println!("expect domain length: {:?}", permission_domain_length);
        println!("offset: {:?}", offset);
        println!(
            "expect total length: {:?}",
            offset + permission_domain_length + 64
        );
        if (encoded.len() as u16) < offset + permission_domain_length + 64 {
            return Err(DoughnutErr::BadEncoding(&"Too short"));
        }

        Ok(DoughnutV0(encoded))
    }

    /// Returns the doughnut payload version
    pub fn payload_version(&self) -> u16 {
        payload_version(self.0)
    }

    /// Returns the doughnut signature scheme version
    pub fn signature_version(&self) -> u8 {
        self.0[1].swap_bits() & SIGNATURE_MASK
    }

    /// Returns the doughnut "permission domain count"
    pub fn permission_domain_count(&self) -> u8 {
        permission_domain_count(self.0)
    }

    /// Whether the doughnut has "not before" bit set
    fn has_not_before(&self) -> bool {
        has_not_before(self.0)
    }

    /// Returns the doughnut "not before" unix timestamp
    pub fn not_before(&self) -> u32 {
        if self.has_not_before() {
            let offset = 71;
            u32::from_le_bytes([
                self.0[offset].swap_bits(),
                self.0[offset + 1].swap_bits(),
                self.0[offset + 2].swap_bits(),
                self.0[offset + 3].swap_bits(),
            ])
        } else {
            0
        }
    }

    /// Returns the doughnut expiry unix timestamp
    pub fn expiry(&self) -> u32 {
        let offset = 67;
        u32::from_le_bytes([
            self.0[offset].swap_bits(),
            self.0[offset + 1].swap_bits(),
            self.0[offset + 2].swap_bits(),
            self.0[offset + 3].swap_bits(),
        ])
    }

    /// Returns the doughnut holder public key
    pub fn holder(&self) -> [u8; 32] {
        let offset = 35;
        unsafe { ptr::read(self.0[offset..offset + 32].as_ptr() as *const [u8; 32]) }
    }

    /// Returns the doughnut issuer public key
    pub fn issuer(&self) -> [u8; 32] {
        let offset = 3;
        unsafe { ptr::read(self.0[offset..offset + 32].as_ptr() as *const [u8; 32]) }
    }

    /// Returns a mapping from key to payload offset of each domain embedded within this doughnut
    /// The payload offsets are not validated, domain decoders should ensure they check bounds before reading
    pub fn domains(&self) -> HashMap<&'a str, &'a [u8]> {
        // Dependent on 'not before' inclusion
        let mut offset = if self.has_not_before() {
            WITH_NOT_BEFORE_OFFSET
        } else {
            WITHOUT_NOT_BEFORE_OFFSET
        };

        // Collect all domains
        let mut domain_offset = offset as u16 + u16::from(self.permission_domain_count() * 18);
        let mut domains: HashMap<&'a str, &'a [u8]> = HashMap::new();
        for _ in 0..self.permission_domain_count() {
            // 16 bytes per key, 2 bytes for payload length
            let domain_len = u16::from_le_bytes([
                self.0[(offset + 16) as usize].swap_bits(),
                self.0[(offset + 17) as usize].swap_bits(),
            ]);

            // TODO: Raise error on invalid UTF-8
            let key = core::str::from_utf8(&self.0[offset as usize..(offset + 16) as usize])
                .unwrap_or("<sentinel>");
            let key_clean = key.trim_matches(char::from(0));
            domains.insert(
                key_clean,
                &self.0[domain_offset as usize..(domain_offset + domain_len) as usize],
            );
            offset += 18;
            domain_offset += domain_len;
        }

        domains
    }
}
