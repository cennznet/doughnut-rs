//!
//! Doughnut V0 codec
//!
use core::ptr;
use hashbrown::HashMap;

const VERSION_MASK: u16 = 0x7FF;
// const SIGNATURE_MASK: u8 = 0x1F;
// const NOT_BEFORE_MASK: u8 = 0x1;
// const PERMISSION_DOMAIN_COUNT_MASK: u8 = 0x7F;

#[derive(Debug)]
pub struct DoughnutV0<'a>(&'a [u8]);

impl<'a> DoughnutV0<'a> {
    /// Returns the doughnut payload version
    pub fn payload_version(&self) -> u16 {
        let payload_version: u16 = unsafe {
            ptr::read(self.0[..2].as_ptr() as *const u16)
        };
        payload_version & VERSION_MASK
    }

    /// Returns the doughnut signature scheme version
    pub fn signature_version(&self) -> u8 {
        self.0[1] << 3
    }

    /// Returns the doughnut "permission domain count"
    pub fn permission_domain_count(&self) -> u8 {
        self.0[2] << 1
    }

    /// Whether the doughnut has "not before" bit set
    fn has_not_before(&self) -> bool {
        self.0[2] & 0x1 == 1
    }

    /// Returns the doughnut "not before" unix timestamp
    pub fn not_before(&self) -> u32 {
        if self.has_not_before() {
            let offset = 71;
            unsafe {
                ptr::read(self.0[offset..offset + 4].as_ptr() as *const u32)
            }
        } else {
            0
        }
    }

    /// Returns the doughnut expiry unix timestamp
    pub fn expiry(&self) -> u32 {
        let offset = 67;
        unsafe {
            ptr::read(self.0[offset..offset + 4].as_ptr() as *const u32)
        }
    }

    /// Returns the doughnut holder public key
    pub fn holder(&self) -> [u8; 32] {
        let offset = 35;
        unsafe {
            ptr::read(self.0[offset..offset + 32].as_ptr() as *const [u8; 32])
        }
    }

    /// Returns the doughnut issuer public key
    pub fn issuer(&self) -> [u8; 32] {
        let offset = 3;
        unsafe {
            ptr::read(self.0[offset..offset + 32].as_ptr() as *const [u8; 32])
        }
    }

    /// Return the domains embedded in this doughnut
    pub fn domains(&self) -> HashMap<&'a [u8], &'a [u8]> {

        // Dependent on 'not before' inclusion
        let mut offset = if self.has_not_before() {
            75
        } else {
            71
        };

        // Collect all domains
        let mut domains: HashMap<&'a [u8], &'a [u8]> = HashMap::new();
        let mut domain_offset = (self.permission_domain_count() * 18) as u16;
        for _ in 0..self.permission_domain_count() {
            // 16 bytes per key, 2 bytes for payload length
            let domain_len: u16 = unsafe { ptr::read(self.0[offset + 16..offset + 18].as_ptr() as *const u16) };
            domains.insert(
                &self.0[offset as usize..(offset + 16) as usize],
                &self.0[domain_offset as usize..(domain_offset + domain_len) as usize],
            );
            offset += 18;
            domain_offset += domain_len;
        }

        domains
    }
}