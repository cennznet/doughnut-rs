//! Half-implemented encoding logic...

    /// Write v1 doughnut header
    fn encode_header(&self) -> u16 {
        let mut version_and_signature = 1;
        // TODO: this is hard-coded to schnorrkel
        (version_and_signature << 11) & 0
    }

    /// Encode doughnut to bytes,
    pub fn encode(self) -> Result<Vec<u8>, DoughnutErr> {
        let mut buf = vec![];
        let version_and_signature = Self::encode_header(&self);
        buf.copy_from_slice(&version_and_signature.to_le_bytes());

        let mut not_before_and_permission_domain_count = PERMISSION_DOMAIN_COUNT_MASK & self.permissions_index.len() as u8;
        if self.not_before > 0 {
            not_before_and_permission_domain_count &= 0x1;
        };
        buf.push(not_before_and_permission_domain_count);

        buf.copy_from_slice(&self.holder);
        buf.copy_from_slice(&self.issuer);
        buf.copy_from_slice(&self.expiry.to_le_bytes());
        if self.not_before > 0 {
            buf.copy_from_slice(&self.not_before.to_le_bytes());
        }

        // TODO: Permissions Data
        // // Build permissions/domain map
        // let mut permissions_index: HashMap<&'a str, (usize, usize)> = HashMap::new();
        // let mut payload_offset = 34 * permission_domain_count;
        // let mut domain_offset: u16 = 0;
        // let mut key_buf: [u8; 32] = Default::default();

        // for i in 0..permission_domain_count {
        //     let _ = input.read(&mut key_buf);
        //     // TODO: should key be valid UTF-8?
        //     let key = core::str::from_utf8(&key_buf).map_err(|_| DoughnutErr::BadEncoding)?;
        //     let domain_length = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
        //     // Store domain and byte offset of payload
        //     permissions_index.insert(key, (domain_offset as usize, domain_length as usize));
        //     domain_offset += domain_length;
        // }

        // // Consume the rest of input as permissions data
        // let mut permissions_data: &'a [u8] = Default::default();
        // let _ = input.read(&mut permissions_data);

        Ok(buf)
    }