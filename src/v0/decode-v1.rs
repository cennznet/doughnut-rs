//!
//! Parity-codec style decode impl
//!
    pub fn decode<I: Input>(input: &mut I) -> Result<Self, DoughnutErr> {

        let (version, signature) = decode_header(input)?;
        if version != 1 {
            return Err(DoughnutErr::UnsupportedVersion)
        }

        let not_before_and_permission_domain_count = input.read_byte()?;
        let has_not_before: bool = not_before_and_permission_domain_count & NOT_BEFORE_MASK == 1;
        let permission_domain_count: u8 = not_before_and_permission_domain_count & PERMISSION_DOMAIN_COUNT_MASK;

        let mut holder: [u8; 32] = Default::default();
        let _ = input.read(&mut holder);
        // for i in 0..32 {
        //     holder[i] = input.read_byte()?;
        // }

        let mut issuer: [u8; 32] = Default::default();
        let _ = input.read(&mut issuer);

        let expiry = u32::from_le_bytes([input.read_byte()?, input.read_byte()?, input.read_byte()?, input.read_byte()?]);

        let not_before = if has_not_before {
            u32::from_le_bytes([input.read_byte()?, input.read_byte()?, input.read_byte()?, input.read_byte()?])
        } else {
            0
        };

        // Build permissions/domain map
        let mut permissions_index: HashMap<&'a str, (usize, usize)> = HashMap::new();
        let mut payload_offset = 34 * permission_domain_count;
        let mut domain_offset: u16 = 0;
        let mut key_buf: [u8; 32] = Default::default();

        for i in 0..permission_domain_count {
            let _ = input.read(&mut key_buf);
            // TODO: should key be valid UTF-8?
            let key = core::str::from_utf8(&key_buf).map_err(|_| DoughnutErr::BadEncoding)?;
            let domain_length = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
            // Store domain and byte offset of payload
            permissions_index.insert(key, (domain_offset as usize, domain_length as usize));
            domain_offset += domain_length;
        }

        // Consume the rest of input as permissions data
        let mut permissions_data: &'a [u8] = Default::default();
        let _ = input.read(&mut permissions_data);

        Ok(DoughnutV1 {
            holder,
            issuer,
            expiry,
            not_before,
            permissions_index,
            permissions_data,
        })
    }