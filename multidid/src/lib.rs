use integer_encoding::*;
use std::str;
use std::collections::HashMap;
use multibase::Base;
use anyhow::{anyhow, Result};

/**
 * Multicodec Codes https://github.com/multiformats/multicodec/blob/master/table.csv
 */
 const MULTIDID_CODEC: u32 = 0xd1d; // did
 const ANY_METHOD_CODE: u32 = 0x55; // raw
 const PKH_METHOD_CODE: u32 = 0xca; // Chain Agnostic
 const SECP256K1_CODE: u32 = 0xe7; // secp256k1-pub
 const BLS12_381_G2_CODE: u32 = 0xeb; // bls12_381-g2-pub
 const X25519_CODE: u32 = 0xec; // x25519-pub
 const ED25519_CODE: u32 = 0xed; // ed25519-pub
 const P256_CODE: u32 = 0x1200; // p256-pub
 const P384_CODE: u32 = 0x1201; // p384-pub
 const P521_CODE: u32 = 0x1202; // p521-pub
 const RSA_CODE: u32 = 0x1205; // rsa-pub
 const KEY_CODES: [u32; 8] = [SECP256K1_CODE, BLS12_381_G2_CODE, X25519_CODE, ED25519_CODE, P256_CODE, P384_CODE, P521_CODE, RSA_CODE];

fn key_method_code_len(code: &u32, key_prefix: &[u8]) ->  Result<u16> {
    if code == &RSA_CODE {
        return Ok(*rsa_code_len(key_prefix)?)
    }

    //MOVE STATIC, any const for map? 
    let km_codes_len: HashMap<u32, u16> = HashMap::from([
        (SECP256K1_CODE, 33),
        (BLS12_381_G2_CODE, 96),
        (X25519_CODE, 32),
        (ED25519_CODE, 32),
        (P256_CODE, 33),
        (P384_CODE, 49),
        (P521_CODE, 67),
    ]);

    let val = *km_codes_len.get(code).ok_or(anyhow!("Key not supported"))?;
    Ok(val)
}

fn is_key_method_code(code: &u32) ->  bool {
    KEY_CODES.contains(code)
}

// 2048-bit modulus, public exponent 65537
const RSA_270_PREFIX: [u8; 9] = [48, 130, 1, 10, 2, 130, 1, 1, 0];
const RSA_270: u16 = 270;
// 4096-bit modulus, public exponent 65537
const RSA_526_PREFIX: [u8; 9] = [48, 130, 2, 10, 2, 130, 2, 1, 0];
const RSA_526: u16 = 526;
const KEY_PREFIX_LEN: u8 = 9;


fn rsa_code_len(key_prefix: &[u8]) -> Result<&u16> {
    if key_prefix == &RSA_270_PREFIX {
        return Ok(&RSA_270) 
    } else if key_prefix == &RSA_526_PREFIX {
        return Ok(&RSA_526) 
    } else {
        return Err(anyhow!("Not a valid RSA did:key"))
    }
}

fn url_index(did: &str) -> Result<usize> {
    for (i, c) in did.chars().enumerate() {
        if c == '?' || c == '#' || c == '/'{
            return Ok(i);
        }
    }

    Ok(did.len())
}

pub struct Multidid {
    method_code: u32,
    method_id_bytes: Vec<u8>,
    url_bytes: Vec<u8>,
}

impl Multidid {

    pub fn new(code: u32, id: Vec<u8>, url: Vec<u8>) -> Self {
        Self {
            method_code: code,
            method_id_bytes: id,
            url_bytes: url,
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let method_code_offset = MULTIDID_CODEC.required_space();
        let method_id_offset = method_code_offset + &self.method_code.required_space();
        
        let method_id_len;
        if &self.method_code == &ANY_METHOD_CODE {
            method_id_len = 0;
        } else if &self.method_code == &PKH_METHOD_CODE {
            return Err(anyhow!("PKH Method not implemented"));
        } else if is_key_method_code(&self.method_code) {
            let prefix = &self.method_id_bytes[0..KEY_PREFIX_LEN as usize];
            method_id_len = key_method_code_len(&self.method_code, prefix)?;
        } else {
            return Err(anyhow!("No matching did method code found"))
        }
    
        let url_len_offset = method_id_offset + method_id_len as usize;
        let url_len = &self.url_bytes.len();
        let url_bytes_offset = url_len_offset + url_len.required_space();
        let total_bytes_len = url_bytes_offset + url_len;

        let mut buff = vec![0;total_bytes_len];
        MULTIDID_CODEC.encode_var(&mut buff[0..method_code_offset]);
        let _ = &self.method_code.encode_var(&mut buff[method_code_offset..method_id_offset]);
        buff[method_id_offset..url_len_offset].clone_from_slice(&self.method_id_bytes);
        url_len.encode_var(&mut buff[url_len_offset..url_bytes_offset]);
        buff[url_bytes_offset..total_bytes_len].clone_from_slice(&self.url_bytes);
        
        Ok(buff)
    }

    fn from_bytes(bytes: Vec<u8>) -> Result<Multidid> {
        let (_, did_code_len) = u32::decode_var(&bytes).ok_or(anyhow!("Decode fail"))?;
        let (method_code, method_code_len) = u32::decode_var(&bytes[did_code_len..]).ok_or(anyhow!("Decode fail"))?;
        let method_id_offset = did_code_len + method_code_len;

        let method_id_len;
        if &method_code == &ANY_METHOD_CODE {
            method_id_len = 0;
        } else if &method_code == &PKH_METHOD_CODE {
            return Err(anyhow!("PKH Method not implemented"));
        } else if is_key_method_code(&method_code) {
            let prefix = &bytes[method_id_offset..method_id_offset + KEY_PREFIX_LEN as usize];
            method_id_len = key_method_code_len(&method_code, prefix)?;
        } else {
            return Err(anyhow!("No matching did method code found"))
        }

        let url_len_offset = method_id_offset + method_id_len as usize;
        let method_id = bytes[method_id_offset..url_len_offset].to_vec();

        let (url_len, url_len_len) = u32::decode_var(&bytes[url_len_offset..]).ok_or(anyhow!("Decode fail"))?;
        let url_bytes_offset = url_len_offset + url_len_len as usize;
        let url = bytes[url_bytes_offset..url_bytes_offset + url_len as usize].to_vec();

        Ok(Multidid::new(method_code, method_id, url))
    } 
    
    pub fn to_multibase(&self, base: Base) -> Result<String> {
        let bytes = &self.to_bytes()?;
        let bs58btc_str = multibase::encode(base, bytes);
        Ok(bs58btc_str)
    }

    pub fn from_multibase(multidid: &str) -> Result<Multidid> {
        let (_, bytes) = multibase::decode(multidid)?;
        Multidid::from_bytes(bytes)
    }
    
    pub fn from_string(did: &str) -> Result<Multidid> {
        let p: Vec<&str> = did.split(":").collect();
        let method = p[1];
        let suffix = p[2];

        let index_break = url_index(&suffix).unwrap();

        let id = &suffix[0..index_break];
        let url = &suffix[index_break..suffix.len()];

        if method == "key" {
            let (_, key_bytes) = multibase::decode(id)?;
            let (code, code_len) = u32::decode_var(&key_bytes).ok_or(anyhow!("Decode fail"))?;
            let url_bytes = url.to_owned().into_bytes();
            let id_bytes = key_bytes[code_len..].to_vec();
            return Ok(Multidid::new(code, id_bytes, url_bytes));
        } else if method == "pkh" {
            Err(anyhow!("PKH Method not implemented"))
        } else {
            let url_str = format!("{}:{}", &method, &suffix);
            let url_bytes = url_str.into_bytes();

            return Ok(Multidid::new(ANY_METHOD_CODE, vec![], url_bytes));
        }
    }

    pub fn to_string(&self) -> Result<String> {
        if &self.method_code == &ANY_METHOD_CODE {
            return Ok(format!("did:{}", str::from_utf8(&self.url_bytes)?));
        } else if &self.method_code == &PKH_METHOD_CODE {
            return Err(anyhow!("PKH Method not implemented"));
        } else if is_key_method_code(&self.method_code) {
            let method_id_offset = &self.method_code.required_space();
            let prefix = &self.method_id_bytes[0..KEY_PREFIX_LEN as usize];
            let method_id_len = key_method_code_len(&self.method_code, prefix)?;
            let total_bytes_len = method_id_offset + method_id_len as usize;
            let mut buff = vec![0;total_bytes_len];
            let _ = &self.method_code.encode_var(&mut buff);
            buff[*method_id_offset as usize..].clone_from_slice(&self.method_id_bytes);
            let bs58btc_str = multibase::encode(Base::Base58Btc, buff);
            let url_str = str::from_utf8(&self.url_bytes)?;

            return Ok(format!("did:key:{}{}", bs58btc_str, url_str));
        } else {
            return Err(anyhow!("Unable to convert to did string, no matching method"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // did string roundtrip did:key, no url portion
    #[test]
    fn didkey_str_rt_no_url() {
        let did_str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
        let mdid = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid.to_string().unwrap(), did_str);
    }
    
    //did string roundtrip did:key, with url portion
    #[test]
    fn didkey_str_rt_with_url() {
        let did_str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
        let mdid = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid.to_string().unwrap(), did_str);
    }

    //did string roundtrip did:*, no url portion
    #[test]
    fn didany_str_rt_no_url() {
        let did_str = "did:example:123456";
        let mdid = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid.to_string().unwrap(), did_str);
    }

    // did string roundtrip did:*, with url portion
    #[test]
    fn didany_str_rt_with_url() {
        let did_str = "did:example:123456?versionId=1";
        let mdid = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid.to_string().unwrap(), did_str);
    }

    // spefication did:* vector 1
    #[test]
    fn spec_didany_vec1() {
        let did_str = "did:example:123456";
        let hex_md = "f9d1a550e6578616d706c653a313233343536";
        let mdid1 = Multidid::from_multibase(hex_md).unwrap();
        let mdid2 = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid1.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid1.to_string().unwrap(), did_str);
        assert_eq!(mdid2.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid2.to_string().unwrap(), did_str);
        assert_eq!(mdid1.to_multibase(Base::Base58Btc).unwrap(), mdid2.to_multibase(Base::Base58Btc).unwrap());
    }

    //spefication did:* vector 2
    #[test]
    fn spec_didany_vec2() {
        let did_str = "did:example:123456?versionId=1";
        let hex_md = "f9d1a551a6578616d706c653a3132333435363f76657273696f6e49643d31";
        let mdid1 = Multidid::from_multibase(hex_md).unwrap();
        let mdid2 = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid1.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid1.to_string().unwrap(), did_str);
        assert_eq!(mdid2.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid2.to_string().unwrap(), did_str);
        assert_eq!(mdid1.to_multibase(Base::Base58Btc).unwrap(), mdid2.to_multibase(Base::Base58Btc).unwrap());
    }

    // spefication did:key vector 1
    #[test]
    fn spec_didkey_vec1() {
        let did_str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
        let hex_md = "f9d1aed013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2900";
        let mdid1 = Multidid::from_multibase(hex_md).unwrap();
        let mdid2 = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid1.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid1.to_string().unwrap(), did_str);
        assert_eq!(mdid2.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid2.to_string().unwrap(), did_str);
        assert_eq!(mdid1.to_multibase(Base::Base58Btc).unwrap(), mdid2.to_multibase(Base::Base58Btc).unwrap());
    }

    // spefication did:key vector 2
    #[test]
    fn spec_didkey_vec2() {
        let did_str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
        let hex_md = "f9d1aed013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2931237a364d6b6954427a31796d75657041513448454859534631483871754735474c5656515233646a6458336d446f6f5770";
        let mdid1 = Multidid::from_multibase(hex_md).unwrap();
        let mdid2 = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid1.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid1.to_string().unwrap(), did_str);
        assert_eq!(mdid2.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid2.to_string().unwrap(), did_str);
        assert_eq!(mdid1.to_multibase(Base::Base58Btc).unwrap(), mdid2.to_multibase(Base::Base58Btc).unwrap());
    }

    #[test]
    fn spec_didkey_vec3() {
        let did_str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
        let hex_md = "f9d1ae70103874c15c7fda20e539c6e5ba573c139884c351188799f5458b4b41f7924f235cd00";
        let mdid1 = Multidid::from_multibase(hex_md).unwrap();
        let mdid2 = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid1.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid1.to_string().unwrap(), did_str);
        assert_eq!(mdid2.to_multibase(Base::Base16Lower).unwrap(), hex_md);
        assert_eq!(mdid2.to_string().unwrap(), did_str);
        assert_eq!(mdid1.to_multibase(Base::Base58Btc).unwrap(), mdid2.to_multibase(Base::Base58Btc).unwrap());
    }
    
    //RSA test vectors https://w3c-ccg.github.io/did-method-key/#rsa-2048
    // spefication did:key RSA 2048-bit
    #[test]
    fn spec_didkey_rsa1() {
        let did_str = "did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i";
        let mdid = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid.to_string().unwrap(), did_str);
    }
    
    // spefication did:key RSA 4096-bit
    #[test]
    fn spec_didkey_rsa2() {
        let did_str = "did:key:zgghBUVkqmWS8e1ioRVp2WN9Vw6x4NvnE9PGAyQsPqM3fnfPf8EdauiRVfBTcVDyzhqM5FFC7ekAvuV1cJHawtfgB9wDcru1hPDobk3hqyedijhgWmsYfJCmodkiiFnjNWATE7PvqTyoCjcmrc8yMRXmFPnoASyT5beUd4YZxTE9VfgmavcPy3BSouNmASMQ8xUXeiRwjb7xBaVTiDRjkmyPD7NYZdXuS93gFhyDFr5b3XLg7Rfj9nHEqtHDa7NmAX7iwDAbMUFEfiDEf9hrqZmpAYJracAjTTR8Cvn6mnDXMLwayNG8dcsXFodxok2qksYF4D8ffUxMRmyyQVQhhhmdSi4YaMPqTnC1J6HTG9Yfb98yGSVaWi4TApUhLXFow2ZvB6vqckCNhjCRL2R4MDUSk71qzxWHgezKyDeyThJgdxydrn1osqH94oSeA346eipkJvKqYREXBKwgB5VL6WF4qAK6sVZxJp2dQBfCPVZ4EbsBQaJXaVK7cNcWG8tZBFWZ79gG9Cu6C4u8yjBS8Ux6dCcJPUTLtixQu4z2n5dCsVSNdnP1EEs8ZerZo5pBgc68w4Yuf9KL3xVxPnAB1nRCBfs9cMU6oL1EdyHbqrTfnjE8HpY164akBqe92LFVsk8RusaGsVPrMekT8emTq5y8v8CabuZg5rDs3f9NPEtogjyx49wiub1FecM5B7QqEcZSYiKHgF4mfkteT2";
        let mdid = Multidid::from_string(did_str).unwrap();
        assert_eq!(mdid.to_string().unwrap(), did_str);
    }
}