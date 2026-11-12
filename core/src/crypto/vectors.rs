//! Fixed inputs and expected bytes for the tests under `crypto`, `key`, `passphrase`, `anchor`,
//! `directory`, `manifest` and the verbs: published vectors, each with where it comes from, and
//! this crate's own known answers.

/// Bytes from hex, skipping whitespace so a long value can be broken over lines. Panics on
/// anything that is not a hex digit, and on an odd number of digits.
pub(crate) fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.chars().filter(|c| !c.is_whitespace()).map(|c| c.to_digit(16).expect("a hex digit") as u8).collect();
    assert!(digits.len().is_multiple_of(2), "hex digits come in pairs");
    digits.chunks(2).map(|pair| (pair[0] << 4) | pair[1]).collect()
}

/// `len` bytes counting up from `start`, wrapping at 256: the fixed inputs of the known-answer tests.
pub(crate) fn seq(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

/// The same bytes as an array, for the arguments that take one. Panics if there are not exactly `N`.
pub(crate) fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("as many bytes as the array holds")
}

// ---- vectors ----

// Test vectors published by others, as hex. Each group names the file it was copied from, the
// commit of that file and the upstream case ids. The hex is lower case; a long value runs over
// several lines, which the string continuation joins with nothing in between.
//
// Wycheproof: github.com/C2SP/wycheproof, directory testvectors_v1, commit 65ca494727a52944c204441c860b039e6786b99b.
// ACVP: github.com/usnistgov/ACVP-Server, directory gen-val/json-files, commit 975de31eb83d87039ec88934fdc47d8c312b892d.
// RFC 6979: rfc-editor.org/rfc/rfc6979.txt, appendix A.2.5.
// RFC 9106: rfc-editor.org/rfc/rfc9106.txt, section 5.3.

/// One HKDF-SHA-384 case (RFC 5869). All three are valid: `okm` is the whole expected output.
pub(crate) struct Hkdf {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// Input key material.
    pub(crate) ikm: &'static str,
    /// The salt; empty means none was given.
    pub(crate) salt: &'static str,
    /// The info.
    pub(crate) info: &'static str,
    /// The expected output; its length is the length asked for.
    pub(crate) okm: &'static str,
}

// Wycheproof testvectors_v1/hkdf_sha384_test.json at 65ca494727a52944c204441c860b039e6786b99b, tcIds 3, 12, 69.
pub(crate) const HKDF_SHA384: &[Hkdf] = &[
    // tcId 3: empty salt, empty info, 64 bytes out (two blocks of the hash).
    Hkdf {
        tc: 3,
        ikm: "a4748031a14d3e6aafe42aa20c568f5f",
        salt: "",
        info: "",
        okm: "61c0d2797276f1b789397e5a4be75c961a77bdbad4cca2bd9a4160cb85fafb1b32f95d610c58766f29769d0c68b0bcfb15916d49b72e52ad2f3e7315618175d3",
    },
    // tcId 12: a 16-byte salt, 20 bytes of info, 64 bytes out.
    Hkdf {
        tc: 12,
        ikm: "7a00817689a3d79001825a864c69c120",
        salt: "08bc01c053a6406c7c4a667c9b9b3894",
        info: "967ccd75395be6e96a67759f070487c9e2107791",
        okm: "bd02e16b6024f2c3b752d1c1d3047583697731915fbbb34418f479b0c9bf84a86bd8e715eca198da8f9b39b25a1229c311853f862340cdefe46ddf41dcf256d9",
    },
    // tcId 69: empty salt, 65 bytes of info (the longest in the file), 32 bytes of input key, 80 bytes out.
    Hkdf {
        tc: 69,
        ikm: "d2ee6859f3e52e456f4b0e19252f3ba453102fb4de685b9823a652acb2f87039",
        salt: "",
        info: "086e8dc0aa05538926dc74e89857232aa7d1fdc3f6ca29dddaba48dd682bcf1cfe08700e2a5a7102d01e57a93bca2668dee95339d5db6b6a2e7e5fa66667b8d5\
            b8",
        okm: "42468de6830ae8814015e90c10c7943f886732fa4c246e3b65124533b7edc5cca6c2c5ae69e63e3b5b35d18b0630db0ec29e1a3f4ee419c924fc4de77d16bc71\
            0b153342254e17e50604545e8e59b393",
    },
];

/// One AES-256-GCM case with a 96-bit nonce and a 128-bit tag. What the cipher returns is `ct` then `tag`.
pub(crate) struct AesGcm {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// The 32-byte key.
    pub(crate) key: &'static str,
    /// The 12-byte nonce.
    pub(crate) iv: &'static str,
    /// The associated data.
    pub(crate) aad: &'static str,
    /// The plaintext.
    pub(crate) msg: &'static str,
    /// The ciphertext, without the tag.
    pub(crate) ct: &'static str,
    /// The 16-byte tag.
    pub(crate) tag: &'static str,
    /// Whether `ct` then `tag` must open to `msg`. When false, the tag was changed and opening must be refused.
    pub(crate) valid: bool,
}

// Wycheproof testvectors_v1/aes_gcm_test.json at 65ca494727a52944c204441c860b039e6786b99b, the group with keySize 256, ivSize 96, tagSize 128:
// tcIds 91, 93, 105 (valid) and 130, 148 (invalid).
pub(crate) const AES_256_GCM: &[AesGcm] = &[
    // tcId 91, valid: 8 bytes of associated data, a 10-byte message.
    AesGcm {
        tc: 91,
        key: "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20",
        iv: "00112233445566778899aabb",
        aad: "00000000ffffffff",
        msg: "00010203040506070809",
        ct: "e27abdd2d2a53d2f136b",
        tag: "9a4a2579529301bcfb71c78d4060f52c",
        valid: true,
    },
    // tcId 93, valid: no associated data, an empty message (the tag alone).
    AesGcm {
        tc: 93,
        key: "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
        iv: "4da5bf8dfd5852c1ea12379d",
        aad: "",
        msg: "",
        ct: "",
        tag: "4771a7c404a472966cea8f73c8bfe17a",
        valid: true,
    },
    // tcId 105, valid: no associated data, a 64-byte message.
    AesGcm {
        tc: 105,
        key: "5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701",
        iv: "d61040a313ed492823cc065b",
        aad: "",
        msg: "d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82",
        ct: "c7d191b601f86c28b6a1bdef6a57b4f6ee3ae417bc125c381cdf1c4dac184ed1d84f1196206d62cad112b038845720e02c061179a8836f02b93fa7008379a6bf",
        tag: "f15612f6c40f2e0db6dc76fc4822fcfe",
        valid: true,
    },
    // tcId 130, invalid (ModifiedTag): bit 0 of the tag flipped.
    AesGcm {
        tc: 130,
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "b2061457c0759fc1749f174ee1ccadfa",
        tag: "9de8fef6d8ab1bf1bf887232eab590dd",
        valid: false,
    },
    // tcId 148, invalid (ModifiedTag): bit 127 of the tag flipped.
    AesGcm {
        tc: 148,
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "b2061457c0759fc1749f174ee1ccadfa",
        tag: "9ce8fef6d8ab1bf1bf887232eab5905d",
        valid: false,
    },
];

/// One P-256 ECDH case. The public value is the bare encoded point, as upstream's "ecpoint" file gives it.
pub(crate) struct Ecdh {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// The other side's point: 65 bytes uncompressed, or 33 bytes in the compressed case.
    pub(crate) public: &'static str,
    /// The 32-byte private scalar, big-endian.
    pub(crate) private: &'static str,
    /// The shared x-coordinate upstream expects; empty where upstream gives none. Read it only when `valid`.
    pub(crate) shared: &'static str,
    /// Whether the exchange must give `shared`. When false it must be refused.
    pub(crate) valid: bool,
}

// Wycheproof testvectors_v1/ecdh_secp256r1_ecpoint_test.json at 65ca494727a52944c204441c860b039e6786b99b, tcIds 1, 3 (valid), 332 (invalid) and 2
// (acceptable upstream; `valid` is false because only uncompressed points are taken here).
pub(crate) const ECDH_P256: &[Ecdh] = &[
    // tcId 1, valid: the normal case.
    Ecdh {
        tc: 1,
        public: "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30\
            cf",
        private: "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
        shared: "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285",
        valid: true,
    },
    // tcId 3, valid: the shared x-coordinate is zero.
    Ecdh {
        tc: 3,
        public: "0458fd4168a87795603e2b04390285bdca6e57de6027fe211dd9d25e2212d29e62080d36bd224d7405509295eed02a17150e03b314f96da37445b0d1d29377d1\
            2c",
        private: "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
        valid: true,
    },
    // tcId 332, invalid (InvalidCurveAttack): 65 bytes starting 0x04 that are not a point of the curve. Upstream gives no shared value.
    Ecdh {
        tc: 332,
        public: "04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00",
        private: "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
        shared: "",
        valid: false,
    },
    // tcId 2, upstream "acceptable" (CompressedPoint): the point of tcId 1 in its 33-byte compressed form. Refused here by rule.
    Ecdh {
        tc: 2,
        public: "0362d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26",
        private: "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
        shared: "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285",
        valid: false,
    },
];

/// One ECDSA P-256 case over SHA-256 of `msg`, the signature as r then s (IEEE P1363).
pub(crate) struct Ecdsa {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// The 65-byte uncompressed public key.
    pub(crate) public: &'static str,
    /// The message, before hashing.
    pub(crate) msg: &'static str,
    /// The signature: 64 bytes, except in the wrong-length case.
    pub(crate) sig: &'static str,
    /// Whether the signature must verify.
    pub(crate) valid: bool,
}

// Wycheproof testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json at 65ca494727a52944c204441c860b039e6786b99b, tcIds 1, 120 (valid) and 4, 137, 121
// (invalid). The file has no case that changes only s and keeps 64 bytes and the range; tcId 137 is its nearest.
pub(crate) const ECDSA_P256_SHA256: &[Ecdsa] = &[
    // tcId 1, valid: an ordinary signature, in the form whose s is in the lower half.
    Ecdsa {
        tc: 1,
        public: "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e734151\
            3e",
        msg: "313233343030",
        sig: "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
        valid: true,
    },
    // tcId 120, valid: r = 5 and s = 1, under a key made for them.
    Ecdsa {
        tc: 120,
        public: "04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e87229\
            6b",
        msg: "313233343030",
        sig: "00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001",
        valid: true,
    },
    // tcId 4, invalid (changed r): the key and message of tcId 1 with r replaced by n - r. Its s is the upper-half twin of tcId 1's.
    Ecdsa {
        tc: 4,
        public: "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e734151\
            3e",
        msg: "313233343030",
        sig: "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        valid: false,
    },
    // tcId 137, invalid (changed s): an s larger than n, under a key for which the same s reduced by n would verify.
    Ecdsa {
        tc: 137,
        public: "043a72476291571193b4d109b2c37b59f2807e8fe9cffd804eacded903e77ca0da592dbc74fee0ca7508cc7bc282b0c51a143286ff53c60131668e7a0929e4ed\
            04",
        msg: "313233343030",
        sig: "0000000000000000000000000000000000000000000000000000000000000006ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
        valid: false,
    },
    // tcId 121, invalid (wrong length): the r and s of tcId 120 in one byte each, 2 bytes in all.
    Ecdsa {
        tc: 121,
        public: "04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e87229\
            6b",
        msg: "313233343030",
        sig: "0501",
        valid: false,
    },
];

/// One deterministic ECDSA P-256 signature over SHA-256 of `msg`, from RFC 6979. Signing `msg` with `x` must give exactly `r` then `s`.
pub(crate) struct Rfc6979 {
    /// The message as hex of its ASCII text ("sample" or "test").
    pub(crate) msg: &'static str,
    /// The 32-byte private key.
    pub(crate) x: &'static str,
    /// The public key, 0x04 then Ux then Uy (65 bytes).
    pub(crate) public: &'static str,
    /// The expected r, 32 bytes.
    pub(crate) r: &'static str,
    /// The expected s, 32 bytes, as the RFC prints it (not reduced to the lower half).
    pub(crate) s: &'static str,
}

// RFC 6979 appendix A.2.5 (curve NIST P-256), the two SHA-256 signatures. The RFC's k is left out.
pub(crate) const RFC6979_P256_SHA256: &[Rfc6979] = &[
    // A.2.5, "With SHA-256, message = "sample"". Its s is in the upper half of the range.
    Rfc6979 {
        msg: "73616d706c65",
        x: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        public: "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d44622\
            99",
        r: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        s: "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    },
    // A.2.5, "With SHA-256, message = "test"". Its s is in the lower half of the range.
    Rfc6979 {
        msg: "74657374",
        x: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        public: "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d44622\
            99",
        r: "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
        s: "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    },
];

/// One ML-KEM-1024 key generation (FIPS 203, ML-KEM.KeyGen_internal): the seeds d and z give the encapsulation key `ek`.
pub(crate) struct MlKemKeyGen {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// The 32-byte seed d. The 64-byte seed of a key is d then z.
    pub(crate) d: &'static str,
    /// The 32-byte seed z.
    pub(crate) z: &'static str,
    /// The 1568-byte encapsulation key.
    pub(crate) ek: &'static str,
}

// ACVP-Server gen-val/json-files/ML-KEM-keyGen-FIPS203 at 975de31eb83d87039ec88934fdc47d8c312b892d, tgId 3 (ML-KEM-1024, AFT), tcId 51:
// d and z from prompt.json, ek from expectedResults.json. Upstream's dk (the expanded key) is left out.
pub(crate) const ML_KEM_1024_KEYGEN: &[MlKemKeyGen] = &[
    // tcId 51: the first case of the ML-KEM-1024 group.
    MlKemKeyGen {
        tc: 51,
        d: "f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009",
        z: "35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275",
        ek: "8d0923ca8a2da2b4146ec25321122b8a5aa8afe0c03415273008a46ee83031e98aaaa125abc75d3b30322560c197e75dd0e48a348099f7b2144d7b8a8660a4a9\
            7bcf19c0583bd9bb2123033cd7bb5a14b08b817831a673a28170f5f6443c0551913a327cba18c3a053c4040250403b70ab9588832403aa0fc37665e04980fe16\
            02e7d2715d9cbc00515df432a4f5b32b3bc92ae3f31700166d498123e94576509b712b18491b1435ee7ab7aeb1ad30d72348c3cc083abe24a8b12097bf32f792\
            476288eecc3bf630adcdac6aca7950d9839501a448500742bae37f109203a809b2b960a307e25347a32c3eab79288173a878789b296e9e8c1c28c5bb3ac47260\
            1c9765f7b77225a810c7b85370bef4a5b079d2015ada54236b8f33840675f9b2eb427a1b5974cd5c61b24010886c5a7bda5bbed974af7217f3338ad719cb308a\
            8bcb1b6d6ed2a1643736c29095e8a8452a3a36c7bb5ae58cbfdc61529466a90f454ed6895b0861083dd1371999b2f559a3a487cf59a074fb49215ea6a6be656f\
            9af17b121a2447cb7985590e9738842b899ba57ac311810ae2d9794f37483dd6bccb64af6d56588ae94665961c025c3aa2861974c236bca4bd8ff5509f7ab774\
            593e7c5549e57c2f18d15c0515094ad9a0dfaa0601e524f8231156b627bb25a0dae04dacd0a66c041cef400583fc13bae640291a39a5c5ca8bca1ad5c683cdd8\
            290891a76940817dd8c9f52678780548e37a05806600801426dbb950c3b2ba34e24cc77864dd91b39f1408c716a69df63342854e50a245fb50977b9410ded2c9\
            3f86b1f9d5a78b87bf81e51ca620a7e8566b19ab700964a40e3266415228d432156e5cbdf52364a90483a55c39b3fb16fc7465a3f8ac801b70b9fb28b583444b\
            a5c1a73722d417a9d6d9b7deb08bc6b330ff27cf61ab8831e27758c64af3b12150cb7b33abc29858106d63686d8762459abf9413850ae53ed6313f76f83d0fb8\
            ab34374e7df693e4a1b3e5a8ad0ce820afe1cf401acde650a8101b0946022d52178e19613c42b88b07cc04eaa81dfb28ac9dc076236b67219a30f8f945dd57bd\
            2f335c52d59372308d38993467db53da3382b74867b616481bd0091a2232c1116dc88a589db9107224a681008c67c589186a6929549beef92253db02b0c8aa9f\
            9c875a670266c72bcbdb4f5625043703c1a0457395832e4c335180462ed2220c59e7361903c107d85457f6cd82eb820d0855d97675c2e0151cdb73c2885ddb78\
            49d74541580124e890116a65bc068093b57914e20c937c60a3eb25576f1a976a9583839b672144cd4a45c3477a45c29b4e0bc2bdbd206585c9b7a7741c8b6b57\
            93a92797a15ae7a5b73a74b2971463634ba52aa792af05530730b6d0a89a346156b733677932bd36593a7496130cc458dcc5ca987c21960604ec8a8c53960566\
            80cbf3f1aac4f401aa5029fb2150434bb4706c31a2d54e4297939fa7c9c6f85700613ceb65c7f03ac56eb86e2d27ccc6dcb7b9394dcdb942ff222d86958a996c\
            0cb6a8a44f97a70441c95fa71250116eec20863c0b5a643458788ab001f8869d909922f51ee547a1e889255b3a0599c65842e5ab8d73872f053bc62392ea5389\
            6d328102d460bf1609583c22c3b43780ec6dad0319eb4a5a65b4756c3cb40eaa935183bf8bd46abe76ba46e199103a5313c3235f49c915e097bca804de680781\
            d8365731beac6789a9203fb8787c4c070e00a13a6722a66a28236db179825653d33ccf898b72c6b8450d97afd3276bb13340519cbeda708d12a858f54c49f454\
            7195b7788a9150b2649e36aa394121926d568a488b16d3557b2a32af57d11fc3373f80a28c0723273d362502e7c428ab44d3cbabf9ea585fd1bd0c9846556a1e\
            196b78cf951592984a0a8487a78c2317d7aca4118e1049750a0788f0d66ad9e48e34731130aba0b427360a856d96d80b3f028fdd3aba9035c10106ba1c0934be\
            d36c6d7c7434249654ea89fc22137f4ab903653b75fb25b6f01635e6cc7d39cf1508690562826b49b6ffc59e0dd35022e541f8ba0d304aa5b4e20606907c4243\
            95666c54abc2b8fb009847c86317685000c231215c8c15945860f6a85ddb98a8c3a527f2749d3c027e694e8f0b0f0fa454913aadb635aadd452f7128bf775256\
            9669a8b93290eb92e78f6adff23e89f57f3890753b51f12f3f3a8a654e677847",
    },
];

/// One ML-KEM-1024 encapsulation with given randomness (FIPS 203, ML-KEM.Encaps_internal): `ek` and `m` give `c` and `k`.
pub(crate) struct MlKemEncap {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// The 1568-byte encapsulation key.
    pub(crate) ek: &'static str,
    /// The 32 bytes of randomness.
    pub(crate) m: &'static str,
    /// The 1568-byte ciphertext.
    pub(crate) c: &'static str,
    /// The 32-byte shared secret.
    pub(crate) k: &'static str,
}

// ACVP-Server gen-val/json-files/ML-KEM-encapDecap-FIPS203 at 975de31eb83d87039ec88934fdc47d8c312b892d, tgId 3 (ML-KEM-1024, AFT, encapsulation),
// tcId 51: ek and m from prompt.json, c and k from expectedResults.json.
pub(crate) const ML_KEM_1024_ENCAP: &[MlKemEncap] = &[
    // tcId 51: the first case of the ML-KEM-1024 encapsulation group.
    MlKemEncap {
        tc: 51,
        ek: "2191abb6d6beee29c5780758a970349879b61a028deea5404731292346c81eeb1d17766afbcaa68c867d91132f34a494e28caa767241b50902f4825771865fc8\
            d633736248963a253dd52c1a07c7177cb6df74c43c3c74d7133da9dc915fe14b5bc30b86153e7b86be04189f4ce8ceb6e5cb69808d35640ac50335b1633162e2\
            8260300646153be7b26a84c1c565956f8577c95cfa80b68978cd7a79e49c7e808b21cdb460ed8388c4859670333b69980b2f9a0f78d7a5b9d8554893a0b5c524\
            47b15318828989816f43406abfa4950607a5a57cba62f5c4340ac3d294191687c7d2b60ef2d83f6bec15b1618129b78577447bd1e36a87142b9c552c8cd2304f\
            35b81b3bc5196c3840c0346d513ec8862ba14a172c051402f7398707a6133c8e88e5b57f9b9eec18aed1404ea1c47be5169e5d558e262a231a75925d25c49965\
            0c8ac031be580cfb185a0e0362ce2194c53713a630cb59600c1942908ff5142b02364b74b3f5474301ab2da4188dca640961142f28584ebe810683c046b59cc2\
            cc07025da63a5e8c5e99e24fbae183329886279c2d58d0b8cac1c7b3033f05e765c75414748687ff03c00b36709d41c5968528f178cd03b813b69054d3e20fb6\
            a04a713b1b169ab5f0369810fc5cd967a866b70a2d87514605794930be9b7b5d49d08f5cb08d84fc5beecb994dd2a5fc10aeeb4cce1ed251fd4815a9d06eea6a\
            77f18c56acabb1f7c478dd52218b7bbf9770a51c3ac96402548a1bb22dd0c29f422330057179ec2d91e1aee27bbcb1eb4671324265e28676090896e332535ba2\
            e9169c54113f19a45229c2448078ae08f7213f347244527ef726855ca054ab7a1ed1a40a285a60d04c00ccfa8fd318cf182705ddb888df652669b3224cf54ed6\
            d00db5121331b40c7e35b1945925e5ac1503a999899317a2370020d81873330327db7cc1d430e32c6570fccffeea90a871a4b04ca9a8065ab20a6459f1806221\
            a5482802f14a68893b111607c4e085a5a6410c027c1bf5fa33adeccea576211f272cc942acacc879de398477780a26e7545ed693edd66ad24772b0c0c4b033a7\
            3ed94e1d02c384d1a288a78f5d8838b5ac0b37855dc59b987ec9b0f5c6868b0319f3372024fc15b247144f925d3edc453fb8551ec1ca734a37a3972b8cc9b84a\
            217a4d0bc0d08c815359aba59a07eed998133587e062cf735a8521a18ac2059e3f142f12ccc5ae024ca33b8e4a285be5a3ced460c2c3675b956294ef2c61c96a\
            88441665d56b2029688efe4540dc35abf5957bf9477f58277851719547510f22d01a13d0047c5b88372a654c732aff395dbf825829a06e6ae6923296218ab9ad\
            33d0b07a0b6a3f3b3dd8428a1f82b72a921853d94c5d400494494f0d168148b5392f386b16c6056d6b8d767b7f4d918a9384c855c8b4de8450eb6ccc2df18528\
            cba0a3552d5704683aa3aaf52751fd5a17801a76a58a75038533c1576e8668b5d290ceb20cb1ff91317d9b418311c11e617d10b4b0e9055aef5cc6ebf8b91f02\
            44ed9854fde463e55112a238038750cd016735613b9c461996b90a3b4d4b0d8b8825ec087fb138ab868a04cb3c9249b5b118f81ed06b99e6b521f206a32a4013\
            e876c6c80b36af39ac197a21b78b5f2713aa45c74335f32676c2ac2902710ec42af5984687a672e0466831c7b436300b30351795b22b3a939347a7b744831baf\
            e78c3bf09a8224a958568f75d71f822941dfd64d8969ada5b73c847272b5914491bbce5f0c09ef501babd95190f93201ab413e833f7924b696d5c2b622722459\
            32a6d9c35e1670aa3bc57cd41b8d61a52aaa6d80bb774f922ecb41cd58469c4dcac698f6730890237602064b148650c17e6edcb3713382fe755e46f3abe0c6c4\
            5184ae5c5c861e35a0e2bab2b4e8a4775584351170152512c7e99e96f285b916605b53b91d6c501f51a93129483046cb2dfa16d4a540ed2b6ab18bbdfba2b201\
            baa20297ab1fe7133757c07dc041971aa4219157d77628f31aaf520650a2250adad1524e58268d21cc62e2469c8425e86359dbcaa066acb466e06947a1c144e5\
            3ee0dc930432c806c493b2bb25757b1e2c775a27a896ec25b58e8a78d4dac91815a1f3d90635ea25ae13cefa77877dc0c2f0678ade307243b438c54aa69dda53\
            9b8a41c1b3c98c77fceb2c0bc2025a272d927943ea338cdf32a0dec8b187df5c",
        m: "2f1e2ca7bd72af847cac38cdefc4d345909d7517543edf32e2fc491ba05eb5c3",
        c: "d892e0948544d020ece56f00c6495b9bd1c469ac0f134002c864d10cf61c6c7887890276a7546310ea077741d83428f22b60e2a40ed8bbf5d9227893bb0b7417\
            df4380323426ebc9744ef35a1bb6dab1181ff0b677e8c9b6574360994f96eb87c3524e15e468283169d90d8a994bed0da9cd778ca239ca6c225390221fd408a3\
            eae541a032d714f3d078dd1ec722ca83fffc92a416f46fc1e8710c3f8e9cd452c016f483985a5c1d951fe2b03c4ac2c9a0ba71f6ffa4b29ede76df69cad594d1\
            0618b94e783fddaf11cc801ed5036feb4a70d071079944b7d9f1ffbb98f123dc34a52a40de57e079a1f8b180da9e6ecaa47a111f3c054dd9563d7e74b95ac65a\
            b453afe0bf0dcec5578fe6fbc2d9eb91932799ea64b2dfa95b2c9c6e931ffb0a5a499ddc42c6d6b563d5a6c1f34dbcb36f57e6c10c69feadc70a3d01f5f3715f\
            6bea0d3e2e7ac2b04e01ca80a2e187bb7d9efa5ee257b9c3caea3947d785ca56a76d0b6692a69418935dfc36fd9b26758f5e1043d5c2a6d5cc1556aed592bbcd\
            652f4024bf324910f8caa2415171f3ec8b1cc494f2b519cbd2b13d317672de60f0a3d400e6079f85c3cdad0da5a17f2efaccec03d3c2e85b063ac3cb29f2fc48\
            50705b8d472e35dc12d06a7d021db302ca883dc7d4a57b7a9e1d023960d4ea5e39c9d5bf328b8e4ac0afc3a6c990f598f373059ad28edbeb90412472c637877e\
            a82e7105caf467a15ce961695f2ff04c750e277e78c1ce9e490a5c45168936bcf79261b95fb20afccdce790e0aedde204da4f6734700fc1ce05239f4ead0a496\
            fd8f733049ef9b6ecc54d5c635b56d6fcac7aba1ba32d707d888b820ce3e794c2562798210d726c6c5db3d22a214f3f2a1f2477fcb77377af41d0f3f0ac635e7\
            bf0674cebb672ea93b9504efa8c5aafb7458e41a1d85c28841877ff2f444005cd1c1e4227573e8151184786489c7cc39549f8a29b9c4d68be38f24081fe239c5\
            d0e14ad5e361720836a72a99ce88e47bf3e6a1a9eb57cdc3724cb4789fb88c135ca9ccd94ccc9bd73ee8a796bfea36e894ed27b0791e8ad23fcda5ae7c167d57\
            74aa00468d97bd0fd2b9bd78d01e1e39a66994a369212d95d7886be00f2b7a1f187c85b873f33cb7d3e4c23993f7bc9ff7abbc6fd9d5c54f06e5f31b79da992b\
            c0f2aa79a36bd00483ca0add2dcb2be36c27dc913668f030128e82281e5e66e87c75dce3fc60431ce6a19c6c45e19a2d84430e945034b7da6c506ef009493af2\
            2f701088e01c20acb21972ff28d284d2a57a69d108161938f028011ba985e2b925532b52eed878646579183eb0ef3fb57be1e05c1bd2b68d0e4a9ce104e0ecdf\
            b30268e6c007812fd88498d97795447e7f88ce8a3bcd161b1e34dcf77413b778f88a3ad66f247f7664d0f6af31ec1dadc00fec09d6ac63fc8a802c3752484b5b\
            43555381043fdd30ef5d7dcf4f5b68eb89f08a0fe5ecb65d6d9418ca5283ca398d3129cd3b44edf5e3568c953ce2b66a28b473cab0c43918a05c5a4358d13926\
            04495d06b395187caa6b36050b436b218485466cb6643eda7ac66aaeea758715a22a8849066879cc966da7e0f7e843a1e234920aecf2a4fed2f78c69a6c103a5\
            a535d77976b1e40bb0d75d6e370212017734f2b0be9f3f87c5583634ea6a998d8fe9ce5e5905f2a6abb9d635425d06731c1227eb634a3603d081cb1a7c2b0c16\
            85942efd6f65992dd39aa67cd954fa0310a0f5866ac6121e27e349d5c2adf37a672c1dfb021a855000f0c0c29489926b997930b20df641120ef8605cfd9482ee\
            a9344918aec689f580a94508f318e63eadc3eb7486b9fcd7a92ba16f5e02cf78ef73f528fae3a43d451c58261a82b3735e09d4f4679ce112803505006cbae6ea\
            f641a6f66b0c51ee90095735d87ad88c3d19cd7888248fcc3872939605f205976ef6c6aa52f8316e9def841594373fcd177f0e24d8975653a29f738fa8f0d457\
            f2d72b7c00a4b7a66fb080f705a8bd599314354e65842af598b8a2a40f6cb3208762ac6cd467d06a2e987a7af72e355bea297da87bc9250ebe8d8f85cf292200\
            a21d93475ba46be78c17c1605c10b97659859f08f980114955e68361e180c98015aa46a776070c4f2b328a903a70ad226742f0022279179fd2530390f190e300\
            8f7202c83a6a15866df848c8a150d12287451dec8ee7f04c1c3121e4bba687d7",
        k: "5087e3b0c90bf601dd6501e071270eff8683621e9f5d67a7a668e50c4f460a75",
    },
];

/// One ML-KEM-1024 decapsulation (FIPS 203): the key made from `seed` opens `c` to `k`.
pub(crate) struct MlKemDecap {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// The 64-byte seed of the key: d then z.
    pub(crate) seed: &'static str,
    /// The 1568-byte ciphertext.
    pub(crate) c: &'static str,
    /// The 32-byte shared secret.
    pub(crate) k: &'static str,
}

// Wycheproof testvectors_v1/mlkem_1024_test.json at 65ca494727a52944c204441c860b039e6786b99b, tcId 2 (valid). Upstream's ek for the same seed is left out.
pub(crate) const ML_KEM_1024_DECAP: &[MlKemDecap] = &[
    // tcId 2, valid: "Test vector based on official round 3 seeds 0", a ciphertext made for this key.
    MlKemDecap {
        tc: 2,
        seed: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f",
        c: "c9bead6b0c1114389bd4761c73ab9095b5809daac9f659bb564af226173052a4a3e7f2e5fd47d2b02aaeb5189e06b9f4ae98b619cb63efbdf3989a94b36e8ea0\
            d700633b950a0ae2a78ed92e85c85c70e13e626fb263fac9681521c3ab22fdab29173c9616a2b037083ff7b2e019b5bcde068fac257ef8f12798411693c1bdcc\
            65420997a513a8a69502620be8e4ce7362e412a76cf51c1f2433f1ab64ce0e5d2f56d7c9ade994d0e35d0aeef3ac515b482437664d8c1d25e5a5507cf80f970d\
            3ea7226aacdc457cbf88a0560aa35bb2c5c455867e2159910a35810befe3aa10eb04d8d57147cb8f66d2b070bac43d1f1ffdd57a9399951f64965727bcb9f66a\
            d42309dafc799c1c540af1af93eff68a86d61f5115db662dee7ac9a362677762b6a164a0fa0a4d859e4b8c8dbdb4e183f5e6808fc52229650caf7cf3e16de3d8\
            95d148c35448ab8c2753c9831b24bd4921497eaa192565cabfd83c0c68dfe7d392abf5e5e6f84bb9f5af4b7118c0b558105f9c10c9b6d70682e1de6e0689d710\
            6a6374bd34aed7229e6cb356f2ea65e680ce7b1e2c3704e116a38542826e8a001141baf2e34de37a03040986d4c0cd5d57f0701ce930986fd9525b58e2e59f45\
            b8dd04c0f35b0f47970cc67079618eb9e6d91e9b0f8c6d2e165cf448a2c1ebf71b6537e0f375185dfafef698b6239bb35580b315bcb5ed408c357f192def89bc\
            1b75cdd6aae8b5faf0c3e13803f6bdfa76fb407fcbda790c329b3ee42fd3d3b03bd5003f0bc432f7ba39631112452dfd12140433ff8980eb6a526ba85ef99477\
            378b4dc76635a5cd5040e43b8c1fe4ee5e158e423bfc0c893c1d5613bed08da719c9073184eeb36fd357380fb1873d8cbd36e2255e985b1b76819743a6584a9b\
            3a580996c9c2eed9bbbfff78a6204b5e5eeae5f4efd2660078b37f0754ab5da862e666b145b5f23f3d0977799929dfa2aedda53d152eda1d0d0e4ea43f6ed889\
            bb965eefe0a7c685bb36770eaa874242c0e229cf6ce56defa5aeae64d0c40dda8aa26eaeb31458f070a3bc72e1619ee9b5f642291c56df5b7e43db6c802fc74f\
            4f3f9b5c0d355c3aae520aa31229d12f3e7cc5d48e691191a36b283765f4133f0ff1fe2f01c6648b2798a74eb5d842a248f524a7e7f8974211297b44f0dd19f3\
            86e86be6ba782de77fde887226f37a1c77bc5eddeee5bf46b67fb7478d559865f262caa84d64a8ce59e4df0818e14861526acd3483600f3dae7959d35d8181ca\
            6a81ce791be00752da7759446a2cfbe00b8248b93491debd520220b755416d2fc6b7c8af2ff75e5bcbb8e7537380a5721c77484957a69271d8bafce0f166735f\
            f869232de5d381afbf0e44d69172b79a35191949de09703b94222b13c385c6081e6d2ede1e57fe184ef8f60196b9a3a7b7eff7497191ca8741b5a01e79cb69a6\
            1142e6f5d080fbb3e566f79e146f75c8a1097860841b4747df604dba954e4a8d9e0dccc1f609d05cf8d31219ecd60c312de684552f09227cb829291c645732c5\
            f5d4d711639f42a23080aa34fe1420f219bd6bcf4e3b29b9d02293b2da81383e0a51d2bb186c7b0a211a0cd63acbfc0210401e985d436b3803d5601c24136afd\
            1562522e45b457cb439178be4a87cce40346d34ae0f3c39103c8a3ebc9c86c8db8fc5561eb0f3a143d4e9fe93a5cba6f6fcae5650d3f43d2668a5956c922893b\
            816647ded0afc052a6c3d9d01a3d3af0f1ba807ff10491e131dc15e165cfd0650a1f2c313d7956141edcc61cb90e9e7abf2fe35fc9dc1bde88939fa11f7bbe3e\
            b4d8ffa643b074d74f45113586e9bb12060003d71941f2da098dc0e96cad3255cf328ea2d3308c1f4585e89c613c426b7e798e1ec4e98fe6c71e7491f5eca0cd\
            05115861bd160e3fe73a58a026ba538e0e256b92f1d7a2497570594856860ffd06b601ac575592f4ac612b5de7866042123ebc60c55768e3a7600a3260551f2b\
            ea22bbf6b6c8246e80f9125c4bb9db354dd64ae695c15f5071f4abb9639207cac7331b310f69a05f54b995de529a023f033b055db95287a14ba30a7cc526bb72\
            4c417fba290636a996f286e3e9e939e4fe1c398b5c6599959d0b4445a327ec469a1653cfaea7552cecec085ccaa68938ae4ac3c424f7e480439ebd2c992b5f6f\
            95ec244b657dbdeaa9ae110aaf4d68bf4e27410d43ceef3e88e9c717dd44c9ee",
        k: "489dd1e9c2be4af3482bdb35bb26ce760e6e414da6ecbe489985748a825f1cd6",
    },
];

/// One ML-KEM-1024 encapsulation key that must be refused: it fails the modulus check of FIPS 203 section 7.2.
pub(crate) struct MlKemBadKey {
    /// The upstream tcId.
    pub(crate) tc: u32,
    /// The 1568 bytes offered as an encapsulation key.
    pub(crate) ek: &'static str,
    /// The 32 bytes of randomness upstream pairs with it.
    pub(crate) m: &'static str,
}

// Wycheproof testvectors_v1/mlkem_1024_encaps_test.json at 65ca494727a52944c204441c860b039e6786b99b, tcId 2 (invalid, ModulusOverflow).
pub(crate) const ML_KEM_1024_BAD_KEY: &[MlKemBadKey] = &[
    // tcId 2, invalid (ModulusOverflow): a coefficient of the key is not below the field prime. Upstream gives no c or K.
    MlKemBadKey {
        tc: 2,
        ek: "01ed3b18940b68a85b55309be11872c3318f89423c32a3ab705202805b0bdf7455aab06eed648c443066ed837435d593cbd1769f3a669ae414394a26b4956680\
            c790b49b80f9b9c8d893656cd001c218789cbc91f22702ce988170093683769216057a865c5a65c54f25f166302b9b73254ad2185df37b83cbfa8aa03439e56a\
            8a6e82410fa82be1874f6b6acc04517eea08391ba190d19cc883482b703493d9102145f55fb5f85f4ae76bca212324c4663acc0df9269b05db081f81b9ee824d\
            4ea6bd59979c3d2ca6b4d689ada3c7f505ad02c5142afa6c48b90bb8316baf479f352066c1e3055ca319c2703ff432cdda2c4d63b45b3852811a5a26328227da\
            eac344856b7adc4808c9ce07e737170603256a2be693cc82f22513b518f2d8974e4146dbb84e49c896adb069b8d32f27a64eabd73664b916f9a3bc7382b16914\
            c807121fe8d351ebd361937142fc29902d1c3fdd923428f20aa9994e796ca185db9910496d7f389b2fd73074369e66f42de4234e88a1669db969f4d738106cb3\
            b47bc07c8cacfda5b828937b6d714a4d23a92d445b7952cda7fa81351c3e431bb520294c2adcb41b31a2535bb1a7b0cc5cc3770a433d3eaa3505768c37e1adfe\
            88b97d2c39cca6a806316cdd663d6d1c4e9e2bacb6aa9de9d52ecc4b88b55020cd45c1db192e5aa0cd631642f7a1ce1a7003648445957418cc7649ac217919b5\
            062a4938ee025b8764015ada5bc43a788a293d7fe82abd328e7d678662db6a218b2fea5138d5808872d0c7fc31b81551906fd357e9a13178a3116c93b460b090\
            03396fee64ad02c915911c798d588bd9f33bab01b91f20b466b89214b7436b96b837070786215dddc61df9e99459168b3c3046ef5877f165c425ec9561aaba87\
            e384a0114973740546e59c4e1c11a45842b772547d247c19d668caaa6edf175abdf7141fd534bf953228b5766f04bd943c38eb7634f252700e2a296d1b688a73\
            166b9c7c8a2ac48e434f0d43434548bef03b4201b943b3e357abfa8d6c8a8bb2f83f04e4a2fad8c830868a53e3c065d33a501a8b030961bbb53eb4a462b600cb\
            094304c2337227074d8c0bade99897056c88655b9edc63515a784b85d3c8fb0910b8f71f7bca332690adcf2b6c513500e53b6dd5431e04f0b7865178d8b19200\
            a432e61c891ab932c75c2ed093b2ef4227013445adeab06442033520643e7012bab1015c027641054c496851181b2182e741b1341d5f27b11df49046290f7b71\
            945bb96dc32c4fb2aa44819c594a300398fc330f95698289caee444651d162c9bbbd7ce09dd595805f12cdb7b70838402eebc79cb9e2526734bf7bd45d01f7c6\
            6e9b542584a1d2811ba15a1ebf699c2d4a4aff9b9c8ce3996e498b7ffb0a4e2943c6e34fbd591046203616d6a60349285bd895a2eb6c231cae9bb87adf21c21a\
            5abdd7e2896965c786019a4661cebed5105aa9633c4091b7c954d034429b5b5f6ce42da49cc93dc46e997170a097900e8b32fc4b5483394ad958096fec7c37c4\
            8018028c3d07917a563d2ddb967d7ac6e9e28d440121f896aea82469d3c49c2f2ac41e8c0c9834201dd9af6eb5087d048e37d1774d521399b07cd6d05f6f24b1\
            f0c07261b03afbfb18c0e4b945e12aaf63c00822894a43a57b8514a5524db703451c7aa678d5100ffca01654c9556095b33700372a9766e9852c5255b774500a\
            29b61aa0ac32f1bd3af61161ba437f58a330dc9d7f0c2c61054a020981a6e406eab200042b69a146387c11295815626dc9cd2ca067376a42800650fe849d6714\
            6918859d917a36dba6c0b3c52802133416b262f555186777c397ab9605cb1a35586ce125a9118a5a48566714a1757c04065ae181a8f0ce80f8a449ec9bc149a1\
            8cec1213e1213a4c2780609d9d839f4b038aed19b1cc8893a9a9277eb25be8b848fb035f04e2cf090682dc61b51b23aad4559d7fec2ba4694d710c5e0fc80458\
            5509f80a720dc84e9131097f8710d8344f4aac62b7b0696fa07c62102f6b0a9280b81f6ac185ac7c14b1f36f9de5770b65afced0ba273a5e1bd210d1d0749c49\
            040b4b605ecc805db803b1c092ee021bb0db9ddb532f22ab87849275d2c9772a37ce4b7a4f0c9c8cf8dc0b0e5bb5bad62cd5b608dac6a282c7658be13ddeb855\
            42256b0eb52ccea708f6fe4295de6d4636ba419ab92618a52b673929972bef0b",
        m: "4242424242424242424242424242424242424242424242424242424242424242",
    },
];

/// One Argon2id case (RFC 9106) with a secret and associated data. `tag` is the whole output; its length is the length asked for.
pub(crate) struct Argon2Id {
    /// The password, P.
    pub(crate) password: &'static str,
    /// The salt, S.
    pub(crate) salt: &'static str,
    /// The secret, K.
    pub(crate) secret: &'static str,
    /// The associated data, X.
    pub(crate) data: &'static str,
    /// Memory in KiB, m.
    pub(crate) m_kib: u32,
    /// Passes, t.
    pub(crate) t: u32,
    /// Lanes, p.
    pub(crate) p: u32,
    /// The tag, T.
    pub(crate) tag: &'static str,
}

// RFC 9106 section 5.3, the one Argon2id case it gives (version 0x13). Its pre-hashing digest and the blocks after each pass are left out.
pub(crate) const ARGON2ID_RFC9106: &[Argon2Id] = &[
    // 32 KiB, 3 passes, 4 lanes, a 32-byte tag: four lanes and a secret, which the passphrase key never uses, so both are checked here.
    Argon2Id {
        password: "0101010101010101010101010101010101010101010101010101010101010101",
        salt: "02020202020202020202020202020202",
        secret: "0303030303030303",
        data: "040404040404040404040404",
        m_kib: 32,
        t: 3,
        p: 4,
        tag: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    },
];

// ---- known answers ----
//
// This crate's own formats have no published vectors. These values were computed by an independent
// implementation written from the specification of the formats, not from this code, and checked against
// the published vectors above before it was trusted. Each is the answer for the fixed inputs just below.

/// The seed of the known answers' hardware key.
pub(crate) fn hardware_seed() -> [u8; 96] {
    arr(&seq(0x00, 96))
}

/// The seed of their recovery key.
pub(crate) fn recovery_seed() -> [u8; 96] {
    arr(&seq(0x60, 96))
}

/// The random bytes of the encapsulation to the hardware key, and of the hardware wrap: 32 for ML-KEM, then 32 for the ephemeral key.
pub(crate) fn hardware_rand() -> [u8; 64] {
    arr(&seq(0xc0, 64))
}

/// The random bytes of the recovery wrap.
pub(crate) fn recovery_rand() -> [u8; 64] {
    arr(&seq(0x30, 64))
}

/// The inner key.
pub(crate) fn inner_bytes() -> [u8; 32] {
    arr(&seq(0x20, 32))
}

/// The workspace id: acme's, in the tests.
pub(crate) fn ws_bytes() -> [u8; 16] {
    arr(&seq(0x10, 16))
}

/// The passphrase of the known answers' passphrase record, sealed for acme under that name: 19 ASCII characters.
pub(crate) const PASSPHRASE: &str = "acme passphrase one";

/// The salt of its key: Argon2id with 65536 KiB, 3 passes and 1 lane.
pub(crate) fn passphrase_salt() -> [u8; 16] {
    arr(&seq(0x90, 16))
}

/// The nonce its seed and commitment are sealed under.
pub(crate) fn passphrase_nonce() -> [u8; 12] {
    arr(&seq(0xa0, 12))
}

/// The nonce acme's first manifest is sealed under.
pub(crate) fn manifest_nonce() -> [u8; 12] {
    arr(&seq(0xb0, 12))
}

/// `derive_scalar(KEM_ID, seq(0x00, 32))`.
pub(crate) const KAT_SCALAR: &str = "c88dfa16bd1d181676c6b316dca1ec7092bb41fab16ba8e270cbcd76f3d5f5fa";

/// The P-256 private scalar of the hardware seed: `derive_scalar(KEM_ID, ..)` of its last 32 bytes.
pub(crate) const KAT_HARDWARE_SCALAR: &str = "c7e2caaedc1877e97fbd32b54028cc0327912451ea90255d1975ca6dc51fd8b0";

/// The P-256 point of the hardware seed's public key.
pub(crate) const KAT_HARDWARE_P256: &str = "04333061ba04606df6bb849ac4b223f14bed83ddd8808d88c9a96af50ace61f85900e1888a8a90f593aec029df25892da20a7ac2e3eb6835f5f24c65b230a85f\
    6e";

/// The first 16 bytes of the hardware seed's ML-KEM encapsulation key.
pub(crate) const KAT_HARDWARE_EK_FIRST: &str = "4b94c29450111191823b3514c9ac1ea3";

/// Its last 16 bytes.
pub(crate) const KAT_HARDWARE_EK_LAST: &str = "eb0c8701ed58dc628776b983882e1175";

/// The P-256 private scalar of the recovery seed.
pub(crate) const KAT_RECOVERY_SCALAR: &str = "3ba47e52c2dcd703e799201e2306baebef884dda703bf46f4b010deab3cc8cc3";

/// The P-256 point of the recovery seed's public key.
pub(crate) const KAT_RECOVERY_P256: &str = "047ee1c1965c8d604396f9b92b4c08d9768d79f11bc795fdf8a410ac6727672d60089682086d08264982e0f501006389b0e77dceb8f83ec854cb991d5e88df83\
    7a";

/// The first 16 bytes of the recovery seed's ML-KEM encapsulation key.
pub(crate) const KAT_RECOVERY_EK_FIRST: &str = "2c951878d5ccbd122405236149a05d89";

/// Its last 16 bytes.
pub(crate) const KAT_RECOVERY_EK_LAST: &str = "2b06df6794a31db69e98c130fb11b745";

/// The ephemeral scalar of the encapsulation: `derive_scalar(KEM_ID, ..)` of the last 32 bytes of its rand.
pub(crate) const KAT_EPHEMERAL_SCALAR: &str = "3d5a9221b8388246f64a6b2be7ce759711e92280b97c8dc48ed778fa654cf5e5";

/// The ephemeral point of the encapsulation to the hardware key. (Its ML-KEM ciphertext is bytes 2 to 1570 of `KAT_HARDWARE_WRAP`.)
pub(crate) const KAT_P256_EPH: &str = "042c2a1891563af82331bd5289df252460ceee9649aee87ce46f7a62d601247aeffdea95a1cad1cbdcf8e79a4ae7816177179591e922f2457b60da32038b0123\
    cc";

/// The ML-KEM share of that encapsulation.
pub(crate) const KAT_SS_M: &str = "cb06b34d7e5af6e011eb9aae422f9e7a431af2a3c8a47078b27d3121f798239c";

/// Its P-256 share.
pub(crate) const KAT_SS_P: &str = "0c491d0ca60fbfdee09c8aef789c190b2f70bf045b51ab50d2d6984dc9cb5fd5";

/// Its combined key: the value to compare with a hardware key's.
pub(crate) const KAT_COMBINED: &str = "28b370287fd516d15e632192d02b3ae6dd2e916375e48ba255eae3b9beb3f424";

/// The cipher key of the hardware wrap: the seal's schedule over `KAT_COMBINED`, the hardware-wrap tag and the workspace id.
pub(crate) const KAT_WRAP_KEY: &str = "38825b046639588dffa61c228ea52e34947abd9c5cc84dd61ac9f42da825d7af";

/// The nonce of the hardware wrap, from the same schedule.
pub(crate) const KAT_WRAP_NONCE: &str = "2539a00c0cb5169a6643ac11";

/// The inner key wrapped to the hardware key for the workspace, all 1683 bytes.
pub(crate) const KAT_HARDWARE_WRAP: &str = "01017e6e515252fb24ca6641f2dff83900611ceee2d1553db24a1474d6606c72ff7beee00992d7b3ec018680841fb64c9619bb026a5bb588ef380b8eba1a854d\
    cefb4bb99f39129f0dbe068e80535a4e97b9f039dd7a4451c1e11adaa64411c7e19d4942475eefeb0c2712574cddebd5e05b3549c38bd27acb786e241e814e36\
    9e0bffd298348b09b5feeaa8d215c47e759268199c24630efe87b7bbd5ee82c7597a92b33e05974636f025bc46be31ac574a24e2e5de023671a660aa251d3dd6\
    ddedc4bff50dbd50157202ad8af23836da6fc774694cbc898d7fe4897892a7f903c6b77b9d3646cfe6ce613ded9b722088be3bd1a27bccb06fb440eeeae12799\
    13957bc5e11aa41e3feb6b89f909d459d58185594d82deab69084677fd326f3c1532b6d8b52dcf2c7c63aaaf192f85c20b085edafb2f55e375b9cbd026ef9ced\
    921ac485ca7e5b4e8fbe5bc9e1ecc3efb707c5a0c067c4022b7c1cd05c47e6fbe1a111fc8693a2b0b7c4ce1bac1327eeaf3b588b4cadad62f6dc5c32a1a78ab2\
    4403ab0261b6e8d08522ccca81299f8272a92ab5628f2476ca3fddc8faa3bec1a9cdc95a7ad64aa2deba290b283f2bd418822b8bd74bfcc55be85b758d261286\
    241b7ca9893bbfcd377e60a16fc4452e7c0a11b769f0ebe1b35c9d95fbc2e70f900b9114a0407f88d234ba382e56caaca82822c681c69e306a873ad5dadaf6a4\
    f7c2c825eed96286d7db3e8018a50dd47b14b80eb1a5272c5e9b7a324d040b41e182cce39f84b44d351292317e44a1d57b29aa6d420459762524eef7aee7ab34\
    0ebffdd9a85d932403bd7adae54dbfb7530c966bdfd72efa42e33a5fa3fd643d0206095511071273bc4be901a2166c3052c0bb99a31162861a8a60c8b8a8a44f\
    b41ad9d866ab7c0ffafa63da2392b802ce90e33874a0cdd93edca05ba119b71e16d002637cc8bbebbeb58dab2d7988ce1032d9fd63578a4de12e1c0b27451927\
    ba483e7cb9c99993750bb790ac1f13015b5f3d9be14558309a65bdcd03b5698061aca2f14407320fed85a8299d438e7f80f9921cbee118d5dfbf9ad243da68b8\
    a2608d30c7b21096cd19958498e0543d62969500d7673a89fb8902f6df3d7e710d1e733a98e11407a1e1ec7263a2b6b0a31c354d11320852f7884d559a3d5991\
    c772f04e97f2a3e7e79c957605f54498d43427e0f9a587543f96e7ec715761f0930610c7aaf05bd65d321387369c998961bc1730fa6f5c47d864e744e7af80bd\
    696c728d3b217fc4139b946f9cdc8a41146fd172a269df0065f3a996e39a0c9a82f33f27bc36a05ed29a0d31153b9f6c69ad60226cef97e97d17362101a13249\
    37b5e635208646dd2add06a536d745511f5062c89e6af9b10c39af1a308d0b7ccca86ca936473f71826d2d052d5f182a75ab2891cf7f03a18cfed1abfe33bafc\
    33ea49aa77e36d3cd138755158a5456284528b9547c420fac925adee064428a0c51c29024f45570661caa9986863cc21692907749f679425b833676e23b73fb7\
    0d55946418799c1e3d6534f3d70b59d39e695b0a05376f0c7fe4a36f46bd28f38c6c8b06f406ed50ddfaa16cc3c7ad9addf6bfaa343c8abe8c74f2925d6fa587\
    2d1b4b1c0f459149d235187169ddffc0b289a9156951505aa0f5ded95cc1cce6c98d7b4b609d96d7d9e862e0cec7dc731902100753f4af9fd2dce12507130520\
    757e87c4d3ead0d9407a4368a0f244e4cd2fcaafc8fc92ec41047ec3d2f48f43f41093f555126d64ce665f7382277783e0f23cb6e54f54a68952101789bbc3eb\
    4243ecfbbfa4b9774c6da179025cc023133228d0f01b896279794309c84d7315656e6bd435c421eefbbd4280938ae0bfbbaceb983765346920637d2013c72361\
    09630b270f7f01d20cd1037c9092f421671c844ec2a109362be1338665a8752707ffef498d175930e410db0ec8ef63fc1780d85a7e15432f84925bc44c6a1602\
    89738dce29542db683f8417803b3c649772a39902624ce5a15743debbe8c0587a4d8c12fd0aacf925b2b7f1788d6c43eb931aa2a4b6bb75478ede91990ec973c\
    088cf4f8099c427314f2886800a1f50197b39f38a5c435f56dd284fbee5ee673e4e23ffb3ee97395ccb5e4938c7aee0a8630f8ebc9a0825dd0643882facc21a8\
    99a2856b23f5c7359fd6ae5862075c08c7e05d51011d55ecd2fb8a198a90a2cb206d042c2a1891563af82331bd5289df252460ceee9649aee87ce46f7a62d601\
    247aeffdea95a1cad1cbdcf8e79a4ae7816177179591e922f2457b60da32038b0123cc65f5500ab4b66d1ad21a6144c539539e68adea44b985a2709dac620fa8\
    b6ed4fb84c764093cd82cee0eed128d6a615c7";

/// The ephemeral point in the recovery wrap: its bytes 1570 to 1635.
pub(crate) const KAT_RECOVERY_P256_EPH: &str = "042501f8ab261a34c40d957622fd466b476d78ded83ec02edbf814d46924f773f7683d0ddc89e5a4a992a2c29b1a29aa7f3225c9f81573bd7191f4faf8b67492\
    0b";

/// The ML-KEM share of the recovery wrap's encapsulation.
pub(crate) const KAT_RECOVERY_SS_M: &str = "0301c54d6129403a289d85770c4987403d75b0cc9a85d1d365ae5dce1232e114";

/// Its P-256 share.
pub(crate) const KAT_RECOVERY_SS_P: &str = "4d7022111460855345f262bb2360ff7dc89e9378eb925e4587cbc75de23de81a";

/// Its combined key.
pub(crate) const KAT_RECOVERY_COMBINED: &str = "5aa24ed5a5401e951ec5bd7b1de178f720d70a744c2fb6ee9d0e463c33afafc7";

/// The last 48 bytes of the recovery wrap: the sealed inner key, then its tag.
pub(crate) const KAT_RECOVERY_WRAP_BODY: &str = "7c42d9fb0cb1d849f5f7bcc4feec191b03203c25e4669d22a6cf9bd4b0b48f46c57643d7b36b68d42e06752fe7454c1a";

/// The working keys of the inner key, in the order `OpenKeys` holds them: secrets.
pub(crate) const KAT_KEY_SECRETS: &str = "b64cef0e9c40973ac8e56c6d21f390e690c14aa21c3230e101305ae3b7e5111d";

/// Logs.
pub(crate) const KAT_KEY_LOGS: &str = "f72f10afa6fce57def74bb5f27c33e6f63c7525a87da9439bafd119fec9575d3";

/// Sessions.
pub(crate) const KAT_KEY_SESSIONS: &str = "df9886b5cf27bfb4b7d00a4ed5797c7c19f9eb1351e9d114922497c58a57b33e";

/// Store.
pub(crate) const KAT_KEY_STORE: &str = "b0c291da5c2fd1556edc8a5c93d98bd6df87957327cbf8b5997c2d54080c168f";

/// Item names.
pub(crate) const KAT_KEY_ITEM_NAMES: &str = "50e1eada82bcc43d4841365ef9882ec18a64ae4804c7b9cb9356d1d148742d3d";

/// The policy signing scalar of the inner key: `derive_scalar(KEYS_ID, inner)`.
pub(crate) const KAT_POLICY_SCALAR: &str = "206e6dbcaacf33d1067ebd84447cace19da6d94ee4eeaa6a047b175f9a029a1c";

/// The policy verifying key of the inner key, 65 bytes.
pub(crate) const KAT_POLICY_VERIFY: &str = "04da6d40d78f87475ea7e745eae50d5db8cfca4b44b6828f7e0da31c11d00b59e699237ee50c4bc787787427400160a54ba7ebdddd950cdcee16252e2fb138cd\
    29";

/// `aead::seal` of the fixed key, nonce, associated data and plaintext: 37 bytes.
pub(crate) const KAT_AEAD_BLOB: &str = "01707172737475767778797a7bb2c5c87dfd2a817e6df3acee91441b3156b5b028647af844";

/// The bytes signed for the fixed policy at version 7.
pub(crate) const KAT_POLICY_MESSAGE: &str = "776f726b73706163652d7631706f6c696379101112131415161718191a1b1c1d1e1f0000000000000007616c6c6f77206e6f7468696e67";

/// Its signature. RFC 6979 gives an s in the lower half here, so nothing was changed to make it.
pub(crate) const KAT_POLICY_SIGNATURE: &str = "c934d368caedaf8c8556244a0cc94f4dc2b1bbeb4039a0cc55ec67063f3825680ab1d311e3353f8a8ca94aea61a1e1887454fbfa3902081155a299869ee0a6cf";

/// The same policy at version 8, as RFC 6979 gives it: this s is in the upper half.
pub(crate) const KAT_POLICY_8_RAW: &str = "ab8aaea15417129caea327a786072f89645496c9165268dce26a083f0df8c1d08f5bfe18282c70f6af3db921a67a1d9560801eb7bf0ddc926c298c17690f8eab";

/// And as `sign_policy` must return it: the same r, and the order less that s.
pub(crate) const KAT_POLICY_8_SIGNATURE: &str = "ab8aaea15417129caea327a786072f89645496c9165268dce26a083f0df8c1d070a401e6d7d38f0a50c246de5985e26a5c66dbf5e809c1f287903eab935396a6";

// The passphrase key and the pin of a new workspace: computed by the same independent implementation, written from the
// specification and not from this code, once it had reproduced RFC 9106's Argon2id case above and the published vectors of
// Argon2id with 64 MiB of memory in one lane.

/// The key Argon2id derives from `PASSPHRASE` under `passphrase_salt()`, with 65536 KiB, 3 passes, 1 lane, no secret and no
/// associated data: 32 bytes.
pub(crate) const KAT_PASSPHRASE_KEK: &str = "991f4d84fb7a64ff43754dbaf699e851d914c2ce93a96c0d82e4cede2d167e05";

/// The record's sealed part: `aead::seal` under that key, with `passphrase_nonce()`, of the hardware seed and the inner key's
/// commitment (`KAT_POLICY_VERIFY`), for acme under its name. 190 bytes.
pub(crate) const KAT_PASSPHRASE_SEALED: &str = "01a0a1a2a3a4a5a6a7a8a9aaabe6c2a58e61ec74b1777677701448836bb5b331dd8bed5570bd987ca23d47044e3c2d107888b896ed21affff253383f93b5910c\
    424035814120b9ced618c572162f33821be795154999dfaf1ee48a7af39a84f825e3e31e05e0ffec47043555e9ef803d41e7f6b161851ca8c0d8ffdd852ee06b\
    c53b2248900c0f3cbca5264e032aefcb6a9ee4935140bc3ae5e61edef9f24700dffa5395b412d7e6fbc39bb9d4059c987ff0bcc72eb3be86a3c936c64a9d";

/// The whole passphrase record, all 1855 bytes: its public key is the hardware seed's, its parameters are the default, and it
/// ends in `KAT_PASSPHRASE_SEALED`.
pub(crate) const KAT_PASSPHRASE_RECORD: &str = "0105014b94c29450111191823b3514c9ac1ea3d9825ccb86393a2dfb04654fa2192d37bfad1c497c6502eee5ca80a73bfce0baf5a54a88585a401397a3d232f4\
    26a7afb082bc21a44317090eaac7592c2ea88a653c4491ea193931335f52e989a3c4cc56d9c553732d57c470fb41ab759b65d2d04445382fcd9c4e344a1128fa\
    9e11e04358e192ed014b23232a7ee2b22e23717f44111ee33575399c37646da9813ec9b212afe94e5dc5c2330a7294cc1f4234a6d3fbb4f1685ab8892c04acb1\
    7cd1c170d7b0611b6a7176c794cc8c67f55fc923c2ad203100f365991882c30243d77813843b5ec7c964032263706092ecf00c7516be64e4598ca4226c069bb5\
    e67e4175cf2286c8dd5c488a6c5861f31baa0bd0269470e8b551dd3bcd38c86c12f9cdb176c77dc8b6c02a701f478902c8553f694c0d82727b4c4a5c2c104121\
    2aa1274808b82111b377ec75214e9b1978f76004d4139d98613f4b8e98d20af7b534073a509a959b7a7564f9b40ca218bf61829320a8502017954d328d7ac6c7\
    69ec29700756e7b0685b340d5e118059504a49a9a50a10198eb10a5784678eb427d7b4babb9552933b062897973e1318eaf0a0eac37584a65401b1703e042acc\
    d837531483f241cadcd1c1d378119e694429db199ac891e4c5343757085bb3ae783667350c4458d97672e861e80b1d2679510ea3a6f2360c77a46942c7a06a55\
    4d228080c84b47aef14db17620cb16c06ab30a1be4cda7082be9f87e9c211c46916349a5ba8eaa5201c7294a3c0885b53b657452108825ec646c90a04612324e\
    e7d031afe5343132cbef67b6efb1a5ec2809b773538ce77b3d8b04eb0b3c2256011e4c716c19a8ba0752bf71492117649f0615c3290fc29a46fde4bd52db9286\
    d603388244259c15a7ac2b640a60cc03376a5841a3fb8a473568fa9b1a267215f34c01697b0f0e627175d72105b7707c29b9e614bdc33a6f6c818a95370b4278\
    82d7b476796a9ec6eb993274cd9b2391a82ba45e3393d2e9ae9721ca9d6c1b988b5827713f90a6585de9433528c02b03ce10bb5f720138d0fbb4c30c1266b918\
    e52925dfe17b37f95d22bca54f475919ac859098c0f0d08ac5875ef29b56fd141e6ef15f700a0b66f39595c588177373c4669b21bc071e4c3aa5f0b4a31b6258\
    f35da24ac3cd29c7f2092410c5078355b138fb53a6b9ae6e0b9c08243e7baa45c47376eb8c7f13d4cf51aa736fa31540c9241f370da544bf9f9c28d9a57e2f2a\
    7ca95a4e4b466e641ab3bcc76adf1139d567a6f12b52f3a65e7ec0aae26bcaa8c55833b04e59998ebc9a1930fbb6d2233c53d2c1f8b9518e3c2de73a19dee6b3\
    80a5b32971cf64e129fd6c1fa6e75d4a234501e966dd3a540af5c8f4f34a6b4a253ee28492566d5e67c6f55855fcb0506fb06c156744d9a03a31a26fa94cad14\
    f157b7f303d07a69c773768fcb4d079c09059703a0c3a94de4b99ea3a2f16583d0f9170a3950db07b4f0bc30802927f9f7961b6259892636a9502a2705303637\
    799dd344da451c1cf7bf67840ceb3079ab8c6b8c1927f64053c612450c45c9e603bc16666e596b3471e103b6f15447424d17022048111ffbd37e1c670f64f14b\
    8a7b32b94c1a49b45dd2fc38cd5289d910ad63602cf5e13042c64ac6797b89fb551ad08e05a92d200cccb7e712ef23c9312cb350f029ab537e287347fd3075ac\
    10906a783f1c6c07ccb88f41228c4be1c640f790b5c3a5d5d3ca792495d74bc461562658c07ac600276b924ab5bc9be1f0494cb76f82f460a7480972663381e1\
    69996061d799859ec54d4f5ca5c411c01db1597b165977669de13a928a34afbac258fea8c4764239c9421dc3119bf5b47699206978327b1c5345ef746a798384\
    1f056e2534100ab24d4e9abbd0b17c6a95bd4c3c0e40f69e1612aceeb28b99086c95116e7204273893390bf46b899b36286b0ebf1947bb9884f732ca27da82b1\
    9b5dc0cc7f8885714910888b2310c4f9319d410b34e6433b9003e2176bb995257456106e8952163b8ba592530cc5aa0aeb43ad398fe9e97baa523d7a4431677c\
    3d3af0719e475db85ca95af5089beabeb05b2faab4896ba60f81c88472a57b46a828826a0cdfb446f8189182d2bf5eac4ec1cc5deaf599c8a13e48235406d17f\
    fddc8344b6c66984a868aa92fa02227a086950eb0c8701ed58dc628776b983882e117504333061ba04606df6bb849ac4b223f14bed83ddd8808d88c9a96af50a\
    ce61f85900e1888a8a90f593aec029df25892da20a7ac2e3eb6835f5f24c65b230a85f6e01000100000000000300000001909192939495969798999a9b9c9d9e\
    9f01a0a1a2a3a4a5a6a7a8a9aaabe6c2a58e61ec74b1777677701448836bb5b331dd8bed5570bd987ca23d47044e3c2d107888b896ed21affff253383f93b591\
    0c424035814120b9ced618c572162f33821be795154999dfaf1ee48a7af39a84f825e3e31e05e0ffec47043555e9ef803d41e7f6b161851ca8c0d8ffdd852ee0\
    6bc53b2248900c0f3cbca5264e032aefcb6a9ee4935140bc3ae5e61edef9f24700dffa5395b412d7e6fbc39bb9d4059c987ff0bcc72eb3be86a3c936c64a9d";

/// The pin's hash of a passphrase key holder's kind and its key ref, `KAT_PASSPHRASE_RECORD`, for acme.
pub(crate) const KAT_PIN_KEY_REF: &str = "2a820add3dcb9200f6ea573a92c30fd048ead4cd81eaa0c9ecb666eea9c93829c63abfe3cf0c5cf8b718b0e1eff3ee3f";

/// Its hash of the hardware seed's public key.
pub(crate) const KAT_PIN_PUBLIC_KEY: &str = "393a49ee8923b29d89c94e8ccf677a4af4a6fe14e1fbfeb0b21ad08767acb494cac8179a651174942b330b85fd393069";

/// Its hash of the name acme, the wrap `KAT_HARDWARE_WRAP`, and no manifest and no policy.
pub(crate) const KAT_PIN_STATE: &str = "ee641624346cbb163d1ffb52045fdbbeffd8071de4603e31b362858fff787da3668321f2354b2876dc51fe885a459f0b";

/// The pin at version 1 over those three hashes, all 153 bytes.
pub(crate) const KAT_PIN: &str = "0100000000000000012a820add3dcb9200f6ea573a92c30fd048ead4cd81eaa0c9ecb666eea9c93829c63abfe3cf0c5cf8b718b0e1eff3ee3f393a49ee8923b2\
    9d89c94e8ccf677a4af4a6fe14e1fbfeb0b21ad08767acb494cac8179a651174942b330b85fd393069ee641624346cbb163d1ffb52045fdbbeffd8071de4603e\
    31b362858fff787da3668321f2354b2876dc51fe885a459f0b";

// A workspace's directory record and sealed manifest: computed by an independent implementation written from the
// specification and not from this code, once it had reproduced `KAT_KEY_STORE`, `KAT_KEY_ITEM_NAMES`, `KAT_AEAD_BLOB` and
// `KAT_PIN_STATE` above. It takes `KAT_HARDWARE_WRAP` as a fixed input.

/// acme's directory record: its id, a passphrase key and a keystore of files. 19 bytes.
pub(crate) const KAT_DIR_RECORD: &str = "01101112131415161718191a1b1c1d1e1f0502";

/// The plaintext of a manifest as a release build on macOS might write it for acme: a passphrase key and a keystore of files,
/// trial, the adapters `passphrase-key` (weaker, lacking bits 0x00000007), `file-anchor` and `dir-files` (weaker, 0x00000060)
/// and `file-keystore` (weaker, 0x00000020), and every place kept for later empty. 154 bytes.
pub(crate) const KAT_MANIFEST_PLAIN: &str = "01020105020104010e706173737068726173652d6b65790200000007020b66696c652d616e63686f72020000006003096469722d66696c65730200000060040d\
    66696c652d6b657973746f7265020000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
    0000000000000000000000000000000000000000000000000000";

/// The key manifests are sealed under, from the inner key: `manifest` under `KEYS_ID`, as the working keys are derived.
pub(crate) const KAT_KEY_MANIFEST: &str = "17239b76b94d6c4490f9a6a9bcf7fc05fcb1e29aca3a000a3c9650077a7c8b20";

/// That plaintext sealed under that key with `manifest_nonce()`, for acme under its name. 183 bytes.
pub(crate) const KAT_MANIFEST: &str = "01b0b1b2b3b4b5b6b7b8b9babb0795e447db8ac0695b9bfbc82af853f46de9f07595a74847a01e21497e6a625cca47d4b6fd6796728699eccef255ea66bc1d99\
    05b5e79713a3d53fb98539621b25fa7389a82d3ad5dc23723c2c4a1987bc60ebed5059b6ca935cb129b4d53bc90708a13d8a52bbca375f97e78e4b003418989b\
    d689dcd14e59142955a93718a1227bd5b6a754330bb5f7481532f29a84ba43e667ebfe0e86d25fcf071420b48c2e8e1a24bf4cdb860526";

/// The pin's hash of the name acme, the wrap `KAT_HARDWARE_WRAP`, the manifest `KAT_MANIFEST` and no policy.
pub(crate) const KAT_WS_PIN_STATE: &str = "3ca3a22478f04fc629222efeaa6db7cd19761d2aed451f019ad8ba938df78751d66063ae03e8cb55b38f4315e73e18d8";

/// The manifest a debug build on macOS writes for acme with the adapters in memory: a key held in software (`soft-key`) and a
/// keystore in memory, trial, `soft-key`, `mem-anchor`, `mem-files` and `mem-keystore` each dev and lacking all thirteen
/// properties (0x00001fff), every place kept for later empty; sealed under the inner key with `manifest_nonce()`. 175 bytes.
pub(crate) const KAT_DEV_MANIFEST: &str = "01b0b1b2b3b4b5b6b7b8b9babb0796e446d88ac0695d98f5dd2da550e3759b9558e13d334fcd7b4c631d0f675dc950f8d7931b011efdf689a3df538003bd07ea\
    28d3910472dcba5ad4a832036f30e7709ee0475facb0a81d4e49481987bc40ebed5059b6ca935cb129b4d53bc90708a13d8a52bbca375f97e78e4b003418989b\
    d689dcd14e59142955a93718a1227bd5b6a754330bb5f7481532f29a84ba43e1e0a5cf0d0d4bc49bb6b5b247d0a447";

/// The pin's hash of the name acme, the wrap `KAT_HARDWARE_WRAP`, the manifest `KAT_DEV_MANIFEST` and no policy: the state of
/// acme's first pin when a debug build makes it with a key held in software.
pub(crate) const KAT_DEV_PIN_STATE: &str = "623c145f562b8922a6892b431050eda1a041e0f191e4536cb94a32e37199d422d48fb2e991eacd4e0911f14e42791d4c";
