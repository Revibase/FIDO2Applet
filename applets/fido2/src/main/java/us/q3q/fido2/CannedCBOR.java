package us.q3q.fido2;

/**
 * Pre-packed CBOR objects for convenience and speed
 */
public abstract class CannedCBOR {
    static final byte[] FIDO_2_RESPONSE = {
            0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30
          //   F     I     D     O     _     2     _     0
    };
    static final byte[] U2F_V2_RESPONSE = {
            0x55, 0x32, 0x46, 0x5F, 0x56, 0x32
          //   U     2     F     _     V     2
    };

    static final byte[] VERSIONS_WITH_U2F = {
            (byte) 0x82, // array - two items
                0x66, // string - six bytes long
                    0x55, 0x32, 0x46, 0x5F, 0x56, 0x32, // U2F_V2
                0x68, // string - eight bytes long
                    0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30, // FIDO_2_0
    };

    /** getInfo versions when U2F is not yet provisioned (no attestation certificate). */
    static final byte[] VERSIONS_WITHOUT_U2F = {
            (byte) 0x81, // array - one item
                0x68, // string - eight bytes long
                    0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30, // FIDO_2_0
    };

    /** getInfo map key 0x03 (aaguid) preamble: 16-byte byte string follows */
    static final byte[] AUTH_INFO_LITE_AAGUID = {
            0x03, // map key: aaguid
            0x50, // byte string, 16 bytes long
    };

    /**
     * getInfo map key 0x04 (options): rk/up true. uv and clientPin are absent, not false:
     * per CTAP2.0, present-but-false means "supported but not configured", which would
     * invite platforms to try SetPIN / built-in UV that this authenticator cannot do.
     */
    static final byte[] AUTH_INFO_LITE_OPTIONS = {
            0x04, // map key: options
            (byte) 0xA2, // map: two entries
                0x62, // string: two bytes long
                    0x72, 0x6B, // rk
                    (byte) 0xF5, // true
                0x62, // string: two bytes long
                    0x75, 0x70, // up
                    (byte) 0xF5, // true (NFC tap satisfies user presence)
    };

    static final byte[] MAKE_CREDENTIAL_RESPONSE_PREAMBLE = {
                0x01, // map key: fmt
                    0x66, // string - six bytes long
                    0x70, 0x61, 0x63, 0x6B, 0x65, 0x64, // packed
                0x02, // map key: authData
    };
    static final byte[] PUBLIC_KEY_ALG_PREAMBLE = {
            (byte) 0xA5, // map - five entries
                0x01, // map key: kty
                    0x02, // integer (2) - means EC2, a two-point elliptic curve key
                0x03, // map key: alg
                    0x26, // integer (-7) - means ES256 algorithm
                0x20, // map key: crv
                    0x01, // integer (1) - means P256 curve
                0x21, // map key: x-point
                    0x58, // byte string with one-byte length next
                        0x20 // 32 bytes long
    };
    static final byte[] SELF_ATTESTATION_STATEMENT_PREAMBLE = {
            0x03, // map key: attestation statement
            (byte) 0xA2, // map - two entries
                    0x63, // string - three bytes long
                        0x61, 0x6C, 0x67, // alg
                        0x26, // integer (-7) - means ES256 algorithm
                    0x63, // string: three characters
                        0x73, 0x69, 0x67, // sig
    };

    static final byte[] BASIC_ATTESTATION_STATEMENT_PREAMBLE = {
            0x03, // map key: attestation statement
            (byte) 0xA3, // map - three entries
                0x63, // string - three bytes long
                    0x61, 0x6C, 0x67, // alg
                    0x26, // integer (-7) - means ES256 algorithm
                0x63, // string: three characters
                    0x73, 0x69, 0x67, // sig
    };

    static final byte[] X5C = {
            0x63, // string: three characters
                0x78, 0x35, 0x63, // x5c
    };

    static final byte[] SINGLE_ID_MAP_PREAMBLE = {
            (byte) 0xA1, // map: one entry
                0x62, // string - two bytes long
                    0x69, 0x64, // id
    };

    static final byte[] PUBLIC_KEY_TYPE = {
            0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79
          //   p     u     b     l     i     c     -     k     e     y
    };

    static final byte[] ES256_ALG_TYPE = {
            (byte) 0x81, // array - one item
                (byte) 0xA2, // map - two entries
                    0x63, // string - three bytes long
                        0x61, 0x6C, 0x67, // alg
                        0x26, // -7 (alg ID for ES256)
                    0x64, // string - four bytes long
                        0x74, 0x79, 0x70, 0x65, // type
                        0x6A, // string - ten bytes long
                            0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, // public-key
    };
}
