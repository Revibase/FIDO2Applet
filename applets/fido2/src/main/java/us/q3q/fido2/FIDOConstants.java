package us.q3q.fido2;

/**
 * Constants defined by the FIDO specifications
 */
public abstract class FIDOConstants {
    // Command byte values
    public static final byte CMD_MAKE_CREDENTIAL = 0x01;
    public static final byte CMD_GET_ASSERTION = 0x02;
    public static final byte CMD_GET_INFO = 0x04;

    /**
     * "Vendor" command, non-FIDO-standard: install attestation certificates
     */
    public static final byte CMD_INSTALL_CERTS = 0x46;

    // Error (and OK) responses
    public static final byte CTAP2_OK = 0x00;
    public static final byte CTAP1_ERR_INVALID_COMMAND = 0x01;
    public static final byte CTAP1_ERR_INVALID_PARAMETER = 0x02;
    public static final byte CTAP1_ERR_INVALID_LENGTH = 0x03;
    public static final byte CTAP1_ERR_INVALID_SEQ = 0x04;
    public static final byte CTAP1_ERR_TIMEOUT = 0x05;
    public static final byte CTAP1_ERR_CHANNEL_BUSY = 0x06;
    public static final byte CTAP1_ERR_LOCK_REQUIRED = 0x0A;
    public static final byte CTAP1_ERR_INVALID_CHANNEL = 0x0B;
    public static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11;
    public static final byte CTAP2_ERR_INVALID_CBOR = 0x12;
    public static final byte CTAP2_ERR_MISSING_PARAMETER = 0x14;
    public static final byte CTAP2_ERR_LIMIT_EXCEEDED = 0x15;
    public static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19;
    public static final byte CTAP2_ERR_PROCESSING = 0x21;
    public static final byte CTAP2_ERR_INVALID_CREDENTIAL = 0x22;
    public static final byte CTAP2_ERR_USER_ACTION_PENDING = 0x23;
    public static final byte CTAP2_ERR_OPERATION_PENDING = 0x24;
    public static final byte CTAP2_ERR_NO_OPERATIONS = 0x25;
    public static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26;
    public static final byte CTAP2_ERR_OPERATION_DENIED = 0x27;
    public static final byte CTAP2_ERR_KEY_STORE_FULL = 0x28;
    public static final byte CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B;
    public static final byte CTAP2_ERR_INVALID_OPTION = 0x2C;
    public static final byte CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D;
    public static final byte CTAP2_ERR_NO_CREDENTIALS = 0x2E;
    public static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F;
    public static final byte CTAP2_ERR_NOT_ALLOWED = 0x30;
    public static final byte CTAP2_ERR_REQUEST_TOO_LARGE = 0x39;
    public static final byte CTAP2_ERR_ACTION_TIMEOUT = 0x3A;
    public static final byte CTAP2_ERR_UP_REQUIRED = 0x3B;
    public static final byte CTAP2_ERR_INTEGRITY_FAILURE = 0x3D;
    public static final byte CTAP2_ERR_INVALID_SUBCOMMAND = 0x3E;
    public static final byte CTAP1_ERR_OTHER = 0x7F;
}
