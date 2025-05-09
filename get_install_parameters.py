#!/usr/bin/env python

import argparse
import base64

if __name__ == '__main__':
    parser = argparse.ArgumentParser("get_install_parameters",
                                     description="Return parameters for installing FIDO2Applet with custom settings")
    parser.add_argument('--enable-attestation', action='store_true', default=None,
                        help="Allows loading an attestation certificate after installing the applet")
    parser.add_argument('--high-security', action='store_true', default=None,
                        help="Does not comply with the FIDO standards, but protects credentials against bugs or "
                             "faulty authenticator hardware. Implies high-security RKs.")
    parser.add_argument('--force-always-uv', action='store_true', default=None,
                        help="Requires the PIN for all operations, always")
    parser.add_argument('--high-security-rks', action='store_true', default=None,
                        help="Protects discoverable credentials against bugs and faulty authenticator hardware, "
                             "at the cost of standards compliance")
    parser.add_argument('--protect-against-reset', action='store_true', default=None,
                        help="Require sending a reset command twice, across two power cycles, to truly reset "
                             "the authenticator")
    parser.add_argument('--kdf-iterations', type=int, default=5,
                        help="Number of iterations of the Key Derivation Function used. Protects against "
                             "brute-force attacks against the PIN (when authenticator hardware is faulty), "
                             "at the cost of performance")
    parser.add_argument('--max-cred-blob-len', type=int, default=32,
                        help="Maximum length of the blob stored with every discoverable credential. Must be >=32")
    parser.add_argument('--large-blob-store-size', type=int, default=1024,
                        help="Length of the large blob array in flash memory. Must be >=1024")
    parser.add_argument('--max-rk-rp-length', type=int, default=32,
                        help="Number of bytes of the relying party identifier stored with each RK. Must be >=32")
    parser.add_argument('--max-ram-scratch', type=int, default=254,
                        help="Number of bytes of RAM to use for working memory. Reduces flash wear.")
    parser.add_argument('--buffer-mem', type=int, default=1024,
                        help="Number of bytes of RAM to use for request processing. Reduces flash wear. Must be >=1024")
    parser.add_argument('--flash-scratch', type=int, default=1024,
                        help="Number of bytes of flash to use when RAM is exhausted. For low-memory situations.")
    parser.add_argument('--do-not-store-pin-length', action='store_false', default=None,
                        help="Avoid storing the length of the user PIN internally. Causes setMinPin to force a PIN "
                             "change")
    parser.add_argument('--cache-pin-token', action='store_false', default=None,
                        help="Allow a PIN token to be potentially used multiple times, within its permissions")
    parser.add_argument('--multiple-writes-per-pin-token', action='store_false', default=None,
                        help="In combination with --cache-pin-token, will allow many reads but only one write/use per "
                             "time obtaining the PIN token")
    parser.add_argument('--certification-level', type=int, default=None,
                        help="Obtained FIDO Alliance certification level")
    parser.add_argument('--attestation-private-key',
                        help="Base64-encoded RAW (32 byte) private key for attestation certificate. Implies --enable-attestation"),
    parser.add_argument('--disable-pin-set',
                        help="Prevent pins from being set on authenticator.", action='store_true', default=None),
    parser.add_argument('--disable-reset',
                        help="Prevent authenticator from being reset.", action='store_true', default=None)

    args = parser.parse_args()

    if args.buffer_mem < 1024:
        parser.error("CTAP standards require at least 1024 bytes of request/response buffer memory")

    if args.large_blob_store_size < 1024 or args.large_blob_store_size > 2048:
        parser.error("Large blob store size must be between 1024 and 2048 bytes")

    if args.max_cred_blob_len < 32 or args.max_cred_blob_len > 255:
        parser.error("Cred blob len must be between 32 and 255 bytes")

    if args.max_rk_rp_length < 32 or args.max_rk_rp_length > 255:
        parser.error("The RP length stored for each RK must be between 32 and 255 bytes")

    if args.attestation_private_key is not None:
        args.enable_attestation = True
        args.attestation_private_key = base64.b64decode(args.attestation_private_key)

    num_options_set = 0
    install_param_bytes = []
    for option_number, option_string in enumerate([
        'enable_attestation',
        'high_security',
        'force_always_uv',
        'high_security_rks',
        'protect_against_reset',
        'kdf_iterations',
        'max_cred_blob_len',
        'large_blob_store_size',
        'max_rk_rp_length',
        'max_ram_scratch',
        'buffer_mem',
        'flash_scratch',
        'do_not_store_pin_length',
        'cache_pin_token',
        'certification_level',
        'attestation_private_key',
        'multiple_writes_per_pin_token',
        'disable_pin_set',
        'disable_reset'
    ]):
        val = getattr(args, option_string)
        if val is None:
            continue
        num_options_set += 1

        bytes_for_option = []
        if val is True:
            bytes_for_option = [0xF5]
        elif val is False:
            bytes_for_option = [0xF4]
        elif isinstance(val, bytes):
            if len(val) <= 23:
                bytes_for_option = [0x40 + len(val)]
            elif len(val) <= 255:
                bytes_for_option = [0x58, len(val)]
            else:
                bytes_for_option = [0x59, (len(val) & 0xFF00) >> 8, len(val) & 0x00FF]
            bytes_for_option += [int(x) for x in val]
        else:
            if val <= 23:
                bytes_for_option = [val]
            elif val <= 255:
                bytes_for_option = [0x18, val]
            else:
                bytes_for_option = [0x19, (val & 0xFF00) >> 8, val & 0x00FF]

        install_param_bytes += [option_number] + bytes_for_option

    install_param_bytes = [0xA0 + num_options_set] + install_param_bytes
    print(bytes(install_param_bytes).hex())
