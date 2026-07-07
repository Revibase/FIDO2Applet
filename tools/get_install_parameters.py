#!/usr/bin/env python

import argparse
import base64

# CBOR install map keys understood by the slim FIDO2Applet constructor.
INSTALL_OPTIONS = [
    ("enable_attestation", 0x00, "bool"),
    ("max_ram_scratch", 0x09, "int"),
    ("buffer_mem", 0x0A, "int"),
    ("flash_scratch", 0x0B, "int"),
    ("attestation_private_key", 0x0F, "bytes"),
]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        "get_install_parameters",
        description="Return CBOR install parameters for the slim FIDO2Applet",
    )
    parser.add_argument('--enable-attestation', action='store_true', default=None,
                        help="Allow loading an attestation certificate after install")
    parser.add_argument('--max-ram-scratch', type=int, default=None,
                        help="RAM working memory size (bytes)")
    parser.add_argument('--buffer-mem', type=int, default=None,
                        help="Request/response buffer size (bytes, min 1024). Prefer card RAM; "
                             "flash fallback increases EEPROM wear on heavy CTAP use.")
    parser.add_argument('--flash-scratch', type=int, default=None,
                        help="Flash scratch when RAM is exhausted (bytes). Keep as small as testAll "
                             "allows; each CTAP op may rewrite these cells.")
    parser.add_argument('--attestation-private-key',
                        help="Base64-encoded 32-byte attestation private key (implies --enable-attestation)")

    args = parser.parse_args()

    if args.buffer_mem is not None and args.buffer_mem < 1024:
        parser.error("CTAP requires at least 1024 bytes of buffer memory")

    if args.attestation_private_key is not None:
        args.enable_attestation = True
        args.attestation_private_key = base64.b64decode(args.attestation_private_key)

    install_param_bytes = []
    num_options_set = 0

    for arg_name, option_key, kind in INSTALL_OPTIONS:
        val = getattr(args, arg_name)
        if val is None:
            continue
        num_options_set += 1

        if kind == "bool":
            bytes_for_option = [0xF5 if val else 0xF4]
        elif kind == "bytes":
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

        install_param_bytes += [option_key] + bytes_for_option

    install_param_bytes = [0xA0 + num_options_set] + install_param_bytes
    print(bytes(install_param_bytes).hex())
