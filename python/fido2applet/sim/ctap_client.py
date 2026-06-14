import abc
import random
import secrets
from datetime import datetime, timedelta
from typing import Any, Callable, Iterator, List, Mapping, Optional, Type

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from fido2 import cbor
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.cose import ES256
from fido2.ctap import CtapDevice
from fido2.ctap2 import AssertionResponse, AttestationResponse, Ctap2
from fido2.ctap2.base import args
from fido2.ctap2.extensions import Ctap2Extension
from fido2.pcsc import CtapPcscDevice
from fido2.webauthn import (
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from fido2applet.sim.jcardsim import FakeSCConnection, JCardSimTestCase, TestModes


class CTAPTestCase(JCardSimTestCase, abc.ABC):
    VIRTUAL_DEVICE_NAME = "Virtual PCD"
    device: CtapDevice
    ctap2: Ctap2
    client_data: bytes
    rp_id: str
    basic_makecred_params: dict[str, Any]
    USE_EXT_APDU = False

    def setUp(self, install_params: Optional[bytes] = None) -> None:
        self.basic_makecred_params = {
            "rp": {},
            "user": {},
            "key_params": [
                {
                    "type": "public-key",
                    "alg": ES256.ALGORITHM
                }
            ],
            "options": {
                "rk": True
            },
        }
        if install_params is None:
            install_params = bytes([0xA1, 0x00, 0xF5])
        super().setUp(install_params)
        if self.MODE == TestModes.PCSC:
            devs = list(CtapPcscDevice.list_devices(self.VIRTUAL_DEVICE_NAME))
            assert 1 == len(devs)
            self.device = devs[0]
        else:
            self.device = CtapPcscDevice(
                FakeSCConnection(self.q_in, self.q_out),
                'fake_device'
            )

        if self.USE_EXT_APDU:
            self.device.use_ext_apdu = True

        self.ctap2 = Ctap2(self.device)
        self.client_data = self.get_random_client_data()
        self.basic_makecred_params["client_data_hash"] = self.client_data
        rpid_length = random.randint(1, 30)
        self.rp_id = secrets.token_hex(rpid_length)
        self.basic_makecred_params['rp']['id'] = self.rp_id
        userid_length = random.randint(1, 64)
        username_length = random.randint(2, 64)
        dn_length = random.randint(0, 20)
        icon_length = random.randint(0, 10)
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(userid_length)
        self.basic_makecred_params['user']['name'] = secrets.token_hex(int(username_length / 2))
        if dn_length > 0:
            self.basic_makecred_params['user']['display_name'] = secrets.token_hex(dn_length)
        if icon_length > 0:
            self.basic_makecred_params['user']['icon'] = secrets.token_hex(icon_length)

    @classmethod
    def rp_id_hash(cls, rp_id: str) -> bytes:
        digester = hashes.Hash(hashes.SHA256())
        digester.update(rp_id.encode())
        return digester.finalize()

    @classmethod
    def get_random_client_data(cls) -> bytes:
        return secrets.token_bytes(32)

    def reset(self):
        self.ctap2.reset()

    def get_assertion_from_cred(self, cred: Optional[AttestationResponse],
                                rp_id: Optional[str] = None,
                                client_data: Optional[bytes] = None,
                                base_allow_list=None,
                                **kwargs) -> AssertionResponse:
        allow_list = kwargs.pop('allow_list', None)
        if allow_list is None:
            allow_list = [] if base_allow_list is None else list(base_allow_list)
        if cred is not None:
            allow_list.append({
                "type": "public-key",
                "id": cred.auth_data.credential_data.credential_id
            })
        if rp_id is None:
            rp_id = self.rp_id
        if client_data is None:
            client_data = self.client_data
        return self.ctap2.get_assertion(
            rp_id=rp_id,
            client_data_hash=client_data,
            allow_list=allow_list,
            **kwargs
        )

    def get_assertion(self, rp_id: str, client_data: Optional[bytes] = None, **kwargs):
        if client_data is None:
            client_data = self.client_data
        kwargs.pop('client_data_hash', None)
        return self.get_assertion_from_cred(cred=None, rp_id=rp_id, client_data=client_data, **kwargs)

    def get_high_level_client(self, extensions: Optional[list[Ctap2Extension]] = None,
                              user_interaction: UserInteraction = None,
                              origin: str = None) -> Fido2Client:
        if extensions is None:
            extensions = []
        if user_interaction is None:
            user_interaction = UserInteraction()
        if origin is None:
            origin = 'https://' + self.rp_id

        collector = DefaultClientDataCollector(origin=origin)

        return Fido2Client(
            self.device,
            collector,
            extensions=extensions,
            user_interaction=user_interaction
        )

    def get_high_level_make_cred_options(self,
                                         resident_key: ResidentKeyRequirement = ResidentKeyRequirement.DISCOURAGED,
                                         extensions=None, rp_id: Optional[str] = None, rp_stuff: Optional[dict] = None,
                                         user_stuff: Optional[dict] = None,
                                         client_data: Optional[bytes] = None,
                                         user_verification: Optional[UserVerificationRequirement] = None,
                                         user_id: Optional[bytes] = None) -> PublicKeyCredentialCreationOptions:
        if extensions is None:
            extensions = {}

        if client_data is None:
            client_data = self.client_data

        if rp_id is None:
            rp_id = self.rp_id

        if user_verification is None:
            user_verification = UserVerificationRequirement.DISCOURAGED

        if rp_stuff is None:
            rp_stuff = {
                "name": "An RP Name",
                "id": rp_id
            }

        if user_stuff is None:
            if user_id is None:
                user_id = self.basic_makecred_params['user']['id']

            user_stuff = {
                "name": self.basic_makecred_params['user']['name'],
                "id": user_id
            }

        return PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(**rp_stuff),
            user=PublicKeyCredentialUserEntity(**user_stuff),
            challenge=client_data,
            pub_key_cred_params=[
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    alg=ES256.ALGORITHM
                )
            ],
            extensions=extensions,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=resident_key,
                user_verification=user_verification
            )
        )

    def get_descriptor_from_cred_id(self, cred_id: bytes) -> PublicKeyCredentialDescriptor:
        return PublicKeyCredentialDescriptor(
            **self.get_mapping_from_cred_id(cred_id)
        )

    def get_descriptor_from_cred(self, cred: AuthenticatorAttestationResponse) -> PublicKeyCredentialDescriptor:
        return self.get_descriptor_from_cred_id(cred.attestation_object.auth_data.credential_data.credential_id)

    def get_allow_list_entry_from_cred(self, cred: AuthenticatorAttestationResponse) -> Mapping[str, Any]:
        return self.get_mapping_from_cred_id(cred.attestation_object.auth_data.credential_data.credential_id)

    def get_mapping_from_cred_id(self, cred_id: bytes) -> Mapping[str, Any]:
        return {
            'type': PublicKeyCredentialType.PUBLIC_KEY,
            'id': cred_id
        }

    def get_allow_list_entry_from_ll_cred(self, cred: AttestationResponse) -> Mapping[str, Any]:
        return self.get_mapping_from_cred_id(cred.auth_data.credential_data.credential_id)

    def get_descriptor_from_ll_cred(self, cred: AttestationResponse) -> PublicKeyCredentialDescriptor:
        return self.get_descriptor_from_cred_id(cred.auth_data.credential_data.credential_id)

    def get_high_level_assertion_opts_from_cred(self, cred: Optional[AuthenticatorAttestationResponse] = None,
                                                client_data: Optional[bytes] = None, rp_id: Optional[str] = None,
                                                extensions: Optional[
                                                    dict[str, Any]] = None,
                                                user_verification: Optional[
                                                    UserVerificationRequirement] = None) -> PublicKeyCredentialRequestOptions:
        if extensions is None:
            extensions = {}
        if client_data is None:
            client_data = self.client_data
        if rp_id is None:
            rp_id = self.rp_id
        assertion_allow_credentials = []
        if cred is not None:
            assertion_allow_credentials = [
                self.get_descriptor_from_cred(cred)
            ]
        if user_verification is None:
            user_verification = UserVerificationRequirement.DISCOURAGED
        return PublicKeyCredentialRequestOptions(
            challenge=client_data,
            rp_id=rp_id,
            allow_credentials=assertion_allow_credentials,
            user_verification=user_verification,
            extensions=extensions
        )


class BasicAttestationTestCase(CTAPTestCase):
    VENDOR_COMMAND_SWITCH_ATT = 0x46
    USE_EXT_APDU = True

    public_key: EllipticCurvePublicKey
    ca_public_key: EllipticCurvePublicKey
    aaguid: bytes
    cert: bytes

    def install_attestation_cert(self, **kwargs):
        cert = self.gen_attestation_cert(**kwargs)
        self.ctap2.send_cbor(
            self.VENDOR_COMMAND_SWITCH_ATT,
            args(cert)
        )

    def _short_to_bytes(self, b: int) -> list[int]:
        return [(b & 0xFF00) >> 8, b & 0x00FF]

    def gen_authenticator_cert_from_ca(self, name: str,
                                       ca_name: x509.Name,
                                       ca_privkey: EllipticCurvePrivateKey,
                                       country: Optional[str] = "US",
                                       org: Optional[str] = "ACME",
                                       ) -> bytes:
        now = datetime.now()

        this_cert_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])

        authenticator_cert_bytes = (
            x509.CertificateBuilder()
            .subject_name(this_cert_name)
            .issuer_name(ca_name)
            .serial_number(x509.random_serial_number())
            .public_key(self.public_key)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            .sign(private_key=ca_privkey, algorithm=hashes.SHA256())
            .public_bytes(Encoding.DER)
        )

        return authenticator_cert_bytes

    def get_ca_cert(self, org: str) -> tuple[bytes, bytes]:
        now = datetime.now()

        ca_privkey = ec.generate_private_key(ec.SECP256R1())
        ca_pubkey = ca_privkey.public_key()
        self.ca_public_key = ca_pubkey

        ca_name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, "AuthCA"),
        ])
        return ca_privkey, (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .serial_number(x509.random_serial_number())
            .public_key(ca_pubkey)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .sign(private_key=ca_privkey, algorithm=hashes.SHA256())
            .public_bytes(Encoding.DER)
        )

    def get_x509_certs(self, private_key: Optional[EllipticCurvePrivateKey] = None,
                       public_key: Optional[EllipticCurvePublicKey] = None, name: Optional[str] = None,
                       country: Optional[str] = "US", org: Optional[str] = "ACME",
                       ca_privkey_and_cert: Optional[tuple[bytes, bytes]] = None) -> list[bytes]:
        if public_key is None and private_key is None:
            raise ValueError("Either public or private key must be passed to get_x509_certs")

        if private_key is not None:
            self.public_key = private_key.public_key()
        else:
            self.public_key = public_key

        if name is None:
            name = secrets.token_hex(4)

        if ca_privkey_and_cert is None:
            ca_privkey_and_cert = self.get_ca_cert(org)

        ca_privkey, ca_cert_bytes = ca_privkey_and_cert

        loaded_cacert = x509.load_der_x509_certificate(ca_cert_bytes)
        ca_name = loaded_cacert.subject

        authenticator_cert_bytes = self.gen_authenticator_cert_from_ca(
            name=name,
            ca_name=ca_name,
            ca_privkey=ca_privkey,
            country=country,
            org=org
        )

        return [authenticator_cert_bytes, ca_cert_bytes]

    def assemble_cbor_from_attestation_certs(self, private_key: Optional[bytes], cert_bytes: list[bytes],
                                             aaguid: bytes) -> bytes:
        num_certs = len(cert_bytes)
        self.cert = cert_bytes[0]
        cert_cbor = cbor.encode(cert_bytes)

        if private_key is not None:
            s = private_key.private_numbers().private_value
            private_bytes = s.to_bytes(length=32, byteorder='big')
            self.assertEqual(32, len(private_bytes))
        else:
            private_bytes = bytes()
        cbor_len_bytes = bytes(self._short_to_bytes(len(cert_cbor)))
        res = aaguid + private_bytes + cbor_len_bytes + cert_cbor
        return res

    def gen_attestation_cert(self, cert_bytes: Optional[list[bytes]] = None, name: Optional[str] = None,
                             aaguid: Optional[bytes] = None,
                             public_key: Optional[EllipticCurvePrivateKey] = None) -> bytes:
        if aaguid is None:
            aaguid = secrets.token_bytes(16)

        self.aaguid = aaguid
        if public_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = None
        else:
            private_key = None
            public_key = public_key

        if cert_bytes is None:
            cert_bytes = self.get_x509_certs(private_key=private_key, name=name, public_key=public_key)

        return self.assemble_cbor_from_attestation_certs(private_key=private_key,
                                                         cert_bytes=cert_bytes,
                                                         aaguid=aaguid)
