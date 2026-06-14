import copy
import secrets

from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.webauthn import Aaguid

from .ctap_test import CTAPTestCase


class CTAPBasicsTestCase(CTAPTestCase):
    def test_info_supported_versions(self):
        info = self.ctap2.get_info()
        self.assertEqual(["FIDO_2_0", "FIDO_2_1", "FIDO_2_1_PRE"], info.versions)

    def test_info_supported_extensions(self):
        info = self.ctap2.get_info()
        self.assertEqual([], info.extensions)

    def test_info_supported_options(self):
        info = self.ctap2.get_info()
        self.assertEqual({
            "alwaysUv": False,
            "clientPin": False,
            "rk": True,
            "up": False,
        }, info.options)

    def test_info_aaguid_none(self):
        info = self.ctap2.get_info()
        self.assertEqual(Aaguid.NONE, info.aaguid)

    def test_info_supported_algs_hint(self):
        info = self.ctap2.get_info()
        self.assertEqual([{'alg': -7, "type": "public-key"}], info.algorithms)

    def test_extreme_makecred_input(self):
        self.basic_makecred_params['user'] = {
            'id': secrets.token_bytes(32),
            'name': secrets.token_hex(10),
            'display_name': secrets.token_hex(100),
            'icon': secrets.token_hex(120)
        }
        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_make_credential_requires_rk(self):
        params = copy.copy(self.basic_makecred_params)
        params['options'] = {'rk': False}
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params)
        self.assertEqual(CtapError.ERR.INVALID_OPTION, ctx.exception.code)

    def test_make_credential_self_attestation(self):
        rp_id = secrets.token_hex(50)
        self.basic_makecred_params['rp']['id'] = rp_id
        res = self.ctap2.make_credential(**self.basic_makecred_params)

        self.assertIsNone(res.ep_att)
        self.assertIsNone(res.auth_data.extensions)
        self.assertIsNotNone(res.att_stmt)
        self.assertIsNone(res.att_stmt.get('x5c'))
        self.assertEqual(res.auth_data.FLAG.ATTESTED, res.auth_data.flags)
        self.assertEqual(self.rp_id_hash(rp_id), res.auth_data.rp_id_hash)
        self.assertEqual(ES256.ALGORITHM, res.att_stmt['alg'])
        self.assertIsNotNone(res.att_stmt['sig'])
        self.assertEqual(Aaguid.NONE, res.auth_data.credential_data.aaguid)
        pubkey = res.auth_data.credential_data.public_key
        pubkey.verify(res.auth_data + self.client_data, res.att_stmt['sig'])
        self.assertEqual(112, len(res.auth_data.credential_data.credential_id))

    def test_get_assertion_handles_nesting(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        self.ctap2.get_assertion(
            rp_id=self.rp_id,
            allow_list=[{
                "type": "public-key",
                "id": cred.auth_data.credential_data.credential_id,
                "transports": {"something": [1, 2, 3, 4]},
            }],
            client_data_hash=secrets.token_bytes(32),
        )

    def test_get_assertion_handles_extraneous_stuff(self):
        cred = self.ctap2.make_credential(**self.basic_makecred_params)
        self.ctap2.get_assertion(
            rp_id=self.rp_id,
            allow_list=[{
                "type": "public-key",
                "id": cred.auth_data.credential_data.credential_id,
                "transports": ["usb", "nfc", "ble"],
            }],
            client_data_hash=secrets.token_bytes(32),
            extensions={"txAuthSimple": "Execute order 66."},
        )

    def test_counter_increases_on_get_assertion(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        assert_res = self.get_assertion(
            rp_id=self.rp_id,
            client_data=self.get_random_client_data(),
            allow_list=[],
        )
        self.assertTrue(assert_res.auth_data.counter > cred_res.auth_data.counter)

    def test_second_makecredential_same_params_rejected(self):
        self.ctap2.make_credential(**self.basic_makecred_params)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.LIMIT_EXCEEDED, ctx.exception.code)

    def test_makecred_disallowed_by_exclude_list(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        params = copy.copy(self.basic_makecred_params)
        params['exclude_list'] = [self.get_allow_list_entry_from_ll_cred(cred_res)]
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**params)
        self.assertEqual(CtapError.ERR.CREDENTIAL_EXCLUDED, ctx.exception.code)

    def test_accepts_long_utf8_display_name(self):
        self.basic_makecred_params['user']['display_name'] = "猫" * 144
        self.ctap2.make_credential(**self.basic_makecred_params)

    def test_makecred_rk_max_len_user_id(self):
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(64)
        self.ctap2.make_credential(**self.basic_makecred_params)
        assert_res = self.get_assertion(rp_id=self.rp_id)
        self.assertEqual(self.basic_makecred_params['user']['id'], assert_res.user['id'])

    def test_stale_allowlist_falls_back_to_resident_key(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        stale_id = secrets.token_bytes(len(cred_res.auth_data.credential_data.credential_id))
        assert_res = self.get_assertion_from_cred(
            cred_res,
            client_data=self.get_random_client_data(),
            base_allow_list=[{
                "type": "public-key",
                "id": stale_id,
            }],
        )
        self.assertEqual(
            cred_res.auth_data.credential_data.credential_id,
            assert_res.credential['id'],
        )

    def test_ignored_allowlist_entry_falls_back(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        assert_res = self.get_assertion_from_cred(
            cred_res,
            client_data=self.get_random_client_data(),
            base_allow_list=[{"type": "bogus", "id": secrets.token_bytes(5)}],
        )
        self.assertEqual(
            cred_res.auth_data.credential_data.credential_id,
            assert_res.credential['id'],
        )

    def test_counter_increases_on_assert(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        assert_res_1 = self.get_assertion_from_cred(cred_res, client_data=self.get_random_client_data())
        assert_res_2 = self.get_assertion_from_cred(cred_res, client_data=self.get_random_client_data())
        self.assertTrue(assert_res_1.auth_data.counter > cred_res.auth_data.counter)
        self.assertTrue(assert_res_2.auth_data.counter > assert_res_1.auth_data.counter)

    def test_basic_assertion(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        assert_client_data = self.get_random_client_data()
        assert_res = self.get_assertion_from_cred(cred_res, client_data=assert_client_data)
        self.assertEqual(cred_res.auth_data.credential_data.credential_id, assert_res.credential['id'])
        self.assertEqual(self.basic_makecred_params['user']['id'], assert_res.user['id'])
        cred_res.auth_data.credential_data.public_key.verify(
            assert_res.auth_data + assert_client_data, assert_res.signature
        )

    def test_wrong_allowlist_still_asserts_resident_key(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        wrong_id = secrets.token_bytes(len(cred_res.auth_data.credential_data.credential_id))
        assert_client_data = self.get_random_client_data()
        assert_res = self.ctap2.get_assertion(
            client_data_hash=assert_client_data,
            allow_list=[self.get_mapping_from_cred_id(wrong_id)],
            rp_id=self.rp_id,
        )
        self.assertEqual(cred_res.auth_data.credential_data.credential_id, assert_res.credential['id'])
        cred_res.auth_data.credential_data.public_key.verify(
            assert_res.auth_data + assert_client_data, assert_res.signature
        )

    def test_empty_allowlist_uses_resident_key(self):
        self.ctap2.make_credential(**self.basic_makecred_params)
        assert_res = self.get_assertion(
            rp_id=self.rp_id,
            client_data=self.get_random_client_data(),
            allow_list=[],
        )
        self.assertEqual(self.basic_makecred_params['user']['id'], assert_res.user['id'])

    def test_non_matching_rp(self):
        cred_res = self.ctap2.make_credential(**self.basic_makecred_params)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.get_assertion(
                rp_id='___different',
                client_data_hash=self.get_random_client_data(),
                allow_list=[self.get_mapping_from_cred_id(
                    cred_res.auth_data.credential_data.credential_id
                )],
            )
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, ctx.exception.code)

    def test_make_credential_with_bogus_extension(self):
        res = self.ctap2.make_credential(
            **self.basic_makecred_params,
            extensions={"bogosity": True},
        )
        self.assertEqual(None, res.auth_data.extensions)

    def test_second_resident_same_rp_different_user_rejected(self):
        self.ctap2.make_credential(**self.basic_makecred_params)
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(16)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.LIMIT_EXCEEDED, ctx.exception.code)

    def test_second_resident_different_rp_rejected(self):
        self.ctap2.make_credential(**self.basic_makecred_params)
        self.basic_makecred_params['rp']['id'] = secrets.token_hex(8) + ".example.com"
        self.basic_makecred_params['user']['id'] = secrets.token_bytes(16)
        with self.assertRaises(CtapError) as ctx:
            self.ctap2.make_credential(**self.basic_makecred_params)
        self.assertEqual(CtapError.ERR.LIMIT_EXCEEDED, ctx.exception.code)
