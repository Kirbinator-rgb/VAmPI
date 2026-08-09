import unittest
from unittest.mock import patch

from config import load_jwt_secret, vuln_app


class JwtSecretTest(unittest.TestCase):
    def test_configured_secret_must_be_at_least_32_bytes(self):
        with patch.dict('os.environ', {'VAMPI_JWT_SECRET': 'short'}, clear=True):
            with self.assertRaises(RuntimeError):
                load_jwt_secret()

    def test_configured_secret_is_loaded_from_environment(self):
        configured_secret = 'a' * 32

        with patch.dict('os.environ',
                        {'VAMPI_JWT_SECRET': configured_secret}, clear=True):
            self.assertEqual(load_jwt_secret(), configured_secret)

    def test_missing_secret_uses_cryptographic_randomness(self):
        with patch.dict('os.environ', {}, clear=True), \
                patch('config.secrets.token_urlsafe',
                      return_value='generated-secret') as token_urlsafe:
            self.assertEqual(load_jwt_secret(), 'generated-secret')

        token_urlsafe.assert_called_once_with(32)

    def test_runtime_does_not_use_known_weak_key(self):
        self.assertNotEqual(vuln_app.app.config['SECRET_KEY'], 'random')


if __name__ == '__main__':
    unittest.main()
