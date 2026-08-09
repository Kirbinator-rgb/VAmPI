import unittest

from config import vuln_app
from api_views.users import is_valid_email


class EmailValidationTest(unittest.TestCase):
    def test_valid_email_is_accepted(self):
        self.assertTrue(is_valid_email('member@example.com'))

    def test_oversized_email_is_rejected_before_complex_processing(self):
        malicious_email = ('a' * 100_000) + '!@example.com'

        self.assertFalse(is_valid_email(malicious_email))

    def test_invalid_domain_labels_are_rejected(self):
        self.assertFalse(is_valid_email('member@-example.com'))
        self.assertFalse(is_valid_email('member@example-.com'))


if __name__ == '__main__':
    unittest.main()
