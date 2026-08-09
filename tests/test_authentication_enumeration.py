import unittest
from types import SimpleNamespace
from unittest.mock import patch

from config import vuln_app
from api_views.users import login_user, register_user


class AuthenticationEnumerationTest(unittest.TestCase):
    def login_failure(self, stored_user):
        with vuln_app.app.test_request_context(
                '/users/v1/login', method='POST',
                json={'username': 'name1', 'password': 'wrong'}):
            with patch('api_views.users.User') as user_model:
                user_model.query.filter_by.return_value.first.return_value = stored_user
                response = login_user()
        return response.status_code, response.get_json()

    def registration_response(self, stored_user):
        with vuln_app.app.test_request_context(
                '/users/v1/register', method='POST',
                json={'username': 'name1', 'password': 'pass1',
                      'email': 'mail1@mail.com'}):
            with patch('api_views.users.User') as user_model, \
                    patch('api_views.users.db'):
                user_model.query.filter_by.return_value.first.return_value = stored_user
                response = register_user()
        return response.status_code, response.get_json()

    def test_login_does_not_distinguish_user_from_password_failure(self):
        wrong_password = self.login_failure(SimpleNamespace(password='pass1'))
        unknown_user = self.login_failure(None)

        self.assertEqual(wrong_password, unknown_user)
        self.assertEqual(unknown_user[1]['message'],
                         'Username or Password Incorrect!')

    def test_registration_does_not_disclose_existing_username(self):
        existing_user = self.registration_response(SimpleNamespace())
        new_user = self.registration_response(None)

        self.assertEqual(existing_user, new_user)


if __name__ == '__main__':
    unittest.main()
