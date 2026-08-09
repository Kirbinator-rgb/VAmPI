import unittest
from types import SimpleNamespace
from unittest.mock import patch

from config import vuln_app
from api_views.users import update_password


class PasswordAuthorizationTest(unittest.TestCase):
    def test_user_cannot_change_another_users_password(self):
        with vuln_app.app.test_request_context(
                '/users/v1/admin/password', method='PUT',
                json={'password': 'new-password'}):
            with patch('api_views.users.token_validator',
                       return_value={'sub': 'name1'}), \
                    patch('api_views.users.User') as user_model, \
                    patch('api_views.users.db') as database:
                response = update_password('admin')

        self.assertEqual(response.status_code, 403)
        user_model.query.filter_by.assert_not_called()
        database.session.commit.assert_not_called()

    def test_user_can_change_own_password(self):
        user = SimpleNamespace(password='old-password')

        with vuln_app.app.test_request_context(
                '/users/v1/name1/password', method='PUT',
                json={'password': 'new-password'}):
            with patch('api_views.users.token_validator',
                       return_value={'sub': 'name1'}), \
                    patch('api_views.users.User') as user_model, \
                    patch('api_views.users.db') as database:
                user_model.query.filter_by.return_value.first.return_value = user
                response = update_password('name1')

        self.assertEqual(response.status_code, 204)
        self.assertEqual(user.password, 'new-password')
        database.session.commit.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
