import unittest
from types import SimpleNamespace
from unittest.mock import patch

from config import vuln_app
from api_views.books import get_by_title


class BookAuthorizationTest(unittest.TestCase):
    def test_book_lookup_is_scoped_to_authenticated_owner(self):
        authenticated_user = object()

        with vuln_app.app.test_request_context('/books/v1/private-book'):
            with patch('api_views.books.token_validator',
                       return_value={'sub': 'name1'}), \
                    patch('api_views.books.User') as user_model, \
                    patch('api_views.books.Book') as book_model:
                user_model.query.filter_by.return_value.first.return_value = authenticated_user
                book_model.query.filter_by.return_value.first.return_value = None

                response = get_by_title('private-book')

        self.assertEqual(response.status_code, 404)
        book_model.query.filter_by.assert_called_once_with(
            user=authenticated_user, book_title='private-book')

    def test_owner_can_retrieve_book_secret(self):
        authenticated_user = object()
        book = SimpleNamespace(
            book_title='owned-book', secret_content='secret',
            user=SimpleNamespace(username='name1'))

        with vuln_app.app.test_request_context('/books/v1/owned-book'):
            with patch('api_views.books.token_validator',
                       return_value={'sub': 'name1'}), \
                    patch('api_views.books.User') as user_model, \
                    patch('api_views.books.Book') as book_model:
                user_model.query.filter_by.return_value.first.return_value = authenticated_user
                book_model.query.filter_by.return_value.first.return_value = book

                response = get_by_title('owned-book')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['secret'], 'secret')


if __name__ == '__main__':
    unittest.main()
