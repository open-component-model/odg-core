import unittest.mock

import aiohttp.web
import github3.exceptions
import pytest

import special_component


class TestRetrieveVersion:
    @staticmethod
    def _version_cfg(exc_or_value):
        cfg = unittest.mock.MagicMock()
        if isinstance(exc_or_value, BaseException):
            cfg.retrieve.side_effect = exc_or_value
        else:
            cfg.retrieve.return_value = exc_or_value
        return cfg

    def test_none_cfg(self):
        assert special_component.retrieve_version(None, 'my-component') is None

    def test_success(self):
        assert (
            special_component.retrieve_version(self._version_cfg('1.2.3'), 'my-component') == '1.2.3'
        )

    def test_value_error_raises_422(self):
        with pytest.raises(aiohttp.web.HTTPUnprocessableEntity) as exc_info:
            special_component.retrieve_version(
                self._version_cfg(ValueError("self.source.type='x' is not supported")),
                'my-component',
            )
        assert 'my-component' in exc_info.value.reason
        assert 'misconfigured' in exc_info.value.reason

    def test_not_found_raises_422(self):
        with pytest.raises(aiohttp.web.HTTPUnprocessableEntity):
            special_component.retrieve_version(
                self._version_cfg(github3.exceptions.NotFoundError(unittest.mock.MagicMock())),
                'my-component',
            )

    def test_unexpected_error_propagates(self):
        with pytest.raises(ConnectionError):
            special_component.retrieve_version(
                self._version_cfg(ConnectionError('GitHub unreachable')),
                'my-component',
            )
