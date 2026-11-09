"""
Round-trip tests for the db cache serialisation layer using the productive
decorator/helper functions from deliverydb.cache_async.

- dbcached_function: compliance summary (rich domain objects reconstructed via dacite)
- dbcached_route: HTTP route response ({status, body, content_type} dict)
"""

import dataclasses
import http
import unittest.mock

import aiohttp.web
import pytest

import deliverydb.cache_async as dca
import compliance_summary as cs
import odg.model


@pytest.mark.asyncio
async def test_compliance_summary_cache_roundtrip(db_session_async):
    artefact = odg.model.ComponentArtefactId(
        component_name='github.com/gardener/gardener',
        component_version='1.2.3',
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
        artefact=odg.model.LocalArtefactId(
            artefact_name='gardener-apiserver',
            artefact_version='1.2.3',
            artefact_type='ociImage',
        ),
    )
    entry = cs.ComplianceSummaryEntry(
        type=odg.model.Datatype.VULNERABILITY_FINDING,
        source=odg.model.Datasource.BDBA,
        categorisation=cs.ComplianceEntryCategorisation.CLEAN,
        value=0,
        scanStatus=cs.ComplianceScanStatus.OK,
    )
    pairs = [[dataclasses.asdict(artefact), dataclasses.asdict(entry)]]

    computed = unittest.mock.AsyncMock(return_value=pairs)

    @dca.dbcached_function(ttl_seconds=60)
    async def _cached(
        db_session,
        shortcut_cache: bool = False,
    ):
        return await computed()

    result = await _cached(db_session=db_session_async)
    assert result == pairs
    assert computed.call_count == 1

    result_cached = await _cached(db_session=db_session_async)
    assert computed.call_count == 1  # not called again — value came from cache

    restored_artefact, restored_entry = cs._parse_summary_pair(result_cached[0])
    assert restored_artefact.component_name == 'github.com/gardener/gardener'
    assert restored_artefact.artefact_kind is odg.model.ArtefactKind.RESOURCE
    assert restored_artefact.artefact.artefact_name == 'gardener-apiserver'
    assert restored_entry.type is odg.model.Datatype.VULNERABILITY_FINDING
    assert restored_entry.source is odg.model.Datasource.BDBA
    assert restored_entry.categorisation is cs.ComplianceEntryCategorisation.CLEAN

    await _cached(db_session=db_session_async, shortcut_cache=True)
    assert computed.call_count == 2  # cache was explicitly shortcut


@pytest.mark.asyncio
async def test_http_route_cache_roundtrip(db_session_async):
    def _make_request(
        shortcut_cache_param: bool = False,
        shortcut_cache_header: bool = False,
    ):
        request = unittest.mock.MagicMock(spec=aiohttp.web.Request)
        request.get.return_value = db_session_async
        request.has_body = False
        request.path = '/test/components'

        if shortcut_cache_param:
            request.url.query = {'shortcutCache': True}
        else:
            request.url.query = {}

        request.rel_url.query = request.url.query

        if shortcut_cache_header:
            request.headers = {'Shortcut-Cache': True}
        else:
            request.headers = {}

        return request

    route_called = unittest.mock.AsyncMock(
        return_value=aiohttp.web.json_response(data={'hello': 'world'}),
    )

    @dca.dbcached_route(ttl_seconds=60)
    async def _route(view):
        return await route_called()

    view = unittest.mock.MagicMock()
    view.request = _make_request()

    result: aiohttp.web.Response = await _route(view)
    assert result.body == b'{"hello": "world"}'
    assert result.status == http.HTTPStatus.OK
    assert route_called.call_count == 1

    result_cached: aiohttp.web.Response = await _route(view)
    assert route_called.call_count == 1  # not called again — value came from cache

    assert result_cached.body == b'{"hello": "world"}'
    assert result_cached.status == http.HTTPStatus.OK

    view.request = _make_request(shortcut_cache_param=True)
    await _route(view)
    assert route_called.call_count == 2  # new cache entry because query params changed

    await _route(view)
    assert route_called.call_count == 3  # cache was explicitly shortcut

    view.request = _make_request(shortcut_cache_header=True)
    await _route(view)
    assert route_called.call_count == 4  # cache was explicitly shortcut
