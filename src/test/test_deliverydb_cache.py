import datetime
import unittest.mock

import pytest
import sqlalchemy.dialects.postgresql
import sqlalchemy.exc
import sqlalchemy.sql.dml

import deliverydb.cache as cache_sync
import deliverydb.cache_async as cache_async
import deliverydb.model as dm


def _make_cache_entry(
    id: str = 'abc123',
    value: bytes = b'data',
    delete_after: datetime.datetime | None = None,
) -> dm.DBCache:
    now = datetime.datetime.now(datetime.timezone.utc)
    return dm.DBCache(
        id=id,
        descriptor={'type': 'test'},
        delete_after=delete_after,
        keep_until=now + datetime.timedelta(seconds=60),
        costs=10,
        size=len(value),
        value=value,
    )


# ---------------------------------------------------------------------------
# deliverydb.cache (sync)
# ---------------------------------------------------------------------------


class TestSyncAddOrUpdateCacheEntry:
    def test_issues_upsert_and_returns_true(self):
        session = unittest.mock.MagicMock()
        entry = _make_cache_entry()

        result = cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=entry,
        )

        assert result is True
        session.execute.assert_called_once()
        session.commit.assert_called_once()
        session.rollback.assert_not_called()

        stmt = session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.dialects.postgresql.Insert)

    def test_returns_false_and_rolls_back_on_exception(self):
        session = unittest.mock.MagicMock()
        session.execute.side_effect = Exception('db error')

        result = cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()
        session.commit.assert_not_called()

    def test_no_integrity_error_raised_to_caller(self):
        session = unittest.mock.MagicMock()
        session.execute.side_effect = sqlalchemy.exc.IntegrityError(
            statement=None,
            params=None,
            orig=Exception('dup key'),
        )

        result = cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()

    def test_insert_includes_revision_and_read_count_defaults(self):
        session = unittest.mock.MagicMock()
        cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )
        stmt = session.execute.call_args[0][0]
        compiled = stmt.compile(dialect=sqlalchemy.dialects.postgresql.dialect())
        assert 'revision' in compiled.params, 'revision missing from INSERT — will be NULL'
        assert compiled.params['revision'] == 0
        assert 'read_count' in compiled.params, 'read_count missing from INSERT — will be NULL'
        assert compiled.params['read_count'] == 0


class TestSyncFindCachedValue:
    def test_returns_none_when_entry_missing(self):
        session = unittest.mock.MagicMock()
        session.get.return_value = None

        assert cache_sync.find_cached_value(db_session=session, id='missing') is None

    def test_returns_none_when_stale(self):
        session = unittest.mock.MagicMock()
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        entry = _make_cache_entry(delete_after=past)
        session.get.return_value = entry

        assert cache_sync.find_cached_value(db_session=session, id=entry.id) is None

    def test_returns_value_and_updates_read_stats(self):
        session = unittest.mock.MagicMock()
        entry = _make_cache_entry(value=b'hello')
        session.get.return_value = entry

        result = cache_sync.find_cached_value(db_session=session, id=entry.id)

        assert result == b'hello'
        session.execute.assert_called_once()
        stmt = session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.sql.dml.Update)
        session.commit.assert_called_once()

    def test_rolls_back_on_commit_error(self):
        session = unittest.mock.MagicMock()
        session.commit.side_effect = Exception('commit failed')
        entry = _make_cache_entry(value=b'hello')
        entry.read_count = 0
        session.get.return_value = entry

        result = cache_sync.find_cached_value(db_session=session, id=entry.id)

        assert result == b'hello'
        session.rollback.assert_called_once()


# ---------------------------------------------------------------------------
# deliverydb.cache_async — add_or_update_cache_entry
# ---------------------------------------------------------------------------


class TestAsyncAddOrUpdateCacheEntry:
    @pytest.mark.asyncio
    async def test_issues_upsert_and_returns_true(self):
        session = unittest.mock.AsyncMock()
        entry = _make_cache_entry()

        result = await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=entry,
        )

        assert result is True
        session.execute.assert_called_once()
        session.commit.assert_called_once()
        session.rollback.assert_not_called()

        stmt = session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.dialects.postgresql.Insert)

    @pytest.mark.asyncio
    async def test_returns_false_and_rolls_back_on_exception(self):
        session = unittest.mock.AsyncMock()
        session.execute.side_effect = Exception('db error')

        result = await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()
        session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_integrity_error_raised_to_caller(self):
        session = unittest.mock.AsyncMock()
        session.execute.side_effect = sqlalchemy.exc.IntegrityError(
            statement=None,
            params=None,
            orig=Exception('dup key'),
        )

        result = await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_insert_includes_revision_and_read_count_defaults(self):
        session = unittest.mock.AsyncMock()
        await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )
        stmt = session.execute.call_args[0][0]
        compiled = stmt.compile(dialect=sqlalchemy.dialects.postgresql.dialect())
        assert 'revision' in compiled.params, 'revision missing from INSERT — will be NULL'
        assert compiled.params['revision'] == 0
        assert 'read_count' in compiled.params, 'read_count missing from INSERT — will be NULL'
        assert compiled.params['read_count'] == 0


# ---------------------------------------------------------------------------
# deliverydb.cache_async — find_cached_value
# ---------------------------------------------------------------------------


class TestAsyncFindCachedValue:
    @pytest.mark.asyncio
    async def test_returns_none_when_entry_missing(self):
        session = unittest.mock.AsyncMock()
        session.get.return_value = None

        assert await cache_async.find_cached_value(db_session=session, id='missing') is None

    @pytest.mark.asyncio
    async def test_returns_none_when_stale(self):
        session = unittest.mock.AsyncMock()
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        entry = _make_cache_entry(id='stale', delete_after=past)
        session.get.return_value = entry

        assert await cache_async.find_cached_value(db_session=session, id='stale') is None

    @pytest.mark.asyncio
    async def test_returns_value_and_issues_server_side_increment(self):
        session = unittest.mock.AsyncMock()
        entry = _make_cache_entry(id='hit1', value=b'payload')
        session.get.return_value = entry

        result = await cache_async.find_cached_value(db_session=session, id='hit1')

        assert result == b'payload'
        session.execute.assert_called_once()
        stmt = session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.sql.dml.Update)
        session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_server_side_increment_not_read_modify_write(self):
        """read_count must be incremented server-side to avoid row-level lock contention."""
        session = unittest.mock.AsyncMock()
        session.get.return_value = _make_cache_entry(id='hit2', value=b'x')

        await cache_async.find_cached_value(db_session=session, id='hit2')

        stmt = session.execute.call_args[0][0]
        compiled = stmt.compile(dialect=sqlalchemy.dialects.postgresql.dialect())
        sql_str = str(compiled)
        assert 'read_count' in sql_str and '+' in sql_str, (
            f'expected server-side increment in SQL, got: {sql_str}'
        )

    @pytest.mark.asyncio
    async def test_rolls_back_on_stat_write_error(self):
        session = unittest.mock.AsyncMock()
        session.get.return_value = _make_cache_entry(id='hit3', value=b'x')
        session.execute.side_effect = Exception('write failed')

        result = await cache_async.find_cached_value(db_session=session, id='hit3')

        assert result == b'x'
        session.rollback.assert_called_once()
        session.commit.assert_not_called()
