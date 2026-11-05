import datetime
import functools

import dateutil.parser
import structlog
import yaml

import eol
import osinfo.alpine
import osinfo.model
import osinfo.paths

logger = structlog.get_logger(__name__)


@functools.cache
def release_infos_from_cfg(
    os_id: str,
    absent_ok: bool = False,
) -> list[osinfo.model.OsReleaseInfo] | None:
    """
    reads os_release_info from filesystem,
    returns `None` if requested os is not supported
    """

    try:
        path = osinfo.paths.for_os(os_id)
    except ValueError as e:
        # os_id not in filesystem allowlist
        if not absent_ok:
            raise e

        return None

    try:
        with open(path) as f:
            release_infos_raw = yaml.safe_load(f)
    except FileNotFoundError as e:
        if not absent_ok:
            raise e

        return None

    return [
        os_release_info_from_release_cycle(
            {
                'eol': release_info_raw.get('eol_date'),
                'cycle': release_info_raw['name'],
                'latest': release_info_raw.get('greatest_version'),
            },
        )
        for release_info_raw in release_infos_raw
    ]


@functools.cache
def osinfo_client(os_id: str):
    if os_id == 'alpine':
        return osinfo.alpine.Client()

    return None


def os_release_infos(
    os_id: str,
    eol_client: eol.EolClient,
) -> list[osinfo.model.OsReleaseInfo] | None:
    """
    returns release_info or `None` for given os_id
    lookup hierarchy:
      1. EOL API
      2. crawling via custom clients
      3. filesystem
    """

    release_cycles = eol_client.cycles(
        product=os_id,
        absent_ok=True,
    )

    if release_cycles:
        return [
            os_release_info_from_release_cycle(release_cycle) for release_cycle in release_cycles
        ]

    if client := osinfo_client(os_id):
        return client.release_infos()

    return release_infos_from_cfg(
        os_id=os_id,
        absent_ok=True,
    )


def os_release_info_from_release_cycle(
    release_cycle: dict,
) -> osinfo.model.OsReleaseInfo:
    def eol_date() -> bool | datetime.datetime | None:
        eol_date = release_cycle.get('extendedSupport')
        if eol_date is None:
            eol_date = release_cycle.get('eol')

        # unfortunately, eol-api yields inconsistent values for `eol` attribute (bool vs timestamp)
        if isinstance(eol_date, bool):
            return eol_date
        elif isinstance(eol_date, str):
            return dateutil.parser.isoparse(eol_date)
        else:
            return None

    def reached_eol(
        eol_date: datetime.datetime | bool = eol_date(),
    ) -> bool | None:
        if isinstance(eol_date, bool):
            return eol_date
        elif isinstance(eol_date, datetime.datetime):
            return eol_date < datetime.datetime.today()
        else:
            return None

    return osinfo.model.OsReleaseInfo(
        name=release_cycle['cycle'],
        # not provided for all products
        greatest_version=release_cycle.get('latest'),
        eol_date=eol_date(),
        reached_eol=reached_eol(),
    )
