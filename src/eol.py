import requests

import util


def normalise_os_id(os_id: str) -> str:
    """
    Some product identifiers differ from the ones we know.
    This function translates known difference from "our" identifier to the
    one EOL API can process.
    """

    if os_id == 'amzn':
        return 'amazon-linux'

    return os_id


class EolRoutes:
    def __init__(
        self,
        base_url: str = 'https://endoflife.date/api',
    ):
        self._base_url = base_url

    def cycles(
        self,
        product: str,
    ):
        return util.urljoin(
            self._base_url,
            f'{product}.json',
        )


class EolClient:
    """
    API client for https://endoflife.date/docs/api.
    """

    def __init__(
        self,
        routes: EolRoutes = EolRoutes(),
    ):
        self._routes = routes

    def cycles(
        self,
        product: str,
        absent_ok: bool = False,
    ) -> list[dict] | None:
        """
        Returns release_cycles as described here https://endoflife.date/docs/api.
        If `absent_ok`, HTTP 404 returns `None`.
        """
        res = requests.get(
            self._routes.cycles(product),
            timeout=(4, 31),
        )
        try:
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if not absent_ok:
                raise
            if e.response.status_code == 404:
                return None
            raise
        return res.json()
