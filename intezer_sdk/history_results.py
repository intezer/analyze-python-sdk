import abc
from typing import List
from typing import Any
from typing import Dict
from typing import Tuple

from intezer_sdk.api import IntezerApiClient


class HistoryResult:
    def __init__(self, request_url_path: str, api: IntezerApiClient, filters: Dict):
        """
        Fetch all history results from server.

        :param request_url_path: Url to request new filter from.
        :param api: Instance of Intezer API for request server.
        :param filters: Filters requested from server.
        """
        self._api = api
        self.filters: Dict = filters
        self._pages: List[Any] = []
        self._current_page: List[Any] = []
        self._request_url_path: str = request_url_path
        self._total_count: int = 0
        self._current_offset: int = 0

    def __iter__(self):
        """Iterate between page."""
        if not self._current_page:
            self._fetch_page()
        if self._current_page:
            yield from self._current_page
            if len(self._pages) * self.filters['limit'] < self._total_count:
                self._fetch_page()
                yield from iter(self)

    def __len__(self) -> int:
        """Amount of results fetched currently."""
        return self._total_count

    @property
    def current_page(self) -> list:
        """Get current page, if not exits, ask a new one from server."""
        return self._current_page or self._fetch_page()

    def all(self) -> list:
        """List all remaining and exists analysis's from server."""
        results = list(self)
        if self._pages:
            self._current_page = self._pages[0]
        return results

    def _fetch_page(self) -> list:
        """Request for new page from server."""
        self.filters['offset'] = self._current_offset
        self._total_count, new_page = self._fetch_history(
            self._request_url_path, self.filters)

        if new_page:
            self._current_page = new_page
            self._update_current_page_metadata()
        return self._current_page

    def _update_current_page_metadata(self):
        """Update all metadata about new current page."""
        self._current_offset += len(self._current_page)
        self._pages.append(self._current_page)


    @abc.abstractmethod
    def _fetch_history(self, url_path: str, data: Dict) -> Tuple[int, List]:
        """
        Request from server filtered history results.
        :param url_path: Url to request new data from.
        :param data: filtered data.
        :return: Count of all results exits in filtered request and amount
        analyses as requested.
        """
        raise NotImplementedError()
