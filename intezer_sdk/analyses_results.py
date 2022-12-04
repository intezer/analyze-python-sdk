from typing import List, Any
from typing import Dict
from typing import Tuple

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import raise_for_status


class AnalysesResults:
    def __init__(self, request_url_path: str, api: IntezerApi, request_filters: Dict):
        """
        All analyses results from server with the ability to iterate results.
        :param request_url_path: Url to request new filter from.
        :param api: Instance of Intezer API for request server.
        :param request_filters: Filters requested from server.
        """
        self.api = api
        self.request_filters = request_filters
        self._pages = []
        self._current_page: List[Any] = None
        self._request_url_path = request_url_path
        self._current_page_number = 0
        self._total_count = 0
        self._current_offset = 0

    def __iter__(self):
        """Iterate between page."""
        if not self._current_page:
            self._fetch_page()
        if self._current_page:
            yield from self._current_page
            if len(self._pages) * self.request_filters['limit'] < self.total_count:
                self._fetch_page()
                yield from iter(self)

    def __len__(self):
        return len(self._pages)

    @property
    def total_count(self):
        return self._total_count

    def current_page(self) -> List:
        """Get current page, if not exits, ask a new one from server."""
        return self._current_page or self._fetch_page()

    def all(self) -> List:
        """Return all exits analysis's from server."""
        self._fetch_all_pages()
        self._current_page_number = 0
        if self._pages:
            self._current_page = self._pages[0]
        return sum(self._pages, [])

    def _fetch_page(self) -> List:
        """Request for new page from server."""
        self.request_filters['offset'] = self._current_offset
        self._total_count, new_page = self._fetch_analyses_history(
            self._request_url_path, self.request_filters)

        if new_page:
            self._current_page = new_page
            self._update_current_page_metadata()
        return self._current_page

    def _update_current_page_metadata(self):
        """Update all metadata about new current page."""
        self._current_offset += len(self._current_page)
        self._pages.append(self._current_page)
        self._current_page_number = len(self._pages) - 1

    def _fetch_all_pages(self):
        """Request for all missing pages didn't request yet."""
        return list(self)

    def _fetch_analyses_history(self, url_path: str, data: Dict
                                ) -> Tuple[int, List]:
        """
        Request from server filtered analyses history.
        :param url_path: Url to request new data from.
        :param data: filtered data.
        :return: Count of all results exits in filtered request and amount
        analyses as requested.
        """
        response = self.api.request_with_refresh_expired_access_token(
            path=url_path, method='POST', data=data)
        raise_for_status(response)
        data_response = response.json()
        return data_response['total_count'], data_response['analyses']
