from typing import List, Dict, Tuple

from intezer_sdk.api import IntezerApi, raise_for_status


class Results:
    def __init__(self, url: str, api: IntezerApi, data: Dict):
        """
        Store list of data into pages.
        :param url: Url to request new data from.
        :param api: Istance of publice intezer api for request server.
        :param data: filtered data.
        """
        self.api = api
        self.data = data
        self.pages = []
        self._current_page = None
        self._url = url
        self._page_size = data["limit"]
        self._current_page_number = 0
        self.total_count = 0
        self._current_offset = 0

    def __iter__(self):
        """Iterate for page."""
        if not self._current_page:
            self._fetch_page()
        yield from self._current_page
        self._fetch_page()
        yield from iter(self)

    @property
    def current_page(self) -> List:
        """Get current page, if not exits, ask a new one from server."""
        return self._current_page or self._fetch_page()

    def all(self) -> List:
        """Return all exits analysis's from server."""
        self._fetch_all_pages()
        self._current_page_number = 0
        self._current_page = self.pages[0]

        return self._unite_all_pages_to_one(list(iter(self)))

    def previous_page(self) -> List:
        """Move to the previous page."""
        if self._current_page_number - 1 >= 0:
            self._current_page_number -= 1
            self._current_page = self.pages[self._current_page_number]
        return self._current_page

    def next_page(self) -> List:
        """Move to the next page"""
        if self._current_page_number == len(self.pages) - 1:
            return self._fetch_page()
        self._current_page_number += 1
        self._current_page = self.pages[self._current_page_number]
        return self._current_page

    def _fetch_page(self) -> List:
        """Request for new page from server."""
        self.data['offset'] = self._current_offset
        self.total_count, new_page = self._fetch_analyses_history(
            self._url, self.data)

        if not new_page:
            raise StopIteration()
        self._current_page = new_page
        return self._update_current_page()

    def _update_current_page(self) -> List:
        """Update all metadata about new current page."""
        self._current_offset += len(self._current_page)
        self.pages.append(self._current_page)
        self._current_page_number = len(self.pages) - 1
        return self._current_page

    def _fetch_all_pages(self):
        """Request for all missing pages didn't request yet."""
        while len(self.pages) * self._page_size < self.total_count:
            self._fetch_page()

    def _fetch_analyses_history(self, url_path: str, data: Dict
                                ) -> Tuple[int, List]:
        """
        Request from server filtered analyses history.
        :param url_path: Url to request new data from.
        :param data: filtered data.
        :return: Count of all results exits in filtered request and amount analyses as requested.
        """
        response = self.api.request_with_refresh_expired_access_token(
            path=url_path, method='POST', data=data)
        raise_for_status(response)
        json_response = response.json()
        return json_response["total_count"], json_response["analyses"]

    @staticmethod
    def _unite_all_pages_to_one(all_pages: List):
        all_analysises = []
        for page in all_pages:
            all_analysises.extend(page)
        return all_analysises
