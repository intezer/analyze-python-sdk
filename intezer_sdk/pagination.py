from typing import List


class Pagination:
    """Store list of data into pages."""
    def __init__(self, *, pages: List[List] = None, page_size: int = 100):
        self.pages = [] if pages is None else pages
        self._page_size = page_size
        self.total_count = 0

    def __iter__(self):  # -> Pagination
        self.page_number = 0
        return self

    def __next__(self) -> List:
        next_page = next(self.pages)
        self.page_number += 1
        return next_page

    @property
    def prev_page(self) -> List:
        if self.page_number - 1 >= 0:
            self.page_number -= 1
        return self.current_page

    def add_page(self, page: List):
        self.pages.append(page)

    @property
    def all(self):
        """All rows as flat list."""
        rows = []
        for row in self.pages:
            rows.extend(row)
        return rows

    @property
    def current_page(self):
        return self.pages[self.page_number]
