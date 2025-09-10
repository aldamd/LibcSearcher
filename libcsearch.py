import requests
import re
import json
from glob import glob
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger(__name__)
aliases = {"binsh": "str_bin_sh"}


class LibcSearch:
    _aliases = aliases

    class _Libc:
        _aliases = aliases

        def __init__(self, name: str, offsets: dict[str, int]) -> None:
            self.name = name
            self._offsets = offsets

        def __getattr__(self, key: str) -> int:
            if key in self._aliases:
                key = self._aliases[key]
                return self._offsets[key]
            if key in self._offsets:
                return self._offsets[key]
            raise AttributeError(f"{key} not found in libc {self.name}")

        def __str__(self) -> str:
            lines = [f"[*]{self.name}"]
            for sym, val in self._offsets.items():
                lines.append(f"    {sym:12} 0x{val:x}")
            return "\n".join(lines)

    def __init__(self, sym: list[str], addr: list[str]) -> None:
        addr = [i.lstrip("0x") for i in addr]

        self._sym = sym
        self._addr = addr
        self._libc_map: dict[str, dict[str, int]] = {}
        self.libc_list: list[LibcSearch._Libc] = []
        self._url: str = ""

        self._check_libc_db()
        self._blukat_search()

    def _check_libc_db(self) -> None:
        for url in ["https://libc.blukat.me/", "https://libc.rip/"]:
            r = requests.head(url, timeout=1)
            if r.status_code == 200:
                self._url = url
                logger.info(f"{url} selected")
                return
        raise RuntimeError(
            "Libc database wrappers are inaccessible! Check your wifi settings"
        )

    def _blukat_search(self) -> None:
        # symbol_search = r"(?:abort|abs) [0-9a-f]+"
        query = "?q="
        params = []
        for s, a in zip(self._sym, self._addr):
            params.append(f"{s}:{a}")
        query += ",".join(params)
        r = requests.get(self._url + query)

        libc_matches = re.findall(r"(?:musl|[g]?libc[0-9]?)_?.*\..*-.*", r.text)
        print(libc_matches)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s:%(name)s: %(message)s"
    )
    sym = ["puts", "binsh", "gets"]
    addr = ["0x7f10101010"]
    libcsrch = LibcSearch(sym, addr)
