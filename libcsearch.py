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
        for idx, s in enumerate(sym):
            if s in self._aliases:
                sym[idx] = self._aliases[s]

        addr = [i.lstrip("0x") for i in addr]

        self._sym = sym
        self._addr = addr
        self._libc_map: dict[str, dict[str, int]] = {}
        self.libc_list: list[LibcSearch._Libc] = []
        self._url: str = ""

        self._check_libc_db()

    def _check_libc_db(self) -> None:
        for url in ["https://libc.blukat.me/", "https://libc.rip/"]:
            r = requests.head(url, timeout=2)
            if r.status_code == 200:
                self._url = url
                logger.info(f"{url} selected")
                return
        raise RuntimeError(
            "Libc database wrappers are inaccessible! Check your wifi settings"
        )

    def _blukat_search(self) -> None:
        query = "?q="
        params = []
        for s, a in zip(self._sym, self._addr):
            params.append(f"{s}:{a}")
        query += ",".join(params)
        r = requests.get(self._url + query)

        matches = re.findall(r"(?:musl|[g]?libc[0-9]?)_?.*\..*-.*", r.text)
        total = len(matches)
        done = 0
        lock = Lock()

        def search_symbols(libc: str) -> tuple[str, dict[str, int]]:
            query = f"d/{libc}.symbols"
            r = requests.get(self._url + query)
            if r.status_code != 200:
                raise RuntimeError(f"Failed to reach {self._url + query}")
            symbols = r.text

            offset_map = {}
            for s in self._sym:
                pattern = rf"(?:{s} [0-9a-f]+)"
                match = re.search(pattern, symbols)
                if not match:
                    raise RuntimeError(f"Failed to find {s} in the {libc} symbol table")
                offset_map[s] = int(match.group().split()[-1], 16)

            return libc, offset_map

        libc_map = {}
        with ThreadPoolExecutor(max_workers=10) as tp:
            futures = [tp.submit(search_symbols, libc) for libc in matches]
            for future in as_completed(futures):
                libc, offsets = future.result()
                libc_map[libc] = offsets

                with lock:
                    done += 1
                    logging.info(
                        "Scraped %s (%d/%d, %.1f%%)",
                        libc,
                        done,
                        total,
                        (done / total) * 100,
                    )

        print(libc_map)
        self._libc_map = libc_map


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s:%(name)s: %(message)s"
    )
    sym = ["puts", "binsh", "gets"]
    addr = ["0x7f10101010"]
    libcsrch = LibcSearch(sym, addr)
