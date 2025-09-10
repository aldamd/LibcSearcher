import requests
import re
import json
from glob import glob
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger(__name__)


class LibcSearch:
    def __init__(self) -> None:
        pass


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s:%(name)s: %(message)s"
    )
    libcsrch = LibcSearch()
