from pathlib import Path

from loganalyser.logs import iter_log_lines


def toRows(path: str | Path = "data") -> list[str]:
    return list(iter_log_lines(path))


if __name__=="__main__":
    print("".join(toRows("data")[:10]))