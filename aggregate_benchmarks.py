import json
from pathlib import Path

"""
Very simple tool to aggregate multiple .json benchmark files.
"""


def main():
    result = []
    path = Path(".")
    pattern = "benchmark_*.json"
    for p in path.glob(pattern):
        with open(p, mode="r") as fp:
            data = json.load(fp)
            result.append(data)
    with open(f"benchmark.json", mode="w") as fp:
        json.dump(result, fp)


if __name__ == '__main__':
    main()
