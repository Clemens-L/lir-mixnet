import logging
import argparse
import re
import json
import tqdm
from collections import defaultdict
from itertools import chain
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)
logging.basicConfig(
        level=logging.DEBUG,
        format=f"%(asctime)s %(module)s: %(message)s",
)


def find_toplevel_eval_folders(path: Path) -> List[Path]:
    pattern = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
    return [p for p in path.glob(pattern) if p.is_dir()]


def find_config_folders(path: Path) -> List[Path]:
    # Note: config folder names changed after we added single identity output
    # The new pattern is: pattern_sr = "m*_c*_u*_r*_*"
    # However, this is also matched by the old pattern, so we leave it as is ...
    pattern = "m*_c*_u*_*"
    return [p for p in path.glob(pattern) if p.is_dir()]


def get_config_parameters(path: Path) -> Dict[str, int]:
    pattern = re.compile(
        r"m(?P<mixpeers>[0-9]+)_c(?P<consortiumpeers>[0-9]+)_u(?P<users>[0-9]+)(_r(?P<recovery>[01]))?_(?P<iter>[0-9]+)"
    )
    match = pattern.match(path.name)
    if match:
        # handle legacy folders (before the implementation of single identity recovery)
        # (for legacy folders, the key recovery will be None)
        d = {k: int(v) if v else 0 for k, v in match.groupdict().items()}
        return d
    raise RuntimeError(f"Could not extract config parameters from {path.name}")


def load_timing_files(path: Path) -> Dict[str, Dict[int, Dict]]:
    result = defaultdict(dict)
    pattern = re.compile(r"(?P<peer_type>\w+)-timings(?P<peer_id>[0-9]+)\.json")
    for file in path.iterdir():
        match = pattern.fullmatch(file.name)
        if match:
            peer_type = match.group("peer_type")
            peer_id = int(match.group("peer_id"))
            # load file contents
            with open(file, mode="r") as fp:
                content = json.load(fp)
            result[peer_type][peer_id] = content
    return dict(result)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="CLI Tool for aggregating evaluation files",
        usage="Specify the path to the output folder to aggregate timings",
        description="Aggregates the timing ouput from different evaluations and configurations.",
        add_help=True
    )

    parser.add_argument("--path", required=False, type=str, default=".",
                        help="Path to the evaluation folders.")
    parser.add_argument("--output", required=False, type=str, default="timings.json",
                        help="Path to the output.")
    args = parser.parse_args()

    path = Path(args.path)
    assert path.is_dir()

    configs = list(chain.from_iterable(find_config_folders(toplevel) for toplevel in find_toplevel_eval_folders(path)))
    assert len(configs) == len(set(configs))

    output = []

    for cfg in tqdm.tqdm(configs):
        params = get_config_parameters(cfg)
        timing_files = load_timing_files(cfg)
        output.append({**params, **timing_files})

    with open(args.output, mode="w+") as fp:
        json.dump(output, fp)


if __name__ == '__main__':
    main()
