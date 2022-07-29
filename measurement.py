import asyncio
import time
import json
import logging
from pathlib import Path
from collections import defaultdict
from typing import DefaultDict, Dict, List, Callable
from functools import wraps


logger = logging.getLogger(__name__)


def _empty_timings(): return defaultdict(list)


_measurement_active: bool = False


timings: DefaultDict[str, List[Dict[str, int]]] = _empty_timings()


def begin_measurement() -> None:
    global _measurement_active
    global timings

    assert not _measurement_active

    _measurement_active = True


def end_measurement(filename: str) -> None:
    global _measurement_active
    global timings

    assert _measurement_active

    # merge with old timings, if they exist on disk
    if Path(filename).is_file():
        with open(filename, mode="r") as fp:
            existing = json.load(fp)
        # convert to defaultdict to avoid KeyErrors
        existing = defaultdict(list, existing)
        keys = set.union(set(timings.keys()), set(existing.keys()))
        merged = {key: existing[key] + timings[key] for key in keys}
        timings = merged
        logger.info(f"Merged with existing measurements.")

    logger.info(f"Saving measurements to file.")
    with open(filename, mode="w+") as fp:
        json.dump(timings, fp)
    timings = _empty_timings()
    _measurement_active = False


def measure(name: str) -> Callable[[Callable], Callable]:
    def measure_decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            global _measurement_active
            global timings

            if not _measurement_active:
                logger.warning(f"measurement not active for {func.__name__}")
                return func(*args, **kwargs)

            start = time.time_ns()
            result = func(*args, **kwargs)
            stop = time.time_ns()
            timings[name].append({
                "start": start,
                "stop": stop,
                "duration": (stop-start)
            })

            return result

        return wrapper

    return measure_decorator


def measure_async(name: str) -> Callable[[Callable], Callable]:
    def measure_decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            global _measurement_active
            global timings

            if not _measurement_active:
                logger.warning(f"measurement not active for {func.__name__}")
                return await func(*args, **kwargs)

            start = time.time_ns()
            result = await func(*args, **kwargs)
            stop = time.time_ns()
            timings[name].append({
                "start": start,
                "stop": stop,
                "duration": (stop - start)
            })

            return result

        return wrapper

    return measure_decorator


async def measure_future(name: str, future: asyncio.Future) -> None:
    global _measurement_active
    global timings

    if not _measurement_active:
        logger.warning(f"measurement not active for {name}")

    start = time.time_ns()
    await future
    stop = time.time_ns()

    timings[name].append({
        "start": start,
        "stop": stop,
        "duration": (stop - start)
    })
