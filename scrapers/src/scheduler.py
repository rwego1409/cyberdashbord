import json
import os
from datetime import datetime, timezone
from pathlib import Path
from time import sleep

from main import run_collection_cycle


def _append_dead_letter(entry: dict) -> str:
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    path = data_dir / "dead_letters.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    return str(path)


def main() -> None:
    interval_seconds = int(os.getenv("SCRAPER_INTERVAL_SECONDS", "900"))
    retries = int(os.getenv("SCRAPER_RETRIES", "2"))
    retry_delay_seconds = float(os.getenv("SCRAPER_RETRY_DELAY_SECONDS", "2"))
    run_once = os.getenv("SCRAPER_RUN_ONCE", "false").lower() == "true"

    while True:
        started = datetime.now(timezone.utc).isoformat()
        result = run_collection_cycle(retries=retries, retry_delay_seconds=retry_delay_seconds)
        errors = result.get("errors", {})
        if errors:
            dead_letter_file = _append_dead_letter(
                {
                    "started_at": started,
                    "errors": errors,
                    "source_counts": result.get("source_counts", {}),
                }
            )
            result["dead_letter_file"] = dead_letter_file

        print(
            {
                "service": "scrapers-scheduler",
                "started_at": started,
                "interval_seconds": interval_seconds,
                "result": result,
            }
        )

        if run_once:
            break
        sleep(interval_seconds)


if __name__ == "__main__":
    main()
