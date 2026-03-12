from execution.scheduler import schedule_scan_cycle


def main() -> None:
    result = schedule_scan_cycle(limit=10)
    print({"service": "scanner-orchestrator", "status": "completed", "result": result})


if __name__ == "__main__":
    main()
