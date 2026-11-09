"""Command line: python -m phishanalyzer {init,analyze,once,run,list-folders}"""
from __future__ import annotations

import argparse
import logging
import shutil
import sys
import webbrowser
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import load_config, resolve_path

PROJECT_DIR = Path(__file__).resolve().parent.parent


def setup_logging(cfg: dict, verbose: bool) -> None:
    log_dir = resolve_path(cfg, cfg["outputs"]["log_dir"])
    log_dir.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    file_handler = RotatingFileHandler(log_dir / "phishanalyzer.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(fmt)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    if sys.stderr is not None:   # pythonw (Task Scheduler) has no console
        root.addHandler(console)
    for noisy in ("urllib3", "olevba", "extract_msg", "chardet", "charset_normalizer", "httpx", "httpx2",
                  "httpcore", "httpcore2", "anthropic"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def setup_network(cfg: dict) -> None:
    if cfg["network"].get("use_system_trust", True):
        try:
            import truststore
            truststore.inject_into_ssl()   # use the Windows certificate store (corporate SSL inspection)
        except ImportError:
            logging.getLogger(__name__).warning("truststore not installed; using certifi CA bundle")


def cmd_init(args) -> int:
    for src, dst in (("config.example.yaml", "config.yaml"), (".env.example", ".env")):
        target = Path(args.config).resolve().parent / dst if dst == ".env" else Path(args.config)
        if target.exists():
            print(f"{target} already exists - left unchanged")
        else:
            shutil.copy(PROJECT_DIR / src, target)
            print(f"Created {target}")
    print("Next: edit config.yaml (internal_domains, source_folder) and put your API keys in .env")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass

    parser = argparse.ArgumentParser(prog="phishanalyzer", description="Analyze reported phishing emails.")
    parser.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml (default: ./config.yaml)")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create config.yaml and .env from the examples")
    p_an = sub.add_parser("analyze", help="analyze .eml/.msg file(s) from disk")
    p_an.add_argument("files", nargs="+", type=Path)
    p_an.add_argument("--report", action="store_true",
                      help="the file is a user's report; analyze the email(s) attached to it")
    p_an.add_argument("--no-intel", action="store_true", help="skip VirusTotal/AbuseIPDB/RDAP lookups")
    p_an.add_argument("--open", action="store_true", help="open the HTML report in the browser")
    sub.add_parser("once", help="process new reports in the Outlook folder once")
    sub.add_parser("run", help="keep watching the Outlook folder")
    sub.add_parser("list-folders", help="show Outlook folders (to set source_folder)")
    p_watch = sub.add_parser("watch", help="continuously add new reports to the shared team log")
    p_watch.add_argument("--once", action="store_true", help="run one cycle and exit")
    p_relog = sub.add_parser("relog", help="re-analyze emails in the shared Excel log and update their rows (after a rule fix)")
    p_relog.add_argument("--days", type=float, help="only rows reported in the last N days")
    p_relog.add_argument("--from", dest="date_from", help="only rows reported on/after this date (YYYY-MM-DD)")
    p_relog.add_argument("--to", dest="date_to", help="only rows reported on/before this date (YYYY-MM-DD)")
    p_daily = sub.add_parser("daily-report", help="analyze recent reports and email a summary with remediation")
    p_daily.add_argument("--hours", type=float, help="look back this many hours (default: daily_report.lookback_hours)")
    p_daily.add_argument("--dry-run", action="store_true", help="build the report but do not send the email")
    p_daily.add_argument("--to", default="", help="recipient (default: daily_report.to or the signed-in user)")
    p_daily.add_argument("--include-reported", action="store_true", help="include reports already sent in an earlier summary")
    p_daily.add_argument("--no-intel", action="store_true", help="skip VirusTotal/AbuseIPDB/RDAP lookups")
    args = parser.parse_args(argv)

    if args.command == "init":
        return cmd_init(args)

    cfg = load_config(args.config)
    setup_logging(cfg, args.verbose)
    setup_network(cfg)
    log = logging.getLogger("phishanalyzer")
    if not cfg["_config_file"]:
        log.warning("No %s found - using defaults. Run 'python -m phishanalyzer init' to create one.", args.config)

    from .intel import Intel
    from .outlook_com import list_folders, print_summary, process_once, run_forever
    from .pipeline import analyze_bytes, analyze_report_bytes, save_case
    from .store import CaseStore

    if args.command == "list-folders":
        list_folders(cfg)
        return 0

    intel = Intel(cfg, offline=getattr(args, "no_intel", False))
    for note in intel.notes:
        log.warning(note)
    store = CaseStore(resolve_path(cfg, cfg["outputs"]["data_dir"]) / "cases.sqlite")

    if args.command == "analyze":
        exit_code = 0
        for path in args.files:
            if not path.exists():
                log.error("File not found: %s", path)
                exit_code = 2
                continue
            data = path.read_bytes()
            results = (analyze_report_bytes(data, path.name, cfg, intel) if args.report
                       else [analyze_bytes(data, path.name, cfg, intel, source=str(path))])
            for result in results:
                paths = save_case(result, cfg, store, data)
                print_summary(result, paths["html"])
                if args.open:
                    webbrowser.open(paths["html"].resolve().as_uri())
                if result.verdict == "MALICIOUS":
                    exit_code = max(exit_code, 1)
        return exit_code
    if args.command == "watch":
        if not cfg["shared_report"].get("folder"):
            log.error("Set shared_report.folder in config.yaml first.")
            return 2
        from .watch import watch_forever, watch_once
        try:
            watch_once(cfg, intel, store) if args.once else watch_forever(cfg, intel, store)
        except KeyboardInterrupt:
            print("Stopped.")
        return 0
    if args.command == "relog":
        from .relog import relog
        from datetime import datetime, timedelta
        start = datetime.now() - timedelta(days=args.days) if args.days else (
            datetime.fromisoformat(args.date_from) if args.date_from else None)
        end = datetime.fromisoformat(args.date_to) + timedelta(days=1) if args.date_to else None
        stats = relog(cfg, intel, store, start, end)
        print(f"Updated {stats['updated']} of {stats['rows']} rows in range; {stats['changed_verdict']} verdict(s) changed; "
              f"{stats['skipped_quota']} left unchanged (quota). Backup: {stats['backup']}")
        return 0
    if args.command == "daily-report":
        from .daily_report import run_daily_report
        run_daily_report(cfg, intel, store, hours=args.hours, dry_run=args.dry_run, to=args.to,
                         include_reported=args.include_reported)
        return 0
    if args.command == "once":
        process_once(cfg, intel, store)
        return 0
    if args.command == "run":
        try:
            run_forever(cfg, intel, store)
        except KeyboardInterrupt:
            print("Stopped.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
