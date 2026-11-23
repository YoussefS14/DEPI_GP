import argparse
import json
import sys
from pathlib import Path

from email_analyzer.pipeline import SAMPLES, analyze_sample
from email_analyzer.pipeline import read_input as read_input


def main():
    parser = argparse.ArgumentParser(description="Analyze local email samples without opening links or executing attachments.")
    parser.add_argument("paths", type=Path, nargs="*", help="EML or TXT files; defaults to the bundled samples")
    parser.add_argument("--output-dir", type=Path, help="Write one JSON report per input instead of printing it")
    parser.add_argument("--macro-file", type=Path, help="Optional locally supplied file for static macro inspection")
    parser.add_argument("--simulated", action="store_true", help="Mark explicitly supplied samples as simulations")
    args = parser.parse_args()
    paths = args.paths or sorted(SAMPLES.glob("*.eml"))
    if not paths:
        parser.error("no samples found")
    if args.macro_file and len(paths) != 1:
        parser.error("--macro-file requires exactly one email or text input")
    status = 0
    for path in paths:
        try:
            if path.suffix.lower() not in {".eml", ".txt"}:
                raise ValueError("expected an .eml or .txt file")
            provenance = "simulated" if args.simulated or path.resolve().parent == SAMPLES else "observed"
            report = analyze_sample(path, provenance, args.macro_file)
            if report["parsed"]["parse_errors"]:
                status = 1
                print(f"{path}: {'; '.join(report['parsed']['parse_errors'])}", file=sys.stderr)
            if args.output_dir:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                destination = args.output_dir / (path.name + ".json")
                with destination.open("x", encoding="utf-8") as stream:
                    json.dump(report, stream, indent=2)
                    stream.write("\n")
                print(destination)
            else:
                print(json.dumps(report))
        except (OSError, ValueError) as error:
            print(f"{path}: {error}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
