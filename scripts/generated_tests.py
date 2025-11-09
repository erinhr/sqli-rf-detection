# scripts/generate_tests.py
import argparse
import sys
import pathlib

def find_endpoints(base: pathlib.Path) -> pathlib.Path | None:
    # Kandidat lokasi relatif ke base
    candidates = [
        base / "data" / "endpoints.txt",
        base.parent / "data" / "endpoints.txt",
        base / "data" / "endpoints/endpoints.txt",
    ]
    # naik beberapa level sambil cari resources/endpoints.txt
    p = base
    for _ in range(3):
        candidates.append(p / "data" / "endpoints.txt")
        p = p.parent

    for c in candidates:
        if c.is_file():
            return c
    return None

HEADER = """
*** Settings ***
Resource          ${CURDIR}/../resources/variables.resource
Resource          ${CURDIR}/../resources/auth_keywords.resource
Resource          ${CURDIR}/../resources/sqli_keywords.resource
Suite Setup       Initialize Suite
Suite Teardown    Finalize SQLi Report

*** Test Cases ***
"""

def parse_line(ln: str):
    s = ln.strip()
    if not s or s.startswith("#"):
        return None
    parts = [p.strip() for p in s.split("|")]
    if len(parts) < 4:
        return None
    method, endpoint, where, param = parts[:4]
    auth = parts[4] if len(parts) >= 5 and parts[4] else "none"
    auth_param = parts[5] if len(parts) >= 6 else ""
    return method, endpoint, where, param, auth, auth_param

def case_name(method: str, endpoint: str, where: str, param: str) -> str:
    return f"{method} {endpoint} [{where}:{param}]"

def ep_pipe_line(m, ep, w, p, a, ap) -> str:
    return f"{m}|{ep}|{w}|{p}|{a}|{ap}"

def main():
    parser = argparse.ArgumentParser(description="Generate Robot tests from endpoints.txt")
    parser.add_argument("--base", type=pathlib.Path, default=None,
                        help="Project base dir (default: parent of this script)")
    parser.add_argument("--endpoints", type=pathlib.Path, default=None,
                        help="Path to resources/endpoints.txt")
    parser.add_argument("--out", type=pathlib.Path, default=None,
                        help="Output .robot file (default: tests/generated_tests.robot)")
    args = parser.parse_args()

    # Base project dir
    if args.base:
        base = args.base.resolve()
    else:
        base = pathlib.Path(__file__).resolve().parent.parent  # <repo>/scripts/.. = <repo>
    res = base / "resources"
    tests = base / "tests"

    # endpoints.txt
    if args.endpoints:
        endpoints_file = args.endpoints.resolve()
    else:
        endpoints_file = find_endpoints(base)  # try to auto-detect

    if not endpoints_file or not endpoints_file.is_file():
        tried = [
            str(base / "resources" / "endpoints.txt"),
            str(base.parent / "resources" / "endpoints.txt"),
            str(base / "resources" / "endpoints/endpoints.txt"),
        ]
        # plus the 3-level walk
        p = base
        for _ in range(3):
            tried.append(str(p / "resources" / "endpoints.txt"))
            p = p.parent

        msg = ["endpoints.txt tidak ditemukan. Coba salah satu solusi:",
               f"- Pastikan file ada: {base}/resources/endpoints.txt",
               "- Atau jalankan dengan argumen: --endpoints /path/ke/endpoints.txt",
               "",
               "Lokasi yang sudah dicoba:"]
        msg += [f"  - {t}" for t in tried]
        print("\n".join(msg), file=sys.stderr)
        sys.exit(1)

    # output file
    out_file = args.out.resolve() if args.out else (tests / "generated_tests.robot")

    # Parse file
    rows = []
    with endpoints_file.open(encoding="utf-8") as f:
        for raw in f:
            parsed = parse_line(raw)
            if parsed is None:
                continue
            rows.append(parsed)

    # Build body
    body_lines = []
    for m, ep, w, p, a, ap in rows:
        name = case_name(m, ep, w, p)
        pipe = ep_pipe_line(m, ep, w, p, a, ap)
        body_lines.append(name)
        body_lines.append(f"    Scan Endpoint For SQLi    {pipe}")
        body_lines.append("")

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        f.write(HEADER)
        f.write("\n".join(body_lines))

    print(f"Generated {out_file} with {len(rows)} test cases.")
    print(f"- Using endpoints: {endpoints_file}")
    print(f"- Project base:   {base}")

if __name__ == "__main__":
    main()
