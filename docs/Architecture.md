# Toolio.py — Architecture Overview

Toolio is a Python-based automated Nmap scanning and reporting tool designed for network reconnaissance, result aggregation, and multi-format reporting. The architecture is modular, leveraging Python’s standard libraries for automation, parallelism, and file handling.

## 1. Command-Line Interface (CLI)

Module: argparse

Purpose: Accepts user input for targets, ports, scan type, threads, output directory, and report title.

Functionality:

Supports single or multiple targets (--targets, --targets-file)

Configurable ports (--ports, --top-ports) and scan types (--scan-type, --extra-args)

Sets defaults for parallel execution and report formatting

Example:
```
python3 toolio.py --targets scanme.nmap.org --ports 22,80,443 --scan-type "-sS -Pn" --threads 4
```

## 2. Nmap Execution

Function: run_nmap(target, ports, scan_type, extra_args, output_dir)

Module: subprocess, os

Purpose: Executes Nmap scans safely for each target and writes raw XML output.

Key Points:

Cleans target names for file safety

Builds command dynamically using user-supplied flags

Captures stdout/stderr for logging and error handling

Treats host-unreachable (returncode = 1) as non-fatal

Output: XML file per target in reports/

## 3. XML Parsing

Function: parse_nmap_xml(xml_path)

Module: xml.etree.ElementTree

Purpose: Converts Nmap XML output into a structured Python dictionary.

Details:

Extracts hosts, addresses, hostnames, port information, service details, OS matches, and script outputs

Handles missing elements gracefully

Output: Dictionary for each target, ready for reporting

## 4. Parallel Execution

Module: multiprocessing

Function: worker_task(args_tuple)

Purpose: Allows multiple scans to run concurrently for faster execution.

Details:

Uses a Pool of worker processes

Each worker executes run_nmap independently

Combines results in a single list for reporting

## 5. Reporting

Modules: json, html, datetime

Functions:

save_json(results, out_path) → Structured JSON output

generate_html_report(results, out_path, title) → Clean, single-page HTML report

make_markdown_summary(results, out_path, title) → GitHub-ready Markdown summary

Details:

HTML uses simple inline CSS for readability

Markdown provides quick summaries with open ports and host info

JSON preserves full scan data for programmatic use

## 6. Metadata Management

Each scan result includes a _meta dictionary:

Target, executed command, return code, timestamp, XML path, and stderr

Enables traceability and debugging of scans

## 7. Execution Flow

Parse CLI arguments and validate targets

Prepare output directories

Build per-target scan arguments

Execute Nmap scans in parallel (or sequentially if one target)

Parse XML results into structured dictionaries

Generate JSON, HTML, and Markdown reports

Print completion status

## 8. Design Principles

Modular: Clear separation of scanning, parsing, and reporting

Robust: Handles unreachable hosts and malformed XML gracefully

Extensible: Easy to add new reporting formats or Nmap flags

Beginner-Friendly: Uses only standard Python libraries
