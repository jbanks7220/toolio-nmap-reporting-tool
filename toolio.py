#!/usr/bin/env python3
"""
toolio.py
A single-file automated nmap scanning + reporting tool suitable for a GitHub portfolio.

Features:
- Run nmap scans (requires nmap installed on the system)
- Parallel scans for multiple targets
- Save raw XML output per-target and a combined JSON and HTML report
- Simple, clean HTML report and a Markdown summary ready for a README
- CLI with sensible defaults and customization

Usage examples:
  python3 toolio.py --targets 192.168.1.1,scanme.nmap.org --ports 22,80,443 --scan-type "-sS -Pn" --threads 4
  python3 toolio.py --targets-file targets.txt --top-ports 1000

Author: Jamir Banks
"""

import argparse
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import json
import multiprocessing
import os
import sys
import datetime
from html import escape


def run_nmap(target: str, ports: str, scan_type: str, extra_args: str, output_dir: str) -> dict:
    """
    Run nmap against a single target and return a parsed result dict.
    Saves raw XML to output_dir/{target}.xml
    """
    safe_target = target.replace("/", "_").replace(":", "_")
    xml_path = os.path.join(output_dir, f"{safe_target}.xml")
    cmd = ["nmap"]

    # user-supplied scan_type might include multiple flags; split safely
    if scan_type:
        cmd.extend(scan_type.split())

    if ports:
        cmd.extend(["-p", ports])

    if extra_args:
        cmd.extend(extra_args.split())

    cmd.extend(["-oX", xml_path, target])

    print(f"[+] Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except FileNotFoundError:
        print("ERROR: nmap binary not found. Please install nmap and ensure it's in your PATH.")
        sys.exit(2)

    if proc.returncode not in (0, 1):
        # nmap returns 1 when host is down/unreachable; treat as non-fatal
        print(f"[!] nmap returned non-zero exit code {proc.returncode} for {target}")

    # if xml not written, try to capture
    if not os.path.exists(xml_path):
        # fallback: write stdout if it contains XML
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(proc.stdout)

    parsed = parse_nmap_xml(xml_path)
    parsed["_meta"] = {
        "target": target,
        "cmd": ' '.join(cmd),
        "returncode": proc.returncode,
        "stderr": proc.stderr,
        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
        "xml_path": xml_path,
    }
    return parsed


def parse_nmap_xml(xml_path: str) -> dict:
    """
    Parse nmap XML into a structured dict with hosts and ports information.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        print(f"[!] Failed to parse XML at {xml_path}")
        return {"hosts": []}

    ns = ''
    # find all host elements
    hosts = []
    for h in root.findall('host'):
        host_dict = {}
        # addresses
        addrs = h.findall('address')
        addresses = []
        for a in addrs:
            addresses.append({
                'addr': a.get('addr'),
                'addrtype': a.get('addrtype')
            })
        host_dict['addresses'] = addresses

        # hostnames
        hostnames = []
        hn = h.find('hostnames')
        if hn is not None:
            for nm in hn.findall('hostname'):
                hostnames.append({'name': nm.get('name'), 'type': nm.get('type')})
        host_dict['hostnames'] = hostnames

        # status
        status = h.find('status')
        host_dict['status'] = status.get('state') if status is not None else 'unknown'

        # ports
        ports_list = []
        ports = h.find('ports')
        if ports is not None:
            for p in ports.findall('port'):
                p_dict = {
                    'protocol': p.get('protocol'),
                    'portid': p.get('portid')
                }
                state = p.find('state')
                service = p.find('service')
                if state is not None:
                    p_dict['state'] = state.get('state')
                    p_dict['reason'] = state.get('reason')
                if service is not None:
                    p_dict['service'] = {k: v for k, v in service.attrib.items()}
                # scripts output
                script_outputs = []
                for s in p.findall('script'):
                    script_outputs.append({'id': s.get('id'), 'output': s.get('output')})
                if script_outputs:
                    p_dict['scripts'] = script_outputs
                ports_list.append(p_dict)
        host_dict['ports'] = ports_list

        # os (simple)
        os_el = h.find('os')
        os_matches = []
        if os_el is not None:
            for m in os_el.findall('osmatch'):
                os_matches.append({'name': m.get('name'), 'accuracy': m.get('accuracy')})
        if os_matches:
            host_dict['os'] = os_matches

        # host scripts
        host_scripts = []
        for hs in h.findall('hostscript'):
            for s in hs.findall('script'):
                host_scripts.append({'id': s.get('id'), 'output': s.get('output')})
        if host_scripts:
            host_dict['host_scripts'] = host_scripts

        hosts.append(host_dict)

    return {'hosts': hosts}


def generate_html_report(results: list, out_path: str, title: str):
    """
    Create a single-file HTML report summarizing all results.
    """
    now = datetime.datetime.utcnow().isoformat() + 'Z'
    html_parts = [
        '<!doctype html>',
        '<html lang="en">',
        '<head>',
        '  <meta charset="utf-8"/>',
        f'  <title>{escape(title)}</title>',
        '  <meta name="viewport" content="width=device-width, initial-scale=1"/>',
        '  <style>',
        '    body{font-family: system-ui, -apple-system, \"Segoe UI\", Roboto, Arial; padding:20px;}',
        '    .card{border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,0.08);padding:12px;margin:12px 0}',
        '    h1,h2{margin:8px 0}',
        '    table{width:100%;border-collapse:collapse}',
        '    th,td{padding:6px;border-bottom:1px solid #eee;text-align:left;font-size:13px}',
        '    .state-open{color:green;font-weight:600}',
        '    .state-closed{color:#888}',
        '    .meta{font-size:12px;color:#666}',
        '    pre{background:#f8f8f8;padding:8px;border-radius:6px;overflow:auto}',
        '  </style>',
        '</head>',
        '<body>',
        f'<h1>{escape(title)}</h1>',
        f'<p class="meta">Generated: {now} — {len(results)} target(s)</p>'
    ]

    for res in results:
        meta = res.get('_meta', {})
        target = meta.get('target', 'unknown')
        html_parts.append(f'<div class="card"><h2>{escape(target)}</h2>')
        html_parts.append('<p class="meta">')
        html_parts.append(f'Cmd: <code>{escape(meta.get("cmd",""))}</code><br/>')
        html_parts.append(f'Return code: {meta.get("returncode")}, xml: {escape(meta.get("xml_path",""))}</p>')

        hosts = res.get('hosts', [])
        if not hosts:
            html_parts.append('<p>No hosts found in XML output.</p>')
        for h in hosts:
            # addresses
            if h.get('addresses'):
                addrs = ', '.join([escape(a['addr']) for a in h['addresses'] if a.get('addr')])
                html_parts.append(f'<p><strong>Addresses:</strong> {addrs}</p>')
            if h.get('hostnames'):
                names = ', '.join([escape(n['name']) for n in h['hostnames'] if n.get('name')])
                html_parts.append(f'<p><strong>Hostnames:</strong> {names}</p>')
            html_parts.append(f'<p><strong>Status:</strong> {escape(h.get("status","unknown"))}</p>')

            # ports summary table
            ports = h.get('ports', [])
            if ports:
                html_parts.append('<table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Notes</th></tr></thead><tbody>')
                for p in ports:
                    state = p.get('state','')
                    state_class = 'state-open' if state == 'open' else 'state-closed'
                    service = p.get('service', {})
                    serv_str = escape(service.get('name','') if isinstance(service, dict) else str(service))
                    notes = ''
                    if p.get('scripts'):
                        notes = '; '.join([escape(f"{s['id']}: {s.get('output','')}") for s in p['scripts']])
                    html_parts.append(f"<tr><td>{escape(p.get('portid',''))}</td><td>{escape(p.get('protocol',''))}</td><td class=\"{state_class}\">{escape(state)}</td><td>{serv_str}</td><td>{notes}</td></tr>")
                html_parts.append('</tbody></table>')

            # os
            if h.get('os'):
                html_parts.append('<p><strong>OS matches:</strong> ' + ', '.join([escape(m['name']) + f" ({m.get('accuracy')}%)" for m in h['os']]) + '</p>')

            if h.get('host_scripts'):
                html_parts.append('<h3>Host script output</h3>')
                for s in h['host_scripts']:
                    html_parts.append(f"<h4>{escape(s.get('id',''))}</h4><pre>{escape(s.get('output',''))}</pre>")

        html_parts.append('</div>')

    html_parts.append('</body></html>')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html_parts))

    print(f"[+] HTML report written to {out_path}")


def save_json(results: list, out_path: str):
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"[+] JSON saved to {out_path}")


def load_targets_from_file(path: str) -> list:
    with open(path, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    return lines


def worker_task(args_tuple):
    target, ports, scan_type, extra_args, output_dir = args_tuple
    return run_nmap(target, ports, scan_type, extra_args, output_dir)


def make_markdown_summary(results: list, out_path: str, title: str):
    md = [f"# {title}", '', f"Generated: {datetime.datetime.utcnow().isoformat()}Z", '']
    for res in results:
        meta = res.get('_meta', {})
        target = meta.get('target')
        md.append(f"## {target}")
        md.append(f"- Command: `{meta.get('cmd')}`")
        hosts = res.get('hosts', [])
        if not hosts:
            md.append('- No hosts found')
            continue
        for h in hosts:
            md.append(f"- Addresses: {', '.join([a['addr'] for a in h.get('addresses', []) if a.get('addr')])}")
            md.append(f"  - Status: {h.get('status')}")
            if h.get('ports'):
                open_ports = [p for p in h['ports'] if p.get('state') == 'open']
                if open_ports:
                    md.append('  - Open ports:')
                    for p in open_ports:
                        md.append(f"    - {p.get('portid')}/{p.get('protocol')} — {p.get('service', {}).get('name','')}")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md))
    print(f"[+] Markdown summary written to {out_path}")


def main():
    parser = argparse.ArgumentParser(description='nmap-report-tool — run nmap and produce reports')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--targets', help='Comma-separated targets (ips/hosts)')
    group.add_argument('--targets-file', help='File with newline-separated targets')
    parser.add_argument('--ports', help='Ports list (eg "1-1000" or "22,80,443")', default=None)
    parser.add_argument('--top-ports', type=int, help='Scan N top ports using --top-ports', default=None)
    parser.add_argument('--scan-type', help='Extra nmap flags for scan type (eg "-sS -Pn")', default='-sS -Pn')
    parser.add_argument('--extra-args', help='Any extra nmap args (eg "-sV --script vuln")', default='')
    parser.add_argument('--output-dir', '-o', help='Directory to put outputs', default='nmap_reports')
    parser.add_argument('--threads', '-t', type=int, help='Parallel scans', default=4)
    parser.add_argument('--title', help='Report title', default='nmap report')
    args = parser.parse_args()

    # prepare targets
    if args.targets:
        targets = [t.strip() for t in args.targets.split(',') if t.strip()]
    else:
        targets = load_targets_from_file(args.targets_file)

    if not targets:
        print('No targets supplied. Exiting.')
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # build port argument
    ports = args.ports
    if args.top_ports:
        ports = f'--top-ports {args.top_ports}'

    # prepare worker args
    work_args = [(t, ports, args.scan_type, args.extra_args, args.output_dir) for t in targets]

    results = []
    # use multiprocessing Pool for parallelism
    pool_size = max(1, min(args.threads, len(work_args)))
    print(f"[+] Starting scans: {len(work_args)} target(s) with {pool_size} worker(s)")
    if pool_size == 1:
        for wa in work_args:
            results.append(worker_task(wa))
    else:
        with multiprocessing.Pool(processes=pool_size) as pool:
            for r in pool.imap_unordered(worker_task, work_args):
                results.append(r)

    # outputs
    timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    json_path = os.path.join(args.output_dir, f'report_{timestamp}.json')
    html_path = os.path.join(args.output_dir, f'report_{timestamp}.html')
    md_path = os.path.join(args.output_dir, f'report_{timestamp}.md')

    save_json(results, json_path)
    generate_html_report(results, html_path, args.title)
    make_markdown_summary(results, md_path, args.title)

    print('[+] Done.')


if __name__ == '__main__':
    main()
