"""
build_modules.py -- Split the master AED into self-contained vulnerability modules.

Every module holds the actions of one attack path of one expert CVE, copied verbatim
from the master AED, so planning on the modules gives the same attack paths as
planning on the master AED (RQ1-RQ3 rely on this; see ModularEADSA). Two module sets
are written, one per master:

    default/<CVE>/<AP>.pddl   from Knowledge/AED:AEDI/Adversarial_Environment_Domain.pddl
    nodyPa/<CVE>/<AP>.pddl    from Knowledge/AED:AEDI/Adversarial_Environment_Domain_nodyPa.pddl

Which actions form which attack path is taken from the expert-authored attack paths of
the vulnerability-scalability workflow (pddl-ap-passall/post-proposs/expert-authored);
only the action names are read from there, never the action bodies, because those
were rewritten by that workflow. A package without that workflow (TeaStore) reads the
split from its own default/ modules instead; its master AED is identical to SEFA's.

A module keeps the shared types and constants and declares only the predicates and
functions its actions use. The CVE's entry action is enabled exactly as
AED_Processor.AED_process enables it. The master defines a few action names twice with
different bodies; both definitions are kept, as the master AED does.

Run from this directory:
    python3 build_modules.py
"""

import re
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIMULATOR = HERE.parent.parent
MASTERS = {
    'default': SIMULATOR / 'src' / 'main' / 'java' / 'saqure' / 'Knowledge' / 'AED:AEDI' / 'Adversarial_Environment_Domain.pddl',
    'nodyPa': SIMULATOR / 'src' / 'main' / 'java' / 'saqure' / 'Knowledge' / 'AED:AEDI' / 'Adversarial_Environment_Domain_nodyPa.pddl',
}
SPLIT_SOURCES = [
    SIMULATOR.parent / 'SAQURE-vulnerability-scalability' / 'pddl-ap-passall' / 'post-proposs' / 'expert-authored',
    HERE / 'default',
]

START, END = ';;@start vulnerability expose@;;', ';;@end vulnerability expose@;;'

# Attack paths the master AED contains but the expert-authored split lacks. CVE-2023-2976's
# three paths end in tampering (AP1) or information disclosure (AP2, AP3); the master also lets
# the disclosed data be used to log in, which ends in spoofing. AP4 is that path: the plan
# Metric-FF finds on the master AED with only CVE-2023-2976 exposed and spoofing as the target
# (TeaStore exposes CVE-2023-2976; SEFA does not).
SUPPLEMENTARY_APS = {
    'CVE-2023-2976': {
        'AP4': [
            'application-exposes-attack-surfaces-to-attackers-cve-2023-2976',
            'attacker-identifies-application-default-java-temp-directory',
            'attacker-predicts-temp-file-naming-pattern',
            'attacker-creates-symbolic-link-to-attacker-controlled-file',
            'user-triggers-filebackedoutputstream-functionality-buffers-data',
            'application-creates-temp-file-resolving-to-symlink',
            'application-writes-data-into-resolved-attacker-controlled-file',
            'attacker-receives-sensitive-information',
            'attacker-uses-user-credentials-login-target-application',
        ],
    },
}

# Steps the master AED needs to finish an expert-authored path. The scalability workflow
# rewrote the last step of these two DoS paths to produce denial-of-service itself; in the
# master, resource exhaustion only yields resource-exhausted, and application-becomes-
# unresponsive turns that into denial-of-service. Without it neither path reaches its target.
SUPPLEMENTARY_ACTIONS = {
    'CVE-2023-44487': {'AP1': ['application-becomes-unresponsive']},
    'CVE-2024-38809': {'AP1': ['application-becomes-unresponsive']},
}

# The expert-authored attack paths renamed these actions; map them back to the master.
RENAMED = {
    'application-prompts-malicious-script-execution': 'application-prompt-malicious-script-execution',
    'application-resource-exhausts': 'application-suffers-resource-exhaustion',
    'application-writes-data-into-resolved-sensitive-file': 'application-writes-data-into-resolved-sensitive-file-',
    'attacker-creates-malicious-script-tampering-env-var-as-malicious-logback-url': 'attacker-creates-malicious-script-tampering-env-var-as-malicious-url',
    'dns-infrastructure-exposes-attack-surface-to-attackers': 'dns-infrastructure-exposes-attack-surfaces-to-attackers',
    'user-confirms-malicious-script-execution': 'user-confirm-malicious-script-execution',
    'user-double-clicks-download-script': 'user-double-click-download-script',
}


# ── AED_Processor.AED_process, line for line ─────────────────────────────────

def aed_process(lines, cve_ids):
    commented, inside = [], False
    for line in lines:
        t = line.strip()
        if START in t:
            inside = True
        commented.append((line if line.startswith(';') else ';' + line) if inside else line)
        if END in t:
            inside = False
    out, in_target = [], False
    for i, line in enumerate(commented):
        t = line.strip()
        if START in t:
            cve = None
            for j in range(i + 1, min(i + 6, len(commented))):
                prev = commented[j].strip()
                if re.match(r';?\(:action.*', prev):
                    cve = next((c for c in cve_ids if c in prev), None)
                    break
            in_target = cve is not None
        if in_target:
            out.append(line if line == START else (line[1:] if line.startswith(';') else line))
            if END in t:
                in_target = False
        else:
            out.append(line)
    return out


# ── Parsing helpers ──────────────────────────────────────────────────────────

def strip_comments(text):
    return '\n'.join(re.sub(r';.*$', '', l).rstrip() for l in text.split('\n'))


def balanced(text, start):
    depth = 0
    for k in range(start, len(text)):
        if text[k] == '(':
            depth += 1
        elif text[k] == ')':
            depth -= 1
            if depth == 0:
                return k + 1
    raise ValueError(f'unbalanced parentheses from offset {start}')


def split_domain(text):
    """(header, {action name: [bodies]}) of a domain with the comments removed."""
    clean = strip_comments(text)
    first = clean.find('(:action')
    header, actions, pos = clean[:first], {}, first
    while (k := clean.find('(:action', pos)) >= 0:
        e = balanced(clean, k)
        name = re.match(r'\(:action\s+(\S+)', clean[k:]).group(1).lower()
        actions.setdefault(name, []).append(clean[k:e])
        pos = e
    return header, actions


def trim_vocabulary(header, blocks):
    """Declare only the predicates and functions the given action bodies use."""
    used = {t.lower() for b in blocks for t in re.findall(r'\(\s*([a-zA-Z][\w-]*)', b)} | {'total-cost'}
    for sec in ('predicates', 'functions'):
        m = re.search(r'\(:' + sec + r'\b', header)
        if not m:
            continue
        e = balanced(header, m.start())
        inner = header[m.start() + len('(:' + sec):e - 1]
        kept = [' '.join(d.split()) for d in re.findall(r'\(([^()]*)\)', inner)
                if d.split() and d.split()[0].lower() in used]
        header = header[:m.start()] + f'(:{sec}\n    (' + ')\n    ('.join(kept) + ')\n  )' + header[e:]
    return re.sub(r'\n\s*\n+', '\n', header)


def attack_path_actions(path):
    names = []
    for n in re.findall(r'\(:action\s+(\S+)', strip_comments(path.read_text())):
        n = RENAMED.get(n.lower(), n.lower())
        if n not in names:
            names.append(n)
    return names


# ── Build ────────────────────────────────────────────────────────────────────

def read_split():
    """{CVE: {attack path: [action names]}}, read before any module is rewritten."""
    source = next((s for s in SPLIT_SOURCES if s.is_dir()), None)
    if source is None:
        raise SystemExit(f'No attack-path split found in {[str(s) for s in SPLIT_SOURCES]}')
    print(f'attack-path split read from {source}')
    split = {cve_dir.name: {ap.stem: attack_path_actions(ap) for ap in sorted(cve_dir.glob('*.pddl'))}
             for cve_dir in sorted(p for p in source.iterdir() if p.is_dir())}
    for cve, aps in SUPPLEMENTARY_APS.items():
        split.setdefault(cve, {}).update(aps)
    for cve, aps in SUPPLEMENTARY_ACTIONS.items():
        for ap, extra in aps.items():
            split[cve][ap] = split[cve][ap] + [n for n in extra if n not in split[cve][ap]]
    return split


def build(variant, master, split):
    lines = master.read_text().split('\n')
    out_root = HERE / variant
    if out_root.exists():
        shutil.rmtree(out_root)
    covered, n_modules = set(), 0
    for cve, aps in split.items():
        header, actions = split_domain('\n'.join(aed_process(lines, [cve])))
        for ap_name, names in aps.items():
            missing = [n for n in names if n not in actions]
            if missing:
                raise SystemExit(f'{cve}/{ap_name}: not enabled in the master AED: {missing}')
            blocks = [b for n in names for b in actions[n]]
            covered.update(names)
            text = (f'; Vulnerability module {cve}/{ap_name}, generated by build_modules.py from\n'
                    f'; {master.name}. Do not edit by hand; rerun the script instead.\n'
                    + trim_vocabulary(header, blocks).strip() + '\n\n'
                    + '\n\n'.join(blocks) + '\n)\n')
            target = out_root / cve / f'{ap_name}.pddl'
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
            n_modules += 1
    all_actions = set(split_domain('\n'.join(aed_process(lines, sorted(split))))[1])
    uncovered = sorted(all_actions - covered)
    print(f'{variant}: {n_modules} modules, {len(covered)} distinct actions; '
          f'master actions in no module: {uncovered or "none"}')


if __name__ == '__main__':
    split = read_split()
    for variant, master in MASTERS.items():
        build(variant, master, split)
