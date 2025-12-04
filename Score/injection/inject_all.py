#!/usr/bin/env python3
import os
import glob
import time
import configparser
import solidifi

BUG_TYPES_CONF = 'configs/bug_types.conf'
CONTRACTS_DIR = 'contracts'


def load_bug_types(conf_file=BUG_TYPES_CONF):
    cfg = configparser.RawConfigParser()
    cfg.read(conf_file)
    types = []
    for section in cfg.sections():
        types.append(cfg.get(section, 'bug_type'))
    return types


def find_contracts(dir=CONTRACTS_DIR):
    return sorted([p for p in glob.glob(os.path.join(dir, '*.sol'))])


def inject_all():
    bug_types = load_bug_types()
    contracts = find_contracts()
    if not contracts:
        print('No contracts found in', CONTRACTS_DIR)
        return

    total = len(bug_types) * len(contracts)
    i = 0
    for bug in bug_types:
        print('\n== Injecting bug type:', bug, '==')
        for c in contracts:
            i += 1
            print(f'[{i}/{total}] Injecting {bug} into {c}...')
            try:
                t0 = time.time()
                solidifi.interior_main('-i', c, bug)
                print('  -> done (%.2fs)' % (time.time()-t0))
            except Exception as e:
                print('  -> ERROR:', e)

    print('\nAll injections attempted. Check the `buggy/` directory for output.')


if __name__ == '__main__':
    inject_all()
