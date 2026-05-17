#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.
#
# Called by api_archive_storage.php to test a storage backend connection.
# Reads JSON config from a temp file passed as argv[1], runs the test,
# prints JSON result to stdout.

import sys
import json
import os

sys.path.insert(0, '/opt/opensiem')

from archive_storage import get_backend


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'ok': False, 'error': 'No config file argument'}))
        sys.exit(1)

    config_path = sys.argv[1]
    try:
        with open(config_path, 'r') as f:
            payload = json.load(f)
    except Exception as e:
        print(json.dumps({'ok': False, 'error': f'Cannot read config: {e}'}))
        sys.exit(1)

    backend_type = payload.get('backend_type', '')
    config       = payload.get('config', {})
    credentials  = payload.get('credentials', {})

    if not backend_type:
        print(json.dumps({'ok': False, 'error': 'backend_type is required'}))
        sys.exit(1)

    try:
        backend = get_backend(backend_type, config, credentials)
        result  = backend.test_connection()
    except Exception as e:
        result = {'ok': False, 'error': str(e), 'steps': []}

    if result.get('available_bytes') is not None:
        result['available_gb'] = round(result['available_bytes'] / (1024**3), 2)

    print(json.dumps(result))


if __name__ == '__main__':
    main()
