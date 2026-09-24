#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.

import sys
import json
import os
import signal
import time

sys.path.insert(0, '/opt/opensiem')


def _timeout_handler(signum, frame):
    raise TimeoutError("Test timed out after 15 seconds")


def _test_local(config: dict) -> dict:
    path   = config.get('path', '').strip()
    steps  = []
    result = {'ok': False, 'steps': steps, 'available_bytes': None, 'error': None}

    if not path:
        result['error'] = 'Path is required'
        steps.append({'step': 'path_check', 'ok': False, 'msg': result['error']})
        return result

    # Check existence — do NOT try to create it during a test
    if not os.path.isdir(path):
        result['error'] = f"Path does not exist: {path}"
        steps.append({'step': 'path_check', 'ok': False, 'msg': result['error']})
        steps.append({'step': 'hint', 'ok': False,
                      'msg': f"Create it first:  sudo mkdir -p {path} && sudo chown www-data:www-data {path}"})
        return result
    steps.append({'step': 'path_check', 'ok': True})

    if not os.access(path, os.W_OK):
        result['error'] = f"No write permission on: {path}"
        steps.append({'step': 'permission_check', 'ok': False, 'msg': result['error']})
        steps.append({'step': 'hint', 'ok': False,
                      'msg': f"Fix with:  sudo chown www-data:www-data {path}"})
        return result
    steps.append({'step': 'permission_check', 'ok': True})

    # Write test
    test_file = os.path.join(path, '_opensiem_connection_test.tmp')
    payload   = b'opensiem-archive-test-' + str(time.time()).encode()
    t0 = time.monotonic()
    try:
        with open(test_file, 'wb') as f:
            f.write(payload)
        ms = round((time.monotonic() - t0) * 1000)
        steps.append({'step': 'write', 'ok': True, 'ms': ms})
    except Exception as e:
        result['error'] = f"Write failed: {e}"
        steps.append({'step': 'write', 'ok': False, 'msg': str(e)})
        return result

    # Read back
    t0 = time.monotonic()
    try:
        with open(test_file, 'rb') as f:
            data = f.read()
        ms = round((time.monotonic() - t0) * 1000)
        if data != payload:
            result['error'] = 'Read data did not match written data'
            steps.append({'step': 'read', 'ok': False, 'msg': result['error']})
            return result
        steps.append({'step': 'read', 'ok': True, 'ms': ms})
    except Exception as e:
        result['error'] = f"Read failed: {e}"
        steps.append({'step': 'read', 'ok': False, 'msg': str(e)})
        return result

    # Delete
    try:
        os.remove(test_file)
        steps.append({'step': 'delete', 'ok': True})
    except Exception as e:
        steps.append({'step': 'delete', 'ok': False, 'msg': str(e)})

    # Available space — use a short timeout in case statvfs blocks
    try:
        stat = os.statvfs(path)
        available = stat.f_bavail * stat.f_frsize
        result['available_bytes'] = available
        steps.append({'step': 'space_check', 'ok': True,
                      'available_gb': round(available / (1024**3), 2)})
    except Exception as e:
        steps.append({'step': 'space_check', 'ok': False, 'msg': str(e)})

    result['ok'] = True
    return result


def _test_sftp(config: dict, credentials: dict) -> dict:
    try:
        from archive_storage import SFTPStorageBackend
        backend = SFTPStorageBackend(config, credentials)
        return backend.test_connection()
    except ImportError:
        return {'ok': False, 'error': 'archive_storage.py not found at /opt/opensiem/', 'steps': []}
    except Exception as e:
        return {'ok': False, 'error': str(e), 'steps': []}


def _test_s3(config: dict, credentials: dict) -> dict:
    try:
        from archive_storage import S3StorageBackend
        backend = S3StorageBackend(config, credentials)
        return backend.test_connection()
    except ImportError:
        return {'ok': False, 'error': 'archive_storage.py not found at /opt/opensiem/', 'steps': []}
    except Exception as e:
        return {'ok': False, 'error': str(e), 'steps': []}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'ok': False, 'error': 'No config file argument', 'steps': []}))
        sys.exit(1)

    config_path = sys.argv[1]
    try:
        with open(config_path, 'r') as f:
            payload = json.load(f)
    except Exception as e:
        print(json.dumps({'ok': False, 'error': f'Cannot read config: {e}', 'steps': []}))
        sys.exit(1)

    backend_type = payload.get('backend_type', '')
    config       = payload.get('config', {})
    credentials  = payload.get('credentials', {})

    if not backend_type:
        print(json.dumps({'ok': False, 'error': 'backend_type is required', 'steps': []}))
        sys.exit(1)

    # Hard 15-second timeout so PHP never hits a gateway timeout
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(15)

    try:
        if backend_type == 'local':
            result = _test_local(config)
        elif backend_type == 'sftp':
            result = _test_sftp(config, credentials)
        elif backend_type == 's3':
            result = _test_s3(config, credentials)
        else:
            result = {'ok': False, 'error': f'Unknown backend_type: {backend_type}', 'steps': []}
    except TimeoutError as e:
        result = {'ok': False, 'error': str(e), 'steps': [],
                  'hint': 'The test timed out. Check that the path/host is reachable.'}
    except Exception as e:
        result = {'ok': False, 'error': str(e), 'steps': []}
    finally:
        signal.alarm(0)

    if result.get('available_bytes') is not None:
        result['available_gb'] = round(result['available_bytes'] / (1024**3), 2)

    print(json.dumps(result))


if __name__ == '__main__':
    main()