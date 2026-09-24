#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.

import os
import io
import json
import time
import hashlib
import logging
import tempfile
from abc import ABC, abstractmethod
from typing import Optional
from datetime import datetime

log = logging.getLogger(__name__)

class StorageBackend(ABC):

    @abstractmethod
    def write(self, remote_path: str, data: bytes) -> bool:
        pass

    @abstractmethod
    def read(self, remote_path: str) -> Optional[bytes]:
        pass

    @abstractmethod
    def delete(self, remote_path: str) -> bool:
        pass

    @abstractmethod
    def exists(self, remote_path: str) -> bool:
        pass

    @abstractmethod
    def available_space_bytes(self) -> Optional[int]:
        pass

    @abstractmethod
    def test_connection(self) -> dict:
        pass

    def _make_test_result(self) -> dict:
        return {
            'ok': False,
            'steps': [],
            'available_bytes': None,
            'error': None,
            'latency_ms': {}
        }

    def _run_write_read_delete_test(self, test_path: str, payload: bytes) -> dict:
        result = self._make_test_result()
        steps  = result['steps']

        t0 = time.monotonic()
        try:
            ok = self.write(test_path, payload)
            ms = round((time.monotonic() - t0) * 1000)
            result['latency_ms']['write'] = ms
            if not ok:
                steps.append({'step': 'write', 'ok': False, 'msg': 'Write returned False'})
                result['error'] = 'Write failed'
                return result
            steps.append({'step': 'write', 'ok': True, 'ms': ms})
        except Exception as e:
            steps.append({'step': 'write', 'ok': False, 'msg': str(e)})
            result['error'] = f'Write error: {e}'
            return result

        t0 = time.monotonic()
        try:
            data = self.read(test_path)
            ms = round((time.monotonic() - t0) * 1000)
            result['latency_ms']['read'] = ms
            if data != payload:
                steps.append({'step': 'read', 'ok': False, 'msg': 'Data mismatch'})
                result['error'] = 'Read verification failed'
                return result
            steps.append({'step': 'read', 'ok': True, 'ms': ms})
        except Exception as e:
            steps.append({'step': 'read', 'ok': False, 'msg': str(e)})
            result['error'] = f'Read error: {e}'
            return result

        t0 = time.monotonic()
        try:
            self.delete(test_path)
            ms = round((time.monotonic() - t0) * 1000)
            result['latency_ms']['delete'] = ms
            steps.append({'step': 'delete', 'ok': True, 'ms': ms})
        except Exception as e:
            steps.append({'step': 'delete', 'ok': False, 'msg': str(e)})

        try:
            result['available_bytes'] = self.available_space_bytes()
            if result['available_bytes'] is not None:
                steps.append({
                    'step': 'space_check',
                    'ok': True,
                    'available_gb': round(result['available_bytes'] / (1024**3), 2)
                })
        except Exception:
            steps.append({'step': 'space_check', 'ok': False, 'msg': 'Could not determine available space'})

        result['ok'] = True
        return result


# Local / NFS backend

class LocalStorageBackend(StorageBackend):

    def __init__(self, config: dict):
        self.base_path = config['path'].rstrip('/\\')
        os.makedirs(self.base_path, exist_ok=True)

    def _full(self, remote_path: str) -> str:
        return os.path.join(self.base_path, remote_path.lstrip('/\\'))

    def write(self, remote_path: str, data: bytes) -> bool:
        full = self._full(remote_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = full + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, full)
        return True

    def read(self, remote_path: str) -> Optional[bytes]:
        full = self._full(remote_path)
        if not os.path.exists(full):
            return None
        with open(full, 'rb') as f:
            return f.read()

    def delete(self, remote_path: str) -> bool:
        full = self._full(remote_path)
        if os.path.exists(full):
            os.remove(full)
        return True

    def exists(self, remote_path: str) -> bool:
        return os.path.exists(self._full(remote_path))

    def available_space_bytes(self) -> Optional[int]:
        stat = os.statvfs(self.base_path)
        return stat.f_bavail * stat.f_frsize

    def test_connection(self) -> dict:
        result = self._make_test_result()
        steps  = result['steps']

        if not os.path.isdir(self.base_path):
            result['error'] = f"Path does not exist: {self.base_path}"
            steps.append({'step': 'path_check', 'ok': False, 'msg': result['error']})
            return result
        steps.append({'step': 'path_check', 'ok': True})

        if not os.access(self.base_path, os.W_OK):
            result['error'] = f"No write permission on: {self.base_path}"
            steps.append({'step': 'permission_check', 'ok': False, 'msg': result['error']})
            return result
        steps.append({'step': 'permission_check', 'ok': True})

        test_path = '_opensiem_connection_test.tmp'
        payload   = b'opensiem-archive-test-' + str(time.time()).encode()
        return self._run_write_read_delete_test(test_path, payload)


# SFTP backend

class SFTPStorageBackend(StorageBackend):

    def __init__(self, config: dict, credentials: dict):
        self.host       = config['host']
        self.port       = int(config.get('port', 22))
        self.username   = credentials.get('username', '')
        self.password   = credentials.get('password')
        self.key_path   = credentials.get('key_path')
        self.remote_base = config.get('remote_path', '/').rstrip('/')
        self._client    = None
        self._sftp      = None

    def _connect(self):
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("paramiko is required for SFTP: pip install paramiko")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            'hostname': self.host,
            'port':     self.port,
            'username': self.username,
            'timeout':  15,
        }
        if self.key_path and os.path.exists(self.key_path):
            connect_kwargs['key_filename'] = self.key_path
        elif self.password:
            connect_kwargs['password'] = self.password

        client.connect(**connect_kwargs)
        self._client = client
        self._sftp   = client.open_sftp()

    def _ensure_connected(self):
        if self._sftp is None:
            self._connect()

    def _remote(self, remote_path: str) -> str:
        return self.remote_base + '/' + remote_path.lstrip('/')

    def _mkdir_p(self, remote_dir: str):
        parts = remote_dir.split('/')
        path  = ''
        for part in parts:
            if not part:
                continue
            path += '/' + part
            try:
                self._sftp.stat(path)
            except IOError:
                try:
                    self._sftp.mkdir(path)
                except IOError:
                    pass

    def write(self, remote_path: str, data: bytes) -> bool:
        self._ensure_connected()
        full = self._remote(remote_path)
        self._mkdir_p(os.path.dirname(full))
        tmp = full + '.tmp'
        with self._sftp.open(tmp, 'wb') as f:
            f.write(data)
        try:
            self._sftp.remove(full)
        except IOError:
            pass
        self._sftp.rename(tmp, full)
        return True

    def read(self, remote_path: str) -> Optional[bytes]:
        self._ensure_connected()
        with self._sftp.open(self._remote(remote_path), 'rb') as f:
            return f.read()

    def delete(self, remote_path: str) -> bool:
        self._ensure_connected()
        try:
            self._sftp.remove(self._remote(remote_path))
        except IOError:
            pass
        return True

    def exists(self, remote_path: str) -> bool:
        self._ensure_connected()
        try:
            self._sftp.stat(self._remote(remote_path))
            return True
        except IOError:
            return False

    def available_space_bytes(self) -> Optional[int]:
        try:
            self._ensure_connected()
            stat = self._sftp.statvfs(self.remote_base)
            return stat.f_bavail * stat.f_frsize
        except Exception:
            return None

    def test_connection(self) -> dict:
        result = self._make_test_result()
        steps  = result['steps']

        t0 = time.monotonic()
        try:
            self._connect()
            ms = round((time.monotonic() - t0) * 1000)
            result['latency_ms']['connect'] = ms
            steps.append({'step': 'connect', 'ok': True, 'ms': ms})
        except Exception as e:
            steps.append({'step': 'connect', 'ok': False, 'msg': str(e)})
            result['error'] = f'Connection failed: {e}'
            return result

        try:
            self._sftp.stat(self.remote_base)
            steps.append({'step': 'remote_path_check', 'ok': True})
        except IOError as e:
            steps.append({'step': 'remote_path_check', 'ok': False,
                          'msg': f"Remote path not found: {self.remote_base}"})
            result['error'] = str(e)
            return result

        test_path = '_opensiem_connection_test.tmp'
        payload   = b'opensiem-archive-test-' + str(time.time()).encode()
        sub = self._run_write_read_delete_test(test_path, payload)
        result['steps']          += sub['steps']
        result['available_bytes'] = sub['available_bytes']
        result['latency_ms'].update(sub['latency_ms'])
        result['ok']    = sub['ok']
        result['error'] = sub['error']
        return result

    def __del__(self):
        try:
            if self._sftp:   self._sftp.close()
            if self._client: self._client.close()
        except Exception:
            pass

# S3-compatible backend

class S3StorageBackend(StorageBackend):

    def __init__(self, config: dict, credentials: dict):
        self.bucket       = config['bucket']
        self.prefix       = config.get('prefix', '').strip('/')
        self.region       = config.get('region', 'us-east-1')
        self.endpoint_url = config.get('endpoint_url') or None
        self.path_style   = config.get('path_style', False)
        self.access_key   = credentials.get('access_key_id', '')
        self.secret_key   = credentials.get('secret_access_key', '')
        self._client      = None

    def _get_client(self):
        if self._client:
            return self._client
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise RuntimeError("boto3 is required for S3: pip install boto3")

        kwargs = {
            'region_name':          self.region,
            'aws_access_key_id':    self.access_key,
            'aws_secret_access_key': self.secret_key,
        }
        if self.endpoint_url:
            kwargs['endpoint_url'] = self.endpoint_url
        if self.path_style:
            kwargs['config'] = Config(s3={'addressing_style': 'path'})

        import boto3
        self._client = boto3.client('s3', **kwargs)
        return self._client

    def _key(self, remote_path: str) -> str:
        if self.prefix:
            return self.prefix + '/' + remote_path.lstrip('/')
        return remote_path.lstrip('/')

    def write(self, remote_path: str, data: bytes) -> bool:
        self._get_client().put_object(
            Bucket=self.bucket,
            Key=self._key(remote_path),
            Body=data
        )
        return True

    def read(self, remote_path: str) -> Optional[bytes]:
        resp = self._get_client().get_object(
            Bucket=self.bucket,
            Key=self._key(remote_path)
        )
        return resp['Body'].read()

    def delete(self, remote_path: str) -> bool:
        self._get_client().delete_object(
            Bucket=self.bucket,
            Key=self._key(remote_path)
        )
        return True

    def exists(self, remote_path: str) -> bool:
        try:
            self._get_client().head_object(
                Bucket=self.bucket,
                Key=self._key(remote_path)
            )
            return True
        except Exception:
            return False

    def available_space_bytes(self) -> Optional[int]:
        return None

    def test_connection(self) -> dict:
        result = self._make_test_result()
        steps  = result['steps']

        t0 = time.monotonic()
        try:
            client = self._get_client()
            client.head_bucket(Bucket=self.bucket)
            ms = round((time.monotonic() - t0) * 1000)
            result['latency_ms']['connect'] = ms
            steps.append({'step': 'connect', 'ok': True, 'ms': ms})
        except Exception as e:
            msg = str(e)
            if '403' in msg or 'Forbidden' in msg:
                msg = 'Authentication failed — check access key and secret key'
            elif '404' in msg or 'NoSuchBucket' in msg:
                msg = f"Bucket not found: {self.bucket}"
            steps.append({'step': 'connect', 'ok': False, 'msg': msg})
            result['error'] = msg
            return result

        test_path = '_opensiem_connection_test.tmp'
        payload   = b'opensiem-archive-test-' + str(time.time()).encode()
        sub = self._run_write_read_delete_test(test_path, payload)
        result['steps']          += sub['steps']
        result['available_bytes'] = sub['available_bytes']
        result['latency_ms'].update(sub['latency_ms'])
        result['ok']    = sub['ok']
        result['error'] = sub['error']
        return result

# Factory

def get_backend(backend_type: str, config: dict,
                credentials: Optional[dict] = None) -> StorageBackend:
    creds = credentials or {}
    if backend_type == 'local':
        return LocalStorageBackend(config)
    if backend_type == 'sftp':
        return SFTPStorageBackend(config, creds)
    if backend_type == 's3':
        return S3StorageBackend(config, creds)
    raise ValueError(f"Unknown backend type: {backend_type}")


def load_backend_from_db(db_conn) -> Optional[StorageBackend]:
    cur = db_conn.cursor()
    cur.execute(
        "SELECT backend_type, config_json, credentials_enc "
        "FROM archive_storage_config WHERE is_active = true LIMIT 1"
    )
    row = cur.fetchone()
    cur.close()
    if not row:
        return None

    backend_type, config_json, credentials_enc = row
    config = json.loads(config_json or '{}')

    credentials = {}
    if credentials_enc:
        try:
            credentials = _decrypt_credentials(credentials_enc)
        except Exception as e:
            log.error(f"Failed to decrypt storage credentials: {e}")

    return get_backend(backend_type, config, credentials)


def _decrypt_credentials(encrypted: str) -> dict:
    key_path = '/etc/opensiem/certs/archive.key'
    if not os.path.exists(key_path):
        raise RuntimeError(f"Archive encryption key not found: {key_path}")
    try:
        from cryptography.fernet import Fernet
        with open(key_path, 'rb') as f:
            key = f.read().strip()
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted.encode())
        return json.loads(decrypted)
    except ImportError:
        raise RuntimeError("cryptography package required: pip install cryptography")


def encrypt_credentials(credentials: dict) -> str:
    key_path = '/etc/opensiem/certs/archive.key'
    if not os.path.exists(key_path):
        _generate_archive_key(key_path)
    try:
        from cryptography.fernet import Fernet
        with open(key_path, 'rb') as f:
            key = f.read().strip()
        fernet = Fernet(key)
        return fernet.encrypt(json.dumps(credentials).encode()).decode()
    except ImportError:
        raise RuntimeError("cryptography package required: pip install cryptography")


def _generate_archive_key(key_path: str):
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise RuntimeError("cryptography package required: pip install cryptography")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    key = Fernet.generate_key()
    with open(key_path, 'wb') as f:
        f.write(key)
    os.chmod(key_path, 0o640)
    log.info(f"Generated archive encryption key: {key_path}")
