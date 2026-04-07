import json

# =============================================================================
# parse_aws_cloudtrail.py — AWS CloudTrail Log Parser
#
# Handles:
# - Management events (IAM, EC2, S3, Lambda, RDS, CloudTrail itself)
# - Authentication / authorization
# - CRUD-style resource manipulation
# - Error / access denied classification
#
# Input: JSON string (CloudTrail event)
# Output: dict compatible with OpenSIEM event contract
# =============================================================================

IAM_EVENTS = {
    'CreateUser': 'IAM_CREATE_USER',
    'DeleteUser': 'IAM_DELETE_USER',
    'AttachUserPolicy': 'IAM_ATTACH_POLICY',
    'PutUserPolicy': 'IAM_INLINE_POLICY',
    'CreateRole': 'IAM_CREATE_ROLE',
    'AttachRolePolicy': 'IAM_ATTACH_ROLE_POLICY',
    'AssumeRole': 'IAM_ASSUME_ROLE',
    'PassRole': 'IAM_PASS_ROLE',
}

AUTH_EVENTS = {
    'ConsoleLogin': 'AUTH_CONSOLE_LOGIN',
}

RESOURCE_EVENTS = {
    # EC2
    'RunInstances': 'EC2_CREATE',
    'TerminateInstances': 'EC2_DELETE',
    'StartInstances': 'EC2_START',
    'StopInstances': 'EC2_STOP',
    # S3
    'CreateBucket': 'S3_CREATE',
    'DeleteBucket': 'S3_DELETE',
    'PutBucketPolicy': 'S3_POLICY_UPDATE',
    # Lambda
    'CreateFunction': 'LAMBDA_CREATE',
    'UpdateFunctionCode': 'LAMBDA_UPDATE',
    'DeleteFunction': 'LAMBDA_DELETE',
}

AUDIT_CONTROL = {
    'CreateTrail': 'CLOUDTRAIL_CREATE',
    'DeleteTrail': 'CLOUDTRAIL_DELETE',
    'StopLogging': 'CLOUDTRAIL_STOP',
}

# CRUD‑style mapping (approximate)
CRUD_MAP = {
    'CREATE': ('Create', 'Run'),
    'READ':   ('Describe', 'Get', 'List'),
    'UPDATE': ('Update', 'Modify', 'Put', 'Attach'),
    'DELETE': ('Delete', 'Terminate'),
}

def _classify_crud(event_name: str) -> str:
    for crud, prefixes in CRUD_MAP.items():
        if event_name.startswith(prefixes):
            return crud
    return ''

def _user_identity(user_identity: dict) -> str:
    if not user_identity:
        return ''
    return (
        user_identity.get('arn')
        or user_identity.get('userName')
        or user_identity.get('principalId', '')
    )

def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    try:
        evt = json.loads(log)
    except Exception:
        return None

    event_name = evt.get('eventName', '')
    event_source = evt.get('eventSource', '')
    event_time = evt.get('eventTime', '')
    aws_region = evt.get('awsRegion', '')
    user = _user_identity(evt.get('userIdentity', {}))
    src_ip = evt.get('sourceIPAddress', '')
    user_agent = evt.get('userAgent', '')
    error_code = evt.get('errorCode', '')
    error_msg = evt.get('errorMessage', '')

    base = {
        'format': 'AWS_CLOUDTRAIL',
        'timestamp': event_time,
        'process': 'aws',
        'service': event_source,
        'action': event_name,
        'user': user,
        'src_ip': src_ip,
        'region': aws_region,
        'user_agent': user_agent,
        'error': error_code,
        'crud': _classify_crud(event_name),
        'message': '',
        # keep raw for deep forensic use
        'raw': evt,
    }

    if event_name in AUTH_EVENTS:
        outcome = 'SUCCESS'
        if evt.get('responseElements', {}).get('ConsoleLogin') == 'Failure':
            outcome = 'FAILURE'

        base.update({
            'format': AUTH_EVENTS[event_name],
            'outcome': outcome,
            'message': (
                f"AWS console login {outcome.lower()}: "
                f"user={user} src={src_ip}"
            ),
        })
        return base

    if event_name in IAM_EVENTS:
        target = (
            evt.get('requestParameters', {}).get('userName')
            or evt.get('requestParameters', {}).get('roleName')
            or ''
        )
        base.update({
            'format': IAM_EVENTS[event_name],
            'target': target,
            'message': (
                f"AWS IAM action {event_name}: "
                f"actor={user} target={target}"
            ),
        })
        return base

    if event_name in RESOURCE_EVENTS:
        base.update({
            'format': RESOURCE_EVENTS[event_name],
            'message': (
                f"AWS resource action {event_name}: "
                f"user={user} region={aws_region}"
            ),
        })
        return base

    if event_name in AUDIT_CONTROL:
        base.update({
            'format': AUDIT_CONTROL[event_name],
            'message': (
                f"AWS CloudTrail control action {event_name}: "
                f"user={user}"
            ),
        })
        return base

    if error_code:
        base.update({
            'format': 'AWS_ACCESS_ERROR',
            'message': (
                f"AWS access error {error_code}: "
                f"action={event_name} user={user} src={src_ip}"
            ),
        })
        return base

    base['message'] = (
        f"AWS event {event_name}: "
        f"user={user} src={src_ip}"
    )
    return base
