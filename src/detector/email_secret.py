# SPDX-License-Identifier: Apache-2.0
"""Email provider API key retrieval from SSM Parameter Store.

The key is stored as a SecureString parameter, created once by the operator:

    aws ssm put-parameter --name /clickops-sentinel/email-api-key \
        --type SecureString --value "re_..."

It is fetched with decryption on first use and cached for the lifetime of
the Lambda execution environment. It never appears in environment variables
or CloudFormation outputs.

This module is duplicated in src/detector and src/investigator because SAM
packages each CodeUri separately. Keep both copies identical.
"""

import os

import boto3

_cache: dict = {}


def get_api_key() -> str:
    """SecureString value of the parameter named by EMAIL_API_KEY_PARAM."""
    parameter_name = os.environ["EMAIL_API_KEY_PARAM"]
    if parameter_name not in _cache:
        response = boto3.client("ssm").get_parameter(
            Name=parameter_name, WithDecryption=True
        )
        _cache[parameter_name] = response["Parameter"]["Value"]
    return _cache[parameter_name]
