import json
import random
import pytest
import botocore.stub

import ssl_config


# Use parametrize to run the test 3 times with different error paths.
@pytest.mark.parametrize('error_code', [None, 'NoSuchBucketPolicy', 'TestException'])
def test_ssl_config_lambda_handler(monkeypatch, error_code):
    # Pass the boto3 client object to the Stubber constructor.
    s3_stubber = botocore.stub.Stubber(ssl_config.s3)

    # Set up test data
    bucket_name = 'test-bucket'
    test_event = {
        'Records': [{
            'Sns': {'Message': bucket_name}
        }]
    }
    original_policy = {
        "Version": "2012-10-17",
        "Statement": [{
                "Effect": "Allow",
                "Action": "test:action",
                "Resource": "arn:aws:iam::test/test-arn"
        }]
    }
    ssl_policy = {
        "Version": "2012-10-17",
        "Id": "Policy1504640911349",
        "Statement": [{
                "Sid": "AWS-Config-Enforce-ssl-test",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::test-bucket/*", "arn:aws:s3:::test-bucket"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
        }]
    }
    original_policy_doc = json.dumps(original_policy)
    # Monkeypatch the random.choices() function so it returns a known result.
    monkeypatch.setattr(random, 'choices', lambda x, k: ['t', 'e', 's', 't'])
    original_policy['Statement'].append(ssl_policy['Statement'][0])
    updated_policy_doc = json.dumps(original_policy)
    ssl_policy_doc = json.dumps(ssl_policy)

    if error_code is None:
        # Add the two S3 calls to the the stubber.
        s3_stubber.add_response(
            'get_bucket_policy',
            expected_params={'Bucket': bucket_name},
            service_response={'Policy': original_policy_doc})
        s3_stubber.add_response(
            'put_bucket_policy',
            expected_params={
                'Bucket': bucket_name, 'Policy': updated_policy_doc},
            service_response={})
    else:
        # Add the error response to the stubber.
        s3_stubber.add_client_error(
            'get_bucket_policy',
            expected_params={'Bucket': bucket_name},
            response_meta={'RequestId': 'test-request-id', 'HostId': 'test-host-id'},
            service_error_code=error_code
        )
        if error_code == 'NoSuchBucketPolicy':
            # For this specific error, expect put_bucket_policy is called with just the
            # SSL policy doc.
            s3_stubber.add_response(
                'put_bucket_policy',
                expected_params={
                    'Bucket': bucket_name, 'Policy': ssl_policy_doc},
                service_response={})

    # Run test. The Stubber must be in a context manager so it is activated and
    # deactivated properly. When activated, the stubber intercepts calls and returns
    # stubbed responses.
    with s3_stubber:
        ssl_config.lambda_handler(test_event, None)
    # Assert there are no more responses left in the Stubber.
    s3_stubber.assert_no_pending_responses()
