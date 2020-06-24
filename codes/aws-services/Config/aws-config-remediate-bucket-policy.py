from __future__ import print_function
import json
import random
import string
import boto3
import botocore
import logging
from botocore.exceptions import ClientError
from pprint import pprint
print('Loading function')

# Initiating Logger
logger = logging.getLogger(__name__)
logger.setLevel('INFO')


def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))
    logger.info(event)
    logger.info("Received event: " + json.dumps(event, indent=2))
    bucket = event['Records'][0]['Sns']['Message']
    logger.info(f"S3 bucket name to be remediated is:  {bucket}")
    # Enable boto3 debug logging
    # boto3.set_stream_logger("")

    # Instantiate S3 Client
    s3 = boto3.client('s3')
    # Creating a random string for the bucket policy SID
    my_rand_str = ''.join(random.choices(string.hexdigits, k=6))
    # Here is a sample bucket policy enforcing SSL requests only, you can customize this
    allow_ssl_only_sample_bucket_policy = {"Version": "2012-10-17", "Id": "Policy1504640911349", "Statement": [
        {"Sid": "Stmt1504640908907", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": ["arn:aws:s3:::awsexamplebucket/*", "arn:aws:s3:::awsexamplebucket"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}

    # Extracting the SID only to be modified to match bucket
    ssl_secure_sid = allow_ssl_only_sample_bucket_policy["Statement"][0]
    # Modifying/Customizing the Values
    ssl_secure_sid["Sid"] = "AWS-Config-Enforce-ssl" + "-" + my_rand_str
    new_value_2 = [x.replace('awsexamplebucket', bucket) for x in ssl_secure_sid["Resource"]]
    # print(new_value_2)
    ssl_secure_sid["Resource"] = new_value_2
    # print(ssl_secure_sid["Resource"])


    # Starting actual S3 API operation
    try:
        # First check if there is an existing bucket policy and append the enforce ssl SID to it
        # Initiate connection to S3
        response = s3.get_bucket_policy(Bucket=bucket)
        # Retrive policy from sample
        raw_bucket_policy = response['Policy']
        # Convert policy to Dict
        mypolicy = json.loads(raw_bucket_policy)
        # Append new policy to existing one
        mypolicy['Statement'].append(ssl_secure_sid)
        # Convert the policy from JSON dict to string
        bucket_policy = json.dumps(mypolicy)
        # Set the new policy on the bucket
        logger.info(f"There is an existing Bucket policy, appending the ssl enforcement SID to it:....\n")
        logger.info(ssl_secure_sid)
        #s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)
        put_bucket_policy(bucket, bucket_policy)
    except ClientError as e:
        # We now check if there is no existing bucket policy, then create a brand new Policy from template
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            logger.info("This Bucket does not have an Existing Bucket Policy, creating a new SSL-Only Bucket Policy: ...\n")
            logger.info(allow_ssl_only_sample_bucket_policy)
            new_bucket_policy = json.dumps(allow_ssl_only_sample_bucket_policy)
            # Set the new policy
            #s3.put_bucket_policy(Bucket=bucket, Policy=new_bucket_policy)
            put_bucket_policy(bucket, new_bucket_policy)
        else:
            # Finally, this block will catch all other errors and return requestIDs for AWS Support
            logger.exception("Unable to complete requested operation, see error details below:")
            logger.exception(f"Error Code: {e.response['Error']['Code']}")
            logger.exception(f"RequestID: {e.response['ResponseMetadata']['RequestId']}")
            logger.exception(f"HostID: {e.response['ResponseMetadata']['HostId']}")


def put_bucket_policy(var_bucket, var_policy):
    # Instantiate S3 Client
    s3 = boto3.client('s3')
    try:
        s3.put_bucket_policy(Bucket=var_bucket, Policy=var_policy)
    except ClientError as e:
            # Finally, this block will catch all other errors and return requestIDs for AWS Support
            logger.exception("Unable to complete requested operation, see error details below:")
            logger.exception(f"Error Code: {e.response['Error']['Code']}")
            logger.exception(f"RequestID: {e.response['ResponseMetadata']['RequestId']}")
            logger.exception(f"HostID: {e.response['ResponseMetadata']['HostId']}")
        
    
