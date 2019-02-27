from os import path as op, stat

from botocore.exceptions import ClientError, ParamValidationError
from tqdm import tqdm

from .utils import human_size

# Note that this is set to 300s, but if connected to
# APIGW, Lambda will max out at 30s.
# Related: https://github.com/Miserlou/Zappa/issues/205
long_config_dict = {
    "region_name": aws_region,
    "connect_timeout": 5,
    "read_timeout": 300,
}
long_config = botocore.client.Config(**long_config_dict)

if load_credentials:
    self.load_credentials(boto_session, profile_name)

    # Initialize clients
    self.s3_client = self.boto_client("s3")
    self.lambda_client = self.boto_client("lambda", config=long_config)
    self.events_client = self.boto_client("events")
    self.apigateway_client = self.boto_client("apigateway")
    # AWS ACM certificates need to be created from us-east-1
    # to be used by API gateway
    east_config = botocore.client.Config(region_name="us-east-1")
    self.acm_client = self.boto_client("acm", config=east_config)
    self.logs_client = self.boto_client("logs")
    self.iam_client = self.boto_client("iam")
    self.iam = self.boto_resource("iam")
    self.cloudwatch = self.boto_client("cloudwatch")
    self.route53 = self.boto_client("route53")
    self.sns_client = self.boto_client("sns")
    self.cf_client = self.boto_client("cloudformation")
    self.dynamodb_client = self.boto_client("dynamodb")
    self.cognito_client = self.boto_client("cognito-idp")
    self.sts_client = self.boto_client("sts")


def configure_boto_session_method_kwargs(self, service, kw):
    """Allow for custom endpoint urls for non-AWS (testing and bootleg
    cloud)
     deployments"""
    if service in self.endpoint_urls and not "endpoint_url" in kw:
        kw["endpoint_url"] = self.endpoint_urls[service]
    return kw


def boto_client(self, service, *args, **kwargs):
    """A wrapper to apply configuration options to boto clients"""
    return self.boto_session.client(
        service, *args,
        **self.configure_boto_session_method_kwargs(service, kwargs)
    )


def boto_resource(self, service, *args, **kwargs):
    """A wrapper to apply configuration options to boto resources"""
    return self.boto_session.resource(
        service, *args,
        **self.configure_boto_session_method_kwargs(service, kwargs)
    )


def upload_to_s3(source_path, bucket_name, disable_progress=False):
    r"""
    Given a file, upload it to S3.
    Credentials should be stored in environment variables or
    ~/.aws/credentials (%USERPROFILE%\.aws\credentials on Windows).

    Returns True on success, false on failure.

    """
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError:
        # This is really stupid S3 quirk. Technically, us-east-1 one has
        # no S3,
        # it's actually "US Standard", or something.
        # More here: https://github.com/boto/boto3/issues/125
        if aws_region == "us-east-1":
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": aws_region},
            )

        if tags:
            tags = {
                "TagSet": [
                    {"Key": key, "Value": tags[key]}
                    for key in tags.keys()
                ]
            }
            s3_client.put_bucket_tagging(Bucket=bucket_name,
                                         Tagging=tags)

    if not op.isfile(source_path) or stat(source_path).st_size == 0:
        print("Problem with source file {}".format(source_path))
        return False

    dest_path = op.split(source_path)[1]
    try:
        source_size = stat(source_path).st_size
        print("Uploading {0} ({1})..".format(dest_path,
                                             human_size(source_size)))
        progress = tqdm(
            total=float(op.getsize(source_path)),
            unit_scale=True,
            unit="B",
            disable=disable_progress,
        )

        # Attempt to upload to S3 using the S3 meta client with the
        # progress bar.
        # If we're unable to do that, try one more time using a session
        # client,
        # which cannot use the progress bar.
        # Related: https://github.com/boto/boto3/issues/611
        try:
            s3_client.upload_file(
                source_path, bucket_name, dest_path,
                Callback=progress.update
            )
        except Exception as e:  # pragma: no cover
            s3_client.upload_file(source_path, bucket_name, dest_path)

        progress.close()
    except (KeyboardInterrupt, SystemExit):  # pragma: no cover
        raise
    except Exception as e:  # pragma: no cover
        print(e)
        return False
    return True


def copy_on_s3(self, src_file_name, dst_file_name, bucket_name):
    """
    Copies src file to destination within a bucket.
    """
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as e:  # pragma: no cover
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response["Error"]["Code"])
        if error_code == 404:
            return False

    copy_src = {"Bucket": bucket_name, "Key": src_file_name}
    try:
        s3_client.copy(
            CopySource=copy_src, Bucket=bucket_name, Key=dst_file_name
        )
        return True
    except ClientError:  # pragma: no cover
        return False


def remove_from_s3(self, file_name, bucket_name):
    """
    Given a file name and a bucket, remove it from S3.

    There's no reason to keep the file hosted on S3 once its been made
    into a
    Lambda function, so we can delete it from S3.

    Returns True on success, False on failure.

    """
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as e:  # pragma: no cover
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response["Error"]["Code"])
        if error_code == 404:
            return False

    try:
        s3_client.delete_object(Bucket=bucket_name, Key=file_name)
        return True
    except (
            ParamValidationError,
            ClientError,
    ):  # pragma: no cover
        return False
