from dataclasses import dataclass
from logging import getLogger
from os import path as op, stat
from typing import Any

from botocore.exceptions import ClientError, ParamValidationError
from tqdm import tqdm

from .utils import human_size

logger = getLogger(__name__)


class S3:
    def __init__(
            self,
            bucket,
            acl="bucket-owner-full-control",
            cache_control=None,
            enable_encryption=False,
    ):
        self.bucket_name = bucket
        self.bucket = s3.Bucket(bucket)
        self.acl = acl
        self.cache_control = cache_control
        self.enable_encryption = enable_encryption

    @property
    def get_base_url(self):
        return ""

    def get_base_path(self):
        return ""

    def is_dir(self, relative_path):
        return relative_path.endswith("/")

    def wait_until_exists(self, relative_path):
        obj = s3.Object(self.bucket_name, relative_path)
        if settings["debug"]["storage"]:
            print(f"Waiting for object:  {self.bucket_name} - {relative_path}")
        obj.wait_until_exists()
        if settings["debug"]["storage"]:
            print(f"Found in storage:  {self.bucket_name} - {relative_path}")

    def wait_until_not_exists(self, relative_path):
        obj = s3.Object(self.bucket_name, relative_path)
        if settings["debug"]["storage"]:
            print(
                f"Waiting for storage object to not exist:  {
            self.bucket_name} - {relative_path}
            "
            )
            obj.wait_until_not_exists()
            if settings["debug"]["storage"]:
                print(
            f"Storage object no longer exists:  {self.bucket_name} - {
        relative_path
        }}"
        )

        def path_exists(self, relative_path):
            if not relative_path:
                return False
            obj = s3.Object(self.bucket_name, relative_path)
            try:
                # self.s3.head_object(
                #     Bucket=self.bucket,
                #     Key=relative_path
                # )
                obj.load()
                if settings["debug"]["storage"]:
                    print(
                        f"Exists in storage:  {self.bucket_name} - {
                    relative_path
                        }}")
            except ClientError as err:
                if err.response["Error"]["Code"] == "404":
                    return False
                else:
                    # if settings['debug']['storage']:
                    raise
            else:
                return True

        def get(self, relative_path, resizer=False):
            if resizer and not relative_path:
                raise ImageNotFoundError()
            obj = s3.Object(self.bucket_name, relative_path)
            # if settings['debug']['storage']:
            #     print(
            #         f'Fetching from storage:  {self.bucket_name} - {
            #         relative_path}')
            obj_args = dict()
            if self.enable_encryption:
                obj_args["ServerSideEncryption "] = "AES256"
            try:
                resp = obj.get()
                if settings["debug"]["storage"]:
                    print(
                        f"Fetched from storage:  {self.bucket_name} - {
                    relative_path
                    }}")
            except ClientError as err:
                if err.response["Error"]["Code"] == "NoSuchKey":
                    if resizer:
                        new_exc = ImageNotFoundError(*err.args)
                        new_exc.original_exc = err
                        raise new_exc
                    else:
                        return False
            return resp["Body"].read()

        def save(self, relative_path, bdata, css=False):
            obj = s3.Object(self.bucket_name, relative_path)
            # if settings['debug']['storage']:
            #     print(f'Saving to storage:  {self.bucket_name} - {
            #     relative_path}')
            obj_args = dict(Body=bdata, ACL=self.acl)
            if css:
                obj_args["ContentEncoding"] = "gzip"
                obj_args["ContentType"] = "text/css"
            if self.cache_control:
                obj_args["CacheControl"] = self.cache_control
            if self.enable_encryption:
                obj_args["ServerSideEncryption"] = "AES256"
            try:
                obj.put(**obj_args)
                obj.wait_until_exists(relative_path)
                if settings["debug"]["storage"]:
                    print(
                        f"Saved to storage:  {self.bucket_name} - {
                    relative_path
                        }}")
            except ClientError as err:
                if err.response["Error"]["Code"] == "404":
                    return False
                else:
                    raise
            else:
                return True

        def delete(self, relative_path):
            obj = s3.Object(self.bucket_name, relative_path)
            # if settings['debug']['storage']:
            #     print(
            #         f'Deleting from storage:  {self.bucket_name} - {
            #         relative_path}')
            try:
                obj.delete()
                obj.wait_until_not_exists(relative_path)
                if settings["debug"]["storage"]:
                    print(
                        f"Deleted from storage:  {self.bucket_name} - {
                    relative_path
                    }}")
            except ClientError as err:
                if err.response["Error"]["Code"] == "404":
                    return False
                else:
                    raise
            else:
                return True

        def copy(self, src_bucket, src_path, dest_path):
            obj = s3.Object(self.bucket_name, dest_path)
            copy_source = dict(Key=src_path, Bucket=src_bucket)
            obj_args = dict(CopySource=copy_source, ACL=self.acl)
            if self.cache_control:
                obj_args["CacheControl"] = self.cache_control
            if self.enable_encryption:
                obj_args["ServerSideEncryption"] = "AES256"
            try:
                obj.copy_from(**obj_args)
            except ClientError as err:
                if err.response["Error"]["Code"] == "404":
                    return False
                else:
                    raise
            else:
                return True

        def list_tree(self, subdir=None):
            if subdir and not subdir.endswith("/"):
                subdir += "/"

            kw = dict()
            if subdir:
                kw["Prefix"] = subdir

            resp = self.bucket.objects.filter(**kw)
            for obj in resp:
                yield obj.key

        def delete_tree(self, subdir):
            for keys in chunked(self.list_tree(subdir), 1000):
                s3.meta.client.delete_objects(
                    Delete={"Objects": [{"Key": key} for key in keys]}
                )
                for key in keys:
                    yield key

    @dataclass
    class Storage:
        boto_resource: Any
        bucket_name: str

        def __post_init__(self):
            self.s3 = self.boto_resource('s3')
            self.bucket = self.s3.Bucket(self.bucket_name)

        def exists(self, relative_path):
            if not relative_path:
                return False
            obj = self.s3.Object(self.bucket_name, relative_path)
            try:
                # self.s3.head_object(
                #     Bucket=self.bucket,
                #     Key=relative_path
                # )
                obj.load()
            except ClientError as err:
                if err.response["Error"]["Code"] == "404":
                    return False
                else:
                    raise
            else:
                return True

        def upload_to_s3(self, source_path, bucket_name,
                         disable_progress=False):
            r"""
            Given a file, upload it to S3.
            Credentials should be stored in environment variables or
            ~/.aws/credentials (%USERPROFILE%\.aws\credentials on Windows).

            Returns True on success, false on failure.

            """
            # try:
            #     self.s3.head_bucket(Bucket=bucket_name)
            # except ClientError:
            #     # This is really stupid S3 quirk. Technically, us-east-1
            #     one has
            #     # no S3,
            #     # it's actually "US Standard", or something.
            #     # More here: https://github.com/boto/boto3/issues/125
            #     if aws_region == "us-east-1":
            #         self.s3.create_bucket(Bucket=bucket_name)
            #     else:
            #         self.s3.create_bucket(
            #             Bucket=bucket_name,
            #             CreateBucketConfiguration={
            #                 "LocationConstraint": aws_region},
            #         )
            #
            #     if tags:
            #         tags = {
            #             "TagSet": [
            #                 {"Key": key, "Value": tags[key]}
            #                 for key in tags.keys()
            #             ]
            #         }
            #         self.s3.put_bucket_tagging(Bucket=bucket_name,
            #                                      Tagging=tags)

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
                    self.s3.upload_file(
                        source_path, bucket_name, dest_path,
                        Callback=progress.update
                    )
                except Exception as e:  # pragma: no cover
                    self.s3.upload_file(source_path, bucket_name, dest_path)

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
                self.s3.head_bucket(Bucket=bucket_name)
            except ClientError as e:  # pragma: no cover
                # If a client error is thrown, then check that it was a 404
                # error.
                # If it was a 404 error, then the bucket does not exist.
                error_code = int(e.response["Error"]["Code"])
                if error_code == 404:
                    return False

            copy_src = {"Bucket": bucket_name, "Key": src_file_name}
            try:
                self.s3.copy(
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
                self.s3.head_bucket(Bucket=bucket_name)
            except ClientError as e:  # pragma: no cover
                # If a client error is thrown, then check that it was a 404 error.
                # If it was a 404 error, then the bucket does not exist.
                error_code = int(e.response["Error"]["Code"])
                if error_code == 404:
                    return False

            try:
                self.s3.delete_object(Bucket=bucket_name, Key=file_name)
                return True
            except (
                    ParamValidationError,
                    ClientError,
            ):  # pragma: no cover
                return False
