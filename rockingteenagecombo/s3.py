from dataclasses import dataclass
from logging import getLogger
from os import path as op, stat

from boto3 import resource
from botocore.exceptions import ClientError, ParamValidationError
from tqdm import tqdm

from .utils import human_size

logger = getLogger(__name__)


@dataclass
class S3:
    bucket_name: str = "zappa-deploy"

    def __post_init__(self):
        self.s3 = resource("s3")
        self.bucket = self.s3.Bucket(self.bucket_name)

    def is_s3_dir(self, relative_path):
        return relative_path.endswith("/")

    def exists_on_s3(self, relative_path):
        if not relative_path:
            return False
        obj = self.s3.Object(self.bucket_name, relative_path)
        try:
            obj.load()
        except ClientError as err:
            if err.response["Error"]["Code"] == "404":
                return False
            else:
                raise
        else:
            return True

    def wait_until_s3_exists(self, source_path):
        obj = self.s3.Object(self.bucket_name, source_path)
        obj.wait_until_exists()

    def wait_until_s3_not_exists(self, source_path):
        obj = self.s3.Object(self.bucket_name, source_path)
        obj.wait_until_not_exists()

    def list_s3_tree(self, subdir=None):
        if subdir and not subdir.endswith("/"):
            subdir += "/"
        kw = dict()
        if subdir:
            kw["Prefix"] = subdir
        resp = self.bucket.objects.filter(**kw)
        for obj in resp:
            yield obj.key

    def get_s3_obj(self, source_path):
        obj = self.s3.Object(self.bucket_name, source_path)
        resp = None
        try:
            resp = obj.get()
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchKey":
                return False
            else:
                raise
        return resp["Body"].read()

    def get_s3_file(self, source_path, dest_path, bucket_name=None,
                    disable_progress=False):
        if not bucket_name:
            bucket_name = self.bucket_name
        try:
            # source_size = stat(source_path).st_size
            # print("Downloading {0} ({1})..".format(dest_path,
            #                                        human_size(source_size)))
            progress = tqdm(
                # total=float(op.getsize(source_path)),
                unit_scale=True,
                unit="B",
                disable=disable_progress,
            )
            try:
                self.s3.bucket.download_file(source_path, dest_path,
                                             Callback=progress.update)
            except ClientError as err:
                if err.response["Error"]["Code"] == "404":
                    return False
            except Exception as err:  # pragma: no cover
                self.s3.meta.client.download_file(bucket_name, source_path,
                                                  dest_path)
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover
            raise
        except Exception as err:  # pragma: no cover
            raise err
            # return False
        return True

    def save_to_s3(self, source_path, bucket_name=None,
                   disable_progress=False):
        if not bucket_name:
            bucket_name = self.bucket_name

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

            obj = self.s3.Object(self.bucket_name, source_path)
            try:
                self.bucket.upload_file(
                    source_path, dest_path,
                    Callback=progress.update
                )
                obj.wait_until_exists(source_path)
            except ClientError as err:
                if err.response["Error"]["Code"] == "404":
                    return False
            except Exception as err:  # pragma: no cover
                self.s3.meta.upload_file(source_path, bucket_name,
                                         dest_path)  # can use Callback
                obj.wait_until_exists(source_path)
            progress.close()
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover
            raise
        except Exception as err:  # pragma: no cover
            return False
        return True

    def copy_on_s3(self, src_path, dest_path, bucket_name):
        obj = self.s3.Object(self.bucket_name, dest_path)
        copy_source = dict(Key=src_path, Bucket=bucket_name)
        obj_args = dict(CopySource=copy_source)
        try:
            obj.copy_from(**obj_args)
        except ClientError as err:
            if err.response["Error"]["Code"] == "404":
                return False
            else:
                raise
        else:
            return True

    def delete_from_s3(self, source_path, bucket_name=None):
        if not bucket_name:
            bucket_name = self.bucket_name

        obj = self.s3.Object(bucket_name, source_path)
        try:
            obj.delete()
            obj.wait_until_not_exists(source_path)
        except ClientError as err:
            if err.response["Error"]["Code"] == "404":
                return False
        except (
                ParamValidationError,
                ClientError,
        ):  # pragma: no cover
            return False
        return True


wheel_storage = S3('lambda-wheels-3-7')
