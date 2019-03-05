import calendar
import datetime
import fnmatch
import io
import re
import shutil
import sys
from fnmatch import fnmatch
from json import dumps
from logging import getLogger
from os import getcwd, listdir, path as op, remove, sep, walk
from pprint import PrettyPrinter

import durationpy
from botocore.exceptions import ClientError

pprint = PrettyPrinter(indent=8).pprint

ppformat = PrettyPrinter(indent=8).pformat

from urllib.parse import urlparse

logger = getLogger(__name__)


##
# Settings / Packaging
##


def get_files(search_dir):
    for directory, subdirs, files in walk(search_dir, followlinks=True):
        for file in files:
            yield op.join(directory, file)


def ignore_files(files, patterns):
    for file in files:
        for pattern in patterns:
            if fnmatch(file, pattern):
                # print(f'Ignoring: ', file.split('/')[3:])
                yield file


def copytree(src, dst, excludes=None, symlinks=True, metadata=True):
    files = list(get_files(src))
    ignore = list(ignore_files(files, excludes))

    # for file in [f for f in files if f not in ignore]:
    # print(f'Copying: ', file)
    # if metadata:
    #     copy2(file, dst, follow_symlinks=symlinks)
    # else:
    #     copy(file, dst, follow_symlinks=symlinks)

    if metadata:
        shutil.copytree(src, dst, symlinks=symlinks)
    else:
        shutil.copytree(src, dst, symlinks=symlinks, copy_function=shutil.copy)

    for file in ignore:
        file = file.replace(src, dst)
        # print('remove ', file)
        remove(file)



def parse_s3_url(url):
    """
    Parses S3 URL.

    Returns bucket (domain) and file (full path).
    """
    bucket = ""
    path = ""
    if url:
        result = urlparse(url)
        bucket = result.netloc
        path = result.path.strip("/")
    return bucket, path


def human_size(num, suffix="B"):
    """
    Convert bytes length to a human-readable version
    """
    for unit in ('', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi'):
        if abs(num) < 1024.0:
            return "{0:3.1f}{1!s}{2!s}".format(num, unit, suffix)
        num /= 1024.0
    return "{0:.1f}{1!s}{2!s}".format(num, "Yi", suffix)


def string_to_timestamp(timestring):
    """
    Accepts a str, returns an int timestamp.
    """

    ts = None

    # Uses an extended version of Go's duration string.
    try:
        delta = durationpy.from_str(timestring)
        past = datetime.datetime.utcnow() - delta
        ts = calendar.timegm(past.timetuple())
        return ts
    except Exception as e:
        pass

    if ts:
        return ts
    # else:
    #     print("Unable to parse timestring.")
    return 0


def detect_flask_apps():
    """
    Automatically try to discover Flask apps files,
    return them as relative module paths.
    """

    matches = []
    for root, dirnames, filenames in walk(getcwd()):
        for filename in fnmatch.filter(filenames, "*.py"):
            full = op.join(root, filename)
            if "site-packages" in full:
                continue

            full = op.join(root, filename)

            with io.open(full, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines:
                    app = None

                    # Kind of janky..
                    if "= Flask(" in line:
                        app = line.split("= Flask(")[0].strip()
                    if "=Flask(" in line:
                        app = line.split("=Flask(")[0].strip()

                    if not app:
                        continue

                    package_path = full.replace(getcwd(), "")
                    package_module = (
                        package_path.replace(sep, ".")
                            .split(".", 1)[1]
                            .replace(".py", "")
                    )
                    app_module = package_module + "." + app

                    matches.append(app_module)

    return matches


def get_venv_from_python_version():
    return 'python{}.{}'.format(*sys.version_info)


def get_runtime_from_python_version():
    """
    """
    minor_version = sys.version_info[1]
    if minor_version in [6, 7]:
        return f"python3.{str(minor_version)}"


##
# Async Tasks
##


def get_topic_name(lambda_name):
    """ Topic name generation """
    return "%s-zappa-async" % lambda_name


##
# Event sources / Kappa
##


##
# Analytics / Surveillance / Nagging
##


def check_new_version_available(this_version):
    """
    Checks if a newer version of Zappa is available.

    Returns True is updateable, else False.

    """
    import requests

    pypi_url = "https://pypi.python.org/pypi/Zappa/json"
    resp = requests.get(pypi_url, timeout=1.5)
    top_version = resp.json()["info"]["version"]

    return this_version != top_version


class InvalidAwsLambdaName(Exception):
    """Exception: proposed AWS Lambda name is invalid"""

    pass


def validate_name(name, maxlen=80):
    """Validate name for AWS Lambda function.
    name: actual name (without `arn:aws:lambda:...:` prefix and without
        `:$LATEST`, alias or version suffix.
    maxlen: max allowed length for name without prefix and suffix.

    The value 80 was calculated from prefix with longest known region name
    and assuming that no alias or version would be longer than `$LATEST`.

    Based on AWS Lambda spec
    http://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html

    Return: the name
    Raise: InvalidAwsLambdaName, if the name is invalid.
    """
    if not isinstance(name, str):
        msg = "Name must be of type string"
        raise InvalidAwsLambdaName(msg)
    if len(name) > maxlen:
        msg = "Name is longer than {maxlen} characters."
        raise InvalidAwsLambdaName(msg.format(maxlen=maxlen))
    if len(name) == 0:
        msg = "Name must not be empty string."
        raise InvalidAwsLambdaName(msg)
    if not re.match("^[a-zA-Z0-9-_]+$", name):
        msg = "Name can only contain characters from a-z, A-Z, 0-9, _ and -"
        raise InvalidAwsLambdaName(msg)
    return name


def contains_python_files_or_subdirs(folder):
    """
    Checks (recursively) if the directory contains .py or .pyc files
    """
    for root, dirs, files in walk(folder):
        if [
            filename
            for filename in files
            if filename.endswith(".py") or filename.endswith(".pyc")
        ]:
            return True

        for d in dirs:
            for _, subdirs, subfiles in walk(d):
                if [
                    filename
                    for filename in subfiles
                    if filename.endswith(".py") or filename.endswith(".pyc")
                ]:
                    return True

    return False


def conflicts_with_a_neighbouring_module(directory_path):
    """
    Checks if a directory lies in the same directory as a .py file with the
    same name.
    """
    parent_dir_path, current_dir_name = op.split(op.normpath(directory_path))
    neighbours = listdir(parent_dir_path)
    conflicting_neighbour_filename = current_dir_name + ".py"
    return conflicting_neighbour_filename in neighbours


# https://github.com/Miserlou/Zappa/issues/1188
def titlecase_keys(d):
    """
    Takes a dict with keys of type str and returns a new dict with all keys
    titlecased.
    """
    return {k.title(): v for k, v in d.items()}


# https://github.com/Miserlou/Zappa/issues/1688
def is_valid_bucket_name(name):
    """
    Checks if an S3 bucket name is valid according to
    https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html
    #bucketnamingrules
    """
    # Bucket names must be at least 3 and no more than 63 characters long.
    if len(name) < 3 or len(name) > 63:
        return False
    # Bucket names must not contain uppercase characters or underscores.
    if any(x.isupper() for x in name):
        return False
    if "_" in name:
        return False
    # Bucket names must start with a lowercase letter or number.
    if not (name[0].islower() or name[0].isdigit()):
        return False
    # Bucket names must be a series of one or more labels. Adjacent labels
    # are separated by a single period (.).
    for label in name.split("."):
        # Each label must start and end with a lowercase letter or a number.
        if len(label) < 1:
            return False
        if not (label[0].islower() or label[0].isdigit()):
            return False
        if not (label[-1].islower() or label[-1].isdigit()):
            return False
    # Bucket names must not be formatted as an IP address (for example,
    # 192.168.5.4).
    looks_like_IP = True
    for label in name.split("."):
        if not label.isdigit():
            looks_like_IP = False
            break
    if looks_like_IP:
        return False

    return True


def get_event_source(
        event_source, lambda_arn, target_function, boto_session, dry=False
):
    """

    Given an event_source dictionary item, a session and a lambda_arn,
    hack into Kappa's Gibson, create out an object we can call
    to schedule this event, and return the event source.

    """
    import kappa.function
    import kappa.restapi
    import kappa.event_source.base
    import kappa.event_source.dynamodb_stream
    import kappa.event_source.kinesis
    import kappa.event_source.s3
    import kappa.event_source.sns
    import kappa.event_source.cloudwatch
    import kappa.policy
    import kappa.role
    import kappa.awsclient

    class PseudoContext(object):
        def __init__(self):
            return

    class PseudoFunction(object):
        def __init__(self):
            return

    # Mostly adapted from kappa - will probably be replaced by kappa support
    class SqsEventSource(kappa.event_source.base.EventSource):
        def __init__(self, context, config):
            super(SqsEventSource, self).__init__(context, config)
            self._lambda = kappa.awsclient.create_client("lambda",
                                                         context.session)

        def _get_uuid(self, function):
            uuid = None
            response = self._lambda.call(
                "list_event_source_mappings",
                FunctionName=function.name,
                EventSourceArn=self.arn,
            )
            logger.debug(response)
            if len(response["EventSourceMappings"]) > 0:
                uuid = response["EventSourceMappings"][0]["UUID"]
            return uuid

        def add(self, function):
            try:
                response = self._lambda.call(
                    "create_event_source_mapping",
                    FunctionName=function.name,
                    EventSourceArn=self.arn,
                    BatchSize=self.batch_size,
                    Enabled=self.enabled,
                )
                logger.debug(response)
            except Exception:
                logger.exception("Unable to add event source")

        def enable(self, function):
            self._config["enabled"] = True
            try:
                response = self._lambda.call(
                    "update_event_source_mapping",
                    UUID=self._get_uuid(function),
                    Enabled=self.enabled,
                )
                logger.debug(response)
            except Exception:
                logger.exception("Unable to enable event source")

        def disable(self, function):
            self._config["enabled"] = False
            try:
                response = self._lambda.call(
                    "update_event_source_mapping",
                    FunctionName=function.name,
                    Enabled=self.enabled,
                )
                logger.debug(response)
            except Exception:
                logger.exception("Unable to disable event source")

        def update(self, function):
            response = None
            uuid = self._get_uuid(function)
            if uuid:
                try:
                    response = self._lambda.call(
                        "update_event_source_mapping",
                        BatchSize=self.batch_size,
                        Enabled=self.enabled,
                        FunctionName=function.arn,
                    )
                    logger.debug(response)
                except Exception:
                    logger.exception("Unable to update event source")

        def remove(self, function):
            response = None
            uuid = self._get_uuid(function)
            if uuid:
                response = self._lambda.call("delete_event_source_mapping",
                                             UUID=uuid)
                logger.debug(response)
            return response

        def status(self, function):
            response = None
            logger.debug("getting status for event source %s", self.arn)
            uuid = self._get_uuid(function)
            if uuid:
                try:
                    response = self._lambda.call(
                        "get_event_source_mapping",
                        UUID=self._get_uuid(function)
                    )
                    logger.debug(response)
                except ClientError:
                    logger.debug("event source %s does not exist", self.arn)
                    response = None
            else:
                logger.debug("No UUID for event source %s", self.arn)
            return response

    class ExtendedSnsEventSource(kappa.event_source.sns.SNSEventSource):
        @property
        def filters(self):
            return self._config.get("filters")

        def add_filters(self, function):
            try:
                subscription = self.exists(function)
                if subscription:
                    response = self._sns.call(
                        "set_subscription_attributes",
                        SubscriptionArn=subscription["SubscriptionArn"],
                        AttributeName="FilterPolicy",
                        AttributeValue=dumps(self.filters),
                    )
                    kappa.event_source.sns.logger.debug(response)
            except Exception:
                kappa.event_source.sns.logger.exception(
                    "Unable to add filters for SNS topic %s", self.arn
                )

        def add(self, function):
            super(ExtendedSnsEventSource, self).add(function)
            if self.filters:
                self.add_filters(function)

    event_source_map = {
        "dynamodb": kappa.event_source.dynamodb_stream
            .DynamoDBStreamEventSource,
        "kinesis": kappa.event_source.kinesis.KinesisEventSource,
        "s3": kappa.event_source.s3.S3EventSource,
        "sns": ExtendedSnsEventSource,
        "sqs": SqsEventSource,
        "events": kappa.event_source.cloudwatch.CloudWatchEventSource,
    }

    arn = event_source["arn"]
    _, _, svc, _ = arn.split(":", 3)

    event_source_func = event_source_map.get(svc, None)
    if not event_source_func:
        raise ValueError("Unknown event source: {0}".format(arn))

    def autoreturn(self, function_name):
        return function_name

    event_source_func._make_notification_id = autoreturn

    ctx = PseudoContext()
    ctx.session = boto_session

    funk = PseudoFunction()
    funk.name = lambda_arn

    # Kappa 0.6.0 requires this nasty hacking,
    # hopefully we can remove at least some of this soon.
    # Kappa 0.7.0 introduces a whole host over other changes we don't
    # really want, so we're stuck here for a little while.

    # Related:  https://github.com/Miserlou/Zappa/issues/684
    #           https://github.com/Miserlou/Zappa/issues/688
    #           https://github.com/Miserlou/Zappa/commit
    #           /3216f7e5149e76921ecdf9451167846b95616313
    if svc == "s3":
        split_arn = lambda_arn.split(":")
        arn_front = ":".join(split_arn[:-1])
        arn_back = split_arn[-1]
        ctx.environment = arn_back
        funk.arn = arn_front
        funk.name = ":".join([arn_back, target_function])
    else:
        funk.arn = lambda_arn

    funk._context = ctx

    event_source_obj = event_source_func(ctx, event_source)

    return event_source_obj, ctx, funk


def add_event_source(
        event_source, lambda_arn, target_function, boto_session, dry=False
):
    """
    Given an event_source dictionary, create the object and add the event
    source.
    """

    event_source_obj, ctx, funk = get_event_source(
        event_source, lambda_arn, target_function, boto_session, dry=False
    )
    # TODO: Detect changes in config and refine exists algorithm
    if not dry:
        if not event_source_obj.status(funk):
            event_source_obj.add(funk)
            return 'successful' if event_source_obj.status(funk) else 'failed'
    else:
            return "exists"

    return "dryrun"


def remove_event_source(
        event_source, lambda_arn, target_function, boto_session, dry=False
):
    """
    Given an event_source dictionary, create the object and remove the event
    source.
    """

    event_source_obj, ctx, funk = get_event_source(
        event_source, lambda_arn, target_function, boto_session, dry=False
    )

    # This is slightly dirty, but necessary for using Kappa this way.
    funk.arn = lambda_arn
    if not dry:
        rule_response = event_source_obj.remove(funk)
        return rule_response
    else:
        return event_source_obj
