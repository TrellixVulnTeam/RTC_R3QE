import calendar
import datetime
import fnmatch
import io
import re
from glob import glob
from os import getcwd, listdir, path as op, sep, walk
from pprint import PrettyPrinter
from shutil import copy, copy2

import durationpy
import sys

pprint = PrettyPrinter(indent=8).pprint

ppformat = PrettyPrinter(indent=8).pformat

from urllib.parse import urlparse



##
# Settings / Packaging
##


def get_files_from_dir(search_dir):
    for directory, subdirs, files in walk(search_dir):
        for file in files:
            if op.isfile(file):
                yield op.join(search_dir, directory, file)


def get_files_from_dirs(search_dir):
    for directory, subdirs, files in walk(search_dir, followlinks=True):
        for subdir in subdirs:
            for directory, subdirs, files in walk(subdir, followlinks=True):
                for file in files:
                    yield op.join(search_dir, directory, file)


def ignore_files(search_dir, patterns):
    for directory, subdirs, files in walk(search_dir):
        for pattern in patterns:
            for file in files:
                if fnmatch.fnmatch(file, pattern):
                    print(f'Ignoring file:  '
                          f'{op.join(search_dir, directory, file)}')
                    yield op.join(search_dir, directory, file)


def ignore_dirs(search_dir, patterns):
    for directory, subdirs, files in walk(search_dir, followlinks=True):
        for pattern in patterns:
            for subdir in subdirs:
                ex = [op.join(search_dir, f) for f in
                      glob(op.join(subdir, pattern))]
                for file in ex:
                    if op.isdir(file):
                        print(f'Ignoring directory:  '
                              f'{op.join(search_dir, directory, file)}')
                        yield file


def copytree(src, dst, excludes=None, symlinks=True, metadata=True):
    exclude_dirs = list(ignore_dirs(src, excludes))
    exclude_files = list(ignore_files(src, excludes))
    for file in list(get_files_from_dir(src)) + list(get_files_from_dirs(src)):
        try:
            for d in exclude_dirs:
                if d in file:
                    raise ValueError
            if file not in exclude_files:
                print(f'Copying:  {file}')
                if metadata:
                    copy2(file, dst, follow_symlinks=symlinks)
                else:
                    copy(file, dst, follow_symlinks=symlinks)
        except ValueError:
            continue


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
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
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


##
# `init` related
##


def detect_django_settings():
    """
    Automatically try to discover Django settings files,
    return them as relative module paths.
    """

    matches = []
    for root, dirnames, filenames in walk(getcwd()):
        for filename in fnmatch.filter(filenames, "*settings.py"):
            full = op.join(root, filename)
            if "site-packages" in full:
                continue
            full = op.join(root, filename)
            package_path = full.replace(getcwd(), "")
            package_module = (
                package_path.replace(sep, ".").split(".", 1)[1].replace(".py",
                                                                        "")
            )

            matches.append(package_module)
    return matches


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
    return "python" + str(sys.version_info[0]) + "." + str(sys.version_info[1])


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

    if this_version != top_version:
        return True
    else:
        return False


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
