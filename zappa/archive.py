import getpass
import json
import subprocess
import tarfile
import tempfile
import zipfile
from distutils.dir_util import copy_tree
from glob import glob
from os import (chmod, environ, getcwd, listdir, makedirs, path as op, remove,
                sep, walk)
from shutil import copy, rmtree
from uuid import uuid4

import requests
import sys
import time
from setuptools import find_packages
from tqdm import tqdm

from .utils import (conflicts_with_a_neighbouring_module,
                    contains_python_files_or_subdirs, copytree,
                    get_venv_from_python_version, pprint)

lambda_packages = dict()

# We never need to include these.
# Related: https://github.com/Miserlou/Zappa/pull/56
# Related: https://github.com/Miserlou/Zappa/pull/581
ZIP_EXCLUDES = [
    "*.exe",
    "*.DS_Store",
    "*.Python",
    "*.git",
    "*/.git*",
    "*.zip",
    "*.tar.gz",
    "*.gz",
    "*.hg",
    "*/pip/*",
    "*/docutils/*",
    "*/setuputils*",
    "*/__pycache__*",
]


def copy_editable_packages(self, egg_links, temp_package_path):
    """ """
    for egg_link in egg_links:
        with open(egg_link, "rb") as df:
            egg_path = df.read().decode("utf-8").splitlines()[0].strip()
            pkgs = set(
                [
                    x.split(".")[0]
                    for x in
                    find_packages(egg_path, exclude=["test", "tests"])
                ]
            )
            for pkg in pkgs:
                copytree(
                    op.join(egg_path, pkg),
                    op.join(temp_package_path, pkg),
                    # metadata=False,
                    symlinks=False,
                )

    if temp_package_path:
        # now remove any egg-links as they will cause issues if they
        # still exist
        for link in glob(
                op.join(temp_package_path, "*.egg-link")):
            remove(link)


def get_deps_list(self, pkg_name, installed_distros=None):
    import pkg_resources

    deps = []
    if not installed_distros:
        installed_distros = pkg_resources.WorkingSet()
    for package in installed_distros:
        if package.project_name.lower() == pkg_name.lower():
            deps = [(package.project_name, package.version)]
            for req in package.requires():
                deps += self.get_deps_list(
                    pkg_name=req.project_name,
                    installed_distros=installed_distros
                )
    return list(set(deps))  # de-dupe before returning


def create_handler_venv(self):
    import subprocess

    current_venv = self.get_current_venv()

    ve_path = op.join(getcwd(), "handler_venv")

    if sys.platform == "win32":
        current_site_packages_dir = op.join(
            current_venv, "Lib", "site-packages"
        )
        venv_site_packages_dir = op.join(ve_path, "Lib",
                                         "site-packages")
    else:
        current_site_packages_dir = op.join(
            current_venv, "lib", get_venv_from_python_version(),
            "site-packages"
        )
        venv_site_packages_dir = op.join(
            ve_path, "lib", get_venv_from_python_version(), "site-packages"
        )

    if not op.isdir(venv_site_packages_dir):
        makedirs(venv_site_packages_dir)

    # Copy zappa* to the new virtualenv
    zappa_things = [
        z for z in listdir(current_site_packages_dir) if
        z.lower()[:5] == "zappa"
    ]
    for z in zappa_things:
        copytree(
            op.join(current_site_packages_dir, z),
            op.join(venv_site_packages_dir, z),
        )

    # Use pip to download zappa's dependencies.
    # Copying from current venv causes issues with things like
    # PyYAML that installs as yaml
    zappa_deps = self.get_deps_list("zappa")
    pkg_list = ["{0!s}=={1!s}".format(dep, version) for dep, version in
                zappa_deps]

    # Need to manually add setuptools
    pkg_list.append("setuptools")
    command = [
                  "pip",
                  "install",
                  "--quiet",
                  "--target",
                  venv_site_packages_dir,
              ] + pkg_list

    # This is the recommended method for installing packages if you don't
    # to depend on `setuptools`
    # https://github.com/pypa/pip/issues/5240#issuecomment-381662679
    pip_process = subprocess.Popen(command, stdout=subprocess.PIPE)
    # Using communicate() to avoid deadlocks
    pip_process.communicate()
    pip_return_code = pip_process.returncode

    if pip_return_code:
        raise EnvironmentError("Pypi lookup failed")

    return ve_path


# staticmethod as per https://github.com/Miserlou/Zappa/issues/780
@staticmethod
def get_current_venv():
    if "VIRTUAL_ENV" in environ:
        venv = environ["VIRTUAL_ENV"]
    elif op.exists(".python-version"):  # pragma: no cover
        try:
            subprocess.check_output(["pyenv", "help"],
                                    stderr=subprocess.STDOUT)
        except OSError:
            print(
                "This directory seems to have pyenv's local venv, "
                "but pyenv executable was not found."
            )
        with open(".python-version", "r") as f:
            env_name = f.readline().strip()
        bin_path = subprocess.check_output(
            ["pyenv", "which", "python"]).decode(
            "utf-8"
        )
        venv = bin_path[: bin_path.rfind(env_name)] + env_name
    else:  # pragma: no cover
        return None
    return venv


def extract_lambda_package(self, wheel_name, path):
    """
    Extracts the lambda package into a given path. Assumes the package
    exists
    in lambda packages.
    """
    print(f'extracting {wheel_name}')
    lambda_package = lambda_packages[wheel_name][self.runtime]

    # Trash the local version to help with package space saving
    rmtree(op.join(path, wheel_name), ignore_errors=True)

    tar = tarfile.open(lambda_package["path"], mode="r:gz")
    for member in tar.getmembers():
        tar.extract(member, path)


@staticmethod
def get_installed_packages(site_packages, site_packages_64):
    """
    Returns a dict of installed packages that Zappa cares about.
    """
    import pkg_resources

    package_to_keep = []
    if op.isdir(site_packages):
        package_to_keep += listdir(site_packages)
    if op.isdir(site_packages_64):
        package_to_keep += listdir(site_packages_64)

    package_to_keep = [x.lower() for x in package_to_keep]
    # print("Packages to keep:")
    # pprint(package_to_keep)

    installed_packages = {
        package.project_name.lower(): package.version
        for package in pkg_resources.WorkingSet()
        if package.project_name.lower() in package_to_keep
           or package.location.lower()
           in [site_packages.lower(), site_packages_64.lower()]
    }

    # print('Installed packages:')
    # pprint(installed_packages)

    return installed_packages


def have_correct_lambda_package_version(self, package_name,
                                        package_version):
    """
    Checks if a given package version binary should be copied over from
    lambda packages.
    package_name should be lower-cased version of package name.
    """
    lambda_package_details = lambda_packages.get(package_name, {}).get(
        self.runtime)

    if lambda_package_details is None:
        return False

    # Binaries can be compiled for different package versions
    # Related: https://github.com/Miserlou/Zappa/issues/800
    if package_version != lambda_package_details["version"]:
        return False
    print(package_name, package_version)

    return True


def have_any_lambda_wheel_version(self, package_name):
    """
    Checks if a given package has any lambda package version.
    We can try and use it with a warning.
    package_name should be lower-cased version of package name.
    """
    return lambda_packages.get(package_name, {}).get(
        self.runtime) is not None


@staticmethod
def download_url_with_progress(url, stream, disable_progress):
    """
    Downloads a given url in chunks and writes to the provided stream
    (can be any io stream).
    Displays the progress bar for the download.
    """
    resp = requests.get(url, timeout=2, stream=True)
    resp.raw.decode_content = True

    progress = tqdm(
        unit="B",
        unit_scale=True,
        total=int(resp.headers.get("Content-Length", 0)),
        disable=disable_progress,
    )
    for chunk in resp.iter_content(chunk_size=1024):
        if chunk:
            progress.update(len(chunk))
            stream.write(chunk)

    progress.close()


def get_cached_manylinux_wheel(
        self, package_name, package_version, local_wheels_dir,
        remote_wheels_url, disable_progress
):
    """
    Gets the locally stored version of a manylinux wheel.
    If one does not exist, the function downloads it.
    """
    cached_wheels_dir = op.join(tempfile.gettempdir(), "cached_wheels")
    if not op.isdir(cached_wheels_dir):
        makedirs(cached_wheels_dir)

    wheel_file = "{0!s}-{1!s}-{2!s}".format(
        package_name, package_version, self.manylinux_wheel_file_suffix
    )

    # local_wheels = [a for a in listdir(local_wheels_dir) if
    #                         ".whl" in a]
    # local_wheel_file = [
    #     a for a in local_wheels if (package_name in a) and (
    #             package_version in a)
    # ][0]
    wheel_path = op.join(cached_wheels_dir, wheel_file)
    if not op.exists(wheel_path) or not zipfile.is_zipfile(wheel_path):
        # The file is not cached, download it.
        wheel_url = self.get_manylinux_wheel_url(package_name,
                                                 package_version)

        if not wheel_url:
            return None

        print(
            " - {}=={}: Downloading".format(package_name, package_version))
        with open(wheel_path, 'wb') as f:
            self.download_url_with_progress(wheel_url, f, disable_progress)

        if not zipfile.is_zipfile(wheel_path):
            return None
    else:
        print(" - {}=={}: Using locally cached manylinux wheel".format(
            package_name, package_version))

    return wheel_path


def get_manylinux_wheel_url(self, package_name, package_version):
    """
    For a given package name, returns a link to the download URL,
    else returns None.

    Related:
    https://github.com/Miserlou/Zappa/issues/398

    Examples here:
    https://gist.github.com/perrygeo/9545f94eaddec18a65fd7b56880adbae

    This function downloads metadata JSON of `package_name` from Pypi
    and examines if the package has a manylinux wheel. This function
    also caches the JSON file so that we don't have to poll Pypi
    every time.
    """
    cached_pypi_info_dir = op.join(tempfile.gettempdir(),
                                   "cached_pypi_info")
    if not op.isdir(cached_pypi_info_dir):
        makedirs(cached_pypi_info_dir)
    # Even though the metadata is for the package, we save it in a
    # filename that includes the package's version. This helps in
    # invalidating the cached file if the user moves to a different
    # version of the package.
    # Related: https://github.com/Miserlou/Zappa/issues/899
    json_file = "{0!s}-{1!s}.json".format(package_name, package_version)
    json_file_path = op.join(cached_pypi_info_dir, json_file)
    if op.exists(json_file_path):
        with open(json_file_path, "rb") as metafile:
            data = json.load(metafile)
    else:
        url = "https://pypi.python.org/pypi/{}/json".format(package_name)
        try:
            res = requests.get(url, timeout=1.5)
            data = res.json()
        except Exception as e:  # pragma: no cover
            return None
        with open(json_file_path, "wb") as metafile:
            jsondata = json.dumps(data)
            metafile.write(bytes(jsondata, "utf-8"))

    if package_version not in data["releases"]:
        return None

    for f in data["releases"][package_version]:
        if f["filename"].endswith(self.manylinux_wheel_file_suffix):
            return f["url"]
    return None


def create_lambda_zip(
        self,
        prefix="lambda_package",
        handler_file=None,
        slim_handler=False,
        minify=True,
        exclude=None,
        temp_dir=None,
        local_wheels_dir=None,
        remote_wheels_url='https://github.com/lesleslie/lambda_wheels_3_7',
        use_precompiled_packages=True,
        include=None,
        venv=None,
        output=None,
        disable_progress=False,
        archive_format="zip",
):
    if archive_format not in ["zip", "tarball"]:
        raise KeyError(
            "The archive format to create a lambda package must be zip or "
            "tarball"
        )

    if not venv:
        venv = self.get_current_venv()

    build_time = str(int(time.time()))
    cwd = getcwd()
    archive_fname = ''
    if not output:
        if archive_format == "zip":
            archive_fname = prefix + "-" + build_time + ".zip"
        elif archive_format == "tarball":
            archive_fname = prefix + "-" + build_time + ".tar.gz"
    else:
        archive_fname = output
    archive_path = op.join(cwd, archive_fname)

    if exclude is None:
        exclude = list()

    exclude.append(archive_path)

    # Make sure that 'concurrent' is always forbidden.
    # https://github.com/Miserlou/Zappa/issues/827
    if not "concurrent" in exclude:
        exclude.append("concurrent")

    def splitpath(path):
        parts = []
        (path, tail) = op.split(path)
        while path and tail:
            parts.append(tail)
            (path, tail) = op.split(path)
        parts.append(op.join(path, tail))
        return list(map(op.normpath, parts))[::-1]

    split_venv = splitpath(venv)
    split_cwd = splitpath(cwd)

    if split_venv[-1] == split_cwd[-1]:  # pragma: no cover
        print(
            "Warning! Your project and virtualenv have the same name! You "
            "may want "
            "to re-create your venv with a new name, or explicitly define "
            "a 'project_name', as this may cause errors."
        )

    # temp_project_path = tempfile.mkdtemp(prefix="zappa-project")
    temp_project_path = op.join(temp_dir, "zappa-project",
                                uuid4().hex)

    if not slim_handler:
        if minify:
            # Related: https://github.com/Miserlou/Zappa/issues/744
            excludes = ZIP_EXCLUDES + exclude + [split_venv[-1]]
            # dir_excludes = self.get_from_dirs(cwd, excludes)
            # file_excludes = self.get_from_dir(cwd, excludes)
            copytree(
                cwd,
                temp_project_path,
                metadata=False,
                excludes=excludes,
                # ignore=ignore_patterns(*list(excludes)),
            )
        else:
            copytree(cwd, temp_project_path,
                     metadata=False,
                     symlinks=False)

    # If a handler_file is supplied, copy that to the root of the package,
    # because that's where AWS Lambda looks for it. It can't be inside a
    # package.
    if handler_file:
        filename = handler_file.split(sep)[-1]
        copy(handler_file, op.join(temp_project_path, filename))

    # Create and populate package ID file and write to temp project path
    package_info = dict()
    package_info["uuid"] = uuid4().hex
    package_info["build_time"] = build_time
    package_info["build_platform"] = sys.platform
    package_info["build_user"] = getpass.getuser()
    # TODO: Add git head and info?

    package_id_file = open(
        op.join(temp_project_path, "package_info.json"), "w"
    )
    dumped = json.dumps(package_info, indent=4)
    try:
        package_id_file.write(dumped)
    except TypeError:  # This is a Python 2/3 issue. TODO: Make pretty!
        package_id_file.write(dumped)
    package_id_file.close()

    # Then, do site site-packages..
    egg_links = []
    # temp_package_path = tempfile.mkdtemp(prefix="zappa-packages")
    temp_package_path = op.join(temp_dir, "zappa-packages",
                                uuid4().hex)
    if sys.platform == "win32":
        site_packages = op.join(venv, "Lib", "site-packages")
    else:
        site_packages = op.join(
            venv, "lib", get_venv_from_python_version(), "site-packages"
        )
    egg_links.extend(glob(op.join(site_packages, "*.egg-link")))

    if minify:
        excludes = ZIP_EXCLUDES + exclude
        # dir_excludes = self.get_from_dirs(cwd, excludes)
        # file_excludes = self.get_from_dir(cwd, excludes)
        copytree(
            site_packages,
            temp_package_path,
            excludes=excludes,
            metadata=False,
            symlinks=False,
            # ignore=ignore_patterns(*excludes),
        )
    else:
        copytree(site_packages, temp_package_path, metadata=False,
                 symlinks=False)

    # We may have 64-bin specific packages too.
    site_packages_64 = op.join(
        venv, "lib64", get_venv_from_python_version(), "site-packages"
    )
    if op.exists(site_packages_64):
        egg_links.extend(
            glob(op.join(site_packages_64, "*.egg-link")))
        if minify:
            excludes = ZIP_EXCLUDES + exclude
            # dir_excludes = self.get_from_dirs(cwd, excludes)
            # file_excludes = self.get_from_dir(cwd, excludes)
            copytree(
                site_packages_64,
                temp_package_path,
                metadata=False,
                symlinks=False,
                excludes=excludes,
                # ignore=ignore_patterns(*list(excludes)),
            )
        else:
            copytree(
                site_packages_64, temp_package_path,  # metadata=False,
                symlinks=False
            )

    if egg_links:
        print("Egg links:")
        pprint(egg_links)
        self.copy_editable_packages(egg_links, temp_package_path)

    copy_tree(temp_package_path, temp_project_path, update=True)

    # Then the pre-compiled packages..
    if use_precompiled_packages:
        print("Downloading and installing dependencies..")
        installed_packages = self.get_installed_packages(
            site_packages, site_packages_64
        )

        # print("Installed packages:")
        # pprint(installed_packages)

        try:
            for (
                    installed_package_name,
                    installed_package_version,
            ) in installed_packages.items():
                if self.have_correct_lambda_package_version(
                        installed_package_name, installed_package_version
                ):
                    print(
                        f"Have correct version -  {installed_package_name}")
                    print(
                        " - %s==%s: Using precompiled lambda package "
                        % (
                            installed_package_name,
                            installed_package_version)
                    )
                    self.extract_lambda_package(
                        installed_package_name, temp_project_path
                    )
                else:
                    cached_wheel_path = self.get_cached_manylinux_wheel(
                        installed_package_name,
                        installed_package_version,
                        local_wheels_dir,
                        remote_wheels_url,
                        disable_progress,
                    )
                    if cached_wheel_path:
                        # Otherwise try to use manylinux packages from
                        # PyPi..
                        # Related:
                        # https://github.com/Miserlou/Zappa/issues/398
                        rmtree(
                            op.join(temp_project_path,
                                    installed_package_name),
                            ignore_errors=True,
                        )
                        with zipfile.ZipFile(cached_wheel_path) as zfile:
                            zfile.extractall(temp_project_path)

            # This is a special case!
            # SQLite3 is part of the _system_ Python, not a package.
            # Still, it lives in `lambda-packages`.
            # Everybody on Python3 gets it!
            # if self.runtime in ("python3.6", "python3.7"):
            #     print(" - sqlite==python3: Using precompiled lambda
            #     package")
            #     self.extract_lambda_package("sqlite3", temp_project_path)

        except Exception as e:
            print(f'Error:  {e}')
            print('Cleaning up...')
            for p in [temp_project_path, temp_package_path]:
                rmtree(p)
            if op.isdir(venv) and slim_handler:
                # Remove the temporary handler venv folder
                rmtree(venv)
            # XXX - What should we do here?

    # Then archive it all up..
    try:
        if archive_format == "zip":
            print("Packaging project as zip.")

            try:
                compression_method = zipfile.ZIP_DEFLATED
            except ImportError:  # pragma: no cover
                compression_method = zipfile.ZIP_STORED
            archivef = zipfile.ZipFile(archive_path, "w",
                                       compression_method)

        elif archive_format == "tarball":
            print("Packaging project as gzipped tarball.")
            archivef = tarfile.open(archive_path, "w|gz")

        for root, dirs, files in walk(temp_project_path):
            for filename in files:

                # Skip .pyc files for Django migrations
                # https://github.com/Miserlou/Zappa/issues/436
                # https://github.com/Miserlou/Zappa/issues/464
                if filename[-4:] == ".pyc" and root[-10:] == "migrations":
                    continue

                # If there is a .pyc file in this package,
                # we can skip the python source code as we'll just
                # use the compiled bytecode anyway..
                if filename[-3:] == ".py" and root[-10:] != "migrations":
                    abs_filname = op.join(root, filename)
                    abs_pyc_filename = abs_filname + "c"
                    if op.isfile(abs_pyc_filename):

                        # but only if the pyc is older than the py,
                        # otherwise we'll deploy outdated code!
                        py_time = stat(abs_filname).st_mtime
                        pyc_time = stat(abs_pyc_filename).st_mtime

                        if pyc_time > py_time:
                            continue

                # Make sure that the files are all correctly chmodded
                # Related: https://github.com/Miserlou/Zappa/issues/484
                # Related: https://github.com/Miserlou/Zappa/issues/682
                chmod(op.join(root, filename), 0o755)

                if archive_format == "zip":
                    # Actually put the file into the proper place in the zip
                    # Related: https://github.com/Miserlou/Zappa/pull/716
                    zipi = zipfile.ZipInfo(
                        op.join(
                            root.replace(temp_project_path, "").lstrip(
                                sep),
                            filename
                        )
                    )
                    zipi.create_system = 3
                    zipi.external_attr = 0o755 << int(
                        16)  # Is this P2/P3 functional?
                    with open(op.join(root, filename), "rb") as f:
                        archivef.writestr(zipi, f.read(),
                                          compression_method)
                elif archive_format == "tarball":
                    tarinfo = tarfile.TarInfo(
                        op.join(
                            root.replace(temp_project_path, "").lstrip(
                                sep),
                            filename
                        )
                    )
                    tarinfo.mode = 0o755

                    stat = stat(op.join(root, filename))
                    tarinfo.mtime = stat.st_mtime
                    tarinfo.size = stat.st_size
                    with open(op.join(root, filename), "rb") as f:
                        archivef.addfile(tarinfo, f)

            # Create python init file if it does not exist
            # Only do that if there are sub folders or python files and
            # does not
            # conflict with a neighbouring module
            # Related: https://github.com/Miserlou/Zappa/issues/766
            if not contains_python_files_or_subdirs(root):
                # if the directory does not contain any .py file at any
                # level,
                # we can skip the rest
                dirs[:] = [d for d in dirs if d != root]
            else:
                if (
                        "__init__.py" not in files
                        and not conflicts_with_a_neighbouring_module(root)
                ):
                    tmp_init = op.join(temp_project_path,
                                       "__init__.py")
                    open(tmp_init, "a").close()
                    chmod(tmp_init, 0o755)

                    arcname = op.join(
                        root.replace(temp_project_path, ""),
                        op.join(
                            root.replace(temp_project_path, ""),
                            "__init__.py"
                        ),
                    )
                    if archive_format == "zip":
                        archivef.write(tmp_init, arcname)
                    elif archive_format == "tarball":
                        archivef.add(tmp_init, arcname)

    except Exception as e:
        print(e)
    finally:
        archivef.close()
        print('Cleaning up...')
        # Trash the temp directory
        rmtree(temp_project_path)
        rmtree(temp_package_path)
        if op.isdir(venv) and slim_handler:
            # Remove the temporary handler venv folder
            rmtree(venv)

        return archive_fname
