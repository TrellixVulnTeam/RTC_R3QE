from io import open
from os import path as op

from setuptools import setup

basedir = op.abspath(op.dirname(__file__))

setup(
    name="RockingTeenageCombo",
    version=open(op.join(basedir, "VERSION")).read().strip(),
    packages=["rockingteenagecombo"],
    test_suite="pytest",
    include_package_data=True,
    license="MIT License",
    description="Server-less Python Web Services for AWS Lambda and API Gateway",
    long_description=open(op.join(basedir, "README.md")).read(),
    long_description_content_type="text/markdown",
    url="https://gitlab.com/lesleslie/RTC",
    author="Rich Jones",
    author_email="rich@openwatch.net",
    maintainer="Les Leslie",
    maintainer_email="les@wedgwoodwebworks.com",
    entry_points={"console_scripts": ["rtc=rockingteenagecombo.cli:handle",
                                      "zappa=rockingteenagecombo.cli:handle",
                                      "z=rockingteenagecombo.cli:handle",
                                      ]},
    classifiers=[
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        # "Framework :: Django",
        # "Framework :: Django :: 1.11",
        # "Framework :: Django :: 2.0",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
)
