import logging
from dataclasses import dataclass
from typing import Any

from boto3 import Session
from botocore.config import Config

from .utils import (ppformat, pprint)

for p in [pprint, ppformat]:
    pass

logging.basicConfig(format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ASSUME_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "apigateway.amazonaws.com",
          "lambda.amazonaws.com",
          "events.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}"""

ATTACH_POLICY = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:*"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "lambda:InvokeFunction"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AttachNetworkInterface",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeInstances",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DetachNetworkInterface",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:ResetNetworkInterfaceAttribute"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": "arn:aws:s3:::*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kinesis:*"
            ],
            "Resource": "arn:aws:kinesis:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:*"
            ],
            "Resource": "arn:aws:sns:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sqs:*"
            ],
            "Resource": "arn:aws:sqs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:*"
            ],
            "Resource": "arn:aws:dynamodb:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "route53:*"
            ],
            "Resource": "*"
        }
    ]
}"""

# Latest list:
# https://docs.aws.amazon.com/general/latest/gr/rande.html#apigateway_region
API_GATEWAY_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-south-1",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "sa-east-1",
]

# Latest list:
# https://docs.aws.amazon.com/general/latest/gr/rande.html#lambda_region
LAMBDA_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-south-1",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "sa-east-1",
    "us-gov-west-1",
]


@dataclass
class ZappaConfig(object):
    boto_session: Session = None
    profile_name: str = None
    aws_region: str = None
    load_credentials: bool = True
    desired_role_name: str = None
    desired_role_arn: str = None
    runtime: str = "python3.7"  # Detected at runtime in CLI
    tags: Any = ()
    endpoint_urls: Any = None
    xray_tracing: bool = False

    http_methods = ["ANY"]
    role_name = "ZappaLambdaExecution"
    extra_permissions = None
    assume_policy = ASSUME_POLICY
    attach_policy = ATTACH_POLICY
    apigateway_policy = None
    cloudwatch_log_levels = ["OFF", "ERROR", "INFO"]
    credentials_arn = None

    # Set aws_region to None to use the system's region instead
    def __post_init__(self):

        if self.aws_region is None:
            # https://github.com/Miserlou/Zappa/issues/413
            self.aws_region = Session().region_name
            logger.debug("Set region from boto: %s", self.aws_region)
        else:
            self.aws_region = self.aws_region

        if self.desired_role_name:
            self.role_name = self.desired_role_name

        if self.desired_role_arn:
            self.credentials_arn = self.desired_role_arn

        self.long_config_dict = {
            "region_name": self.aws_region,
            "connect_timeout": 5,
            "read_timeout": 300,
        }
        self.long_config = Config(**self.long_config_dict)
        self.east_config = Config(region_name="us-east-1")

    # def load_credentials(self, boto_session=None, profile_name=None):
    #     """
    #     Load AWS credentials.
    #
    #     An optional boto_session can be provided, but that's usually for
    #     testing.
    #
    #     An optional profile_name can be provided for config files that have
    #     multiple sets
    #     of credentials.
    #     """
    #     # Automatically load credentials from config or environment
    #     if not boto_session:
    #
    #         # If provided, use the supplied profile name.
    #         if profile_name:
    #             self.boto_session = Session(
    #                 profile_name=profile_name, region_name=self.aws_region
    #             )
    #         elif environ.get("AWS_ACCESS_KEY_ID") and environ.get(
    #                 "AWS_SECRET_ACCESS_KEY"
    #         ):
    #             region_name = environ.get(
    #                 "AWS_DEFAULT_REGION") or self.aws_region
    #             session_kw = {
    #                 "aws_access_key_id": environ.get("AWS_ACCESS_KEY_ID"),
    #                 "aws_secret_access_key": environ.get(
    #                     "AWS_SECRET_ACCESS_KEY"),
    #                 "region_name": region_name,
    #             }
    #
    #             # If we're executing in a role, AWS_SESSION_TOKEN will be
    #             # present, too.
    #             if environ.get("AWS_SESSION_TOKEN"):
    #                 session_kw["aws_session_token"] = environ.get(
    #                     "AWS_SESSION_TOKEN"
    #                 )
    #
    #             self.boto_session = Session(**session_kw)
    #         else:
    #             self.boto_session = Session(region_name=self.aws_region)
    #
    #         logger.debug("Loaded boto session from config: %s", boto_session)
    #     else:
    #         logger.debug("Using provided boto session: %s", boto_session)
    #         self.boto_session = boto_session
    #
    #     # use provided session's region in case it differs
    #     self.aws_region = self.boto_session.region_name
    #
    #     if self.boto_session.region_name not in LAMBDA_REGIONS:
    #         print(
    #             "Warning! AWS Lambda may not be available in this AWS
    #             Region!")
    #
    #     if self.boto_session.region_name not in API_GATEWAY_REGIONS:
    #         print(
    #             "Warning! AWS API Gateway may not be available in this AWS "
    #             "Region!")
