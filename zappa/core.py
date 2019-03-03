import logging
import os
from dataclasses import dataclass
from random import choice
from string import ascii_uppercase, digits

from boto3 import Session
from botocore.config import Config
from botocore.exceptions import ClientError
from troposphere import Template

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
class Zappa(object):
    """
    Zappa!

    Makes it easy to run Python web applications on AWS Lambda/API Gateway.

    """

    http_methods = ["ANY"]
    role_name = "ZappaLambdaExecution"
    extra_permissions = None
    assume_policy = ASSUME_POLICY
    attach_policy = ATTACH_POLICY
    apigateway_policy = None
    cloudwatch_log_levels = ["OFF", "ERROR", "INFO"]
    xray_tracing = False

    boto_session = None
    credentials_arn = None

    def __init__(
            self,
            boto_session=None,
            profile_name=None,
            aws_region=None,
            load_credentials=True,
            desired_role_name=None,
            desired_role_arn=None,
            runtime="python3.7",  # Detected at runtime in CLI
            tags=tuple(),
            endpoint_urls=None,
            xray_tracing=False,
    ):

        """
        Instantiate this new Zappa instance, loading any custom credentials
        if necessary.
        """

        # Set aws_region to None to use the system's region instead
        if aws_region is None:
            # https://github.com/Miserlou/Zappa/issues/413
            self.aws_region = Session().region_name
            logger.debug("Set region from boto: %s", self.aws_region)
        else:
            self.aws_region = aws_region

        if desired_role_name:
            self.role_name = desired_role_name

        if desired_role_arn:
            self.credentials_arn = desired_role_arn

        self.runtime = runtime

        self.endpoint_urls = dict()
        if endpoint_urls:
            self.endpoint_urls = endpoint_urls

        self.xray_tracing = xray_tracing

        self.tags = tags

        # Some common invocations, such as DB migrations,
        # can take longer than the default.

        # Note that this is set to 300s, but if connected to
        # APIGW, Lambda will max out at 30s.
        # Related: https://github.com/Miserlou/Zappa/issues/205

        long_config_dict = {
            "region_name": aws_region,
            "connect_timeout": 5,
            "read_timeout": 300,
        }
        long_config = Config(**long_config_dict)
        east_config = Config(region_name="us-east-1")

        if load_credentials:
            self.load_credentials(boto_session, profile_name)

            # Initialize clients
            self.s3 = self.boto_resource("s3")
            self.lambda_ = self.boto_client("lambda",
                                            config=long_config)
            self.events = self.boto_client("events")
            self.apigateway = self.boto_client("apigateway")
            self.acm = self.boto_client("acm", config=east_config)
            self.logs = self.boto_client("logs")
            # self.iam_client = self.boto_client("iam")
            self.iam = self.boto_resource("iam")
            self.cloudwatch = self.boto_client("cloudwatch")
            self.route53 = self.boto_client("route53")
            self.sns = self.boto_resource("sns")
            self.cloudformation = self.boto_client("cloudformation")
            self.dynamodb = self.boto_resource("dynamodb")
            self.cognito = self.boto_client("cognito-idp")
            self.sts = self.boto_client("sts")

            self.cloudformation_template = Template()
            self.cloudformation_api_resources = list()
            self.cloudformation_parameters = dict()

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

    def shell(self):
        """
        Spawn a PDB shell.
        """
        import pdb

        pdb.set_trace()

    def get_credentials_arn(self):
        """
        Given our role name, get and set the credentials_arn.

        """
        role = self.iam.Role(self.role_name)
        self.credentials_arn = role.arn
        return role, self.credentials_arn

    def load_credentials(self, boto_session=None, profile_name=None):
        """
        Load AWS credentials.

        An optional boto_session can be provided, but that's usually for
        testing.

        An optional profile_name can be provided for config files that have
        multiple sets
        of credentials.
        """
        # Automatically load credentials from config or environment
        if not boto_session:

            # If provided, use the supplied profile name.
            if profile_name:
                self.boto_session = Session(
                    profile_name=profile_name, region_name=self.aws_region
                )
            elif os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get(
                    "AWS_SECRET_ACCESS_KEY"
            ):
                region_name = os.environ.get(
                    "AWS_DEFAULT_REGION") or self.aws_region
                session_kw = {
                    "aws_access_key_id": os.environ.get("AWS_ACCESS_KEY_ID"),
                    "aws_secret_access_key": os.environ.get(
                        "AWS_SECRET_ACCESS_KEY"),
                    "region_name": region_name,
                }

                # If we're executing in a role, AWS_SESSION_TOKEN will be
                # present, too.
                if os.environ.get("AWS_SESSION_TOKEN"):
                    session_kw["aws_session_token"] = os.environ.get(
                        "AWS_SESSION_TOKEN"
                    )

                self.boto_session = Session(**session_kw)
            else:
                self.boto_session = Session(region_name=self.aws_region)

            logger.debug("Loaded boto session from config: %s", boto_session)
        else:
            logger.debug("Using provided boto session: %s", boto_session)
            self.boto_session = boto_session

        # use provided session's region in case it differs
        self.aws_region = self.boto_session.region_name

        if self.boto_session.region_name not in LAMBDA_REGIONS:
            print(
                "Warning! AWS Lambda may not be available in this AWS Region!")

        if self.boto_session.region_name not in API_GATEWAY_REGIONS:
            print(
                "Warning! AWS API Gateway may not be available in this AWS "
                "Region!")

    @staticmethod
    def service_from_arn(arn):
        return arn.split(":")[2]

    @staticmethod
    def get_event_name(lambda_name, name):
        """
        Returns an AWS-valid Lambda event name.

        """
        return "{prefix:.{width}}-{postfix}".format(
            prefix=lambda_name, width=max(0, 63 - len(name)), postfix=name
        )[:64]

    def get_event_rule_names_for_lambda(self, lambda_arn):
        """
        Get all of the rule names associated with a lambda function.
        """
        response = self.events.list_rule_names_by_target(
            TargetArn=lambda_arn)
        rule_names = response["RuleNames"]
        # Iterate when the results are paginated
        while "NextToken" in response:
            response = self.events.list_rule_names_by_target(
                TargetArn=lambda_arn, NextToken=response["NextToken"]
            )
            rule_names.extend(response["RuleNames"])
        return rule_names

    def get_event_rules_for_lambda(self, lambda_arn):
        """
        Get all of the rule details associated with this function.
        """
        rule_names = self.get_event_rule_names_for_lambda(lambda_arn=lambda_arn)
        return [self.events.describe_rule(Name=r) for r in rule_names]

    def create_event_permission(self, lambda_name, principal, source_arn):
        """
        Create permissions to link to an event.

        Related: http://docs.aws.amazon.com/lambda/latest/dg/with-s3-example
        -configure-event-source.html
        """
        logger.debug(
            "Adding new permission to invoke Lambda function: {}".format(
                lambda_name)
        )
        permission_response = self.lambda_.add_permission(
            FunctionName=lambda_name,
            StatementId="".join(
                choice(ascii_uppercase + digits) for _ in
                range(8)
            ),
            Action="lambda:InvokeFunction",
            Principal=principal,
            SourceArn=source_arn,
        )
        if permission_response["ResponseMetadata"]["HTTPStatusCode"] != \
                201:
            print("Problem creating permission to invoke Lambda function")
            return None  # XXX: Raise?

        return permission_response

    def remove_log_group(self, group_name):
        """
        Filter all log groups that match the name given in log_filter.
        """
        print("Removing log group: {}".format(group_name))
        try:
            self.logs.delete_log_group(logGroupName=group_name)
        except ClientError as e:
            print("Couldn't remove '{}' because of: {}".format(group_name, e))

    def get_patch_op(self, keypath, value, op="replace"):
        """
        Return an object that describes a change of configuration on the
        given staging.
        Setting will be applied on all available HTTP methods.
        """
        if isinstance(value, bool):
            value = str(value).lower()
        return {"op": op, "path": "/*/*/{}".format(keypath), "value": value}

    def get_rest_apis(self, project_name):
        """
        Generator that allows to iterate per every available apis.
        """
        all_apis = self.apigateway.get_rest_apis(limit=500)

        for api in all_apis["items"]:
            if api["name"] != project_name:
                continue
            yield api

    def delete_stack(self, name, wait=False):
        """
        Delete the CF stack managed by Zappa.
        """
        try:
            stack = \
                self.cloudformation.describe_stacks(StackName=name)["Stacks"][0]
        except:  # pragma: no cover
            print("No Zappa stack named {0}".format(name))
            return False

        tags = {x["Key"]: x["Value"] for x in stack["Tags"]}
        if tags.get("ZappaProject") == name:
            self.cloudformation.delete_stack(StackName=name)
            if wait:
                waiter = self.cloudformation.get_waiter("stack_delete_complete")
                print("Waiting for stack {0} to be deleted..".format(name))
                waiter.wait(StackName=name)
            return True
        else:
            print(
                "ZappaProject tag not found on {0}, doing nothing".format(name))
            return False
