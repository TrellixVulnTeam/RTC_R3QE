import json
import logging
import os
from string import digits

import botocore
import time
import troposphere
import troposphere.apigateway
from boto3 import Session, resource
from botocore.exceptions import ClientError
from builtins import int

from .utils import (add_event_source, get_topic_name, ppformat, pprint)

for p in [pprint, ppformat]:
    pass

# We lower-case lambda package keys to match lower-cased
# keys in get_installed_packages()
# lambda_packages = {
#     package_name.lower(): val for package_name, val in
#     lambda_packages_orig.items()
# }

boto_resource = resource("s3")

lambda_packages = dict()

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
            tags=(),
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

        self.fn_version = "".join([d for d in runtime if d in digits])
        self.manylinux_wheel_file_suffix = (
            f"cp{self.fn_version}mu-manylinux1_x86_64.whl"
        )

        self.endpoint_urls = dict()
        if endpoint_urls:
            self.endpoint_urls = endpoint_urls

        self.xray_tracing = xray_tracing

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
        long_config = botocore.client.Config(**long_config_dict)

        if load_credentials:
            self.load_credentials(boto_session, profile_name)

            # Initialize clients
            self.s3_client = self.boto_client("s3")
            self.lambda_client = self.boto_client("lambda",
                                                  config=long_config)
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

        self.tags = tags
        self.cf_template = troposphere.Template()
        self.cf_api_resources = []
        self.cf_parameters = {}

    def configure_boto_session_method_kwargs(self, service, kw):
        """Allow for custom endpoint urls for non-AWS (testing and bootleg
        cloud)
         deployments"""
        if service in self.endpoint_urls and not "endpoint_url" in kw:
            kw["endpoint_url"] = self.endpoint_urls[service]
        return kw

    # def boto_client(self, service, *args, **kwargs):
    #     """A wrapper to apply configuration options to boto clients"""
    #     return self.boto_session.client(
    #         service, *args,
    #         **self.configure_boto_session_method_kwargs(service, kwargs)
    #     )

    def boto_resource(self, service, *args, **kwargs):
        """A wrapper to apply configuration options to boto resources"""
        return self.boto_session.resource(
            service, *args,
            **self.configure_boto_session_method_kwargs(service, kwargs)
        )

    def cache_param(self, value):
        """Returns a troposphere Ref to a value cached as a parameter."""

        if value not in self.cf_parameters:
            keyname = chr(ord("A") + len(self.cf_parameters))
            param = self.cf_template.add_parameter(
                troposphere.Parameter(
                    keyname, Type="String", Default=value, tags=self.tags
                )
            )

            self.cf_parameters[value] = param

        return troposphere.Ref(self.cf_parameters[value])




    ##
    # S3
    ##



    ##
    # Lambda
    ##


    ##
    # IAM
    ##

    def get_credentials_arn(self):
        """
        Given our role name, get and set the credentials_arn.

        """
        role = self.iam.Role(self.role_name)
        self.credentials_arn = role.arn
        return role, self.credentials_arn

    def create_iam_roles(self):
        """
        Create and defines the IAM roles and policies necessary for Zappa.

        If the IAM role already exists, it will be updated if necessary.
        """
        attach_policy_obj = json.loads(self.attach_policy)
        assume_policy_obj = json.loads(self.assume_policy)

        if self.extra_permissions:
            for permission in self.extra_permissions:
                attach_policy_obj["Statement"].append(dict(permission))
            self.attach_policy = json.dumps(attach_policy_obj)

        updated = False

        # Create the role if needed
        try:
            role, credentials_arn = self.get_credentials_arn()

        except botocore.client.ClientError:
            print("Creating " + self.role_name + " IAM Role..")

            role = self.iam.create_role(
                RoleName=self.role_name,
                AssumeRolePolicyDocument=self.assume_policy
            )
            self.credentials_arn = role.arn
            updated = True

        # create or update the role's policies if needed
        policy = self.iam.RolePolicy(self.role_name, "zappa-permissions")
        try:
            if policy.policy_document != attach_policy_obj:
                print(
                    "Updating zappa-permissions policy on "
                    + self.role_name
                    + " IAM Role."
                )

                policy.put(PolicyDocument=self.attach_policy)
                updated = True

        except botocore.client.ClientError:
            print(
                "Creating zappa-permissions policy on " + self.role_name + " IAM Role."
            )
            policy.put(PolicyDocument=self.attach_policy)
            updated = True

        if role.assume_role_policy_document != assume_policy_obj and set(
                role.assume_role_policy_document["Statement"][0]["Principal"][
                    "Service"]
        ) != set(assume_policy_obj["Statement"][0]["Principal"]["Service"]):
            print(
                "Updating assume role policy on " + self.role_name + " IAM "
                                                                     "Role.")
            self.iam_client.update_assume_role_policy(
                RoleName=self.role_name, PolicyDocument=self.assume_policy
            )
            updated = True

        return self.credentials_arn, updated

    def _clear_policy(self, lambda_name):
        """
        Remove obsolete policy statements to prevent policy from bloating
        over the limit after repeated updates.
        """
        try:
            policy_response = self.lambda_client.get_policy(
                FunctionName=lambda_name)
            if policy_response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                statement = json.loads(policy_response["Policy"])["Statement"]
                for s in statement:
                    delete_response = self.lambda_client.remove_permission(
                        FunctionName=lambda_name, StatementId=s["Sid"]
                    )
                    if delete_response["ResponseMetadata"][
                        "HTTPStatusCode"] != 204:
                        logger.error(
                            "Failed to delete an obsolete policy statement: {"
                            "}".format(
                                policy_response
                            )
                        )
            else:
                logger.debug(
                    "Failed to load Lambda function policy: {}".format(
                        policy_response)
                )
        except ClientError as e:
            if e.args[0].find("ResourceNotFoundException") > -1:
                logger.debug("No policy found, must be first run.")
            else:
                logger.error("Unexpected client error {}".format(e.args[0]))

    ##
    # CloudWatch Events
    ##


    ###
    # Async / SNS
    ##

    def create_async_sns_topic(self, lambda_name, lambda_arn):
        """
        Create the SNS-based async topic.
        """
        topic_name = get_topic_name(lambda_name)
        # Create SNS topic
        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]
        # Create subscription
        self.sns_client.subscribe(
            TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn
        )
        # Add Lambda permission for SNS to invoke function
        self.create_event_permission(
            lambda_name=lambda_name, principal="sns.amazonaws.com",
            source_arn=topic_arn
        )
        # Add rule for SNS topic as a event source
        add_event_source(
            event_source={"arn": topic_arn, "events": ["sns:Publish"]},
            lambda_arn=lambda_arn,
            target_function="zappa.asynchronous.route_task",
            boto_session=self.boto_session,
        )
        return topic_arn

    def remove_async_sns_topic(self, lambda_name):
        """
        Remove the async SNS topic.
        """
        topic_name = get_topic_name(lambda_name)
        removed_arns = []
        for sub in self.sns_client.list_subscriptions()["Subscriptions"]:
            if topic_name in sub["TopicArn"]:
                self.sns_client.delete_topic(TopicArn=sub["TopicArn"])
                removed_arns.append(sub["TopicArn"])
        return removed_arns

    ###
    # Async / DynamoDB
    ##

    def _set_async_dynamodb_table_ttl(self, table_name):
        self.dynamodb_client.update_time_to_live(
            TableName=table_name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
        )

    def create_async_dynamodb_table(self, table_name, read_capacity,
                                    write_capacity):
        """
        Create the DynamoDB table for async task return values
        """
        try:
            dynamodb_table = self.dynamodb_client.describe_table(
                TableName=table_name)
            return False, dynamodb_table

        # catch this exception (triggered if the table doesn't exist)
        except botocore.exceptions.ClientError:
            dynamodb_table = self.dynamodb_client.create_table(
                AttributeDefinitions=[
                    {"AttributeName": "id", "AttributeType": "S"}],
                TableName=table_name,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                ProvisionedThroughput={
                    "ReadCapacityUnits": read_capacity,
                    "WriteCapacityUnits": write_capacity,
                },
            )
            if dynamodb_table:
                try:
                    self._set_async_dynamodb_table_ttl(table_name)
                except botocore.exceptions.ClientError:
                    # this fails because the operation is async, so retry
                    time.sleep(10)
                    self._set_async_dynamodb_table_ttl(table_name)

        return True, dynamodb_table

    def remove_async_dynamodb_table(self, table_name):
        """
        Remove the DynamoDB Table used for async return values
        """
        self.dynamodb_client.delete_table(TableName=table_name)

    ##
    # CloudWatch Logging
    ##

    def fetch_logs(self, lambda_name, filter_pattern="", limit=10000,
                   start_time=0):
        """
        Fetch the CloudWatch logs for a given Lambda name.
        """
        log_name = "/aws/lambda/" + lambda_name
        streams = self.logs_client.describe_log_streams(
            logGroupName=log_name, descending=True, orderBy="LastEventTime"
        )

        all_streams = streams["logStreams"]
        all_names = [stream["logStreamName"] for stream in all_streams]

        events = []
        response = {}
        while not response or "nextToken" in response:
            extra_args = {}
            if "nextToken" in response:
                extra_args["nextToken"] = response["nextToken"]

            # Amazon uses millisecond epoch for some reason.
            # Thanks, Jeff.
            start_time = start_time * 1000
            end_time = int(time.time()) * 1000

            response = self.logs_client.filter_log_events(
                logGroupName=log_name,
                logStreamNames=all_names,
                startTime=start_time,
                endTime=end_time,
                filterPattern=filter_pattern,
                limit=limit,
                interleaved=True,  # Does this actually improve performance?
                **extra_args,
            )
            if response and "events" in response:
                events += response["events"]

        return sorted(events, key=lambda k: k["timestamp"])

    def remove_log_group(self, group_name):
        """
        Filter all log groups that match the name given in log_filter.
        """
        print("Removing log group: {}".format(group_name))
        try:
            self.logs_client.delete_log_group(logGroupName=group_name)
        except botocore.exceptions.ClientError as e:
            print("Couldn't remove '{}' because of: {}".format(group_name, e))

    def remove_lambda_function_logs(self, lambda_function_name):
        """
        Remove all logs that are assigned to a given lambda function id.
        """
        self.remove_log_group("/aws/lambda/{}".format(lambda_function_name))

    def remove_api_gateway_logs(self, project_name):
        """
        Removed all logs that are assigned to a given rest api id.
        """
        for rest_api in self.get_rest_apis(project_name):
            for stage in \
                    self.apigateway_client.get_stages(restApiId=rest_api["id"])[
                        "item"
                    ]:
                self.remove_log_group(
                    "API-Gateway-Execution-Logs_{}/{}".format(
                        rest_api["id"], stage["stageName"]
                    )
                )

    ##
    # Route53 Domain Name Entries
    ##

    def get_hosted_zone_id_for_domain(self, domain):
        """
        Get the Hosted Zone ID for a given domain.

        """
        all_zones = self.get_all_zones()
        return self.get_best_match_zone(all_zones, domain)

    @staticmethod
    def get_best_match_zone(all_zones, domain):
        """Return zone id which name is closer matched with domain name."""

        # Related: https://github.com/Miserlou/Zappa/issues/459
        public_zones = [
            zone
            for zone in all_zones["HostedZones"]
            if not zone["Config"]["PrivateZone"]
        ]

        zones = {
            zone["Name"][:-1]: zone["Id"]
            for zone in public_zones
            if zone["Name"][:-1] in domain
        }
        if zones:
            keys = max(
                zones.keys(), key=lambda a: len(a)
            )  # get longest key -- best match.
            return zones[keys]
        else:
            return None

    def set_dns_challenge_txt(self, zone_id, domain, txt_challenge):
        """
        Set DNS challenge TXT.
        """
        print("Setting DNS challenge..")
        resp = self.route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch=self.get_dns_challenge_change_batch(
                "UPSERT", domain, txt_challenge
            ),
        )

        return resp

    def remove_dns_challenge_txt(self, zone_id, domain, txt_challenge):
        """
        Remove DNS challenge TXT.
        """
        print("Deleting DNS challenge..")
        resp = self.route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch=self.get_dns_challenge_change_batch(
                "DELETE", domain, txt_challenge
            ),
        )

        return resp

    @staticmethod
    def get_dns_challenge_change_batch(action, domain, txt_challenge):
        """
        Given action, domain and challenge, return a change batch to use with
        route53 call.

        :param action: DELETE | UPSERT
        :param domain: domain name
        :param txt_challenge: challenge
        :return: change set for a given action, domain and TXT challenge.
        """
        return {
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": "_acme-challenge.{0}".format(domain),
                        "Type": "TXT",
                        "TTL": 60,
                        "ResourceRecords": [
                            {"Value": '"{0}"'.format(txt_challenge)}],
                    },
                }
            ]
        }

    ##
    # Utility
    ##

    def shell(self):
        """
        Spawn a PDB shell.
        """
        import pdb

        pdb.set_trace()

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
