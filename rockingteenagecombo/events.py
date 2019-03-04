from dataclasses import dataclass
from hashlib import sha1
from json import dumps, loads
from logging import getLogger
from random import choice
from string import digits

from boto3 import client
from botocore.exceptions import ClientError

from .lambda_ import Lambda
# from .core import Zappa
from .utils import add_event_source, get_event_source, remove_event_source

logger = getLogger(__name__)


@dataclass
class Events(Lambda):

    def __post_init__(self):
        self.events = client("events")

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

    def get_event_source_status(
            event_source, lambda_arn, target_function, boto_session, dry=False
    ):
        """
        Given an event_source dictionary, create the object and get the event
        source status.
        """

        event_source_obj, ctx, funk = get_event_source(
            event_source, lambda_arn, target_function, boto_session, dry=False
        )
        return event_source_obj.status(funk)

    def _clear_policy(self, lambda_name):
        """
        Remove obsolete policy statements to prevent policy from bloating
        over the limit after repeated updates.
        """
        try:
            policy_response = self.lambda_.get_policy(
                FunctionName=lambda_name)
            if policy_response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                statement = loads(policy_response["Policy"])["Statement"]
                for s in statement:
                    delete_response = self.lambda_.remove_permission(
                        FunctionName=lambda_name, StatementId=s["Sid"]
                    )
                    if delete_response["ResponseMetadata"][
                        "HTTPStatusCode"] != 204:
                        logger.error(
                            "Failed to delete an obsolete policy statement: "
                            "{}".format(policy_response)
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

    def unschedule_events(
            self, events, lambda_arn=None, lambda_name=None,
            excluded_source_services=None
    ):
        excluded_source_services = excluded_source_services or []
        """
        Given a list of events, unschedule these CloudWatch Events.

        'events' is a list of dictionaries, where the dict must contains the 
        string
        of a 'function' and the string of the event 'expression', and an 
        optional 'name' and 'description'.
        """
        self._clear_policy(lambda_name)

        rule_names = self.get_event_rule_names_for_lambda(lambda_arn=lambda_arn)
        for rule_name in rule_names:
            self.delete_rule(rule_name)
            print("Unscheduled " + rule_name + ".")

        non_cwe = [e for e in events if "event_source" in e]
        for event in non_cwe:
            # TODO: This WILL miss non CW events that have been deployed but
            #  changed names. Figure out a way to remove
            # them no matter what.
            # These are non CWE event sources.
            function = event["function"]
            name = event.get("name", function)
            event_source = event.get("event_source", function)
            service = self.service_from_arn(event_source["arn"])
            # DynamoDB and Kinesis streams take quite a while to setup after
            # they are created and do not need to be
            # re-scheduled when a new Lambda function is deployed. Therefore,
            # they should not be removed during zappa
            # update or zappa schedule.
            if service not in excluded_source_services:
                remove_event_source(
                    event_source, lambda_arn, function, self.boto_session
                )
                print(
                    "Removed event {}{}.".format(
                        name,
                        " ({})".format(str(event_source["events"]))
                        if "events" in event_source
                        else "",
                    )
                )

    def schedule_events(self, lambda_arn, lambda_name, events, default=True):
        """
        Given a Lambda ARN, name and a list of events, schedule this as
        CloudWatch Events.

        'events' is a list of dictionaries, where the dict must contains the
        string
        of a 'function' and the string of the event 'expression', and an
        optional 'name' and 'description'.

        Expressions can be in rate or cron format:
            http://docs.aws.amazon.com/lambda/latest/dg/tutorial-scheduled
            -events-schedule-expressions.html
        """

        # The stream sources - DynamoDB, Kinesis and SQS - are working
        # differently than the other services (pull vs push)
        # and do not require event permissions. They do require additional
        # permissions on the Lambda roles though.
        # http://docs.aws.amazon.com/lambda/latest/dg/lambda-api-permissions
        # -ref.html
        pull_services = ["dynamodb", "kinesis", "sqs"]

        # XXX: Not available in Lambda yet.
        # We probably want to execute the latest code.
        # if default:
        #     lambda_arn = lambda_arn + ":$LATEST"

        self.unschedule_events(
            lambda_name=lambda_name,
            lambda_arn=lambda_arn,
            events=events,
            excluded_source_services=pull_services,
        )
        for event in events:
            function = event["function"]
            expression = event.get("expression", None)  # single expression
            expressions = event.get("expressions", None)  # multiple expression
            kwargs = event.get(
                "kwargs", {}
            )  # optional dict of keyword arguments for the event
            event_source = event.get("event_source", None)
            description = event.get("description", function)

            #   - If 'cron' or 'rate' in expression, use ScheduleExpression
            #   - Else, use EventPattern
            #       - ex https://github.com/awslabs/aws-lambda-ddns-function

            if not self.credentials_arn:
                self.get_credentials_arn()

            if expression:
                expressions = [
                    expression
                ]  # same code for single and multiple expression

            if expressions:
                for index, expression in enumerate(expressions):
                    name = self.get_scheduled_event_name(
                        event, function, lambda_name, index
                    )
                    # if it's possible that we truncated name, generate a
                    # unique, shortened name
                    # https://github.com/Miserlou/Zappa/issues/970
                    if len(name) >= 64:
                        rule_name = self.get_hashed_rule_name(
                            event, function, lambda_name
                        )
                    else:
                        rule_name = name

                    rule_response = self.events.put_rule(
                        Name=rule_name,
                        ScheduleExpression=expression,
                        State="ENABLED",
                        Description=description,
                        RoleArn=self.credentials_arn,
                    )

                    if "RuleArn" in rule_response:
                        logger.debug(
                            "Rule created. ARN {}".format(
                                rule_response["RuleArn"])
                        )

                    # Specific permissions are necessary for any trigger to
                    # work.
                    self.create_event_permission(
                        lambda_name, "events.amazonaws.com",
                        rule_response["RuleArn"]
                    )

                    # Overwriting the input, supply the original values and
                    # add kwargs
                    input_template = (
                            '{"time": <time>, '
                            '"detail-type": <detail-type>, '
                            '"source": <source>,'
                            '"account": <account>, '
                            '"region": <region>,'
                            '"detail": <detail>, '
                            '"version": <version>,'
                            '"resources": <resources>,'
                            '"id": <id>,'
                            '"kwargs": %s'
                            "}" % dumps(kwargs)
                    )

                    # Create the CloudWatch event ARN for this function.
                    # https://github.com/Miserlou/Zappa/issues/359
                    target_response = self.events.put_targets(
                        Rule=rule_name,
                        Targets=[
                            {
                                "Id": "Id"
                                      + "".join(
                                    choice(digits) for _ in
                                    range(12)
                                ),
                                "Arn": lambda_arn,
                                "InputTransformer": {
                                    "InputPathsMap": {
                                        "time": "$.time",
                                        "detail-type": "$.detail-type",
                                        "source": "$.source",
                                        "account": "$.account",
                                        "region": "$.region",
                                        "detail": "$.detail",
                                        "version": "$.version",
                                        "resources": "$.resources",
                                        "id": "$.id",
                                    },
                                    "InputTemplate": input_template,
                                },
                            }
                        ],
                    )

                    if target_response["ResponseMetadata"][
                        "HTTPStatusCode"] == 200:
                        print(
                            "Scheduled {} with expression {}!".format(
                                rule_name, expression
                            )
                        )
                    else:
                        print(
                            "Problem scheduling {} with expression {}.".format(
                                rule_name, expression
                            )
                        )

            elif event_source:
                service = self.service_from_arn(event_source["arn"])

                if service not in pull_services:
                    svc = ",".join(event["event_source"]["events"])
                    self.create_event_permission(
                        lambda_name,
                        service + ".amazonaws.com",
                        event["event_source"]["arn"],
                    )
                else:
                    svc = service

                rule_response = add_event_source(
                    event_source, lambda_arn, function, self.boto_session
                )

                if rule_response == "successful":
                    print("Created {} event schedule for {}!".format(svc,
                                                                     function))
                elif rule_response == "failed":
                    print(
                        "Problem creating {} event schedule for {}!".format(
                            svc, function
                        )
                    )
                elif rule_response == "exists":
                    print(
                        "{} event schedule for {} already exists - Nothing to "
                        "do here.".format(
                            svc, function
                        )
                    )
                elif rule_response == "dryrun":
                    print(
                        "Dryrun for creating {} event schedule for {}!!".format(
                            svc, function
                        )
                    )
            else:
                print(
                    "Could not create event {} - Please define either an "
                    "expression or an event source".format(name)
                )

    @staticmethod
    def get_scheduled_event_name(event, function, lambda_name, index=0):
        name = event.get("name", function)
        if name != function:
            # a custom event name has been provided, make sure function name
            # is included as postfix,
            # otherwise zappa's handler won't be able to locate the function.
            name = "{}-{}".format(name, function)
        if index:
            # to ensure unique cloudwatch rule names in the case of multiple
            # expressions
            # prefix all entries bar the first with the index
            # Related: https://github.com/Miserlou/Zappa/pull/1051
            name = "{}-{}".format(index, name)
        # prefix scheduled event names with lambda name. So we can look them
        # up later via the prefix.
        return Zappa.get_event_name(lambda_name, name)

    @staticmethod
    def get_hashed_rule_name(event, function, lambda_name):
        """
        Returns an AWS-valid CloudWatch rule name using a digest of the event
        name, lambda name, and function.
        This allows support for rule names that may be longer than the 64
        char limit.
        """
        event_name = event.get("name", function)
        name_hash = sha1(
            "{}-{}".format(lambda_name, event_name).encode("UTF-8")
        ).hexdigest()
        return Zappa.get_event_name(name_hash, function)

    def delete_rule(self, rule_name):
        """
        Delete a CWE rule.

        This  deletes them, but they will still show up in the AWS console.
        Annoying.

        """
        logger.debug("Deleting existing rule {}".format(rule_name))

        # All targets must be removed before
        # we can actually delete the rule.
        try:
            targets = self.events.list_targets_by_rule(Rule=rule_name)
        except ClientError as e:
            # This avoids misbehavior if low permissions, related:
            # https://github.com/Miserlou/Zappa/issues/286
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                raise
            else:
                logger.debug(
                    "No target found for this rule: {} {}".format(rule_name,
                                                                  e.args[0])
                )
                return

        if "Targets" in targets and targets["Targets"]:
            self.events.remove_targets(
                Rule=rule_name, Ids=[x["Id"] for x in targets["Targets"]]
            )
        else:  # pragma: no cover
            logger.debug("No target to delete")

        # Delete our rule.
        self.events.delete_rule(Name=rule_name)
