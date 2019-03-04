from dataclasses import dataclass
from hashlib import sha1
from json import dumps
from random import choice
from string import digits

from boto3 import resource

from .config import logger
from .dynamodb import DynamoDB
from .events import Events
from .route53 import Route53
from .sns import SNS
from .utils import add_event_source, ppformat, pprint, remove_event_source

for p in [pprint, ppformat]:
    pass


@dataclass
class Zappa(Events, DynamoDB, SNS, Route53):

    def __post_init__(self):
        self.cloudwatch = resource('cloudwatch')

    def shell(self):
        """
        Spawn a PDB shell.
        """
        import pdb

        pdb.set_trace()

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
