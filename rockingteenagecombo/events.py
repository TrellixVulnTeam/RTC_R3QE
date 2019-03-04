from dataclasses import dataclass
from json import loads
from logging import getLogger

from boto3 import client
from botocore.exceptions import ClientError

from .lambda_ import Lambda
from .utils import get_event_source

logger = getLogger(__name__)


@dataclass
class Events(Lambda):
    events = client("events")

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
