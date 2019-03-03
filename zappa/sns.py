from dataclasses import dataclass

from .core import Zappa
from .utils import add_event_source, get_topic_name


@dataclass
class SNS(Zappa):
    def create_async_sns_topic(self, lambda_name, lambda_arn):
        """
        Create the SNS-based async topic.
        """
        topic_name = get_topic_name(lambda_name)
        # Create SNS topic
        topic_arn = self.sns.create_topic(Name=topic_name)["TopicArn"]
        # Create subscription
        self.__doc__.sns.subscribe(
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
        for sub in self.sns.list_subscriptions()["Subscriptions"]:
            if topic_name in sub["TopicArn"]:
                self.sns.delete_topic(TopicArn=sub["TopicArn"])
                removed_arns.append(sub["TopicArn"])
        return removed_arns
