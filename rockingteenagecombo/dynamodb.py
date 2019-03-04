from dataclasses import dataclass
from time import sleep

from boto3 import resource
from botocore.exceptions import ClientError


@dataclass
class DynamoDB(object):

    def __post_init__(self):
        self.dynamodb = resource("dynamodb")

    def _set_async_dynamodb_table_ttl(self, table_name):
        self.dynamodb.update_time_to_live(
            TableName=table_name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
        )

    def create_async_dynamodb_table(self, table_name, read_capacity,
                                    write_capacity):
        """
        Create the DynamoDB table for async task return values
        """
        try:
            dynamodb_table = self.dynamodb.describe_table(
                TableName=table_name)
            return False, dynamodb_table

        # catch this exception (triggered if the table doesn't exist)
        except ClientError:
            dynamodb_table = self.dynamodb.create_table(
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
                except ClientError:
                    # this fails because the operation is async, so retry
                    sleep(10)
                    self._set_async_dynamodb_table_ttl(table_name)

        return True, dynamodb_table

    def remove_async_dynamodb_table(self, table_name):
        """
        Remove the DynamoDB Table used for async return values
        """
        self.dynamodb.delete_table(TableName=table_name)
