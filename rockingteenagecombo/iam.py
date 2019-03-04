from dataclasses import dataclass
from json import dumps, loads
from logging import getLogger

from boto3 import resource
from botocore.exceptions import ClientError

from .config import ZappaConfig

logger = getLogger(__name__)




@dataclass
class IAM(ZappaConfig):
    iam = resource("iam")

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
        attach_policy_obj = loads(self.attach_policy)
        assume_policy_obj = loads(self.assume_policy)

        if self.extra_permissions:
            for permission in self.extra_permissions:
                attach_policy_obj["Statement"].append(dict(permission))
            self.attach_policy = dumps(attach_policy_obj)

        updated = False

        # Create the role if needed
        try:
            role, credentials_arn = self.get_credentials_arn()

        except ClientError:
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
        except ClientError:
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
            self.iam.update_assume_role_policy(
                RoleName=self.role_name, PolicyDocument=self.assume_policy
            )
            updated = True

        return self.credentials_arn, updated
