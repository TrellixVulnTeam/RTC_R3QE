from dataclasses import dataclass
from logging import getLogger
from os import remove
from random import choice
from string import ascii_uppercase, digits
from time import sleep, time

from boto3 import client
from botocore.exceptions import ClientError
from requests import get
from tqdm import tqdm

from .apigateway import ApiGateway
from .s3 import S3
from .utils import ppformat, pprint

logger = getLogger(__name__)

for p in [pprint, ppformat]:
    pass


@dataclass
class Lambda(ApiGateway):
    lambda_storage = S3("splashstand-deploy")
    lambda_ = client("lambda")
    cognito = client("cognito-idp")
    sts = client("sts")

    def create_lambda_function(
        self,
        bucket=None,
        function_name=None,
        handler=None,
        s3_key=None,
        description="Zappa Deployment",
        timeout=30,
        memory_size=512,
        publish=True,
        vpc_config=None,
        dead_letter_config=None,
        runtime="python3.7",
        aws_environment_variables=None,
        aws_kms_key_arn=None,
        xray_tracing=False,
        local_zip=None,
    ):
        """
        Given a bucket and key (or a local path) of a valid Lambda-zip,
        a function name and a handler, register that Lambda function.
        """
        if not vpc_config:
            vpc_config = {}
        if not dead_letter_config:
            dead_letter_config = {}
        if not self.credentials_arn:
            self.get_credentials_arn()
        if not aws_environment_variables:
            aws_environment_variables = {}
        if not aws_kms_key_arn:
            aws_kms_key_arn = ""

        kwargs = dict(
            FunctionName=function_name,
            Runtime=runtime,
            Role=self.credentials_arn,
            Handler=handler,
            Description=description,
            Timeout=timeout,
            MemorySize=memory_size,
            Publish=publish,
            VpcConfig=vpc_config,
            DeadLetterConfig=dead_letter_config,
            Environment={"Variables": aws_environment_variables},
            KMSKeyArn=aws_kms_key_arn,
            TracingConfig={"Mode": "Active" if self.xray_tracing else "PassThrough"},
        )
        if local_zip:
            kwargs["Code"] = {"ZipFile": local_zip}
        else:
            kwargs["Code"] = {"S3Bucket": bucket, "S3Key": s3_key}

        response = self.lambda_.create_function(**kwargs)

        resource_arn = response["FunctionArn"]

        if self.tags:
            self.lambda_.tag_resource(Resource=resource_arn, Tags=self.tags)

        return resource_arn

    def update_lambda_function(
        self,
        bucket,
        function_name,
        s3_key=None,
        publish=True,
        local_zip=None,
        num_revisions=None,
    ):
        """
        Given a bucket and key (or a local path) of a valid Lambda-zip,
        a function name
         and a handler, update that Lambda function's code.
        Optionally, delete previous versions if they exceed the optional limit.
        """
        print("Updating Lambda function code..")

        kwargs = dict(FunctionName=function_name, Publish=publish)
        if local_zip:
            kwargs["ZipFile"] = local_zip
        else:
            kwargs["S3Bucket"] = bucket
            kwargs["S3Key"] = s3_key

        response = self.lambda_.update_function_code(**kwargs)

        if num_revisions:
            # Find the existing revision IDs for the given function
            # Related: https://github.com/Miserlou/Zappa/issues/1402
            versions_in_lambda = []
            versions = self.lambda_.list_versions_by_function(
                FunctionName=function_name
            )
            for version in versions["Versions"]:
                versions_in_lambda.append(version["Version"])
            while "NextMarker" in versions:
                versions = self.lambda_.list_versions_by_function(
                    FunctionName=function_name, Marker=versions["NextMarker"]
                )
                for version in versions["Versions"]:
                    versions_in_lambda.append(version["Version"])
            versions_in_lambda.remove("$LATEST")
            # Delete older revisions if their number exceeds the specified limit
            for version in versions_in_lambda[::-1][num_revisions:]:
                self.lambda_.delete_function(
                    FunctionName=function_name, Qualifier=version
                )

        return response["FunctionArn"]

    def update_lambda_configuration(
        self,
        lambda_arn,
        function_name,
        handler,
        description="Zappa Deployment",
        timeout=30,
        memory_size=512,
        publish=True,
        vpc_config=None,
        runtime="python2.7",
        aws_environment_variables=None,
        aws_kms_key_arn=None,
    ):
        """
        Given an existing function ARN, update the configuration variables.
        """
        print("Updating Lambda function configuration..")

        if not vpc_config:
            vpc_config = {}
        if not self.credentials_arn:
            self.get_credentials_arn()
        if not aws_kms_key_arn:
            aws_kms_key_arn = ""
        if not aws_environment_variables:
            aws_environment_variables = {}

        # Check if there are any remote aws lambda env vars so they don't get
        # trashed.
        # https://github.com/Miserlou/Zappa/issues/987,
        # Related: https://github.com/Miserlou/Zappa/issues/765
        lambda_aws_config = self.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        if "Environment" in lambda_aws_config:
            lambda_aws_environment_variables = lambda_aws_config["Environment"].get(
                "Variables", {}
            )
            # Append keys that are remote but not in settings file
            for key, value in lambda_aws_environment_variables.items():
                if key not in aws_environment_variables:
                    aws_environment_variables[key] = value

        response = self.lambda_.update_function_configuration(
            FunctionName=function_name,
            Runtime=runtime,
            Role=self.credentials_arn,
            Handler=handler,
            Description=description,
            Timeout=timeout,
            MemorySize=memory_size,
            VpcConfig=vpc_config,
            Environment={"Variables": aws_environment_variables},
            KMSKeyArn=aws_kms_key_arn,
            TracingConfig={"Mode": "Active" if self.xray_tracing else "PassThrough"},
        )

        resource_arn = response["FunctionArn"]

        if self.tags:
            self.lambda_.tag_resource(Resource=resource_arn, Tags=self.tags)

        return resource_arn

    def invoke_lambda_function(
        self,
        function_name,
        payload,
        invocation_type="Event",
        log_type="Tail",
        client_context=None,
        qualifier=None,
    ):
        """
        Directly invoke a named Lambda function with a payload.
        Returns the response.
        """
        return self.lambda_.invoke(
            FunctionName=function_name,
            InvocationType=invocation_type,
            LogType=log_type,
            Payload=payload,
        )

    def rollback_lambda_function_version(
        self, function_name, versions_back=1, publish=True
    ):
        """
        Rollback the lambda function code 'versions_back' number of revisions.
    
        Returns the Function ARN.
        """
        response = self.lambda_.list_versions_by_function(FunctionName=function_name)

        # Take into account $LATEST
        if len(response["Versions"]) < versions_back + 1:
            print("We do not have {} revisions. Aborting".format(str(versions_back)))
            return False

        revisions = [
            int(revision["Version"])
            for revision in response["Versions"]
            if revision["Version"] != "$LATEST"
        ]
        revisions.sort(reverse=True)

        response = self.lambda_.get_function(
            FunctionName="function:{}:{}".format(
                function_name, revisions[versions_back]
            )
        )
        response = get(response["Code"]["Location"])

        if response.status_code != 200:
            print(
                "Failed to get version {} of {} code".format(
                    versions_back, function_name
                )
            )
            return False

        response = self.lambda_.update_function_code(
            FunctionName=function_name, ZipFile=response.content, Publish=publish
        )  # pragma: no cover

        return response["FunctionArn"]

    def get_lambda_function(self, function_name):
        """
        Returns the lambda function ARN, given a name
    
        This requires the "lambda:GetFunction" role.
        """
        response = self.lambda_.get_function(FunctionName=function_name)
        return response["Configuration"]["FunctionArn"]

    def get_lambda_function_versions(self, function_name):
        """
        Simply returns the versions available for a Lambda function,
        given a function name.
    
        """
        try:
            response = self.lambda_.list_versions_by_function(
                FunctionName=function_name
            )
            return response.get("Versions", [])
        except Exception:
            return []

    def delete_lambda_function(self, function_name):
        """
        Given a function name, delete it from AWS Lambda.
    
        Returns the response.
    
        """
        print("Deleting Lambda function..")

        return self.lambda_.delete_function(FunctionName=function_name)

    def update_stage_config(
        self,
        project_name,
        stage_name,
        cloudwatch_log_level,
        cloudwatch_data_trace,
        cloudwatch_metrics_enabled,
    ):
        """
        Update CloudWatch metrics configuration.
        """
        if cloudwatch_log_level not in self.cloudwatch_log_levels:
            cloudwatch_log_level = "OFF"

        for api in self.get_rest_apis(project_name):
            self.apigateway.update_stage(
                restApiId=api["id"],
                stageName=stage_name,
                patchOperations=[
                    self.get_patch_op("logging/loglevel", cloudwatch_log_level),
                    self.get_patch_op("logging/dataTrace", cloudwatch_data_trace),
                    self.get_patch_op("metrics/enabled", cloudwatch_metrics_enabled),
                ],
            )

    def create_event_permission(self, lambda_name, principal, source_arn):
        """
        Create permissions to link to an event.

        Related: http://docs.aws.amazon.com/lambda/latest/dg/with-s3-example
        -configure-event-source.html
        """
        logger.debug(
            "Adding new permission to invoke Lambda function: {}".format(lambda_name)
        )
        permission_response = self.lambda_.add_permission(
            FunctionName=lambda_name,
            StatementId="".join(choice(ascii_uppercase + digits) for _ in range(8)),
            Action="lambda:InvokeFunction",
            Principal=principal,
            SourceArn=source_arn,
        )
        if permission_response["ResponseMetadata"]["HTTPStatusCode"] != 201:
            print("Problem creating permission to invoke Lambda function")
            return None  # XXX: Raise?

        return permission_response

    def update_cognito(self, lambda_name, user_pool, lambda_configs, lambda_arn):
        LambdaConfig = {}
        for config in lambda_configs:
            LambdaConfig[config] = lambda_arn
        description = self.cognito.describe_user_pool(UserPoolId=user_pool)
        description_kwargs = {}
        for key, value in description["UserPool"].items():
            if key in (
                "UserPoolId",
                "Policies",
                "AutoVerifiedAttributes",
                "SmsVerificationMessage",
                "EmailVerificationMessage",
                "EmailVerificationSubject",
                "VerificationMessageTemplate",
                "SmsAuthenticationMessage",
                "MfaConfiguration",
                "DeviceConfiguration",
                "EmailConfiguration",
                "SmsConfiguration",
                "UserPoolTags",
                "AdminCreateUserConfig",
            ):
                description_kwargs[key] = value
            elif key is "LambdaConfig":
                for lckey, lcvalue in value.items():
                    if lckey in LambdaConfig:
                        value[lckey] = LambdaConfig[lckey]
                print("value", value)
                description_kwargs[key] = value
        if "LambdaConfig" not in description_kwargs:
            description_kwargs["LambdaConfig"] = LambdaConfig
        result = self.cognito.update_user_pool(
            UserPoolId=user_pool, **description_kwargs
        )
        if result["ResponseMetadata"]["HTTPStatusCode"] != 200:
            print("Cognito:  Failed to update user pool", result)

        # Now we need to add a policy to the IAM that allows cognito access
        result = self.create_event_permission(
            lambda_name,
            "cognito-idp.amazonaws.com",
            "arn:aws:cognito-idp:{}:{}:userpool/{}".format(
                self.aws_region,
                self.sts.get_caller_identity().get("Account"),
                user_pool,
            ),
        )
        if result["ResponseMetadata"]["HTTPStatusCode"] != 201:
            print("Cognito:  Failed to update lambda permission", result)

    def update_stack(
        self,
        name,
        working_bucket,
        wait=False,
        update_only=False,
        disable_progress=False,
    ):
        """
        Update or create the CF stack managed by Zappa.
        """
        capabilities = []
        template = name + "-template-" + str(int(time())) + ".json"
        with open(template, "wb") as out:
            out.write(
                bytes(
                    self.cloudformation_template.to_json(
                        indent=None, separators=(",", ":")
                    ),
                    "utf-8",
                )
            )

        self.lambda_storage.save(
            template, working_bucket, disable_progress=disable_progress
        )
        # if self.boto_session.region_name == "us-gov-west-1":
        #     url = "https://s3-us-gov-west-1.amazonaws.com/{0}/{1}".format(
        #         working_bucket, template
        #     )
        # else:
        url = "https://s3.amazonaws.com/{0}/{1}".format(working_bucket, template)

        tags = [
            {"Key": key, "Value": self.tags[key]}
            for key in self.tags.keys()
            if key != "ZappaProject"
        ]
        tags.append({"Key": "ZappaProject", "Value": name})
        update = True

        try:
            self.cloudformation.describe_stacks(StackName=name)
        except ClientError:
            update = False

        if update_only and not update:
            print("CloudFormation stack missing, re-deploy to enable updates")
            return

        if not update:
            self.cloudformation.create_stack(
                StackName=name, Capabilities=capabilities, TemplateURL=url, Tags=tags
            )
            print(
                "Waiting for stack {0} to create (this can take a "
                "bit)..".format(name)
            )
        else:
            try:
                self.cloudformation.update_stack(
                    StackName=name,
                    Capabilities=capabilities,
                    TemplateURL=url,
                    Tags=tags,
                )
                print("Waiting for stack {0} to update..".format(name))
            except ClientError as e:
                if e.response["Error"]["Message"] == "No updates are to be performed.":
                    wait = False
                else:
                    raise

        if wait:
            total_resources = len(self.cloudformation_template.resources)
            current_resources = 0
            sr = self.cloudformation.get_paginator("list_stack_resources")
            progress = tqdm(total=total_resources, unit="res", disable=disable_progress)
            while True:
                sleep(3)
                result = self.cloudformation.describe_stacks(StackName=name)
                if not result["Stacks"]:
                    continue  # might need to wait a bit

                if result["Stacks"][0]["StackStatus"] in [
                    "CREATE_COMPLETE",
                    "UPDATE_COMPLETE",
                ]:
                    break

                # Something has gone wrong.
                # Is raising enough? Should we also remove) the Lambda function?

                if result["Stacks"][0]["StackStatus"] in [
                    "DELETE_COMPLETE",
                    "DELETE_IN_PROGRESS",
                    "ROLLBACK_IN_PROGRESS",
                    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
                    "UPDATE_ROLLBACK_COMPLETE",
                ]:
                    raise EnvironmentError(
                        "Stack creation failed. "
                        "Please check your CloudFormation console. "
                        "You may also need to `undeploy`."
                    )

                count = 0
                for result in sr.paginate(StackName=name):
                    done = (
                        1
                        for x in result["StackResourceSummaries"]
                        if "COMPLETE" in x["ResourceStatus"]
                    )
                    count += sum(done)
                if count:
                    # We can end up in a situation where we have more
                    # resources being created
                    # than anticipated.
                    if (count - current_resources) > 0:
                        progress.update(count - current_resources)
                current_resources = count
            progress.close()

        try:
            remove(template)
        except OSError:
            pass

        self.lambda_storage.delete(template, working_bucket)
