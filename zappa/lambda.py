from json import loads
from os import remove

from botocore.exceptions import ClientError
from requests import get
from time import sleep, time
from tqdm import tqdm
from troposphere import GetAtt, Ref, Template, apigateway

from .core import logger


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
        TracingConfig={
            "Mode": "Active" if self.xray_tracing else "PassThrough"},
    )
    if local_zip:
        kwargs["Code"] = {"ZipFile": local_zip}
    else:
        kwargs["Code"] = {"S3Bucket": bucket, "S3Key": s3_key}

    response = self.lambda_client.create_function(**kwargs)

    resource_arn = response["FunctionArn"]

    if self.tags:
        self.lambda_client.tag_resource(Resource=resource_arn,
                                        Tags=self.tags)

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

    response = self.lambda_client.update_function_code(**kwargs)

    if num_revisions:
        # Find the existing revision IDs for the given function
        # Related: https://github.com/Miserlou/Zappa/issues/1402
        versions_in_lambda = []
        versions = self.lambda_client.list_versions_by_function(
            FunctionName=function_name
        )
        for version in versions["Versions"]:
            versions_in_lambda.append(version["Version"])
        while "NextMarker" in versions:
            versions = self.lambda_client.list_versions_by_function(
                FunctionName=function_name, Marker=versions["NextMarker"]
            )
            for version in versions["Versions"]:
                versions_in_lambda.append(version["Version"])
        versions_in_lambda.remove("$LATEST")
        # Delete older revisions if their number exceeds the specified limit
        for version in versions_in_lambda[::-1][num_revisions:]:
            self.lambda_client.delete_function(
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
    lambda_aws_config = self.lambda_client.get_function_configuration(
        FunctionName=function_name
    )
    if "Environment" in lambda_aws_config:
        lambda_aws_environment_variables = lambda_aws_config[
            "Environment"].get(
            "Variables", {}
        )
        # Append keys that are remote but not in settings file
        for key, value in lambda_aws_environment_variables.items():
            if key not in aws_environment_variables:
                aws_environment_variables[key] = value

    response = self.lambda_client.update_function_configuration(
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
        TracingConfig={
            "Mode": "Active" if self.xray_tracing else "PassThrough"},
    )

    resource_arn = response["FunctionArn"]

    if self.tags:
        self.lambda_client.tag_resource(Resource=resource_arn,
                                        Tags=self.tags)

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
    return self.lambda_client.invoke(
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
    response = self.lambda_client.list_versions_by_function(
        FunctionName=function_name
    )

    # Take into account $LATEST
    if len(response["Versions"]) < versions_back + 1:
        print("We do not have {} revisions. Aborting".format(
            str(versions_back)))
        return False

    revisions = [
        int(revision["Version"])
        for revision in response["Versions"]
        if revision["Version"] != "$LATEST"
    ]
    revisions.sort(reverse=True)

    response = self.lambda_client.get_function(
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

    response = self.lambda_client.update_function_code(
        FunctionName=function_name, ZipFile=response.content,
        Publish=publish
    )  # pragma: no cover

    return response["FunctionArn"]


def get_lambda_function(self, function_name):
    """
    Returns the lambda function ARN, given a name

    This requires the "lambda:GetFunction" role.
    """
    response = self.lambda_client.get_function(FunctionName=function_name)
    return response["Configuration"]["FunctionArn"]


def get_lambda_function_versions(self, function_name):
    """
    Simply returns the versions available for a Lambda function,
    given a function name.

    """
    try:
        response = self.lambda_client.list_versions_by_function(
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

    return self.lambda_client.delete_function(FunctionName=function_name)


def create_api_gateway_routes(
        self,
        lambda_arn,
        api_name=None,
        api_key_required=False,
        authorization_type="NONE",
        authorizer=None,
        cors_options=None,
        description=None,
):
    restapi = apigateway.RestApi("Api")
    restapi.Name = api_name or lambda_arn.split(":")[-1]
    if not description:
        description = "Created automatically by Zappa."
    restapi.Description = description
    if self.boto_session.region_name == "us-gov-west-1":
        endpoint = apigateway.EndpointConfiguration()
        endpoint.Types = ["REGIONAL"]
        restapi.EndpointConfiguration = endpoint
    if self.apigateway_policy:
        restapi.Policy = loads(self.apigateway_policy)
    self.cf_template.add_resource(restapi)

    root_id = GetAtt(restapi, "RootResourceId")
    invocation_prefix = (
        "aws" if self.boto_session.region_name != "us-gov-west-1" else
        "aws-us-gov"
    )
    invocations_uri = (
            "arn:"
            + invocation_prefix
            + ":apigateway:"
            + self.boto_session.region_name
            + ":lambda:path/2015-03-31/functions/"
            + lambda_arn
            + "/invocations"
    )

    authorizer_resource = None
    if authorizer:
        authorizer_lambda_arn = authorizer.get("arn", lambda_arn)
        lambda_uri = "arn:{invocation_prefix}:apigateway:{" \
                     "region_name}:lambda:path/2015-03-31/functions/{" \
                     "lambda_arn}/invocations".format(
            invocation_prefix=invocation_prefix,
            region_name=self.boto_session.region_name,
            lambda_arn=authorizer_lambda_arn,
        )
        authorizer_resource = self.create_authorizer(
            restapi, lambda_uri, authorizer
        )

    self.create_and_setup_methods(
        restapi,
        root_id,
        api_key_required,
        invocations_uri,
        authorization_type,
        authorizer_resource,
        0,
    )

    if cors_options:
        self.create_and_setup_cors(
            restapi, root_id, invocations_uri, 0, cors_options
        )

    resource = apigateway.Resource("ResourceAnyPathSlashed")
    self.cf_api_resources.append(resource.title)
    resource.RestApiId = Ref(restapi)
    resource.ParentId = root_id
    resource.PathPart = "{proxy+}"
    self.cf_template.add_resource(resource)

    self.create_and_setup_methods(
        restapi,
        resource,
        api_key_required,
        invocations_uri,
        authorization_type,
        authorizer_resource,
        1,
    )  # pragma: no cover

    if cors_options:
        self.create_and_setup_cors(
            restapi, resource, invocations_uri, 1, cors_options
        )  # pragma: no cover
    return restapi


def create_authorizer(self, restapi, uri, authorizer):
    authorizer_type = authorizer.get("type", "TOKEN").upper()
    identity_validation_expression = authorizer.get("validation_expression",
                                                    None)

    authorizer_resource = apigateway.Authorizer("Authorizer")
    authorizer_resource.RestApiId = Ref(restapi)
    authorizer_resource.Name = authorizer.get("name", "ZappaAuthorizer")
    authorizer_resource.Type = authorizer_type
    authorizer_resource.AuthorizerUri = uri
    authorizer_resource.IdentitySource = (
            "method.request.header.%s" % authorizer.get("token_header",
                                                        "Authorization")
    )
    if identity_validation_expression:
        authorizer_resource.IdentityValidationExpression = (
            identity_validation_expression
        )

    if authorizer_type == "TOKEN":
        if not self.credentials_arn:
            self.get_credentials_arn()
        authorizer_resource.AuthorizerResultTtlInSeconds = authorizer.get(
            "result_ttl", 300
        )
        authorizer_resource.AuthorizerCredentials = self.credentials_arn
    if authorizer_type == "COGNITO_USER_POOLS":
        authorizer_resource.ProviderARNs = authorizer.get("provider_arns")

    self.cf_api_resources.append(authorizer_resource.title)
    self.cf_template.add_resource(authorizer_resource)

    return authorizer_resource


def create_and_setup_methods(
        self,
        restapi,
        resource,
        api_key_required,
        uri,
        authorization_type,
        authorizer_resource,
        depth,
):
    for method_name in self.http_methods:
        method = apigateway.Method(method_name + str(depth))
        method.RestApiId = Ref(restapi)
        if type(resource) is apigateway.Resource:
            method.ResourceId = Ref(resource)
        else:
            method.ResourceId = resource
        method.HttpMethod = method_name.upper()
        method.AuthorizationType = authorization_type
        if authorizer_resource:
            method.AuthorizerId = Ref(authorizer_resource)
        method.ApiKeyRequired = api_key_required
        method.MethodResponses = []
        self.cf_template.add_resource(method)
        self.cf_api_resources.append(method.title)

        if not self.credentials_arn:
            self.get_credentials_arn()
        credentials = self.credentials_arn  # This must be a Role ARN

        integration = apigateway.Integration()
        integration.CacheKeyParameters = []
        integration.CacheNamespace = "none"
        integration.Credentials = credentials
        integration.IntegrationHttpMethod = "POST"
        integration.IntegrationResponses = []
        integration.PassthroughBehavior = "NEVER"
        integration.Type = "AWS_PROXY"
        integration.Uri = uri
        method.Integration = integration


def create_and_setup_cors(self, restapi, resource, uri, depth, config):
    if config is True:
        config = {}
    method_name = "OPTIONS"
    method = apigateway.Method(method_name + str(depth))
    method.RestApiId = Ref(restapi)
    if type(resource) is apigateway.Resource:
        method.ResourceId = Ref(resource)
    else:
        method.ResourceId = resource
    method.HttpMethod = method_name.upper()
    method.AuthorizationType = "NONE"
    method_response = apigateway.MethodResponse()
    method_response.ResponseModels = {"application/json": "Empty"}
    response_headers = {
        "Access-Control-Allow-Headers": "'%s'"
                                        % ",".join(
            config.get(
                "allowed_headers",
                [
                    "Content-Type",
                    "X-Amz-Date",
                    "Authorization",
                    "X-Api-Key",
                    "X-Amz-Security-Token",
                ],
            )
        ),
        "Access-Control-Allow-Methods": "'%s'"
                                        % ",".join(
            config.get(
                "allowed_methods",
                ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST",
                 "PUT"],
            )
        ),
        "Access-Control-Allow-Origin": "'%s'" % config.get("allowed_origin",
                                                           "*"),
    }
    method_response.ResponseParameters = {
        "method.response.header.%s" % key: True for key in response_headers
    }
    method_response.StatusCode = "200"
    method.MethodResponses = [method_response]
    self.cf_template.add_resource(method)
    self.cf_api_resources.append(method.title)

    integration = apigateway.Integration()
    integration.Type = "MOCK"
    integration.PassthroughBehavior = "NEVER"
    integration.RequestTemplates = {
        "application/json": '{"statusCode": 200}'}
    integration_response = apigateway.IntegrationResponse()
    integration_response.ResponseParameters = {
        "method.response.header.%s" % key: value
        for key, value in response_headers.items()
    }
    integration_response.ResponseTemplates = {"application/json": ""}
    integration_response.StatusCode = "200"
    integration.IntegrationResponses = [integration_response]

    integration.Uri = uri
    method.Integration = integration


def deploy_api_gateway(
        self,
        api_id,
        stage_name,
        stage_description="",
        description="",
        cache_cluster_enabled=False,
        cache_cluster_size="0.5",
        variables=None,
        cloudwatch_log_level="OFF",
        cloudwatch_data_trace=False,
        cloudwatch_metrics_enabled=False,
        cache_cluster_ttl=300,
        cache_cluster_encrypted=False,
):
    print("Deploying API Gateway..")

    self.apigateway_client.create_deployment(
        restApiId=api_id,
        stageName=stage_name,
        stageDescription=stage_description,
        description=description,
        cacheClusterEnabled=cache_cluster_enabled,
        cacheClusterSize=cache_cluster_size,
        variables=variables or {},
    )

    if cloudwatch_log_level not in self.cloudwatch_log_levels:
        cloudwatch_log_level = "OFF"

    self.apigateway_client.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            self.get_patch_op("logging/loglevel", cloudwatch_log_level),
            self.get_patch_op("logging/dataTrace", cloudwatch_data_trace),
            self.get_patch_op("metrics/enabled",
                              cloudwatch_metrics_enabled),
            self.get_patch_op("caching/ttlInSeconds",
                              str(cache_cluster_ttl)),
            self.get_patch_op("caching/dataEncrypted",
                              cache_cluster_encrypted),
        ],
    )

    return "https://{}.execute-api.{}.amazonaws.com/{}".format(
        api_id, self.boto_session.region_name, stage_name
    )


def add_binary_support(self, api_id, cors=False):
    response = self.apigateway_client.get_rest_api(restApiId=api_id)
    if (
            "binaryMediaTypes" not in response
            or "*/*" not in response["binaryMediaTypes"]
    ):
        self.apigateway_client.update_rest_api(
            restApiId=api_id,
            patchOperations=[
                {"op": "add", "path": "/binaryMediaTypes/*~1*"}],
        )

    if cors:
        # fix for issue 699 and 1035, cors+binary support don't work
        # together
        # go through each resource and update the contentHandling type
        response = self.apigateway_client.get_resources(restApiId=api_id)
        resource_ids = [
            item["id"]
            for item in response["items"]
            if "OPTIONS" in item.get("resourceMethods", {})
        ]

        for resource_id in resource_ids:
            self.apigateway_client.update_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod="OPTIONS",
                patchOperations=[
                    {
                        "op": "replace",
                        "path": "/contentHandling",
                        "value": "CONVERT_TO_TEXT",
                    }
                ],
            )


def remove_binary_support(self, api_id, cors=False):
    response = self.apigateway_client.get_rest_api(restApiId=api_id)
    if "binaryMediaTypes" in response and "*/*" in response[
        "binaryMediaTypes"]:
        self.apigateway_client.update_rest_api(
            restApiId=api_id,
            patchOperations=[
                {"op": "remove", "path": "/binaryMediaTypes/*~1*"}],
        )
    if cors:
        # go through each resource and change the contentHandling type
        response = self.apigateway_client.get_resources(restApiId=api_id)
        resource_ids = [
            item["id"]
            for item in response["items"]
            if "OPTIONS" in item.get("resourceMethods", {})
        ]

        for resource_id in resource_ids:
            self.apigateway_client.update_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod="OPTIONS",
                patchOperations=[
                    {"op": "replace", "path": "/contentHandling",
                     "value": ""}
                ],
            )


def add_api_compression(self, api_id, min_compression_size):
    """
    Add Rest API compression
    """
    self.apigateway_client.update_rest_api(
        restApiId=api_id,
        patchOperations=[
            {
                "op": "replace",
                "path": "/minimumCompressionSize",
                "value": str(min_compression_size),
            }
        ],
    )


def remove_api_compression(self, api_id):
    self.apigateway_client.update_rest_api(
        restApiId=api_id,
        patchOperations=[
            {"op": "replace", "path": "/minimumCompressionSize"}],
    )


def get_api_keys(self, api_id, stage_name):
    response = self.apigateway_client.get_api_keys(limit=500)
    stage_key = "{}/{}".format(api_id, stage_name)
    for api_key in response.get("items"):
        if stage_key in api_key.get("stageKeys"):
            yield api_key.get("id")


def create_api_key(self, api_id, stage_name):
    response = self.apigateway_client.create_api_key(
        name="{}_{}".format(stage_name, api_id),
        description="Api Key for {}".format(api_id),
        enabled=True,
        stageKeys=[
            {"restApiId": "{}".format(api_id),
             "stageName": "{}".format(stage_name)}
        ],
    )
    print("Created a new x-api-key: {}".format(response["id"]))


def remove_api_key(self, api_id, stage_name):
    response = self.apigateway_client.get_api_keys(
        limit=1, nameQuery="{}_{}".format(stage_name, api_id)
    )
    for api_key in response.get("items"):
        self.apigateway_client.delete_api_key(
            apiKey="{}".format(api_key["id"]))


def add_api_stage_to_api_key(self, api_key, api_id, stage_name):
    self.apigateway_client.update_api_key(
        apiKey=api_key,
        patchOperations=[
            {
                "op": "add",
                "path": "/stages",
                "value": "{}/{}".format(api_id, stage_name),
            }
        ],
    )


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
    all_apis = self.apigateway_client.get_rest_apis(limit=500)

    for api in all_apis["items"]:
        if api["name"] != project_name:
            continue
        yield api


def undeploy_api_gateway(self, lambda_name, domain_name=None,
                         base_path=None):
    """
    Delete a deployed REST API Gateway.
    """
    print("Deleting API Gateway..")

    api_id = self.get_api_id(lambda_name)

    if domain_name:

        # XXX - Remove Route53 smartly here?
        # XXX - This doesn't raise, but doesn't work either.

        try:
            self.apigateway_client.delete_base_path_mapping(
                domainName=domain_name,
                basePath="(none)" if base_path is None else base_path,
            )
        except Exception as e:
            # We may not have actually set up the domain.
            pass

    was_deleted = self.delete_stack(lambda_name, wait=True)

    if not was_deleted:
        # try erasing it with the older method
        for api in self.get_rest_apis(lambda_name):
            self.apigateway_client.delete_rest_api(restApiId=api["id"])


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
        self.apigateway_client.update_stage(
            restApiId=api["id"],
            stageName=stage_name,
            patchOperations=[
                self.get_patch_op("logging/loglevel", cloudwatch_log_level),
                self.get_patch_op("logging/dataTrace",
                                  cloudwatch_data_trace),
                self.get_patch_op("metrics/enabled",
                                  cloudwatch_metrics_enabled),
            ],
        )


def update_cognito(self, lambda_name, user_pool, lambda_configs,
                   lambda_arn):
    LambdaConfig = {}
    for config in lambda_configs:
        LambdaConfig[config] = lambda_arn
    description = self.cognito_client.describe_user_pool(
        UserPoolId=user_pool)
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
    result = self.cognito_client.update_user_pool(
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
            self.sts_client.get_caller_identity().get("Account"),
            user_pool,
        ),
    )
    if result["ResponseMetadata"]["HTTPStatusCode"] != 201:
        print("Cognito:  Failed to update lambda permission", result)


def delete_stack(self, name, wait=False):
    """
    Delete the CF stack managed by Zappa.
    """
    try:
        stack = self.cf_client.describe_stacks(StackName=name)["Stacks"][0]
    except:  # pragma: no cover
        print("No Zappa stack named {0}".format(name))
        return False

    tags = {x["Key"]: x["Value"] for x in stack["Tags"]}
    if tags.get("ZappaProject") == name:
        self.cf_client.delete_stack(StackName=name)
        if wait:
            waiter = self.cf_client.get_waiter("stack_delete_complete")
            print("Waiting for stack {0} to be deleted..".format(name))
            waiter.wait(StackName=name)
        return True
    else:
        print(
            "ZappaProject tag not found on {0}, doing nothing".format(name))
        return False


def create_stack_template(
        self,
        lambda_arn,
        lambda_name,
        api_key_required,
        iam_authorization,
        authorizer,
        cors_options=None,
        description=None,
):
    """
    Build the entire CF stack.
    Just used for the API Gateway, but could be expanded in the future.
    """

    auth_type = "NONE"
    if iam_authorization and authorizer:
        logger.warning(
            "Both IAM Authorization and Authorizer are specified, this is "
            "not possible. "
            "Setting Auth method to IAM Authorization"
        )
        authorizer = None
        auth_type = "AWS_IAM"
    elif iam_authorization:
        auth_type = "AWS_IAM"
    elif authorizer:
        auth_type = authorizer.get("type", "CUSTOM")

    # build a fresh template
    self.cf_template = Template()
    self.cf_template.set_description("Automatically generated with Zappa")
    self.cf_api_resources = []
    self.cf_parameters = {}

    restapi = self.create_api_gateway_routes(
        lambda_arn,
        api_name=lambda_name,
        api_key_required=api_key_required,
        authorization_type=auth_type,
        authorizer=authorizer,
        cors_options=cors_options,
        description=description,
    )
    return self.cf_template


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
                self.cf_template.to_json(indent=None,
                                         separators=(",", ":")),
                "utf-8",
            )
        )

    self.upload_to_s3(template, working_bucket,
                      disable_progress=disable_progress)
    if self.boto_session.region_name == "us-gov-west-1":
        url = "https://s3-us-gov-west-1.amazonaws.com/{0}/{1}".format(
            working_bucket, template
        )
    else:
        url = "https://s3.amazonaws.com/{0}/{1}".format(working_bucket,
                                                        template)

    tags = [
        {"Key": key, "Value": self.tags[key]}
        for key in self.tags.keys()
        if key != "ZappaProject"
    ]
    tags.append({"Key": "ZappaProject", "Value": name})
    update = True

    try:
        self.cf_client.describe_stacks(StackName=name)
    except ClientError:
        update = False

    if update_only and not update:
        print("CloudFormation stack missing, re-deploy to enable updates")
        return

    if not update:
        self.cf_client.create_stack(
            StackName=name, Capabilities=capabilities, TemplateURL=url,
            Tags=tags
        )
        print(
            "Waiting for stack {0} to create (this can take a "
            "bit)..".format(
                name)
        )
    else:
        try:
            self.cf_client.update_stack(
                StackName=name,
                Capabilities=capabilities,
                TemplateURL=url,
                Tags=tags,
            )
            print("Waiting for stack {0} to update..".format(name))
        except ClientError as e:
            if e.response["Error"][
                "Message"] == "No updates are to be performed.":
                wait = False
            else:
                raise

    if wait:
        total_resources = len(self.cf_template.resources)
        current_resources = 0
        sr = self.cf_client.get_paginator("list_stack_resources")
        progress = tqdm(total=total_resources, unit="res",
                        disable=disable_progress)
        while True:
            sleep(3)
            result = self.cf_client.describe_stacks(StackName=name)
            if not result["Stacks"]:
                continue  # might need to wait a bit

            if result["Stacks"][0]["StackStatus"] in [
                "CREATE_COMPLETE",
                "UPDATE_COMPLETE",
            ]:
                break

            # Something has gone wrong.
            # Is raising enough? Should we also remove the Lambda function?
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

    self.remove_from_s3(template, working_bucket)


def stack_outputs(self, name):
    """
    Given a name, describes CloudFront stacks and returns dict of the
    stack Outputs
    , else returns an empty dict.
    """
    try:
        stack = self.cf_client.describe_stacks(StackName=name)["Stacks"][0]
        return {x["OutputKey"]: x["OutputValue"] for x in stack["Outputs"]}
    except ClientError:
        return {}


def get_api_url(self, lambda_name, stage_name):
    """
    Given a lambda_name and stage_name, return a valid API URL.
    """
    api_id = self.get_api_id(lambda_name)
    if api_id:
        return "https://{}.execute-api.{}.amazonaws.com/{}".format(
            api_id, self.boto_session.region_name, stage_name
        )
    else:
        return None


def get_api_id(self, lambda_name):
    """
    Given a lambda_name, return the API id.
    """
    try:
        response = self.cf_client.describe_stack_resource(
            StackName=lambda_name, LogicalResourceId="Api"
        )
        return response["StackResourceDetail"].get("PhysicalResourceId",
                                                   None)
    except:  # pragma: no cover
        try:
            # Try the old method (project was probably made on an older,
            # non CF version)
            response = self.apigateway_client.get_rest_apis(limit=500)

            for item in response["items"]:
                if item["name"] == lambda_name:
                    return item["id"]

            logger.exception("Could not get API ID.")
            return None
        except:  # pragma: no cover
            # We don't even have an API deployed. That's okay!
            return None


def create_domain_name(
        self,
        domain_name,
        certificate_name,
        certificate_body=None,
        certificate_private_key=None,
        certificate_chain=None,
        certificate_arn=None,
        lambda_name=None,
        stage=None,
        base_path=None,
):
    """
    Creates the API GW domain and returns the resulting DNS name.
    """

    # This is a Let's Encrypt or custom certificate
    if not certificate_arn:
        agw_response = self.apigateway_client.create_domain_name(
            domainName=domain_name,
            certificateName=certificate_name,
            certificateBody=certificate_body,
            certificatePrivateKey=certificate_private_key,
            certificateChain=certificate_chain,
        )
    # This is an AWS ACM-hosted Certificate
    else:
        agw_response = self.apigateway_client.create_domain_name(
            domainName=domain_name,
            certificateName=certificate_name,
            certificateArn=certificate_arn,
        )

    api_id = self.get_api_id(lambda_name)
    if not api_id:
        raise LookupError("No API URL to certify found - did you deploy?")

    self.apigateway_client.create_base_path_mapping(
        domainName=domain_name,
        basePath="" if base_path is None else base_path,
        restApiId=api_id,
        stage=stage,
    )

    return agw_response["distributionDomainName"]


def update_route53_records(self, domain_name, dns_name):
    """
    Updates Route53 Records following GW domain creation
    """
    zone_id = self.get_hosted_zone_id_for_domain(domain_name)

    is_apex = (
            self.route53.get_hosted_zone(Id=zone_id)["HostedZone"]["Name"][
            :-1]
            == domain_name
    )
    if is_apex:
        record_set = {
            "Name": domain_name,
            "Type": "A",
            "AliasTarget": {
                "HostedZoneId": "Z2FDTNDATAQYW2",
                # This is a magic value that means "CloudFront"
                "DNSName": dns_name,
                "EvaluateTargetHealth": False,
            },
        }
    else:
        record_set = {
            "Name": domain_name,
            "Type": "CNAME",
            "ResourceRecords": [{"Value": dns_name}],
            "TTL": 60,
        }

    # Related: https://github.com/boto/boto3/issues/157
    # and: http://docs.aws.amazon.com/Route53/latest/APIReference
    # /CreateAliasRRSAPI.html
    # and policy: https://spin.atomicobject.com/2016/04/28/route-53
    # -hosted-zone-managment/
    # pure_zone_id = zone_id.split('/hostedzone/')[1]

    # XXX: ClientError: An error occurred (InvalidChangeBatch) when
    # calling the ChangeResourceRecordSets operation:
    # Tried to create an alias that targets
    # d1awfeji80d0k2.cloudfront.net., type A in zone Z1XWOQP59BYF6Z,
    # but the alias target name does not lie within the target zone
    response = self.route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {"Action": "UPSERT", "ResourceRecordSet": record_set}]
        },
    )

    return response


def update_domain_name(
        self,
        domain_name,
        certificate_name=None,
        certificate_body=None,
        certificate_private_key=None,
        certificate_chain=None,
        certificate_arn=None,
        lambda_name=None,
        stage=None,
        route53=True,
        base_path=None,
):
    """
    This updates your certificate information for an existing domain,
    with similar arguments to boto's update_domain_name API Gateway api.

    It returns the resulting new domain information including the new
    certificate's ARN
    if created during this process.

    Previously, this method involved downtime that could take up to 40
    minutes
    because the API Gateway api only allowed this by deleting, and then
    creating it.

    Related issues:     https://github.com/Miserlou/Zappa/issues/590
                        https://github.com/Miserlou/Zappa/issues/588
                        https://github.com/Miserlou/Zappa/pull/458
                        https://github.com/Miserlou/Zappa/issues/882
                        https://github.com/Miserlou/Zappa/pull/883
    """

    print("Updating domain name!")

    certificate_name = certificate_name + str(time())

    api_gateway_domain = self.apigateway_client.get_domain_name(
        domainName=domain_name
    )
    if (
            not certificate_arn
            and certificate_body
            and certificate_private_key
            and certificate_chain
    ):
        acm_certificate = self.acm_client.import_certificate(
            Certificate=certificate_body,
            PrivateKey=certificate_private_key,
            CertificateChain=certificate_chain,
        )
        certificate_arn = acm_certificate["CertificateArn"]

    self.update_domain_base_path_mapping(domain_name, lambda_name, stage,
                                         base_path)

    return self.apigateway_client.update_domain_name(
        domainName=domain_name,
        patchOperations=[
            {
                "op": "replace",
                "path": "/certificateName",
                "value": certificate_name,
            },
            {"op": "replace", "path": "/certificateArn",
             "value": certificate_arn},
        ],
    )


def update_domain_base_path_mapping(
        self, domain_name, lambda_name, stage, base_path
):
    """
    Update domain base path mapping on API Gateway if it was changed
    """
    api_id = self.get_api_id(lambda_name)
    if not api_id:
        print("Warning! Can't update base path mapping!")
        return
    base_path_mappings = self.apigateway_client.get_base_path_mappings(
        domainName=domain_name
    )
    found = False
    for base_path_mapping in base_path_mappings["items"]:
        if (
                base_path_mapping["restApiId"] == api_id
                and base_path_mapping["stage"] == stage
        ):
            found = True
            if base_path_mapping["basePath"] != base_path:
                self.apigateway_client.update_base_path_mapping(
                    domainName=domain_name,
                    basePath=base_path_mapping["basePath"],
                    patchOperations=[
                        {
                            "op": "replace",
                            "path": "/basePath",
                            "value": "" if base_path is None else base_path,
                        }
                    ],
                )
    if not found:
        self.apigateway_client.create_base_path_mapping(
            domainName=domain_name,
            basePath="" if base_path is None else base_path,
            restApiId=api_id,
            stage=stage,
        )


def get_all_zones(self):
    """Same behaviour of list_host_zones, but transparently handling
    pagination."""
    zones = {"HostedZones": []}

    new_zones = self.route53.list_hosted_zones(MaxItems="100")
    while new_zones["IsTruncated"]:
        zones["HostedZones"] += new_zones["HostedZones"]
        new_zones = self.route53.list_hosted_zones(
            Marker=new_zones["NextMarker"], MaxItems="100"
        )

    zones["HostedZones"] += new_zones["HostedZones"]
    return zones


def get_domain_name(self, domain_name, route53=True):
    """
    Scan our hosted zones for the record of a given name.

    Returns the record entry, else None.

    """
    # Make sure api gateway domain is present
    try:
        self.apigateway_client.get_domain_name(domainName=domain_name)
    except Exception:
        return None

    if not route53:
        return True

    try:
        zones = self.get_all_zones()
        for zone in zones["HostedZones"]:
            records = self.route53.list_resource_record_sets(
                HostedZoneId=zone["Id"]
            )
            for record in records["ResourceRecordSets"]:
                if (
                        record["Type"] in ("CNAME", "A")
                        and record["Name"][:-1] == domain_name
                ):
                    return record

    except Exception as e:
        return None

    ##
    # Old, automatic logic.
    # If re-introduced, should be moved to a new function.
    # Related ticket: https://github.com/Miserlou/Zappa/pull/458
    ##

    # We may be in a position where Route53 doesn't have a domain,
    # but the API Gateway does.
    # We need to delete this before we can create the new Route53.
    # try:
    #     api_gateway_domain = self.apigateway_client.get_domain_name(
    #     domainName=domain_name)
    #     self.apigateway_client.delete_domain_name(domainName=domain_name)
    # except Exception:
    #     pass

    return None
