from dataclasses import dataclass
from logging import getLogger
from time import time

from botocore.exceptions import ClientError
from troposphere import Parameter, Ref, apigateway as apigw

from .core import Zappa

logger = getLogger(__name__)


@dataclass
class ApiGateway(Zappa):

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
            method = apigw.Method(method_name + str(depth))
            method.RestApiId = Ref(restapi)
            if type(resource) is apigw.Resource:
                method.ResourceId = Ref(resource)
            else:
                method.ResourceId = resource
            method.HttpMethod = method_name.upper()
            method.AuthorizationType = authorization_type
            if authorizer_resource:
                method.AuthorizerId = Ref(authorizer_resource)
            method.ApiKeyRequired = api_key_required
            method.MethodResponses = []
            self.cloudformation_template.add_resource(method)
            self.cloudformation_api_resources.append(method.title)

            if not self.credentials_arn:
                self.get_credentials_arn()
            credentials = self.credentials_arn  # This must be a Role ARN

            integration = apigw.Integration()
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
        method = apigw.Method(method_name + str(depth))
        method.RestApiId = Ref(restapi)
        if type(resource) is apigw.Resource:
            method.ResourceId = Ref(resource)
        else:
            method.ResourceId = resource
        method.HttpMethod = method_name.upper()
        method.AuthorizationType = "NONE"
        method_response = apigw.MethodResponse()
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
        self.cloudformation_template.add_resource(method)
        self.cloudformation_api_resources.append(method.title)

        integration = apigw.Integration()
        integration.Type = "MOCK"
        integration.PassthroughBehavior = "NEVER"
        integration.RequestTemplates = {
            "application/json": '{"statusCode": 200}'}
        integration_response = apigw.IntegrationResponse()
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

        self.apigateway.create_deployment(
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

        self.apigateway.update_stage(
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
        response = self.apigateway.get_rest_api(restApiId=api_id)
        if (
                "binaryMediaTypes" not in response
                or "*/*" not in response["binaryMediaTypes"]
        ):
            self.apigateway.update_rest_api(
                restApiId=api_id,
                patchOperations=[
                    {"op": "add", "path": "/binaryMediaTypes/*~1*"}],
            )

        if cors:
            # fix for issue 699 and 1035, cors+binary support don't work
            # together
            # go through each resource and update the contentHandling type
            response = self.apigateway.get_resources(restApiId=api_id)
            resource_ids = [
                item["id"]
                for item in response["items"]
                if "OPTIONS" in item.get("resourceMethods", {})
            ]

            for resource_id in resource_ids:
                self.apigateway.update_integration(
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
        response = self.apigateway.get_rest_api(restApiId=api_id)
        if "binaryMediaTypes" in response and "*/*" in response[
            "binaryMediaTypes"]:
            self.apigateway.update_rest_api(
                restApiId=api_id,
                patchOperations=[
                    {"op": "remove", "path": "/binaryMediaTypes/*~1*"}],
            )
        if cors:
            # go through each resource and change the contentHandling type
            response = self.apigateway.get_resources(restApiId=api_id)
            resource_ids = [
                item["id"]
                for item in response["items"]
                if "OPTIONS" in item.get("resourceMethods", {})
            ]

            for resource_id in resource_ids:
                self.apigateway.update_integration(
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
        self.apigateway.update_rest_api(
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
        self.apigateway.update_rest_api(
            restApiId=api_id,
            patchOperations=[
                {"op": "replace", "path": "/minimumCompressionSize"}],
        )

    def get_api_keys(self, api_id, stage_name):
        response = self.apigateway.get_api_keys(limit=500)
        stage_key = "{}/{}".format(api_id, stage_name)
        for api_key in response.get("items"):
            if stage_key in api_key.get("stageKeys"):
                yield api_key.get("id")

    def create_api_key(self, api_id, stage_name):
        response = self.apigateway.create_api_key(
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
        response = self.apigateway.get_api_keys(
            limit=1, nameQuery="{}_{}".format(stage_name, api_id)
        )
        for api_key in response.get("items"):
            self.apigateway.delete_api_key(
                apiKey="{}".format(api_key["id"]))

    def add_api_stage_to_api_key(self, api_key, api_id, stage_name):
        self.apigateway.update_api_key(
            apiKey=api_key,
            patchOperations=[
                {
                    "op": "add",
                    "path": "/stages",
                    "value": "{}/{}".format(api_id, stage_name),
                }
            ],
        )

    def get_api_id(self, lambda_name):
        """
        Given a lambda_name, return the API id.
        """
        try:
            response = self.cloudformation.describe_stack_resource(
                StackName=lambda_name, LogicalResourceId="Api"
            )
            return response["StackResourceDetail"].get("PhysicalResourceId",
                                                       None)
        except:  # pragma: no cover
            try:
                # Try the old method (project was probably made on an older,
                # non CF version)
                response = self.apigateway.get_rest_apis(limit=500)

                for item in response["items"]:
                    if item["name"] == lambda_name:
                        return item["id"]

                logger.exception("Could not get API ID.")
                return None
            except:  # pragma: no cover
                # We don't even have an API deployed. That's okay!
                return None

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
                self.apigateway.delete_base_path_mapping(
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
                self.apigateway.delete_rest_api(restApiId=api["id"])

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
            agw_response = self.apigateway.create_domain_name(
                domainName=domain_name,
                certificateName=certificate_name,
                certificateBody=certificate_body,
                certificatePrivateKey=certificate_private_key,
                certificateChain=certificate_chain,
            )
        # This is an AWS ACM-hosted Certificate
        else:
            agw_response = self.apigateway.create_domain_name(
                domainName=domain_name,
                certificateName=certificate_name,
                certificateArn=certificate_arn,
            )

        api_id = self.get_api_id(lambda_name)
        if not api_id:
            raise LookupError("No API URL to certify found - did you deploy?")

        self.apigateway.create_base_path_mapping(
            domainName=domain_name,
            basePath="" if base_path is None else base_path,
            restApiId=api_id,
            stage=stage,
        )

        return agw_response["distributionDomainName"]

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

        api_gateway_domain = self.apigateway.get_domain_name(
            domainName=domain_name
        )
        if (
                not certificate_arn
                and certificate_body
                and certificate_private_key
                and certificate_chain
        ):
            acm_certificate = self.acm.import_certificate(
                Certificate=certificate_body,
                PrivateKey=certificate_private_key,
                CertificateChain=certificate_chain,
            )
            certificate_arn = acm_certificate["CertificateArn"]

        self.update_domain_base_path_mapping(domain_name, lambda_name, stage,
                                             base_path)

        return self.apigateway.update_domain_name(
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
        base_path_mappings = self.apigateway.get_base_path_mappings(
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
                    self.apigateway.update_base_path_mapping(
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
            self.apigateway.create_base_path_mapping(
                domainName=domain_name,
                basePath="" if base_path is None else base_path,
                restApiId=api_id,
                stage=stage,
            )

    def remove_api_gateway_logs(self, project_name):
        """
        Removed all logs that are assigned to a given rest api id.
        """
        for rest_api in self.get_rest_apis(project_name):
            for stage in \
                    self.apigateway.get_stages(restApiId=rest_api["id"])[
                        "item"
                    ]:
                self.remove_log_group(
                    "API-Gateway-Execution-Logs_{}/{}".format(
                        rest_api["id"], stage["stageName"]
                    )
                )

    def cache_param(self, value):
        """Returns a troposphere Ref to a value cached as a parameter."""

        if value not in self.cloudformation_parameters:
            keyname = chr(ord("A") + len(self.cloudformation_parameters))
            param = self.cloudformation_template.add_parameter(
                Parameter(
                    keyname, Type="String", Default=value, tags=self.tags
                )
            )

            self.cloudformation_parameters[value] = param

        return Ref(self.cloudformation_parameters[value])

    def stack_outputs(self, name):
        """
        Given a name, describes CloudFront stacks and returns dict of the
        stack Outputs
        , else returns an empty dict.
        """
        try:
            stack = \
                self.cloudformation.describe_stacks(StackName=name)["Stacks"][0]
            return {x["OutputKey"]: x["OutputValue"] for x in stack["Outputs"]}
        except ClientError:
            return {}
