import json
import typing as tp

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field


class CreateFunction(BaseModel):
    function_name: str
    runtime: tp.Literal[
        "python3.9",
        "python3.10",
        "python3.11",
        "python3.12",
        "nodejs18.x",
        "nodejs20.x",
        "java11",
        "java17",
        "java21",
        "dotnet6",
        "dotnet8",
        "go1.x",
        "ruby3.2",
        "ruby3.3",
        "provided.al2",
        "provided.al2023",
    ]
    role: str
    handler: str
    code: tp.Dict[str, tp.Any]
    description: str = ""
    timeout: int = 3
    memory_size: int = 128
    publish: bool = False
    environment_variables: tp.Dict[str, str] = Field(default_factory=dict)
    dead_letter_config: tp.Dict[str, str] = Field(default_factory=dict)
    kms_key_arn: str | None = None
    tracing_config: tp.Dict[str, str] = Field(default_factory=dict)
    tags: tp.Dict[str, str] = Field(default_factory=dict)
    layers: tp.List[str] = Field(default_factory=list)
    file_system_configs: tp.List[tp.Dict[str, tp.Any]]
    image_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    code_signing_config_arn: str | None = None
    architectures: tp.List[tp.Literal["x86_64", "arm64"]] | None = None
    ephemeral_storage: tp.Dict[str, int] = Field(default_factory=dict)
    snap_start: tp.Dict[str, str] = Field(default_factory=dict)
    logging_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)


class UpdateFunctionCode(BaseModel):
    function_name: str
    zip_file: bytes | None = None
    s3_bucket: str | None = None
    s3_key: str | None = None
    s3_object_version: str | None = None
    image_uri: str | None = None
    publish: bool = False
    dry_run: bool = False
    revision_id: str | None = None
    architectures: tp.List[tp.Literal["x86_64", "arm64"]] | None = None


class UpdateFunctionConfiguration(BaseModel):
    function_name: str
    role: str | None = None
    handler: str | None = None
    description: str | None = None
    timeout: int | None = None
    memory_size: int | None = None
    environment_variables: tp.Dict[str, str] = Field(default_factory=dict)
    dead_letter_config: tp.Dict[str, str] = Field(default_factory=dict)
    kms_key_arn: str | None = None
    tracing_config: tp.Dict[str, str] = Field(default_factory=dict)
    layers: tp.List[str] = Field(default_factory=list)
    file_system_configs: tp.List[tp.Dict[str, tp.Any]]
    image_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    ephemeral_storage: tp.Dict[str, int] = Field(default_factory=dict)
    snap_start: tp.Dict[str, str] = Field(default_factory=dict)
    logging_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    revision_id: str | None = None


class InvokeFunction(BaseModel):
    function_name: str
    invocation_type: tp.Literal["Event", "RequestResponse", "DryRun"] = (
        "RequestResponse"
    )
    log_type: tp.Literal["None", "Tail"] = "None"
    client_context: str | None = None
    payload: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    qualifier: str | None = None


class CreateAlias(BaseModel):
    function_name: str
    name: str
    function_version: str
    description: str = ""
    routing_config: tp.Dict[str, tp.Any]


class UpdateAlias(BaseModel):
    function_name: str
    name: str
    function_version: str | None = None
    description: str | None = None
    routing_config: tp.Dict[str, tp.Any]
    revision_id: str | None = None


class CreateLayerVersion(BaseModel):
    layer_name: str
    description: str = ""
    content: tp.Dict[str, tp.Any]
    compatible_runtimes: tp.List[str]
    license_info: str | None = None
    compatible_architectures: tp.List[tp.Literal["x86_64", "arm64"]]


class AddPermission(BaseModel):
    function_name: str
    statement_id: str
    action: str
    principal: str
    source_arn: str | None = None
    source_account: str | None = None
    event_source_token: str | None = None
    qualifier: str | None = None
    revision_id: str | None = None
    principal_org_id: str | None = None
    function_url_auth_type: tp.Literal["AWS_IAM", "NONE"] | None = None


class CreateEventSourceMapping(BaseModel):
    event_source_arn: str
    function_name: str
    enabled: bool = True
    batch_size: int = 100
    maximum_batching_window_in_seconds: int = 0
    parallelization_factor: int = 1
    starting_position: tp.Literal["TRIM_HORIZON", "LATEST", "AT_TIMESTAMP"] = "LATEST"
    starting_position_timestamp: int | None = None
    destination_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    maximum_record_age_in_seconds: int = -1
    bisect_batch_on_function_error: bool = False
    maximum_retry_attempts: int = -1
    tumbling_window_in_seconds: int = 0
    topics: tp.List[str] = Field(default_factory=list)
    queues: tp.List[str] = Field(default_factory=list)
    source_access_configurations: tp.List[tp.Dict[str, tp.Any]]
    self_managed_event_source: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    function_response_types: tp.List[tp.Literal["ReportBatchItemFailures"]]
    amazon_managed_kafka_event_source_config: tp.Dict[str, tp.Any] = Field(
        default_factory=dict
    )
    self_managed_kafka_event_source_config: tp.Dict[str, tp.Any] = Field(
        default_factory=dict
    )
    scaling_config: tp.Dict[str, int] = Field(default_factory=dict)
    document_db_event_source_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)


class UpdateEventSourceMapping(BaseModel):
    uuid: str	
    function_name: str | None = None
    enabled: bool | None = None
    batch_size: int | None = None
    maximum_batching_window_in_seconds: int | None = None
    destination_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    maximum_record_age_in_seconds: int | None = None
    bisect_batch_on_function_error: bool | None = None
    maximum_retry_attempts: int | None = None
    parallelization_factor: int | None = None
    source_access_configurations: tp.List[tp.Dict[str, tp.Any]]
    tumbling_window_in_seconds: int | None = None
    function_response_types: tp.List[tp.Literal["ReportBatchItemFailures"]]
    scaling_config: tp.Dict[str, int] = Field(default_factory=dict)
    document_db_event_source_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)


class CreateFunctionUrlConfig(BaseModel):
    function_name: str
    config: tp.Dict[str, tp.Any]
    qualifier: str | None = None


class CodeSigningConfig(BaseModel):
    code_signing_config_arn: str
    description: str | None = None
    allowed_publishers: tp.Dict[str, tp.List[str]]
    code_signing_policies: tp.Dict[str, tp.Literal["Warn", "Enforce"]]


class CreateProvisionedConcurrencyConfig(BaseModel):
    function_name: str
    qualifier: str
    provisioned_concurrent_executions: int
    provisioned_concurrency_config: tp.Dict[str, tp.Any]


class CreateCodeSigningConfig(BaseModel):
    description: str | None = None
    allowed_publishers: tp.Dict[str, tp.List[str]]
    code_signing_policies: tp.Dict[str, tp.Literal["Warn", "Enforce"]]


class PutFunctionConcurrency(BaseModel):
    function_name: str
    reserved_concurrent_executions: int


class LambdaClient:
    def __init__(
        self,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        region_name: str = "us-east-1",
    ):
        self.lambda_client = boto3.client(
            "lambda",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            endpoint_url="https://aws.oscarbahamonde.com",
        )

    def create_function(self, config: CreateFunction):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": config.function_name,
            "Runtime": config.runtime,
            "Role": config.role,
            "Handler": config.handler,
            "Code": config.code,
            "Description": config.description,
            "Timeout": config.timeout,
            "MemorySize": config.memory_size,
            "Publish": config.publish,
            "Architectures": config.architectures,
        }

        if config.environment_variables:
            params["Environment"] = {"Variables": config.environment_variables}
        if config.dead_letter_config:
            params["DeadLetterConfig"] = config.dead_letter_config
        if config.kms_key_arn:
            params["KMSKeyArn"] = config.kms_key_arn
        if config.tracing_config:
            params["TracingConfig"] = config.tracing_config
        if config.tags:
            params["Tags"] = config.tags
        if config.layers:
            params["Layers"] = config.layers
        if config.file_system_configs:
            params["FileSystemConfigs"] = config.file_system_configs
        if config.image_config:
            params["ImageConfig"] = config.image_config
        if config.code_signing_config_arn:
            params["CodeSigningConfigArn"] = config.code_signing_config_arn
        if config.ephemeral_storage:
            params["EphemeralStorage"] = config.ephemeral_storage
        if config.snap_start:
            params["SnapStart"] = config.snap_start
        if config.logging_config:
            params["LoggingConfig"] = config.logging_config

        response = self.lambda_client.create_function(**params)
        return response

    def delete_function(self, function_name: str, qualifier: str | None = None):
        params = {"FunctionName": function_name}
        if qualifier:
            params["Qualifier"] = qualifier

        try:
            self.lambda_client.delete_function(**params)
            return True
        except ClientError:
            return False

    def get_function(self, function_name: str, qualifier: str | None = None):
        params = {"FunctionName": function_name}
        if qualifier:
            params["Qualifier"] = qualifier

        response = self.lambda_client.get_function(**params)
        return response

    def list_functions(
        self,
        function_version: str = "ALL",
        marker: str | None = None,
        max_items: int = 10000,
    ):
        params: tp.Dict[str, tp.Any] = {
            "FunctionVersion": function_version,
            "MaxItems": max_items,
        }
        if marker:
            params["Marker"] = marker

        response = self.lambda_client.list_functions(**params)
        return response

    def update_function_code(self, config: UpdateFunctionCode):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": config.function_name,
            "Publish": config.publish,
            "DryRun": config.dry_run,
        }

        if config.zip_file:
            params["ZipFile"] = config.zip_file
        if config.s3_bucket:
            params["S3Bucket"] = config.s3_bucket
        if config.s3_key:
            params["S3Key"] = config.s3_key
        if config.s3_object_version:
            params["S3ObjectVersion"] = config.s3_object_version
        if config.image_uri:
            params["ImageUri"] = config.image_uri
        if config.revision_id:
            params["RevisionId"] = config.revision_id
        if config.architectures:
            params["Architectures"] = config.architectures

        response = self.lambda_client.update_function_code(**params)
        return response

    def update_function_configuration(self, config: UpdateFunctionConfiguration):
        params: tp.Dict[str, tp.Any] = {"FunctionName": config.function_name}

        if config.role:
            params["Role"] = config.role
        if config.handler:
            params["Handler"] = config.handler
        if config.description is not None:
            params["Description"] = config.description
        if config.timeout:
            params["Timeout"] = config.timeout
        if config.memory_size:
            params["MemorySize"] = config.memory_size
        if config.environment_variables:
            params["Environment"] = {"Variables": config.environment_variables}
        if config.dead_letter_config:
            params["DeadLetterConfig"] = config.dead_letter_config
        if config.kms_key_arn:
            params["KMSKeyArn"] = config.kms_key_arn
        if config.tracing_config:
            params["TracingConfig"] = config.tracing_config
        if config.layers:
            params["Layers"] = config.layers
        if config.file_system_configs:
            params["FileSystemConfigs"] = config.file_system_configs
        if config.image_config:
            params["ImageConfig"] = config.image_config
        if config.ephemeral_storage:
            params["EphemeralStorage"] = config.ephemeral_storage
        if config.snap_start:
            params["SnapStart"] = config.snap_start
        if config.logging_config:
            params["LoggingConfig"] = config.logging_config
        if config.revision_id:
            params["RevisionId"] = config.revision_id

        response = self.lambda_client.update_function_configuration(**params)
        return response

    def invoke_function(self, config: InvokeFunction):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": config.function_name,
            "InvocationType": config.invocation_type,
            "LogType": config.log_type,
        }

        if config.client_context:
            params["ClientContext"] = config.client_context
        if config.payload:
            params["Payload"] = json.dumps(config.payload)
        if config.qualifier:
            params["Qualifier"] = config.qualifier

        response = self.lambda_client.invoke(**params)

        # Handle response payload
        if "Payload" in response:
            response["Payload"] = json.loads(response["Payload"].read().decode("utf-8"))

        return response

    def publish_version(
        self,
        function_name: str,
        code_sha256: str | None = None,
        description: str = "",
        revision_id: str | None = None,
    ):
        params = {"FunctionName": function_name, "Description": description}
        if code_sha256:
            params["CodeSha256"] = code_sha256
        if revision_id:
            params["RevisionId"] = revision_id

        response = self.lambda_client.publish_version(**params)
        return response

    def create_alias(self, config: CreateAlias):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": config.function_name,
            "Name": config.name,
            "FunctionVersion": config.function_version,
            "Description": config.description,
        }

        if config.routing_config:
            params["RoutingConfig"] = config.routing_config

        response = self.lambda_client.create_alias(**params)
        return response

    def update_alias(self, config: UpdateAlias):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": config.function_name,
            "Name": config.name,
        }

        if config.function_version:
            params["FunctionVersion"] = config.function_version
        if config.description is not None:
            params["Description"] = config.description
        if config.routing_config:
            params["RoutingConfig"] = config.routing_config
        if config.revision_id:
            params["RevisionId"] = config.revision_id

        response = self.lambda_client.update_alias(**params)
        return response

    def delete_alias(self, function_name: str, name: str):
        try:
            self.lambda_client.delete_alias(FunctionName=function_name, Name=name)
            return True
        except ClientError:
            return False

    def get_alias(self, function_name: str, name: str):
        response = self.lambda_client.get_alias(FunctionName=function_name, Name=name)
        return response

    def list_aliases(
        self,
        function_name: str,
        function_version: str | None = None,
        marker: str | None = None,
        max_items: int = 10000,
    ):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": function_name,
            "MaxItems": max_items,
        }
        if function_version:
            params["FunctionVersion"] = function_version
        if marker:
            params["Marker"] = marker

        response = self.lambda_client.list_aliases(**params)
        return response

    def create_layer_version(self, config: CreateLayerVersion):
        params: tp.Dict[str, tp.Any] = {
            "LayerName": config.layer_name,
            "Description": config.description,
            "Content": config.content,
        }

        if config.compatible_runtimes:
            params["CompatibleRuntimes"] = config.compatible_runtimes
        if config.license_info:
            params["LicenseInfo"] = config.license_info
        if config.compatible_architectures:
            params["CompatibleArchitectures"] = config.compatible_architectures

        response = self.lambda_client.publish_layer_version(**params)
        return response

    def create_provisioned_concurrency_config(
        self, config: CreateProvisionedConcurrencyConfig
    ):
        response = self.lambda_client.put_provisioned_concurrency_config(
            FunctionName=config.function_name,
            Qualifier=config.qualifier,
            ProvisionedConcurrentExecutions=config.provisioned_concurrent_executions,
        )
        return response

    def list_versions_by_function(
        self, function_name: str, marker: str | None = None, max_items: int = 10000
    ):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": function_name,
            "MaxItems": max_items,
        }
        if marker is not None:
            params["Marker"] = str(marker)

        if "Marker" in params:
            response = self.lambda_client.list_versions_by_function(
                FunctionName=str(params["FunctionName"]),
                Marker=str(params["Marker"]),
                MaxItems=int(params["MaxItems"]),
            )
        else:
            response = self.lambda_client.list_versions_by_function(
                FunctionName=str(params["FunctionName"]),
                MaxItems=int(params["MaxItems"]),
            )
        return response

    def get_function_configuration(
        self, function_name: str, qualifier: str | None = None
    ):
        params: tp.Dict[str, tp.Any] = {"FunctionName": function_name}
        if qualifier:
            params["Qualifier"] = qualifier

        response = self.lambda_client.get_function_configuration(**params)
        return response

    def get_function_code_signing_config(self, function_name: str):
        response = self.lambda_client.get_function_code_signing_config(
            FunctionName=function_name
        )
        return response

    def list_function_event_source_mappings(self, function_name: str):
        response = self.lambda_client.list_event_source_mappings(
            FunctionName=function_name
        )
        return response

    def get_account_settings(self):
        response = self.lambda_client.get_account_settings()
        return response

    def create_event_source_mapping(self, config: CreateEventSourceMapping):
        params: tp.Dict[str, tp.Any] = {
            "EventSourceArn": config.event_source_arn,
            "FunctionName": config.function_name,
            "Enabled": config.enabled,
            "BatchSize": config.batch_size,
            "MaximumBatchingWindowInSeconds": config.maximum_batching_window_in_seconds,
            "ParallelizationFactor": config.parallelization_factor,
            "StartingPosition": config.starting_position,
            "StartingPositionTimestamp": config.starting_position_timestamp,
            "DestinationConfig": config.destination_config,
            "MaximumRecordAgeInSeconds": config.maximum_record_age_in_seconds,
            "BisectBatchOnFunctionError": config.bisect_batch_on_function_error,
            "MaximumRetryAttempts": config.maximum_retry_attempts,
            "TumblingWindowInSeconds": config.tumbling_window_in_seconds,
            "Topics": config.topics,
            "Queues": config.queues,
            "SourceAccessConfigurations": config.source_access_configurations,
            "SelfManagedEventSource": config.self_managed_event_source,
            "FunctionResponseTypes": config.function_response_types,
            "AmazonManagedKafkaEventSourceConfig": config.amazon_managed_kafka_event_source_config,
            "SelfManagedKafkaEventSourceConfig": config.self_managed_kafka_event_source_config,
            "ScalingConfig": config.scaling_config,
            "DocumentDBEventSourceConfig": config.document_db_event_source_config,
        }
        response = self.lambda_client.create_event_source_mapping(**params)
        return response

    def get_event_source_mapping(self, uuid: str):
        response = self.lambda_client.get_event_source_mapping(UUID=uuid)
        return response

    def delete_event_source_mapping(self, uuid: str):
        response = self.lambda_client.delete_event_source_mapping(UUID=uuid)
        return response

    def update_event_source_mapping(self, config: UpdateEventSourceMapping):
        params: tp.Dict[str, tp.Any] = {"UUID": config.uuid}
        if config.function_name:
            params["FunctionName"] = config.function_name
        if config.enabled is not None:
            params["Enabled"] = config.enabled
        if config.batch_size:
            params["BatchSize"] = config.batch_size
        if config.maximum_batching_window_in_seconds:
            params["MaximumBatchingWindowInSeconds"] = (
                config.maximum_batching_window_in_seconds
            )
        if config.destination_config:
            params["DestinationConfig"] = config.destination_config
        if config.maximum_record_age_in_seconds:
            params["MaximumRecordAgeInSeconds"] = config.maximum_record_age_in_seconds
        if config.bisect_batch_on_function_error is not None:
            params["BisectBatchOnFunctionError"] = config.bisect_batch_on_function_error
        if config.maximum_retry_attempts:
            params["MaximumRetryAttempts"] = config.maximum_retry_attempts
        if config.parallelization_factor:
            params["ParallelizationFactor"] = config.parallelization_factor
        if config.source_access_configurations:
            params["SourceAccessConfigurations"] = config.source_access_configurations
        if config.tumbling_window_in_seconds:
            params["TumblingWindowInSeconds"] = config.tumbling_window_in_seconds
        if config.function_response_types:
            params["FunctionResponseTypes"] = config.function_response_types
        if config.scaling_config:
            params["ScalingConfig"] = config.scaling_config
        if config.document_db_event_source_config:
            params["DocumentDBEventSourceConfig"] = (
                config.document_db_event_source_config
            )

        response = self.lambda_client.update_event_source_mapping(**params)
        return response

    def list_event_source_mappings(
        self,
        event_source_arn: str | None = None,
        function_name: str | None = None,
        marker: str | None = None,
        max_items: int = 10000,
    ):
        params: tp.Dict[str, tp.Any] = {"MaxItems": max_items}
        if event_source_arn:
            params["EventSourceArn"] = event_source_arn
        if function_name:
            params["FunctionName"] = function_name
        if marker:
            params["Marker"] = marker

        response = self.lambda_client.list_event_source_mappings(**params)
        return response

    def get_code_signing_config(self, code_signing_config_arn: str):
        response = self.lambda_client.get_code_signing_config(
            CodeSigningConfigArn=code_signing_config_arn
        )
        return response

    def delete_code_signing_config(self, code_signing_config_arn: str):
        response = self.lambda_client.delete_code_signing_config(
            CodeSigningConfigArn=code_signing_config_arn
        )
        return response

    def update_code_signing_config(self, config: CodeSigningConfig):
        params: tp.Dict[str, tp.Any] = {
            "CodeSigningConfigArn": config.code_signing_config_arn
        }
        if config.description:
            params["Description"] = config.description
        if config.allowed_publishers:
            params["AllowedPublishers"] = config.allowed_publishers
        if config.code_signing_policies:
            params["CodeSigningPolicies"] = config.code_signing_policies

        response = self.lambda_client.update_code_signing_config(**params)
        return response

    def list_code_signing_configs(
        self, marker: str | None = None, max_items: int = 10000
    ):
        params: tp.Dict[str, tp.Any] = {"MaxItems": max_items}
        if marker:
            params["Marker"] = marker

        response = self.lambda_client.list_code_signing_configs(**params)
        return response

    def create_code_signing_config(self, config: CreateCodeSigningConfig):
        params: tp.Dict[str, tp.Any] = {
            "AllowedPublishers": config.allowed_publishers,
            "CodeSigningPolicies": config.code_signing_policies,
        }
        if config.description:
            params["Description"] = config.description

        response = self.lambda_client.create_code_signing_config(**params)
        return response

    def get_function_concurrency(self, function_name: str):
        response = self.lambda_client.get_function_concurrency(
            FunctionName=function_name
        )
        return response

    def delete_function_concurrency(self, function_name: str):
        response = self.lambda_client.delete_function_concurrency(
            FunctionName=function_name
        )
        return response

    def put_function_concurrency(
        self, function_name: str, reserved_concurrent_executions: int
    ):
        response = self.lambda_client.put_function_concurrency(
            FunctionName=function_name,
            ReservedConcurrentExecutions=reserved_concurrent_executions,
        )
        return response

    def get_provisioned_concurrency_config(self, function_name: str, qualifier: str):
        response = self.lambda_client.get_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=qualifier
        )
        return response

    def delete_provisioned_concurrency_config(self, function_name: str, qualifier: str):
        response = self.lambda_client.delete_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=qualifier
        )
        return response

    def list_provisioned_concurrency_configs(
        self, function_name: str, marker: str | None = None, max_items: int = 10000
    ):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": function_name,
            "MaxItems": max_items,
        }
        if marker:
            params["Marker"] = marker

        response = self.lambda_client.list_provisioned_concurrency_configs(**params)
        return response

    def put_provisioned_concurrency_config(
        self, function_name: str, qualifier: str, provisioned_concurrent_executions: int
    ):
        response = self.lambda_client.put_provisioned_concurrency_config(
            FunctionName=function_name,
            Qualifier=qualifier,
            ProvisionedConcurrentExecutions=provisioned_concurrent_executions,
        )
        return response

    def get_function_url_config(self, function_name: str, qualifier: str | None = None):
        params: tp.Dict[str, tp.Any] = {"FunctionName": function_name}
        if qualifier:
            params["Qualifier"] = qualifier

        response = self.lambda_client.get_function_url_config(**params)
        return response

    def delete_function_url_config(
        self, function_name: str, qualifier: str | None = None
    ):
        params: tp.Dict[str, tp.Any] = {"FunctionName": function_name}
        if qualifier:
            params["Qualifier"] = qualifier

        response = self.lambda_client.delete_function_url_config(**params)
        return response

    def update_function_url_config(
        self,
        function_name: str,
        config: tp.Dict[str, tp.Any],
        qualifier: str | None = None,
    ):
        params: tp.Dict[str, tp.Any] = {"FunctionName": function_name, "Config": config}
        if qualifier:
            params["Qualifier"] = qualifier

        response = self.lambda_client.update_function_url_config(**params)
        return response

    def create_function_url_config(
        self,
        function_name: str,
        config: tp.Dict[str, tp.Any],
        qualifier: str | None = None,
    ):
        params: tp.Dict[str, tp.Any] = {"FunctionName": function_name, "Config": config}
        if qualifier:
            params["Qualifier"] = qualifier

        response = self.lambda_client.create_function_url_config(**params)
        return response

    def get_policy(self, function_name: str, qualifier: str | None = None):
        params: tp.Dict[str, tp.Any] = {"FunctionName": function_name}
        if qualifier:
            params["Qualifier"] = qualifier

        response = self.lambda_client.get_policy(**params)
        return response

    def remove_permission(
        self,
        function_name: str,
        statement_id: str,
        qualifier: str | None = None,
        revision_id: str | None = None,
    ):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": function_name,
            "StatementId": statement_id,
        }
        if qualifier:
            params["Qualifier"] = qualifier
        if revision_id:
            params["RevisionId"] = revision_id

        response = self.lambda_client.remove_permission(**params)
        return response

    def add_permission(self, config: AddPermission):
        params: tp.Dict[str, tp.Any] = {
            "FunctionName": config.function_name,
            "StatementId": config.statement_id,
            "Action": config.action,
            "Principal": config.principal,
        }

        if config.source_arn:
            params["SourceArn"] = config.source_arn
        if config.source_account:
            params["SourceAccount"] = config.source_account
        if config.event_source_token:
            params["EventSourceToken"] = config.event_source_token
        if config.qualifier:
            params["Qualifier"] = config.qualifier
        if config.revision_id:
            params["RevisionId"] = config.revision_id
        if config.principal_org_id:
            params["PrincipalOrgID"] = config.principal_org_id
        if config.function_url_auth_type:
            params["FunctionUrlAuthType"] = config.function_url_auth_type

        response = self.lambda_client.add_permission(**params)
        return response

    def list_layers(
        self,
        compatible_runtime: str | None = None,
        compatible_architecture: str | None = None,
        marker: str | None = None,
        max_items: int = 50,
    ):
        params: tp.Dict[str, tp.Any] = {"MaxItems": max_items}
        if compatible_runtime:
            params["CompatibleRuntime"] = compatible_runtime
        if compatible_architecture:
            params["CompatibleArchitecture"] = compatible_architecture
        if marker:
            params["Marker"] = marker

        response = self.lambda_client.list_layers(**params)
        return response

    def get_layer_version(self, layer_name: str, version_number: int):
        response = self.lambda_client.get_layer_version(
            LayerName=layer_name, VersionNumber=version_number
        )
        return response

    def delete_layer_version(self, layer_name: str, version_number: int):
        response = self.lambda_client.delete_layer_version(
            LayerName=layer_name, VersionNumber=version_number
        )
        return response

    def list_layer_versions(
        self,
        layer_name: str,
        compatible_runtime: str | None = None,
        compatible_architecture: str | None = None,
        marker: str | None = None,
        max_items: int = 50,
    ):
        params: tp.Dict[str, tp.Any] = {"LayerName": layer_name, "MaxItems": max_items}
        if compatible_runtime:
            params["CompatibleRuntime"] = compatible_runtime
        if compatible_architecture:
            params["CompatibleArchitecture"] = compatible_architecture
        if marker:
            params["Marker"] = marker

        response = self.lambda_client.list_layer_versions(**params)
        return response

    def list_tags(self, resource: str):
        response = self.lambda_client.list_tags(Resource=resource)
        return response

    def tag_resource(self, resource: str, tags: tp.Dict[str, str]):
        try:
            self.lambda_client.tag_resource(Resource=resource, Tags=tags)
            return True
        except ClientError:
            return False

    def untag_resource(self, resource: str, tag_keys: tp.List[str]):
        try:
            self.lambda_client.untag_resource(Resource=resource, TagKeys=tag_keys)
            return True
        except ClientError:
            return False


client = LambdaClient()
app = APIRouter()


# Lambda Function Endpoints
@app.post("/api/v1/functions", status_code=status.HTTP_201_CREATED)
async def create_function(config: CreateFunction):
    try:
        response = client.create_function(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions")
async def list_functions(
    function_version: str = "ALL", marker: str | None = None, max_items: int = 10000
):
    try:
        response = client.list_functions(function_version, marker, max_items)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/account-settings")
async def get_account_settings():
    try:
        response = client.get_account_settings()
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}")
async def get_function(function_name: str, qualifier: str | None = None):
    try:
        response = client.get_function(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/functions/{function_name}")
async def delete_function(function_name: str, qualifier: str | None = None):
    result = client.delete_function(function_name, qualifier)
    if result:
        return {"message": "Function deleted successfully"}
    raise HTTPException(status_code=400, detail="Failed to delete function")


@app.put("/api/v1/functions/{function_name}/code")
async def update_function_code(function_name: str, config: UpdateFunctionCode):
    config.function_name = function_name
    try:
        response = client.update_function_code(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/v1/functions/{function_name}/configuration")
async def update_function_configuration(
    function_name: str, config: UpdateFunctionConfiguration
):
    config.function_name = function_name
    try:
        response = client.update_function_configuration(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/configuration")
async def get_function_configuration(function_name: str, qualifier: str | None = None):
    try:
        response = client.get_function_configuration(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/functions/{function_name}/code-signing-config")
async def get_function_code_signing_config(function_name: str):
    try:
        response = client.get_function_code_signing_config(function_name)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/functions/{function_name}/event-source-mappings")
async def list_function_event_source_mappings(function_name: str):
    try:
        response = client.list_function_event_source_mappings(function_name)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/event-source-mappings")
async def create_event_source_mapping(config: CreateEventSourceMapping):
    try:
        response = client.create_event_source_mapping(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/event-source-mappings/{uuid}")
async def get_event_source_mapping(uuid: str):
    try:
        response = client.get_event_source_mapping(uuid)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/event-source-mappings/{uuid}")
async def delete_event_source_mapping(uuid: str):
    try:
        response = client.delete_event_source_mapping(uuid)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/v1/event-source-mappings/{uuid}")
async def update_event_source_mapping(uuid: str, config: UpdateEventSourceMapping):
    config.uuid = uuid
    try:
        response = client.update_event_source_mapping(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/event-source-mappings")
async def list_event_source_mappings(
    event_source_arn: str | None = None,
    function_name: str | None = None,
    marker: str | None = None,
    max_items: int = 10000,
):
    try:
        response = client.list_event_source_mappings(
            event_source_arn, function_name, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/code-signing-configs/{code_signing_config_arn}")
async def get_code_signing_config(code_signing_config_arn: str):
    try:
        response = client.get_code_signing_config(code_signing_config_arn)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/code-signing-configs/{code_signing_config_arn}")
async def delete_code_signing_config(code_signing_config_arn: str):
    try:
        response = client.delete_code_signing_config(code_signing_config_arn)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/v1/code-signing-configs/{code_signing_config_arn}")
async def update_code_signing_config(
    code_signing_config_arn: str, config: CodeSigningConfig
):
    config.code_signing_config_arn = code_signing_config_arn
    try:
        response = client.update_code_signing_config(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/code-signing-configs")
async def list_code_signing_configs(marker: str | None = None, max_items: int = 10000):
    try:
        response = client.list_code_signing_configs(marker, max_items)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/code-signing-configs")
async def create_code_signing_config(config: CreateCodeSigningConfig):
    try:
        response = client.create_code_signing_config(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/concurrency")
async def get_function_concurrency_endpoint(function_name: str):
    try:
        response = client.get_function_concurrency(function_name)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/functions/{function_name}/concurrency")
async def delete_function_concurrency_endpoint(function_name: str):
    try:
        response = client.delete_function_concurrency(function_name)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/v1/functions/{function_name}/concurrency")
async def put_function_concurrency_endpoint(
    function_name: str, config: PutFunctionConcurrency
):
    config.function_name = function_name
    try:
        response = client.put_function_concurrency(
            config.function_name, config.reserved_concurrent_executions
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get(
    "/api/v1/functions/{function_name}/provisioned-concurrency-configs/{qualifier}"
)
async def get_provisioned_concurrency_config_endpoint(
    function_name: str, qualifier: str
):
    try:
        response = client.get_provisioned_concurrency_config(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete(
    "/api/v1/functions/{function_name}/provisioned-concurrency-configs/{qualifier}"
)
async def delete_provisioned_concurrency_config_endpoint(
    function_name: str, qualifier: str
):
    try:
        response = client.delete_provisioned_concurrency_config(
            function_name, qualifier
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/provisioned-concurrency-configs")
async def list_provisioned_concurrency_configs_endpoint(
    function_name: str, marker: str | None = None, max_items: int = 10000
):
    try:
        response = client.list_provisioned_concurrency_configs(
            function_name, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/v1/functions/{function_name}/provisioned-concurrency-configs")
async def put_provisioned_concurrency_config(
    function_name: str, config: CreateProvisionedConcurrencyConfig
):
    config.function_name = function_name
    try:
        response = client.put_provisioned_concurrency_config(
            config.function_name,
            config.qualifier,
            config.provisioned_concurrent_executions,
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/url-configs")
async def get_function_url_config_endpoint(
    function_name: str, qualifier: str | None = None
):
    try:
        response = client.get_function_url_config(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/functions/{function_name}/url-configs")
async def delete_function_url_config_endpoint(
    function_name: str, qualifier: str | None = None
):
    try:
        response = client.delete_function_url_config(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/v1/functions/{function_name}/url-configs")
async def update_function_url_config_endpoint(
    function_name: str, config: tp.Dict[str, tp.Any], qualifier: str | None = None
):
    try:
        response = client.update_function_url_config(function_name, config, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/functions/{function_name}/url-configs")
async def create_function_url_config_endpoint(
    function_name: str, config: CreateFunctionUrlConfig
):
    config.function_name = function_name
    try:
        response = client.create_function_url_config(
            config.function_name, config.config, config.qualifier
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/policy")
async def get_policy_endpoint(function_name: str, qualifier: str | None = None):
    try:
        response = client.get_policy(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/functions/{function_name}/permissions/{statement_id}")
async def remove_permission_endpoint(
    function_name: str,
    statement_id: str,
    qualifier: str | None = None,
    revision_id: str | None = None,
):
    try:
        response = client.remove_permission(
            function_name, statement_id, qualifier, revision_id
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/functions/{function_name}/permissions")
async def add_permission_endpoint(function_name: str, config: AddPermission):
    config.function_name = function_name
    try:
        response = client.add_permission(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/layers")
async def list_layers_endpoint(
    compatible_runtime: str | None = None,
    compatible_architecture: str | None = None,
    marker: str | None = None,
    max_items: int = 50,
):
    try:
        response = client.list_layers(
            compatible_runtime, compatible_architecture, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/layers/{layer_name}/versions/{version_number}")
async def get_layer_version_endpoint(layer_name: str, version_number: int):
    try:
        response = client.get_layer_version(layer_name, version_number)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/layers/{layer_name}/versions/{version_number}")
async def delete_layer_version_endpoint(layer_name: str, version_number: int):
    try:
        response = client.delete_layer_version(layer_name, version_number)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/layers/{layer_name}/versions")
async def list_layer_versions_endpoint(
    layer_name: str,
    compatible_runtime: str | None = None,
    compatible_architecture: str | None = None,
    marker: str | None = None,
    max_items: int = 50,
):
    try:
        response = client.list_layer_versions(
            layer_name, compatible_runtime, compatible_architecture, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/functions/{function_name}/invocations")
async def invoke_function(function_name: str, config: InvokeFunction):
    config.function_name = function_name
    try:
        response = client.invoke_function(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/functions/{function_name}/versions")
async def publish_version(
    function_name: str,
    code_sha256: str | None = None,
    description: str = "",
    revision_id: str | None = None,
):
    try:
        response = client.publish_version(
            function_name, code_sha256, description, revision_id
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/versions")
async def list_versions_by_function(
    function_name: str, marker: str | None = None, max_items: int = 10000
):
    try:
        response = client.list_versions_by_function(function_name, marker, max_items)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Lambda Alias Endpoints
@app.post("/api/v1/functions/{function_name}/aliases")
async def create_alias(function_name: str, config: CreateAlias):
    config.function_name = function_name
    try:
        response = client.create_alias(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/aliases")
async def list_aliases(
    function_name: str,
    function_version: str | None = None,
    marker: str | None = None,
    max_items: int = 10000,
):
    try:
        response = client.list_aliases(
            function_name, function_version, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/functions/{function_name}/aliases/{alias_name}")
async def get_alias(function_name: str, alias_name: str):
    try:
        response = client.get_alias(function_name, alias_name)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.put("/api/v1/functions/{function_name}/aliases/{alias_name}")
async def update_alias(function_name: str, alias_name: str, config: UpdateAlias):
    config.function_name = function_name
    config.name = alias_name
    try:
        response = client.update_alias(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/functions/{function_name}/aliases/{alias_name}")
async def delete_alias(function_name: str, alias_name: str):
    result = client.delete_alias(function_name, alias_name)
    if result:
        return {"message": "Alias deleted successfully"}
    raise HTTPException(status_code=400, detail="Failed to delete alias")


# Lambda Layer Endpoints
@app.post("/api/v1/layers/{layer_name}/versions")
async def create_layer_version(layer_name: str, config: CreateLayerVersion):
    config.layer_name = layer_name
    try:
        response = client.create_layer_version(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/layers")
async def list_layers(
    compatible_runtime: str | None = None,
    compatible_architecture: str | None = None,
    marker: str | None = None,
    max_items: int = 50,
):
    try:
        response = client.list_layers(
            compatible_runtime, compatible_architecture, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/layers/{layer_name}/versions")
async def list_layer_versions(
    layer_name: str,
    compatible_runtime: str | None = None,
    compatible_architecture: str | None = None,
    marker: str | None = None,
    max_items: int = 50,
):
    try:
        response = client.list_layer_versions(
            layer_name, compatible_runtime, compatible_architecture, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/layers/{layer_name}/versions/{version_number}")
async def get_layer_version(layer_name: str, version_number: int):
    try:
        response = client.get_layer_version(layer_name, version_number)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/api/v1/layers/{layer_name}/versions/{version_number}")
async def delete_layer_version(layer_name: str, version_number: int):
    try:
        result = client.delete_layer_version(layer_name, version_number)
        if result:
            return {"message": "Layer version deleted successfully"}
        raise HTTPException(status_code=400, detail="Failed to delete layer version")
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/functions/{function_name}/permissions")
async def add_permission(function_name: str, config: AddPermission):
    config.function_name = function_name
    try:
        response = client.add_permission(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/functions/{function_name}/permissions/{statement_id}")
async def remove_permission(
    function_name: str,
    statement_id: str,
    qualifier: str | None = None,
    revision_id: str | None = None,
):
    result = client.remove_permission(
        function_name, statement_id, qualifier, revision_id
    )
    if result:
        return {"message": "Permission removed successfully"}
    raise HTTPException(status_code=400, detail="Failed to remove permission")


@app.get("/api/v1/functions/{function_name}/policy")
async def get_policy(function_name: str, qualifier: str | None = None):
    try:
        response = client.get_policy(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/functions/{function_name}/url-configs")
async def create_function_url_config(
    function_name: str, config: CreateFunctionUrlConfig
):
    config.function_name = function_name
    try:
        response = client.create_function_url_config(
            config.function_name, config.config, config.qualifier
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/functions/{function_name}/url-configs")
async def delete_function_url_config(function_name: str, qualifier: str | None = None):
    result = client.delete_function_url_config(function_name, qualifier)
    if result:
        return {"message": "Function URL config deleted successfully"}
    raise HTTPException(status_code=400, detail="Failed to delete function URL config")


@app.get("/api/v1/functions/{function_name}/url-configs")
async def get_function_url_config(function_name: str, qualifier: str | None = None):
    try:
        response = client.get_function_url_config(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.put("/api/v1/functions/{function_name}/url-configs")
async def update_function_url_config(
    function_name: str, config: tp.Dict[str, tp.Any], qualifier: str | None = None
):
    try:
        response = client.update_function_url_config(function_name, config, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/functions/{function_name}/provisioned-concurrency-configs")
async def create_provisioned_concurrency_config(
    function_name: str, config: CreateProvisionedConcurrencyConfig
):
    config.function_name = function_name
    try:
        response = client.create_provisioned_concurrency_config(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete(
    "/api/v1/functions/{function_name}/provisioned-concurrency-configs/{qualifier}"
)
async def delete_provisioned_concurrency_config(function_name: str, qualifier: str):
    result = client.delete_provisioned_concurrency_config(function_name, qualifier)
    if result:
        return {"message": "Provisioned concurrency config deleted successfully"}
    raise HTTPException(
        status_code=400, detail="Failed to delete provisioned concurrency config"
    )


@app.get(
    "/api/v1/functions/{function_name}/provisioned-concurrency-configs/{qualifier}"
)
async def get_provisioned_concurrency_config(function_name: str, qualifier: str):
    try:
        response = client.get_provisioned_concurrency_config(function_name, qualifier)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/functions/{function_name}/provisioned-concurrency-configs")
async def list_provisioned_concurrency_configs(
    function_name: str, marker: str | None = None, max_items: int = 50
):
    try:
        response = client.list_provisioned_concurrency_configs(
            function_name, marker, max_items
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Lambda Concurrency Endpoints
@app.put("/api/v1/functions/{function_name}/concurrency")
async def put_function_concurrency(function_name: str, config: PutFunctionConcurrency):
    config.function_name = function_name
    try:
        response = client.put_function_concurrency(
            config.function_name, config.reserved_concurrent_executions
        )
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/functions/{function_name}/concurrency")
async def delete_function_concurrency(function_name: str):
    result = client.delete_function_concurrency(function_name)
    if result:
        return {"message": "Function concurrency deleted successfully"}
    raise HTTPException(status_code=400, detail="Failed to delete function concurrency")


@app.get("/api/v1/functions/{function_name}/concurrency")
async def get_function_concurrency(function_name: str):
    try:
        response = client.get_function_concurrency(function_name)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/resources/{resource_arn}/tags")
async def tag_resource(resource_arn: str, tags: tp.Dict[str, str]):
    result = client.tag_resource(resource_arn, tags)
    if result:
        return {"message": "Tags added successfully"}
    raise HTTPException(status_code=400, detail="Failed to add tags")


@app.delete("/api/v1/resources/{resource_arn}/tags")
async def untag_resource(resource_arn: str, tag_keys: tp.List[str]):
    result = client.untag_resource(resource_arn, tag_keys)
    if result:
        return {"message": "Tags removed successfully"}
    raise HTTPException(status_code=400, detail="Failed to remove tags")


@app.get("/api/v1/resources/{resource_arn}/tags")
async def list_tags(resource_arn: str):
    try:
        response = client.list_tags(resource_arn)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))
