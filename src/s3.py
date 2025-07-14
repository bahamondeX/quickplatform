import typing as tp
import boto3
from pydantic import BaseModel, Field
from botocore.exceptions import ClientError
import json
from fastapi import APIRouter, status, HTTPException


class CreateBucket(BaseModel):
    bucket: str
    region: tp.Literal[
        "EU",
        "af-south-1",
        "ap-east-1",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ap-southeast-5",
        "ca-central-1",
        "cn-north-1",
        "cn-northwest-1",
        "eu-central-1",
        "eu-north-1",
        "eu-south-1",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "me-central-1",
        "me-south-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    ]
    acl: tp.Literal["authenticated-read", "private", "public-read", "public-read-write"]
    versioning: bool = False
    encryption: bool = False
    logging: bool = False


class CreateBucketWebsiteHosting(BaseModel):
    bucket: str
    index_document: str = "index.html"
    error_document: str = "error.html"


class CreateBucketPolicy(BaseModel):
    bucket: str
    policy: str


class CreateBucketNotification(BaseModel):
    bucket: str
    notification: str


class CreateBucketLogging(BaseModel):
    bucket: str
    target_bucket: str
    target_prefix: str = ""


class LambdaEventSourceMapping(BaseModel):
    event_source_arn: str
    function_name: str
    enabled: bool = True
    batch_size: int = 10
    maximum_batching_window_in_seconds: int = 0
    parallelization_factor: int = 1
    starting_position: tp.Literal["TRIM_HORIZON", "LATEST", "AT_TIMESTAMP"] = "LATEST"
    starting_position_timestamp: float | None = None
    maximum_record_age_in_seconds: int | None = None
    bisect_batch_on_function_error: bool = False
    maximum_retry_attempts: int | None = None
    tumbling_window_in_seconds: int | None = None
    topics: tp.List[str] = Field(default_factory=list)
    queues: tp.List[str] = Field(default_factory=list)
    source_access_configurations: tp.List[tp.Dict[str, str]]
    self_managed_event_source: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    function_response_types: tp.List[str] = Field(default_factory=list)
    filter_criteria: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    destination_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)


class UpdateEventSourceMapping(BaseModel):
    uuid: str
    enabled: bool | None = None
    batch_size: int | None = None
    maximum_batching_window_in_seconds: int | None = None
    parallelization_factor: int | None = None
    function_name: str | None = None
    maximum_record_age_in_seconds: int | None = None
    bisect_batch_on_function_error: bool | None = None
    maximum_retry_attempts: int | None = None
    tumbling_window_in_seconds: int | None = None
    filter_criteria: tp.Dict[str, tp.Any] = Field(default_factory=dict)
    destination_config: tp.Dict[str, tp.Any] = Field(default_factory=dict)


class DeleteEventSourceMapping(BaseModel):
    uuid: str


class GetEventSourceMapping(BaseModel):
    uuid: str


class UploadObject(BaseModel):
    bucket: str
    key: str
    file_path: str
    content_type: str | None = None
    metadata: tp.Dict[str, str] = Field(default_factory=dict)


class DownloadObject(BaseModel):
    bucket: str
    key: str
    file_path: str


class DeleteObject(BaseModel):
    bucket: str
    key: str


class ListObjects(BaseModel):
    bucket: str
    prefix: str = ""
    max_keys: int = 1000


class S3Client:
    def __init__(
        self,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        region_name: str = "us-east-1",
    ):
        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            endpoint_url="https://aws.oscarbahamonde.com"
        )
        self.lambda_client = boto3.client(
            "lambda",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            endpoint_url="https://aws.oscarbahamonde.com"
        )

    def create_bucket(self, config: CreateBucket):
        try:
            if config.region != "us-east-1":
                self.s3_client.create_bucket(
                    Bucket=config.bucket,
                    CreateBucketConfiguration={"LocationConstraint": config.region},
                    ACL=config.acl,
                )
            else:
                self.s3_client.create_bucket(Bucket=config.bucket, ACL=config.acl)

            if config.versioning:
                self.s3_client.put_bucket_versioning(
                    Bucket=config.bucket, VersioningConfiguration={"Status": "Enabled"}
                )

            if config.encryption:
                self.s3_client.put_bucket_encryption(
                    Bucket=config.bucket,
                    ServerSideEncryptionConfiguration={
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "AES256"
                                }
                            }
                        ]
                    },
                )

            return True
        except ClientError:
            return False

    def configure_website_hosting(self, config: CreateBucketWebsiteHosting):
        try:
            self.s3_client.put_bucket_website(
                Bucket=config.bucket,
                WebsiteConfiguration={
                    "IndexDocument": {"Suffix": config.index_document},
                    "ErrorDocument": {"Key": config.error_document},
                },
            )
            return True
        except ClientError:
            return False

    def set_bucket_policy(self, config: CreateBucketPolicy):
        try:
            self.s3_client.put_bucket_policy(Bucket=config.bucket, Policy=config.policy)
            return True
        except ClientError:
            return False

    def set_bucket_notification(self, config: CreateBucketNotification):
        try:
            notification_config = json.loads(config.notification)
            self.s3_client.put_bucket_notification_configuration(
                Bucket=config.bucket, NotificationConfiguration=notification_config
            )
            return True
        except ClientError:
            return False

    def configure_logging(self, config: CreateBucketLogging):
        try:
            self.s3_client.put_bucket_logging(
                Bucket=config.bucket,
                BucketLoggingStatus={
                    "LoggingEnabled": {
                        "TargetBucket": config.target_bucket,
                        "TargetPrefix": config.target_prefix,
                    }
                },
            )
            return True
        except ClientError:
            return False

    def upload_object(self, config: UploadObject):
        try:
            extra_args: tp.Dict[str, tp.Any] = {}
            if config.content_type:
                extra_args["ContentType"] = config.content_type
            if config.metadata:
                extra_args["Metadata"] = config.metadata

            self.s3_client.upload_file(
                config.file_path, config.bucket, config.key, ExtraArgs=extra_args
            )
            return True
        except ClientError:
            return False

    def download_object(self, config: DownloadObject):
        try:
            self.s3_client.download_file(config.bucket, config.key, config.file_path)
            return True
        except ClientError:
            return False

    def delete_object(self, config: DeleteObject):
        try:
            self.s3_client.delete_object(Bucket=config.bucket, Key=config.key)
            return True
        except ClientError:
            return False

    def list_objects(self, config: ListObjects):
        response = self.s3_client.list_objects_v2(
            Bucket=config.bucket, Prefix=config.prefix, MaxKeys=config.max_keys
        )
        return response.get("Contents", [])

    def delete_bucket(self, bucket: str):
        try:
            self.s3_client.delete_bucket(Bucket=bucket)
            return True
        except ClientError:
            return False

    def bucket_exists(self, bucket: str):
        try:
            self.s3_client.head_bucket(Bucket=bucket)
            return True
        except ClientError:
            return False

    def get_bucket_location(self, bucket: str) -> str:
        response = self.s3_client.get_bucket_location(Bucket=bucket)
        return response["LocationConstraint"] or "us-east-1"

    def create_event_source_mapping(self, config: LambdaEventSourceMapping):

        params: tp.Dict[str, tp.Any] = {
            "EventSourceArn": config.event_source_arn,
            "FunctionName": config.function_name,
            "Enabled": config.enabled,
            "BatchSize": config.batch_size,
            "MaximumBatchingWindowInSeconds": config.maximum_batching_window_in_seconds,
            "ParallelizationFactor": config.parallelization_factor,
            "StartingPosition": config.starting_position,
        }

        if config.starting_position_timestamp:
            params["StartingPositionTimestamp"] = config.starting_position_timestamp
        if config.maximum_record_age_in_seconds:
            params["MaximumRecordAgeInSeconds"] = config.maximum_record_age_in_seconds
        if config.bisect_batch_on_function_error:
            params["BisectBatchOnFunctionError"] = config.bisect_batch_on_function_error
        if config.maximum_retry_attempts:
            params["MaximumRetryAttempts"] = config.maximum_retry_attempts
        if config.tumbling_window_in_seconds:
            params["TumblingWindowInSeconds"] = config.tumbling_window_in_seconds
        if config.topics:
            params["Topics"] = config.topics
        if config.queues:
            params["Queues"] = config.queues
        if config.source_access_configurations:
            params["SourceAccessConfigurations"] = config.source_access_configurations
        if config.self_managed_event_source:
            params["SelfManagedEventSource"] = config.self_managed_event_source
        if config.function_response_types:
            params["FunctionResponseTypes"] = config.function_response_types
        if config.filter_criteria:
            params["FilterCriteria"] = config.filter_criteria
        if config.destination_config:
            params["DestinationConfig"] = config.destination_config

        response = self.lambda_client.create_event_source_mapping(**params)
        return response

    def update_event_source_mapping(self, config: UpdateEventSourceMapping):
        params: tp.Dict[str, tp.Any] = {"UUID": config.uuid}
        if config.enabled:
            params["Enabled"] = config.enabled
        if config.batch_size:
            params["BatchSize"] = config.batch_size
        if config.maximum_batching_window_in_seconds:
            params["MaximumBatchingWindowInSeconds"] = (
                config.maximum_batching_window_in_seconds
            )
        if config.parallelization_factor:
            params["ParallelizationFactor"] = config.parallelization_factor
        if config.function_name:
            params["FunctionName"] = config.function_name
        if config.maximum_record_age_in_seconds:
            params["MaximumRecordAgeInSeconds"] = config.maximum_record_age_in_seconds
        if config.bisect_batch_on_function_error:
            params["BisectBatchOnFunctionError"] = config.bisect_batch_on_function_error
        if config.maximum_retry_attempts:
            params["MaximumRetryAttempts"] = config.maximum_retry_attempts
        if config.tumbling_window_in_seconds:
            params["TumblingWindowInSeconds"] = config.tumbling_window_in_seconds
        if config.filter_criteria:
            params["FilterCriteria"] = config.filter_criteria
        if config.destination_config:
            params["DestinationConfig"] = config.destination_config

        response = self.lambda_client.update_event_source_mapping(**params)
        return response

    def delete_event_source_mapping(self, config: DeleteEventSourceMapping):
        try:
            self.lambda_client.delete_event_source_mapping(UUID=config.uuid)
            return True
        except ClientError:
            return False

    def get_event_source_mapping(self, config: GetEventSourceMapping):
        response = self.lambda_client.get_event_source_mapping(UUID=config.uuid)
        return response

    def list_event_source_mappings(
        self, function_name: str | None = None, event_source_arn: str | None = None
    ):
        params: tp.Dict[str, tp.Any] = {}
        if function_name:
            params["FunctionName"] = function_name
        if event_source_arn:
            params["EventSourceArn"] = event_source_arn

        response = self.lambda_client.list_event_source_mappings(**params)
        return response.get("EventSourceMappings", [])


client = S3Client()
app = APIRouter()


# S3 Bucket Endpoints
@app.post("/api/v1/buckets", status_code=status.HTTP_201_CREATED)
async def create_bucket(config: CreateBucket):
    result = client.create_bucket(config)
    if result:
        return {"message": "Bucket created successfully", "bucket": config.bucket}
    raise HTTPException(status_code=400, detail="Failed to create bucket")


@app.get("/api/v1/buckets")
async def list_buckets():
    try:
        response = client.s3_client.list_buckets()
        return {"buckets": response["Buckets"]}
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/buckets/{bucket_name}")
async def delete_bucket(bucket_name: str):
    result = client.delete_bucket(bucket_name)
    if result:
        return {"message": "Bucket deleted successfully"}
    raise HTTPException(status_code=400, detail="Failed to delete bucket")


@app.get("/api/v1/buckets/{bucket_name}/exists")
async def bucket_exists(bucket_name: str):
    exists = client.bucket_exists(bucket_name)
    return {"exists": exists}


@app.get("/api/v1/buckets/{bucket_name}/location")
async def get_bucket_location(bucket_name: str):
    location = client.get_bucket_location(bucket_name)
    return {"location": location}


# S3 Object Endpoints
@app.post("/api/v1/buckets/{bucket_name}/objects")
async def upload_object(bucket_name: str, config: UploadObject):
    config.bucket = bucket_name
    result = client.upload_object(config)
    if result:
        return {"message": "Object uploaded successfully", "key": config.key}
    raise HTTPException(status_code=400, detail="Failed to upload object")


@app.get("/api/v1/buckets/{bucket_name}/objects")
async def list_objects(bucket_name: str, prefix: str = "", max_keys: int = 1000):
    config = ListObjects(bucket=bucket_name, prefix=prefix, max_keys=max_keys)
    objects = client.list_objects(config)
    return {"objects": objects}


@app.delete("/api/v1/buckets/{bucket_name}/objects/{key}")
async def delete_object(bucket_name: str, key: str):
    config = DeleteObject(bucket=bucket_name, key=key)
    result = client.delete_object(config)
    if result:
        return {"message": "Object deleted successfully"}
    raise HTTPException(status_code=400, detail="Failed to delete object")


@app.post("/api/v1/buckets/{bucket_name}/objects/{key}/download")
async def download_object(bucket_name: str, key: str, file_path: str):
    config = DownloadObject(bucket=bucket_name, key=key, file_path=file_path)
    result = client.download_object(config)
    if result:
        return {"message": "Object downloaded successfully", "file_path": file_path}
    raise HTTPException(status_code=400, detail="Failed to download object")


# S3 Website Hosting Endpoints
@app.post("/api/v1/buckets/{bucket_name}/website")
async def configure_website_hosting(
    bucket_name: str, config: CreateBucketWebsiteHosting
):
    config.bucket = bucket_name
    result = client.configure_website_hosting(config)
    if result:
        return {"message": "Website hosting configured successfully"}
    raise HTTPException(status_code=400, detail="Failed to configure website hosting")


# S3 Policy Endpoints
@app.post("/api/v1/buckets/{bucket_name}/policy")
async def set_bucket_policy(bucket_name: str, config: CreateBucketPolicy):
    config.bucket = bucket_name
    result = client.set_bucket_policy(config)
    if result:
        return {"message": "Bucket policy set successfully"}
    raise HTTPException(status_code=400, detail="Failed to set bucket policy")


# S3 Notification Endpoints
@app.post("/api/v1/buckets/{bucket_name}/notifications")
async def set_bucket_notification(bucket_name: str, config: CreateBucketNotification):
    config.bucket = bucket_name
    result = client.set_bucket_notification(config)
    if result:
        return {"message": "Bucket notification configured successfully"}
    raise HTTPException(
        status_code=400, detail="Failed to configure bucket notification"
    )


# S3 Logging Endpoints
@app.post("/api/v1/buckets/{bucket_name}/logging")
async def configure_logging(bucket_name: str, config: CreateBucketLogging):
    config.bucket = bucket_name
    result = client.configure_logging(config)
    if result:
        return {"message": "Logging configured successfully"}
    raise HTTPException(status_code=400, detail="Failed to configure logging")


# Lambda Event Source Mapping Endpoints
@app.post("/api/v1/lambda/event-source-mappings", status_code=status.HTTP_201_CREATED)
async def create_event_source_mapping(config: LambdaEventSourceMapping):
    try:
        response = client.create_event_source_mapping(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/lambda/event-source-mappings")
async def list_event_source_mappings(
    function_name: str | None = None, event_source_arn: str | None = None
):
    mappings = client.list_event_source_mappings(function_name, event_source_arn)
    return {"event_source_mappings": mappings}


@app.get("/api/v1/lambda/event-source-mappings/{uuid}")
async def get_event_source_mapping(uuid: str):
    config = GetEventSourceMapping(uuid=uuid)
    try:
        response = client.get_event_source_mapping(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.put("/api/v1/lambda/event-source-mappings/{uuid}")
async def update_event_source_mapping(uuid: str, config: UpdateEventSourceMapping):
    config.uuid = uuid
    try:
        response = client.update_event_source_mapping(config)
        return response
    except ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/lambda/event-source-mappings/{uuid}")
async def delete_event_source_mapping(uuid: str):
    config = DeleteEventSourceMapping(uuid=uuid)
    result = client.delete_event_source_mapping(config)
    if result:
        return {"message": "Event source mapping deleted successfully"}
    raise HTTPException(status_code=400, detail="Failed to delete event source mapping")
