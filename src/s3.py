from __future__ import annotations

import json
from typing import Any, List, Literal, Optional, Sequence, Union

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, File, UploadFile, status
from pydantic import BaseModel, Field
from typing_extensions import NotRequired, TypedDict
from datetime import datetime

# =======================================================================
# 1. Clientes Boto3 y Excepción Personalizada
# =======================================================================


s3_client = boto3.client("s3", endpoint_url="https://aws.oscarbahamonde.com")
s3_resource = boto3.resource("s3", endpoint_url="https://aws.oscarbahamonde.com")

BucketLocationConstraintType = Literal[
	"us-east-1",
	"eu-west-1",
	"ap-southeast-1",
	"sa-east-1",
	"ca-central-1",
	"ap-southeast-2",
]


ChecksumAlgorithmType = Literal["CRC32", "CRC32C", "SHA1", "SHA256"]


class LocationInfoTypeDef(TypedDict):
	Bucket: str
	Region: str


class BucketInfoTypeDef(TypedDict):
	Name: str
	CreationDate: datetime


class TagTypeDef(TypedDict):
	Key: str
	Value: str


class CopySourceTypeDef(TypedDict):
	Bucket: str
	Key: str
	VersionId: NotRequired[str]


class CreateBucketConfigurationTypeDef(TypedDict):
	LocationConstraint: NotRequired[BucketLocationConstraintType]
	Location: NotRequired[LocationInfoTypeDef]
	Bucket: NotRequired[BucketInfoTypeDef]
	Tags: NotRequired[Sequence[TagTypeDef]]


class S3Error(Exception):
	"""Excepción personalizada para errores de la API de S3."""

	def __init__(self, message: str, status_code: int = 400):
		self.message = message
		self.status_code = status_code
		super().__init__(self.message)


# =======================================================================
# 2. Modelos Pydantic para Configuración de Buckets
# =======================================================================


class CORSRuleTypeDef(TypedDict):
	AllowedMethods: Sequence[str]
	AllowedOrigins: Sequence[str]
	ID: NotRequired[str]
	AllowedHeaders: NotRequired[Sequence[str]]
	ExposeHeaders: NotRequired[Sequence[str]]
	MaxAgeSeconds: NotRequired[int]


class MessageResponse(TypedDict):
	message: str


class CORSRuleOutputTypeDef(TypedDict):
	AllowedMethods: List[str]
	AllowedOrigins: List[str]
	ID: NotRequired[str]
	AllowedHeaders: NotRequired[List[str]]
	ExposeHeaders: NotRequired[List[str]]
	MaxAgeSeconds: NotRequired[int]


class WebsiteConfiguration(TypedDict):
	"""Define la configuración de sitio web estático para un bucket."""

	ErrorDocument: Optional[dict[str, str]]
	IndexDocument: dict[str, str]


class PublicAccessBlockConfiguration(TypedDict):
	"""Define la configuración de bloqueo de acceso público."""

	BlockPublicAcls: bool
	IgnorePublicAcls: bool
	BlockPublicPolicy: bool
	RestrictPublicBuckets: bool


class CORSConfigurationTypeDef(TypedDict):
	CORSRules: Sequence[Union[CORSRuleTypeDef, CORSRuleOutputTypeDef]]


class ErrorDocumentTypeDef(TypedDict):
	Key: str


class IndexDocumentTypeDef(TypedDict):
	Suffix: str


class RedirectAllRequestsToTypeDef(TypedDict):
	HostName: str
	Protocol: NotRequired[Literal["http", "https"]]


class RoutingRuleTypeDef(TypedDict):
	Condition: NotRequired[RoutingRuleConditionTypeDef]
	Redirect: NotRequired[RedirectTypeDef]


class RoutingRuleConditionTypeDef(TypedDict):
	HttpErrorCodeReturnedEquals: NotRequired[str]
	KeyPrefixEquals: NotRequired[str]


class RedirectTypeDef(TypedDict):
	HostName: NotRequired[str]
	ReplaceKeyPrefixWith: NotRequired[str]
	ReplaceKeyWith: NotRequired[str]
	HttpRedirectCode: NotRequired[str]
	Protocol: NotRequired[str]


class WebsiteConfigurationTypeDef(TypedDict):
	ErrorDocument: NotRequired[ErrorDocumentTypeDef]
	IndexDocument: NotRequired[IndexDocumentTypeDef]
	RedirectAllRequestsTo: NotRequired[RedirectAllRequestsToTypeDef]
	RoutingRules: NotRequired[Any]


class PublicAccessBlockConfigurationTypeDef(TypedDict):
	BlockPublicAcls: bool
	IgnorePublicAcls: bool
	BlockPublicPolicy: bool
	RestrictPublicBuckets: bool


class PutBucketWebsiteRequestTypeDef(TypedDict):
	Bucket: str
	WebsiteConfiguration: WebsiteConfigurationTypeDef
	ChecksumAlgorithm: NotRequired[ChecksumAlgorithmType]
	ExpectedBucketOwner: NotRequired[str]


class PutBucketWebsiteResponseTypeDef(TypedDict):
	Location: str
	WebsiteURL: str


class PutObjectResponseTypeDef(TypedDict):
	ETag: str
	VersionId: str
	Location: str
	Expiration: str
	ServerSideEncryption: str
	ChecksumAlgorithm: str


# =======================================================================
# 3. Modelos Pydantic para Requests y Responses de la API
# =======================================================================


class BucketPolicyRequest(BaseModel):
	policy: dict[str, Any] = Field(
		..., description="Documento JSON de la política del bucket."
	)


class CopyObjectAdvancedRequest(BaseModel):
	source_bucket: str
	source_key: str
	metadata_directive: Literal["COPY", "REPLACE"] = "COPY"
	acl: Literal[
		"private", "public-read", "public-read-write", "authenticated-read"
	] = "private"
	storage_class: Literal[
		"STANDARD", "STANDARD_IA", "REDUCED_REDUNDANCY", "GLACIER", "DEEP_ARCHIVE"
	] = "STANDARD"


class BucketCreateRequest(BaseModel):
	bucket_name: str = Field(..., description="Nombre del bucket a crear.")
	region: BucketLocationConstraintType = Field(
		"us-east-1", description="Región de AWS donde se creará el bucket."
	)


class ObjectInfo(BaseModel):
	key: str = Field(..., alias="Key")
	last_modified: datetime = Field(..., alias="LastModified")
	size: int = Field(..., alias="Size")

	class Config:
		allow_population_by_field_name = True


class CopyObjectRequest(BaseModel):
	source_bucket: str
	source_key: str


class PresignedUrlResponse(BaseModel):
	method: str
	url: str


class BucketInfo(BaseModel):
	name: str = Field(..., alias="Name")
	creation_date: datetime = Field(..., alias="CreationDate")

	class Config:
		allow_population_by_field_name = True


# =======================================================================
# 4. Clase S3Bucket con Lógica OOP Integrada
# =======================================================================


class S3Bucket(BaseModel):
	name: str

	@classmethod
	def create(
		cls, bucket_name: str, region: BucketLocationConstraintType
	) -> "S3Bucket":
		"""Crea un nuevo bucket S3."""
		try:
			s3_client.create_bucket(Bucket=bucket_name)
			return cls(name=bucket_name)
		except ClientError as e:
			raise S3Error(f"No se pudo crear el bucket '{bucket_name}': {e}")

	@classmethod
	def list_all(cls) -> List[BucketInfo]:
		"""Lista todos los buckets S3 en la cuenta."""
		try:
			response = s3_client.list_buckets()
			return [
				BucketInfo.model_validate(bucket)
				for bucket in response.get("Buckets", [])
			]
		except ClientError as e:
			raise S3Error(f"No se pudieron listar los buckets: {e}")

	def empty_and_delete(self):
		"""Vacía completamente el bucket (incluyendo versiones) y luego lo elimina."""
		try:
			bucket_resource = s3_resource.Bucket(self.name)
			# Elimina todas las versiones de objetos y marcadores de eliminación
			bucket_resource.object_versions.delete()
			bucket_resource.delete()
		except ClientError as e:
			raise S3Error(f"No se pudo vaciar y eliminar el bucket '{self.name}': {e}")

	def list_objects(self) -> List[ObjectInfo]:
		"""Lista los objetos dentro de este bucket."""
		try:
			response = s3_client.list_objects_v2(Bucket=self.name)
			return [
				ObjectInfo.model_validate(obj) for obj in response.get("Contents", [])
			]
		except ClientError as e:
			raise S3Error(f"No se pudieron listar los objetos de '{self.name}': {e}")

	def put_object(self, object_key: str, file: UploadFile):
		"""Sube un objeto a este bucket."""
		try:
			s3_client.upload_fileobj(file.file, self.name, object_key)
		except ClientError as e:
			raise S3Error(
				f"No se pudo subir el objeto '{object_key}' a '{self.name}': {e}"
			)

	def delete_object(self, object_key: str):
		"""Elimina un objeto de este bucket."""
		try:
			s3_client.delete_object(Bucket=self.name, Key=object_key)
		except ClientError as e:
			raise S3Error(
				f"No se pudo eliminar el objeto '{object_key}' de '{self.name}': {e}"
			)

	def copy_object(self, source_key: str, dest_key: str, source_bucket: str):
		"""Copia un objeto a este bucket."""
		try:
			copy_source = CopySourceTypeDef(Bucket=source_bucket, Key=source_key)
			s3_client.copy_object(
				CopySource=copy_source, Bucket=self.name, Key=dest_key
			)
		except ClientError as e:
			raise S3Error(f"No se pudo copiar el objeto: {e}")

	def generate_presigned_url(
		self, object_key: str, expiration: int = 3600, method: str = "get_object"
	) -> str:
		"""Genera una URL prefirmada para un objeto."""
		try:
			params = {"Bucket": self.name, "Key": object_key}
			url = s3_client.generate_presigned_url(
				method, Params=params, ExpiresIn=expiration
			)
			return url
		except ClientError as e:
			raise S3Error(
				f"No se pudo generar la URL prefirmada para '{object_key}': {e}"
			)

	# --- Métodos de Configuración ---
	def configure_cors(self, cors_config: CORSConfigurationTypeDef):
		try:
			s3_client.put_bucket_cors(Bucket=self.name, CORSConfiguration=cors_config)
		except ClientError as e:
			raise S3Error(f"Error configurando CORS para '{self.name}': {e}")

	def configure_website(self, website_config: WebsiteConfigurationTypeDef):
		try:
			s3_client.put_bucket_website(
				Bucket=self.name, WebsiteConfiguration=website_config
			)
		except ClientError as e:
			raise S3Error(f"Error configurando el sitio web para '{self.name}': {e}")

	def copy_object_advanced(
		self,
		source_key: str,
		dest_key: str,
		source_bucket: str,
		metadata_directive: Literal["COPY", "REPLACE"] = "COPY",
		acl: Literal[
			"private",
			"public-read",
			"public-read-write",
			"aws-exec-read",
			"authenticated-read",
			"bucket-owner-read",
			"bucket-owner-full-control",
		] = "private",
		storage_class: Literal[
			"STANDARD", "STANDARD_IA", "REDUCED_REDUNDANCY", "GLACIER", "DEEP_ARCHIVE"
		] = "STANDARD",
	):
		try:
			s3_client.copy_object(
				Bucket=self.name,
				Key=dest_key,
				CopySource={"Bucket": source_bucket, "Key": source_key},
				MetadataDirective=metadata_directive,
				ACL=acl,
				StorageClass=storage_class,
			)
		except ClientError as e:
			raise S3Error(f"No se pudo copiar el objeto con opciones avanzadas: {e}")

	def set_bucket_policy(self, policy_document: dict[str, Any]):
		try:
			s3_client.put_bucket_policy(
				Bucket=self.name,
				Policy=json.dumps(policy_document),
			)
		except ClientError as e:
			raise S3Error(f"No se pudo establecer la política del bucket: {e}")

	def get_bucket_policy(self) -> dict[str, Any]:
		try:
			response = s3_client.get_bucket_policy(Bucket=self.name)
			return json.loads(response["Policy"])
		except ClientError as e:
			if e.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
				return {}
			raise S3Error(f"No se pudo obtener la política del bucket: {e}")

	def delete_bucket_policy(self):
		try:
			s3_client.delete_bucket_policy(Bucket=self.name)
		except ClientError as e:
			raise S3Error(f"No se pudo eliminar la política del bucket: {e}")


# =======================================================================
# 5. Definición del APIRouter con todos los Endpoints
# =======================================================================

app = APIRouter(prefix="/s3", tags=["S3 Management"])


# --- Endpoints de Buckets ---
@app.get("/buckets", response_model=List[BucketInfo])
def list_buckets():
	return S3Bucket.list_all()


@app.post("/buckets", response_model=S3Bucket, status_code=status.HTTP_201_CREATED)
def create_bucket(req: BucketCreateRequest):
	return S3Bucket.create(bucket_name=req.bucket_name, region=req.region)


@app.delete("/buckets/{bucket_name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_bucket(bucket_name: str):
	bucket = S3Bucket(name=bucket_name)
	bucket.empty_and_delete()


# --- Endpoints de Objetos ---
@app.get("/buckets/{bucket_name}/objects", response_model=List[ObjectInfo])
def list_objects(bucket_name: str):
	bucket = S3Bucket(name=bucket_name)
	return bucket.list_objects()


@app.put(
	"/buckets/{bucket_name}/objects/{object_key}",
	response_model=MessageResponse,
)
async def upload_object(
	bucket_name: str, object_key: str, file: UploadFile = File(...)
):
	s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=file.file, ContentType=file.content_type or "application/octet-stream", ContentDisposition="inline")
	return {"message": s3_client.generate_presigned_url(
		ClientMethod="get_object",
		Params={"Bucket": bucket_name, "Key": object_key},
		ExpiresIn=3600,
	)}

@app.delete(
	"/buckets/{bucket_name}/objects/{object_key}",
	status_code=status.HTTP_204_NO_CONTENT,
)
def delete_object(bucket_name: str, object_key: str):
	bucket = S3Bucket(name=bucket_name)
	bucket.delete_object(object_key=object_key)


@app.post(
	"/buckets/{dest_bucket}/objects/{dest_key}/copy", response_model=MessageResponse
)
def copy_object(dest_bucket: str, dest_key: str, req: CopyObjectRequest):
	bucket = S3Bucket(name=dest_bucket)
	bucket.copy_object(
		source_key=req.source_key, dest_key=dest_key, source_bucket=req.source_bucket
	)
	return {"message": "Copia exitosa"}


# --- Endpoints de Utilidades y Configuración ---
@app.post(
	"/buckets/{bucket_name}/objects/{object_key}/presigned-url",
	response_model=PresignedUrlResponse,
)
def get_presigned_url(bucket_name: str, object_key: str):
	bucket = S3Bucket(name=bucket_name)
	url = bucket.generate_presigned_url(object_key=object_key)
	return PresignedUrlResponse(method="GET", url=url)


@app.put("/buckets/{bucket_name}/cors", status_code=status.HTTP_204_NO_CONTENT)
def set_bucket_cors(bucket_name: str, cors_config: CORSConfigurationTypeDef):
	bucket = S3Bucket(name=bucket_name)
	bucket.configure_cors(cors_config)


@app.put("/buckets/{bucket_name}/website", status_code=status.HTTP_204_NO_CONTENT)
def set_bucket_website(bucket_name: str, website_config: WebsiteConfigurationTypeDef):
	bucket = S3Bucket(name=bucket_name)
	bucket.configure_website(website_config)


@app.post(
	"/buckets/{dest_bucket}/objects/{dest_key}/copy/advanced",
	response_model=MessageResponse,
)
def copy_object_advanced(
	dest_bucket: str, dest_key: str, req: CopyObjectAdvancedRequest
):
	bucket = S3Bucket(name=dest_bucket)
	bucket.copy_object_advanced(
		source_key=req.source_key,
		dest_key=dest_key,
		source_bucket=req.source_bucket,
		metadata_directive=req.metadata_directive,
		acl=req.acl,
		storage_class=req.storage_class,
	)
	return {"message": "Copia avanzada exitosa"}


@app.put("/buckets/{bucket_name}/policy", response_model=MessageResponse)
def set_bucket_policy(bucket_name: str, req: BucketPolicyRequest):
	bucket = S3Bucket(name=bucket_name)
	bucket.set_bucket_policy(req.policy)
	return {"message": "Política aplicada correctamente"}


@app.get("/buckets/{bucket_name}/policy", response_model=dict)
def get_bucket_policy(bucket_name: str):
	bucket = S3Bucket(name=bucket_name)
	return bucket.get_bucket_policy()


@app.delete("/buckets/{bucket_name}/policy", response_model=MessageResponse)
def delete_bucket_policy(bucket_name: str):
	bucket = S3Bucket(name=bucket_name)
	bucket.delete_bucket_policy()
	return {"message": "Política eliminada correctamente"}
