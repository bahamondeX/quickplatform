"""
DynamoDB Client
"""

from __future__ import annotations

import typing as tp
import uuid
from functools import lru_cache

import typing_extensions as tpe
from boto3 import client
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from mypy_boto3_dynamodb.client import DynamoDBClient
from pydantic import BaseModel, Field, InstanceOf

P = tpe.ParamSpec("P")


class Model(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class KeySchema(tpe.TypedDict):
    AttributeName: str
    KeyType: tpe.Literal["HASH", "RANGE"]


class AttributeDefinition(tpe.TypedDict):
    AttributeName: str
    AttributeType: tpe.Literal["S", "N", "B"]


class ProvisionedThroughput(tpe.TypedDict):
    ReadCapacityUnits: int
    WriteCapacityUnits: int


class CreateTable(tpe.TypedDict):
    TableName: str
    KeySchema: tp.List[KeySchema]
    AttributeDefinitions: tp.List[AttributeDefinition]
    ProvisionedThroughput: ProvisionedThroughput | tp.Literal["PAY_PER_REQUEST"]


T = tp.TypeVar("T", bound=Model)


class DynamoORM(tpe.Generic[T]):
    types: tp.Dict[str, tpe.Type[T]] = {}

    @classmethod
    def __call__(cls, klass: tp.Type[T]) -> tp.Type[T]:
        cls.types[klass.__name__] = klass
        return klass

    @classmethod
    def __class_getitem__(cls, item: tp.Type[T]) -> tp.Type[DynamoORM[T]]:
        cls.types[item.__name__] = item
        return cls

    @lru_cache(maxsize=1)
    def table_name(self) -> str:
        return "-".join(self.types.keys()).lower()

    @lru_cache(maxsize=1)
    def _serializer(self) -> TypeSerializer:
        return TypeSerializer()

    @lru_cache(maxsize=1)
    def _deserializer(self) -> TypeDeserializer:
        return TypeDeserializer()

    @lru_cache(maxsize=1)
    def _client(self) -> DynamoDBClient:
        return client("dynamodb", endpoint_url="https://aws.oscarbahamonde.com")

    def create_table(
        self,
        *,
        key_schema: tp.List[KeySchema],
        attribute_definitions: tp.List[AttributeDefinition],
    ) -> None:
        self._client().create_table(
            TableName=self.table_name(),
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
        )
        self._client().get_waiter("table_exists").wait(TableName=self.table_name())

    def delete_table(self) -> None:
        self._client().delete_table(TableName=self.table_name())
        self._client().get_waiter("table_not_exists").wait(TableName=self.table_name())

    def serialize(self, item: T):
        return self._serializer().serialize(item.model_dump()).get("M")

    def deserialize(self, item: tp.Dict[str, tp.Any]) -> T:
        return self._deserializer().deserialize({"M": item})

    def create(self, *, item: T) -> T:
        serialized = self.serialize(item)
        if serialized is None:
            raise ValueError("Item is not serializable")
        self._client().put_item(TableName=self.table_name(), Item=serialized)
        return item

    def retrieve(self, *, id: str) -> T:
        response = self._client().get_item(
            TableName=self.table_name(), Key={"id": {"S": id}}
        )
        return self.deserialize(response.get("Item", {}))

    def update(self, *, item: T, **kwargs: tp.Any) -> T:
        query = "set " + ", ".join([f"#{key} = :{key}" for key in kwargs.keys()])
        expression_attribute_values = {
            f":{key}": value for key, value in kwargs.items()
        }
        expression_attribute_names = {f"#{key}": key for key in kwargs.keys()}
        serialized = self.serialize(item)
        if serialized is None:
            raise ValueError("Item is not serializable")
        self._client().update_item(
            TableName=self.table_name(),
            Key={"id": {"S": item.id}},
            UpdateExpression=query,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
        )
        return item

    def delete_(self, *, id: str) -> None:
        self._client().delete_item(TableName=self.table_name(), Key={"id": {"S": id}})

    def delete(self, *, item: T) -> None:
        serialized = self.serialize(item)
        if serialized is None:
            raise ValueError("Item is not serializable")
        self._client().update_item(
            TableName=self.table_name(),
            Key={"id": {"S": item.id}},
            UpdateExpression="set #id = :id",
            ExpressionAttributeNames={"#id": "id"},
            ExpressionAttributeValues={":id": {"S": item.id}},
        )

    def query(
        self,
        *,
        key: str,
        value: tp.Any,
        op: tpe.Literal[
            "=",
            "<",
            "<=",
            ">",
            ">=",
            "BETWEEN",
            "IN",
            "BEGINS_WITH",
            "CONTAINS",
            "NOT_CONTAINS",
            "NOT_NULL",
            "NULL",
            "EXISTS",
            "NOT_EXISTS",
            "IN_SET",
            "NOT_IN_SET",
        ] = "=",
    ) -> tp.Iterator[T]:
        response = self._client().query(
            TableName=self.table_name(),
            KeyConditionExpression=f"{key} {op} :value",
            ExpressionAttributeValues={":value": value},
        )
        for item in response.get("Items", []):
            yield self.deserialize(item)

    def scan(self) -> tp.Iterator[InstanceOf[T]]:
        response = self._client().scan(TableName=self.table_name())
        for item in response.get("Items", []):
            yield self.deserialize(item)
