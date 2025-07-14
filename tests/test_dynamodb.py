"""
DynamoDB ORM Tests
"""

import pytest
import uuid
from unittest.mock import Mock, patch, MagicMock
from . import DynamoORM, Model, KeySchema, AttributeDefinition


class User(Model):
    name: str
    email: str
    password: str


class Post(Model):
    title: str
    content: str
    author: User


class Comment(Model):
    content: str
    author: User


DynamoORM = DynamoORM[User][Post][Comment]  # type: ignore


class TestDynamoORM:

    def setup_method(self):
        """Setup for each test method"""
        self.orm = DynamoORM()

    def test_table_name_generation(self):
        """Test table name is generated correctly from registered types"""
        expected = "user-post-comment"
        assert self.orm.table_name() == expected

    def test_decorator_registration(self):
        """Test that decorator properly registers classes"""
        assert "User" in DynamoORM.types
        assert "Post" in DynamoORM.types
        assert "Comment" in DynamoORM.types
        assert DynamoORM.types["User"] == User

    def test_model_instantiation(self):
        """Test model instances are created with auto-generated IDs"""
        user = User(name="John", email="john@example.com", password="secret")
        assert user.id is not None
        assert len(user.id) == 36  # UUID4 length
        assert user.name == "John"
        assert user.email == "john@example.com"

    def test_create_table(self):
        """Test table creation with proper schema"""
        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.create_table.return_value = {}
            mock_client.return_value.get_waiter.return_value.wait.return_value = None

            key_schema = [{"AttributeName": "id", "KeyType": "HASH"}]
            attribute_definitions = [{"AttributeName": "id", "AttributeType": "S"}]

            self.orm.create_table(
                key_schema=key_schema, attribute_definitions=attribute_definitions
            )

            mock_client.return_value.create_table.assert_called_once()
            mock_client.return_value.get_waiter.assert_called_once_with("table_exists")

    def test_delete_table(self):
        """Test table deletion"""
        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.delete_table.return_value = {}
            mock_client.return_value.get_waiter.return_value.wait.return_value = None

            self.orm.delete_table()

            mock_client.return_value.delete_table.assert_called_once()
            mock_client.return_value.get_waiter.assert_called_once_with(
                "table_not_exists"
            )

    def test_serialize_deserialize(self):
        """Test serialization and deserialization of models"""
        user = User(name="Jane", email="jane@example.com", password="secret123")

        # Test serialization
        serialized = self.orm.serialize(user)
        assert serialized is not None
        assert isinstance(serialized, dict)

        # Test deserialization
        deserialized = self.orm.deserialize(serialized)
        assert deserialized["name"] == "Jane"
        assert deserialized["email"] == "jane@example.com"

    def test_create_item(self):
        """Test creating an item in DynamoDB"""
        user = User(name="Bob", email="bob@example.com", password="password")

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.put_item.return_value = {}

            result = self.orm.create(item=user)

            assert result == user
            mock_client.return_value.put_item.assert_called_once()

    def test_retrieve_item(self):
        """Test retrieving an item from DynamoDB"""
        user_id = str(uuid.uuid4())
        mock_response = {
            "Item": {
                "id": {"S": user_id},
                "name": {"S": "Alice"},
                "email": {"S": "alice@example.com"},
                "password": {"S": "secret"},
            }
        }

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.get_item.return_value = mock_response

            result = self.orm.retrieve(id=user_id)

            assert result["id"] == user_id
            assert result["name"] == "Alice"
            mock_client.return_value.get_item.assert_called_once_with(
                TableName=self.orm.table_name(), Key={"id": {"S": user_id}}
            )

    def test_update_item(self):
        """Test updating an item in DynamoDB"""
        user = User(name="Charlie", email="charlie@example.com", password="oldpass")

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.update_item.return_value = {}

            result = self.orm.update(item=user, password="newpass", name="Charles")

            assert result == user
            mock_client.return_value.update_item.assert_called_once()
            call_args = mock_client.return_value.update_item.call_args
            assert (
                "set #password = :password, #name = :name"
                in call_args[1]["UpdateExpression"]
            )

    def test_delete_item_by_id(self):
        """Test deleting an item by ID"""
        user_id = str(uuid.uuid4())

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.delete_item.return_value = {}

            self.orm.delete_(id=user_id)

            mock_client.return_value.delete_item.assert_called_once_with(
                TableName=self.orm.table_name(), Key={"id": {"S": user_id}}
            )

    def test_delete_item_by_object(self):
        """Test deleting an item by object"""
        user = User(name="David", email="david@example.com", password="pass")

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.update_item.return_value = {}

            self.orm.delete(item=user)

            mock_client.return_value.update_item.assert_called_once()

    def test_query_with_default_operator(self):
        """Test querying with default equals operator"""
        mock_response = {
            "Items": [
                {
                    "id": {"S": "123"},
                    "name": {"S": "Eve"},
                    "email": {"S": "eve@example.com"},
                    "password": {"S": "secret"},
                }
            ]
        }

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.query.return_value = mock_response

            results = list(self.orm.query(key="name", value="Eve"))

            assert len(results) == 1
            assert results[0]["name"] == "Eve"
            mock_client.return_value.query.assert_called_once_with(
                TableName=self.orm.table_name(),
                KeyConditionExpression="name = :value",
                ExpressionAttributeValues={":value": "Eve"},
            )

    def test_query_with_custom_operator(self):
        """Test querying with custom operator"""
        mock_response = {"Items": []}

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.query.return_value = mock_response

            list(self.orm.query(key="age", value=25, op=">"))

            mock_client.return_value.query.assert_called_once_with(
                TableName=self.orm.table_name(),
                KeyConditionExpression="age > :value",
                ExpressionAttributeValues={":value": 25},
            )

    def test_scan_all_items(self):
        """Test scanning all items"""
        mock_response = {
            "Items": [
                {
                    "id": {"S": "123"},
                    "name": {"S": "Frank"},
                    "email": {"S": "frank@example.com"},
                    "password": {"S": "secret"},
                },
                {
                    "id": {"S": "456"},
                    "name": {"S": "Grace"},
                    "email": {"S": "grace@example.com"},
                    "password": {"S": "password"},
                },
            ]
        }

        with patch.object(self.orm, "_client") as mock_client:
            mock_client.return_value.scan.return_value = mock_response

            results = list(self.orm.scan())

            assert len(results) == 2
            assert results[0]["name"] == "Frank"
            assert results[1]["name"] == "Grace"
            mock_client.return_value.scan.assert_called_once_with(
                TableName=self.orm.table_name()
            )

    def test_serialize_none_handling(self):
        """Test handling of None serialization"""
        with patch.object(self.orm._serializer(), "serialize") as mock_serialize:
            mock_serialize.return_value = {}  # No 'M' key

            user = User(name="Test", email="test@example.com", password="pass")

            with pytest.raises(ValueError, match="Item is not serializable"):
                self.orm.create(item=user)

    def test_complex_model_relationships(self):
        """Test complex model with relationships"""
        user = User(name="Author", email="author@example.com", password="pass")
        post = Post(title="Test Post", content="Content", author=user)
        comment = Comment(content="Great post!", author=user)

        # Test that all models have proper IDs
        assert user.id is not None
        assert post.id is not None
        assert comment.id is not None

        # Test that relationships work
        assert post.author == user
        assert comment.author == user

    def test_cached_properties(self):
        """Test that cached properties work correctly"""
        # Test table_name caching
        table_name1 = self.orm.table_name()
        table_name2 = self.orm.table_name()
        assert table_name1 == table_name2

        # Test serializer caching
        serializer1 = self.orm._serializer()
        serializer2 = self.orm._serializer()
        assert serializer1 is serializer2

        # Test deserializer caching
        deserializer1 = self.orm._deserializer()
        deserializer2 = self.orm._deserializer()
        assert deserializer1 is deserializer2

        # Test client caching
        client1 = self.orm._client()
        client2 = self.orm._client()
        assert client1 is client2

    def test_table_name(self):
        """Test table name is generated correctly from registered types"""
        expected = "user-post-comment"
        assert self.orm.table_name() == expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
