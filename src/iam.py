import json
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Union

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from pydantic import BaseModel, Field
from typing_extensions import TypedDict

# =======================================================================
# 1. Configuration and Logging
# =======================================================================

DEFAULT_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": "*"},
                "Condition": {},
            }
        ],
    }
)

# Clients with error handling
try:
    iam_client = boto3.client("iam", endpoint_url="https://aws.oscarbahamonde.com")
    sts_client = boto3.client("sts", endpoint_url="https://aws.oscarbahamonde.com")
except Exception as e:
    logger.error(f"Failed to initialize AWS clients: {e}")
    raise

# =======================================================================
# 2. Custom Exceptions and Types
# =======================================================================


class IAMError(Exception):
    def __init__(
        self, message: str, status_code: int = 400, error_code: str = "IAM_ERROR"
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(self.message)


class CredentialsResponse(TypedDict):
    AccessKeyId: str
    SecretAccessKey: str
    SessionToken: str
    Expiration: str


class AssumeRoleParams(TypedDict):
    RoleArn: str
    RoleSessionName: str
    DurationSeconds: int
    Policy: str


class TrustPolicyParams(TypedDict):
    RoleArn: str
    RoleSessionName: str
    DurationSeconds: int
    Policy: str
    ExternalId: str


class AccessKey(BaseModel):
    access_key_id: str = Field(alias="AccessKeyId")
    secret_access_key: str = Field(alias="SecretAccessKey")
    status: Literal["Active", "Inactive"] = Field(alias="Status")
    create_date: datetime = Field(alias="CreateDate")


class AccessKeyStatusRequest(BaseModel):
    access_key_id: str = Field(alias="AccessKeyId")
    status: Literal["Active", "Inactive"] = Field(alias="Status")


# =======================================================================
# 3. Enhanced Policy Models with Validation
# =======================================================================


class PolicyStatement(BaseModel):
    Sid: Optional[str] = Field(None, description="Statement identifier", max_length=128)
    Effect: Literal["Allow", "Deny"]
    Action: Union[str, List[str]]
    Resource: Union[str, List[str]]
    Condition: Optional[Dict[str, Any]] = None


class TrustPolicyStatement(BaseModel):
    Sid: Optional[str] = Field(None, max_length=128)
    Effect: Literal["Allow", "Deny"]
    Action: Union[str, List[str]]
    Principal: Dict[str, Union[str, List[str]]]
    Condition: Optional[Dict[str, Any]] = None


class IdentityPolicyDocument(BaseModel):
    Version: Literal["2012-10-17"] = "2012-10-17"
    Statement: List[PolicyStatement]


class TrustPolicyDocument(BaseModel):
    Version: Literal["2012-10-17"] = "2012-10-17"
    Statement: List[TrustPolicyStatement]


# =======================================================================
# 4. Enhanced Entity Models with Caching and Validation
# =======================================================================


class User(BaseModel):
    user_name: str = Field(alias="UserName")
    user_id: str = Field(alias="UserId")
    arn: str = Field(alias="Arn")
    create_date: Optional[datetime] = Field(None, alias="CreateDate")
    path: Optional[str] = Field(None, alias="Path")

    class Config:
        allow_population_by_field_name = True

    @classmethod
    def create(cls, user_name: str, path: str = "/") -> "User":
        try:
            response = iam_client.create_user(UserName=user_name, Path=path)
            logger.info(f"User created: {user_name}")
            return cls.model_validate(response["User"])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "EntityAlreadyExists":
                raise IAMError(f"User {user_name} already exists", 409, error_code)
            raise IAMError(f"Error creating user: {e}", 500, error_code or "IAM_ERROR")

    @classmethod
    def get(cls, user_name: str) -> Optional["User"]:
        try:
            response = iam_client.get_user(UserName=user_name)
            return cls.model_validate(response["User"])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return None
            raise IAMError(f"Error getting user: {e}")

    @classmethod
    def list_all(cls, path_prefix: str = "/") -> List["User"]:
        try:
            paginator = iam_client.get_paginator("list_users")
            users: List[User] = []
            for page in paginator.paginate(PathPrefix=path_prefix):
                users.extend([cls.model_validate(user) for user in page["Users"]])
            return users
        except ClientError as e:
            raise IAMError(f"Error listing users: {e}")

    def delete(self) -> bool:
        try:
            # First detach all policies
            try:
                attached_policies = iam_client.list_attached_user_policies(
                    UserName=self.user_name
                )
                for policy in attached_policies["AttachedPolicies"]:
                    policy_arn = policy.get("PolicyArn")
                    assert policy_arn is not None
                    iam_client.detach_user_policy(
                        UserName=self.user_name, PolicyArn=policy_arn
                    )
            except ClientError:
                pass

            # Delete access keys
            try:
                keys = iam_client.list_access_keys(UserName=self.user_name)
                for key in keys["AccessKeyMetadata"]:
                    access_key_id = key.get("AccessKeyId")
                    assert access_key_id is not None
                    iam_client.delete_access_key(
                        UserName=self.user_name, AccessKeyId=access_key_id
                    )
            except ClientError:
                pass

            # Delete user
            iam_client.delete_user(UserName=self.user_name)
            logger.info(f"User deleted: {self.user_name}")
            return True
        except ClientError as e:
            raise IAMError(f"Error deleting user: {e}")

    def list_access_keys(self) -> List[AccessKey]:
        try:
            response = iam_client.list_access_keys(UserName=self.user_name)
            return [
                AccessKey.model_validate(key) for key in response["AccessKeyMetadata"]
            ]
        except ClientError as e:
            raise IAMError(f"Error listing access keys: {e}")

    def create_access_key(self) -> AccessKey:
        try:
            response = iam_client.create_access_key(UserName=self.user_name)
            return AccessKey.model_validate(response["AccessKey"])
        except ClientError as e:
            raise IAMError(f"Error creating access key: {e}")

    def update_access_key_status(
        self, access_key_id: str, status: Literal["Active", "Inactive"]
    ) -> bool:
        try:
            iam_client.update_access_key(
                UserName=self.user_name, AccessKeyId=access_key_id, Status=status
            )
            return True
        except ClientError as e:
            raise IAMError(f"Error updating access key status: {e}")

    def delete_access_key(self, access_key_id: str) -> bool:
        try:
            iam_client.delete_access_key(
                UserName=self.user_name, AccessKeyId=access_key_id
            )
            return True
        except ClientError as e:
            raise IAMError(f"Error deleting access key: {e}")

    def list_attached_policies(self):
        try:
            response = iam_client.list_attached_user_policies(UserName=self.user_name)
            attached_policies = response.get("AttachedPolicies")
            assert attached_policies is not None
            return attached_policies
        except ClientError as e:
            raise IAMError(f"Error listing attached policies: {e}")

    def attach_policy(self, policy_arn: str):
        try:
            iam_client.attach_user_policy(UserName=self.user_name, PolicyArn=policy_arn)
            logger.info(f"Policy {policy_arn} attached to user {self.user_name}")
        except ClientError as e:
            raise IAMError(f"Error attaching policy: {e}")

    def detach_policy(self, policy_arn: str):
        try:
            iam_client.detach_user_policy(UserName=self.user_name, PolicyArn=policy_arn)
            logger.info(f"Policy {policy_arn} detached from user {self.user_name}")
        except ClientError as e:
            raise IAMError(f"Error detaching policy: {e}")

    def get_policy(self, policy_arn: str) -> Optional["IdentityPolicyDocument"]:
        try:
            response = iam_client.get_policy(PolicyArn=policy_arn)
            return IdentityPolicyDocument.model_validate(response["Policy"])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return None
            raise IAMError(f"Error getting policy: {e}")


class Policy(BaseModel):
    policy_name: str = Field(alias="PolicyName")
    arn: str = Field(alias="Arn")
    description: Optional[str] = Field(None, alias="Description")
    create_date: Optional[datetime] = Field(None, alias="CreateDate")
    path: Optional[str] = Field(None, alias="Path")

    class Config:
        allow_population_by_field_name = True

    @classmethod
    def create(
        cls,
        policy_name: str,
        document: IdentityPolicyDocument,
        description: str | None = "",
        path: str = "/",
    ) -> "Policy":
        try:
            response = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=document.model_dump_json(exclude_none=True),
                Description=description or "",
                Path=path,
            )
            logger.info(f"Policy created: {policy_name}")
            return cls.model_validate(response["Policy"])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "EntityAlreadyExists":
                raise IAMError(f"Policy {policy_name} already exists", 409, error_code)
            raise IAMError(
                f"Error creating policy: {e}", 500, error_code or "IAM_ERROR"
            )

    @classmethod
    def get(cls, policy_arn: str) -> Optional["Policy"]:
        try:
            response = iam_client.get_policy(PolicyArn=policy_arn)
            return cls.model_validate(response["Policy"])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return None
            raise IAMError(f"Error getting policy: {e}")

    @classmethod
    def list_all(
        cls, path_prefix: str = "/", only_attached: bool = False
    ) -> List["Policy"]:
        try:
            paginator = iam_client.get_paginator("list_policies")
            policies: List[Policy] = []
            for page in paginator.paginate(
                PathPrefix=path_prefix, OnlyAttached=only_attached
            ):
                policies.extend(
                    [cls.model_validate(policy) for policy in page["Policies"]]
                )
            return policies
        except ClientError as e:
            raise IAMError(f"Error listing policies: {e}")

    def get_document(self) -> IdentityPolicyDocument:
        try:
            response = iam_client.get_policy_version(PolicyArn=self.arn, VersionId="v1")
            policy_version = response["PolicyVersion"]
            policy_document = policy_version.get("Document")
            assert policy_document is not None
            return IdentityPolicyDocument.model_validate(policy_document)
        except ClientError as e:
            raise IAMError(f"Error getting policy document: {e}")

    def delete(self) -> bool:
        try:
            # First detach from all entities
            try:
                entities = iam_client.list_entities_for_policy(PolicyArn=self.arn)
                for user in entities["PolicyUsers"]:
                    user_name = user.get("UserName")
                    assert user_name is not None
                    iam_client.detach_user_policy(
                        UserName=user_name, PolicyArn=self.arn
                    )
                for role in entities["PolicyRoles"]:
                    role_name = role.get("RoleName")
                    assert role_name is not None
                    iam_client.detach_role_policy(
                        RoleName=role_name, PolicyArn=self.arn
                    )
                for group in entities["PolicyGroups"]:
                    group_name = group.get("GroupName")
                    assert group_name is not None
                    iam_client.detach_group_policy(
                        GroupName=group_name, PolicyArn=self.arn
                    )
            except ClientError:
                pass

            iam_client.delete_policy(PolicyArn=self.arn)
            logger.info(f"Policy deleted: {self.policy_name}")
            return True
        except ClientError as e:
            raise IAMError(f"Error deleting policy: {e}")


class Role(BaseModel):
    role_name: str = Field(alias="RoleName")
    arn: str = Field(alias="Arn")
    create_date: Optional[datetime] = Field(None, alias="CreateDate")
    path: Optional[str] = Field(None, alias="Path")
    description: Optional[str] = Field(None, alias="Description")

    class Config:
        allow_population_by_field_name = True

    @classmethod
    def create(
        cls,
        role_name: str,
        trust_policy_document: TrustPolicyDocument,
        description: str | None = "",
        path: str = "/",
    ) -> "Role":
        try:
            response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_policy_document.model_dump_json(
                    exclude_none=True
                ),
                Description=description or "",
                Path=path,
            )
            logger.info(f"Role created: {role_name}")
            return cls.model_validate(response["Role"])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "EntityAlreadyExists":
                raise IAMError(f"Role {role_name} already exists", 409, error_code)
            raise IAMError(f"Error creating role: {e}", 500, error_code or "IAM_ERROR")

    @classmethod
    def get(cls, role_name: str) -> Optional["Role"]:
        try:
            response = iam_client.get_role(RoleName=role_name)
            return cls.model_validate(response["Role"])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return None
            raise IAMError(f"Error getting role: {e}")

    @classmethod
    def list_all(cls, path_prefix: str = "/") -> List["Role"]:
        try:
            paginator = iam_client.get_paginator("list_roles")
            roles: List[Role] = []
            for page in paginator.paginate(PathPrefix=path_prefix):
                roles.extend([cls.model_validate(role) for role in page["Roles"]])
            return roles
        except ClientError as e:
            raise IAMError(f"Error listing roles: {e}")

    def attach_policy(self, policy_arn: str):
        try:
            iam_client.attach_role_policy(RoleName=self.role_name, PolicyArn=policy_arn)
            logger.info(f"Policy {policy_arn} attached to role {self.role_name}")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "NoSuchEntity":
                raise IAMError(f"Policy or role not found", 404, error_code)
            raise IAMError(f"Error attaching policy: {e}")

    def detach_policy(self, policy_arn: str):
        try:
            iam_client.detach_role_policy(RoleName=self.role_name, PolicyArn=policy_arn)
            logger.info(f"Policy {policy_arn} detached from role {self.role_name}")
        except ClientError as e:
            raise IAMError(f"Error detaching policy: {e}")

    def list_attached_policies(self):
        try:
            response = iam_client.list_attached_role_policies(RoleName=self.role_name)
            attached_policies = response.get("AttachedPolicies")
            assert attached_policies is not None
            return attached_policies
        except ClientError as e:
            raise IAMError(f"Error listing attached policies: {e}")

    def get_trust_policy(self) -> TrustPolicyDocument:
        try:
            response = iam_client.get_role(RoleName=self.role_name)
            role = response["Role"]
            doc = role.get("AssumeRolePolicyDocument")
            assert doc is not None
            return TrustPolicyDocument.model_validate(doc)
        except ClientError as e:
            raise IAMError(f"Error getting trust policy: {e}")

    def assume(
        self,
        session_name: str,
        duration: int = 3600,
        session_policy: Optional[IdentityPolicyDocument] = None,
        external_id: Optional[str] = None,
    ) -> CredentialsResponse:
        try:
            params: TrustPolicyParams = TrustPolicyParams(
                RoleArn=self.arn,
                RoleSessionName=session_name,
                DurationSeconds=max(900, min(duration, 43200)),
                Policy=(
                    session_policy.model_dump_json(exclude_none=True)
                    if session_policy
                    else ""
                ),
                ExternalId=external_id or "",
            )

            if session_policy:
                params["Policy"] = session_policy.model_dump_json(exclude_none=True)

            if external_id:
                params["ExternalId"] = external_id

            response = sts_client.assume_role(**params)
            creds = response["Credentials"]

            logger.info(f"Role assumed: {self.role_name} by session {session_name}")

            return {
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "SessionToken": creds["SessionToken"],
                "Expiration": creds["Expiration"].isoformat(),
            }
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "AccessDenied":
                raise IAMError(f"Access denied when assuming role", 403, error_code)
            raise IAMError(f"Error assuming role: {e}")

    def delete(self) -> bool:
        try:
            # First detach all policies
            try:
                attached_policies = iam_client.list_attached_role_policies(
                    RoleName=self.role_name
                )
                for policy in attached_policies["AttachedPolicies"]:
                    policy_arn = policy.get("PolicyArn")
                    assert policy_arn is not None
                    iam_client.detach_role_policy(
                        RoleName=self.role_name, PolicyArn=policy_arn
                    )
            except ClientError:
                pass

            # Delete inline policies
            try:
                inline_policies = iam_client.list_role_policies(RoleName=self.role_name)
                for policy_name in inline_policies["PolicyNames"]:
                    iam_client.delete_role_policy(
                        RoleName=self.role_name, PolicyName=policy_name
                    )
            except ClientError:
                pass

            # Delete role
            iam_client.delete_role(RoleName=self.role_name)
            logger.info(f"Role deleted: {self.role_name}")
            return True
        except ClientError as e:
            raise IAMError(f"Error deleting role: {e}")


# =======================================================================
# 5. Enhanced Request Models with Validation
# =======================================================================


class UserCreateRequest(BaseModel):
    user_name: str = Field(...)
    path: str = Field("/", max_length=512)


class PolicyCreateRequest(BaseModel):
    policy_name: str = Field(...)
    document: IdentityPolicyDocument
    description: Optional[str] = Field("", max_length=1000)
    path: str = Field("/", max_length=512)


class RoleCreateRequest(BaseModel):
    role_name: str = Field(...)
    trust_policy_document: TrustPolicyDocument
    description: Optional[str]
    path: str = Field("/", max_length=512)


class PolicyAttachmentRequest(BaseModel):
    policy_arn: str = Field(...)


class AssumeRoleRequest(BaseModel):
    session_name: str = Field(...)
    duration_seconds: int = Field(3600, ge=900, le=43200)  # 15 min to 12 hours
    session_policy: Optional[IdentityPolicyDocument] = None
    external_id: Optional[str] = Field(None, min_length=2, max_length=1224)


class ListRequest(BaseModel):
    path_prefix: str = Field("/", max_length=512)
    max_items: int = Field(100, ge=1, le=1000)


# =======================================================================
# 6. Error Handler
# =======================================================================


def handle_iam_error(error: IAMError):
    logger.error(f"IAM Error: {error.message}")
    raise HTTPException(
        status_code=error.status_code,
        detail={"error": error.error_code, "message": error.message},
    )


# =======================================================================
# 7. Enhanced API Router with Comprehensive Endpoints
# =======================================================================

app = APIRouter(prefix="/iam", tags=["IAM Management"])


# --- Policy Endpoints ---
@app.post("/policies", response_model=Policy, status_code=status.HTTP_201_CREATED)
def create_policy(req: PolicyCreateRequest):
    try:
        return Policy.create(req.policy_name, req.document, req.description, req.path)
    except IAMError as e:
        handle_iam_error(e)


@app.get("/policies", response_model=List[Policy])
def list_policies(req: ListRequest = Depends()):
    try:
        return Policy.list_all(req.path_prefix)[: req.max_items]
    except IAMError as e:
        handle_iam_error(e)


@app.get("/policies/{policy_arn:path}", response_model=Policy)
def get_policy(policy_arn: str):
    try:
        policy = Policy.get(policy_arn)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        return policy
    except IAMError as e:
        handle_iam_error(e)


@app.get("/policies/{policy_arn:path}/document", response_model=IdentityPolicyDocument)
def get_policy_document(policy_arn: str):
    try:
        policy = Policy.get(policy_arn)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        return policy.get_document()
    except IAMError as e:
        handle_iam_error(e)


@app.delete("/policies/{policy_arn:path}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(policy_arn: str):
    try:
        policy = Policy.get(policy_arn)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        policy.delete()
    except IAMError as e:
        handle_iam_error(e)


# --- Role Endpoints ---
@app.post("/roles", response_model=Role, status_code=status.HTTP_201_CREATED)
def create_role(req: RoleCreateRequest):
    try:
        return Role.create(
            req.role_name, req.trust_policy_document, req.description, req.path
        )
    except IAMError as e:
        handle_iam_error(e)


@app.get("/roles", response_model=List[Role])
def list_roles(req: ListRequest = Depends()):
    try:
        return Role.list_all(req.path_prefix)[: req.max_items]
    except IAMError as e:
        handle_iam_error(e)


@app.get("/roles/{role_name}", response_model=Role)
def get_role(role_name: str):
    try:
        role = Role.get(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return role
    except IAMError as e:
        handle_iam_error(e)


@app.get("/roles/{role_name}/policies", response_model=List[Dict[str, str]])
def list_role_policies(role_name: str):
    try:
        role = Role.get(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return role.list_attached_policies()
    except IAMError as e:
        handle_iam_error(e)


@app.get("/roles/{role_name}/trust-policy", response_model=TrustPolicyDocument)
def get_role_trust_policy(role_name: str):
    try:
        role = Role.get(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return role.get_trust_policy()
    except IAMError as e:
        handle_iam_error(e)


@app.post("/roles/{role_name}/policies", status_code=status.HTTP_204_NO_CONTENT)
def attach_policy_to_role(role_name: str, attachment: PolicyAttachmentRequest):
    try:
        role = Role.get(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        role.attach_policy(attachment.policy_arn)
    except IAMError as e:
        handle_iam_error(e)


@app.delete(
    "/roles/{role_name}/policies/{policy_arn:path}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def detach_policy_from_role(role_name: str, policy_arn: str):
    try:
        role = Role.get(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        role.detach_policy(policy_arn)
    except IAMError as e:
        handle_iam_error(e)


@app.post("/roles/{role_name}/assume", response_model=CredentialsResponse)
def assume_role(role_name: str, req: AssumeRoleRequest):
    try:
        role = Role.get(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return role.assume(
            req.session_name, req.duration_seconds, req.session_policy, req.external_id
        )
    except IAMError as e:
        handle_iam_error(e)


@app.delete("/roles/{role_name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(role_name: str):
    try:
        role = Role.get(role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        role.delete()
    except IAMError as e:
        handle_iam_error(e)


# --- User Endpoints ---


@app.get("/users/{user_name}/access-keys", response_model=List[AccessKey])
def list_user_access_keys(user_name: str):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user.list_access_keys()
    except IAMError as e:
        handle_iam_error(e)


@app.post(
    "/users/{user_name}/access-keys",
    response_model=AccessKey,
    status_code=status.HTTP_201_CREATED,
)
def create_user_access_key(user_name: str):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user.create_access_key()
    except IAMError as e:
        handle_iam_error(e)


@app.put(
    "/users/{user_name}/access-keys/status", status_code=status.HTTP_204_NO_CONTENT
)
def update_user_access_key_status(user_name: str, req: AccessKeyStatusRequest):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.update_access_key_status(req.access_key_id, req.status)
    except IAMError as e:
        handle_iam_error(e)


@app.delete(
    "/users/{user_name}/access-keys/{access_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_user_access_key(user_name: str, access_key_id: str):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.delete_access_key(access_key_id)
    except IAMError as e:
        handle_iam_error(e)


@app.get("/users/{user_name}/policies", response_model=List[Dict[str, str]])
def list_user_policies(user_name: str):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user.list_attached_policies()
    except IAMError as e:
        handle_iam_error(e)


@app.post("/users/{user_name}/policies", status_code=status.HTTP_204_NO_CONTENT)
def attach_policy_to_user(user_name: str, attachment: PolicyAttachmentRequest):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.attach_policy(attachment.policy_arn)
    except IAMError as e:
        handle_iam_error(e)


@app.delete(
    "/users/{user_name}/policies/{policy_arn:path}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def detach_policy_from_user(user_name: str, policy_arn: str):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.detach_policy(policy_arn)
    except IAMError as e:
        handle_iam_error(e)


@app.post("/users", response_model=User, status_code=status.HTTP_201_CREATED)
def create_user(req: UserCreateRequest):
    try:
        return User.create(req.user_name, req.path)
    except IAMError as e:
        handle_iam_error(e)


@app.get("/users", response_model=List[User])
def list_users(req: ListRequest = Depends()):
    try:
        return User.list_all(req.path_prefix)[: req.max_items]
    except IAMError as e:
        handle_iam_error(e)


@app.get("/users/{user_name}", response_model=User)
def get_user(user_name: str):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except IAMError as e:
        handle_iam_error(e)


@app.delete("/users/{user_name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_name: str):
    try:
        user = User.get(user_name)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.delete()
    except IAMError as e:
        handle_iam_error(e)
