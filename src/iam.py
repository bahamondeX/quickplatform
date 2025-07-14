import typing as tp
import boto3
from pydantic import BaseModel, Field
from botocore.exceptions import ClientError
import json
from fastapi import APIRouter, status, HTTPException, Query
\


# Extended Pydantic Models for IAM Operations

class CreateUser(BaseModel):
    user_name: str
    path: str = "/"
    permissions_boundary: str | None = None
    tags: tp.List[tp.Dict[str, str]] = Field(default_factory=list)


class UpdateUser(BaseModel):
    user_name: str
    new_user_name: str | None = None
    new_path: str | None = None
    permissions_boundary: str | None = None


class CreateAccessKey(BaseModel):
    user_name: str


class DeleteAccessKey(BaseModel):
    user_name: str
    access_key_id: str


class UpdateAccessKey(BaseModel):
    user_name: str
    access_key_id: str
    status: tp.Literal["Active", "Inactive"]


class CreateRole(BaseModel):
    role_name: str
    assume_role_policy_document: str
    path: str = "/"
    description: str | None = None
    max_session_duration: int = 3600
    permissions_boundary: str | None = None
    tags: tp.List[tp.Dict[str, str]] = Field(default_factory=list)


class UpdateRole(BaseModel):
    role_name: str
    new_role_name: str | None = None
    description: str | None = None
    max_session_duration: int | None = None


class CreatePolicy(BaseModel):
    policy_name: str
    policy_document: str
    description: str | None = None
    path: str = "/"
    tags: tp.List[tp.Dict[str, str]] = Field(default_factory=list)


class CreatePolicyVersion(BaseModel):
    policy_arn: str
    policy_document: str
    set_as_default: bool = False


class AttachUserPolicy(BaseModel):
    user_name: str
    policy_arn: str


class DetachUserPolicy(BaseModel):
    user_name: str
    policy_arn: str


class AttachRolePolicy(BaseModel):
    role_name: str
    policy_arn: str


class DetachRolePolicy(BaseModel):
    role_name: str
    policy_arn: str


class AttachGroupPolicy(BaseModel):
    group_name: str
    policy_arn: str


class DetachGroupPolicy(BaseModel):
    group_name: str
    policy_arn: str


class AddUserToGroup(BaseModel):
    group_name: str
    user_name: str


class RemoveUserFromGroup(BaseModel):
    group_name: str
    user_name: str


class CreateGroup(BaseModel):
    group_name: str
    path: str = "/"


class UpdateGroup(BaseModel):
    group_name: str
    new_group_name: str | None = None
    new_path: str | None = None


class CreateLoginProfile(BaseModel):
    user_name: str
    password: str
    password_reset_required: bool = False


class UpdateLoginProfile(BaseModel):
    user_name: str
    password: str | None = None
    password_reset_required: bool | None = None


class CreateInstanceProfile(BaseModel):
    instance_profile_name: str
    path: str = "/"
    tags: tp.List[tp.Dict[str, str]] = Field(default_factory=list)


class AddRoleToInstanceProfile(BaseModel):
    instance_profile_name: str
    role_name: str


class RemoveRoleFromInstanceProfile(BaseModel):
    instance_profile_name: str
    role_name: str


class PutUserPolicy(BaseModel):
    user_name: str
    policy_name: str
    policy_document: str


class PutRolePolicy(BaseModel):
    role_name: str
    policy_name: str
    policy_document: str


class PutGroupPolicy(BaseModel):
    group_name: str
    policy_name: str
    policy_document: str


class CreateSAMLProvider(BaseModel):
    name: str
    saml_metadata_document: str
    tags: tp.List[tp.Dict[str, str]] = Field(default_factory=list)


class CreateOIDCProvider(BaseModel):
    url: str
    client_id_list: tp.List[str]
    thumbprint_list: tp.List[str]
    tags: tp.List[tp.Dict[str, str]] = Field(default_factory=list)


class CreateServiceSpecificCredential(BaseModel):
    user_name: str
    service_name: str


class CreateVirtualMFADevice(BaseModel):
    virtual_mfa_device_name: str
    path: str = "/"
    tags: tp.List[tp.Dict[str, str]] = Field(default_factory=list)


class EnableMFADevice(BaseModel):
    user_name: str
    serial_number: str
    authentication_code_1: str
    authentication_code_2: str


class DeactivateMFADevice(BaseModel):
    user_name: str
    serial_number: str


class ResyncMFADevice(BaseModel):
    user_name: str
    serial_number: str
    authentication_code_1: str
    authentication_code_2: str


class CreateAccountAlias(BaseModel):
    account_alias: str


class CreateServiceLinkedRole(BaseModel):
    aws_service_name: str
    description: str | None = None
    custom_suffix: str | None = None


class TagResource(BaseModel):
    resource_arn: str
    tags: tp.List[tp.Dict[str, str]]


class UntagResource(BaseModel):
    resource_arn: str
    tag_keys: tp.List[str]


class GenerateCredentialReport(BaseModel):
    pass


class GenerateOrganizationsAccessReport(BaseModel):
    entity_path: str
    organizations_policy_id: str | None = None


class GenerateServiceLastAccessedDetails(BaseModel):
    arn: str
    granularity: tp.Literal["SERVICE_LEVEL", "ACTION_LEVEL"] = "SERVICE_LEVEL"


class SimulatePrincipalPolicy(BaseModel):
    policy_source_arn: str
    action_names: tp.List[str]
    resource_arns: tp.List[str] | None = None
    policy_input_list: tp.List[str] | None = None
    context_entries: tp.List[tp.Dict[str, tp.Any]] | None = None
    resource_policy: str | None = None
    max_items: int = 1000
    marker: str | None = None


class CreateAccountPasswordPolicy(BaseModel):
    minimum_password_length: int = 6
    require_symbols: bool = False
    require_numbers: bool = False
    require_uppercase_characters: bool = False
    require_lowercase_characters: bool = False
    allow_users_to_change_password: bool = True
    max_password_age: int | None = None
    password_reuse_prevention: int | None = None
    hard_expiry: bool = False


class IAMClient:
    """Complete IAM client implementation with full AWS IAM API coverage"""

    def __init__(self, aws_access_key_id: str | None = None, aws_secret_access_key: str | None = None, region_name: str = 'us-east-1'):
        self.iam_client = boto3.client(
            'iam',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name
        )

    # User Management
    def create_user(self, config: CreateUser):
        params = {
            'UserName': config.user_name,
            'Path': config.path,
            'Tags': config.tags
        }
        if config.permissions_boundary:
            params['PermissionsBoundary'] = config.permissions_boundary
        return self.iam_client.create_user(**params)

    def get_user(self, user_name: str | None = None):
        params = {}
        if user_name:
            params['UserName'] = user_name
        return self.iam_client.get_user(**params)

    def list_users(self, path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_users(**params)

    def delete_user(self, user_name: str):
        self.iam_client.delete_user(UserName=user_name)
        return True

    def update_user(self, config: UpdateUser):
        params = {'UserName': config.user_name}
        if config.new_user_name:
            params['NewUserName'] = config.new_user_name
        if config.new_path:
            params['NewPath'] = config.new_path
        return self.iam_client.update_user(**params)

    # Access Key Management
    def create_access_key(self, config: CreateAccessKey):
        return self.iam_client.create_access_key(UserName=config.user_name)

    def delete_access_key(self, config: DeleteAccessKey):
        self.iam_client.delete_access_key(UserName=config.user_name, AccessKeyId=config.access_key_id)
        return True

    def update_access_key(self, config: UpdateAccessKey):
        self.iam_client.update_access_key(
            UserName=config.user_name,
            AccessKeyId=config.access_key_id,
            Status=config.status
        )
        return True

    def list_access_keys(self, user_name: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'MaxItems': max_items}
        if user_name:
            params['UserName'] = user_name
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_access_keys(**params)

    # Role Management
    def create_role(self, config: CreateRole):
        params = {
            'RoleName': config.role_name,
            'AssumeRolePolicyDocument': config.assume_role_policy_document,
            'Path': config.path,
            'MaxSessionDuration': config.max_session_duration,
            'Tags': config.tags
        }
        if config.description:
            params['Description'] = config.description
        if config.permissions_boundary:
            params['PermissionsBoundary'] = config.permissions_boundary
        return self.iam_client.create_role(**params)

    def get_role(self, role_name: str):
        return self.iam_client.get_role(RoleName=role_name)

    def list_roles(self, path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_roles(**params)

    def delete_role(self, role_name: str):
        self.iam_client.delete_role(RoleName=role_name)
        return True

    def update_role(self, config: UpdateRole):
        params = {'RoleName': config.role_name}
        if config.description:
            params['Description'] = config.description
        if config.max_session_duration:
            params['MaxSessionDuration'] = config.max_session_duration
        if config.new_role_name:
            params['NewRoleName'] = config.new_role_name
        return self.iam_client.update_role(**params)

    def update_assume_role_policy(self, role_name: str, policy_document: str):
        return self.iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=policy_document
        )

    # Policy Management
    def create_policy(self, config: CreatePolicy):
        params = {
            'PolicyName': config.policy_name,
            'PolicyDocument': config.policy_document,
            'Path': config.path,
            'Tags': config.tags
        }
        if config.description:
            params['Description'] = config.description
        return self.iam_client.create_policy(**params)

    def get_policy(self, policy_arn: str):
        return self.iam_client.get_policy(PolicyArn=policy_arn)

    def list_policies(self, scope: tp.Literal["All", "AWS", "Local"] = "All", only_attached: bool = False,
                      path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'Scope': scope, 'OnlyAttached': only_attached, 'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_policies(**params)

    def delete_policy(self, policy_arn: str):
        self.iam_client.delete_policy(PolicyArn=policy_arn)
        return True

    def create_policy_version(self, config: CreatePolicyVersion):
        return self.iam_client.create_policy_version(
            PolicyArn=config.policy_arn,
            PolicyDocument=config.policy_document,
            SetAsDefault=config.set_as_default
        )

    def get_policy_version(self, policy_arn: str, version_id: str):
        return self.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)

    def list_policy_versions(self, policy_arn: str, marker: str | None = None, max_items: int = 1000):
        params = {'PolicyArn': policy_arn, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_policy_versions(**params)

    def delete_policy_version(self, policy_arn: str, version_id: str):
        self.iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return True

    def set_default_policy_version(self, policy_arn: str, version_id: str):
        self.iam_client.set_default_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return True

    # Policy Attachments
    def attach_user_policy(self, config: AttachUserPolicy):
        self.iam_client.attach_user_policy(UserName=config.user_name, PolicyArn=config.policy_arn)
        return True

    def detach_user_policy(self, config: DetachUserPolicy):
        self.iam_client.detach_user_policy(UserName=config.user_name, PolicyArn=config.policy_arn)
        return True

    def attach_role_policy(self, config: AttachRolePolicy):
        self.iam_client.attach_role_policy(RoleName=config.role_name, PolicyArn=config.policy_arn)
        return True

    def detach_role_policy(self, config: DetachRolePolicy):
        self.iam_client.detach_role_policy(RoleName=config.role_name, PolicyArn=config.policy_arn)
        return True

    def attach_group_policy(self, config: AttachGroupPolicy):
        self.iam_client.attach_group_policy(GroupName=config.group_name, PolicyArn=config.policy_arn)
        return True

    def detach_group_policy(self, config: DetachGroupPolicy):
        self.iam_client.detach_group_policy(GroupName=config.group_name, PolicyArn=config.policy_arn)
        return True

    def list_attached_user_policies(self, user_name: str, path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'UserName': user_name, 'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_attached_user_policies(**params)

    def list_attached_role_policies(self, role_name: str, path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'RoleName': role_name, 'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_attached_role_policies(**params)

    def list_attached_group_policies(self, group_name: str, path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'GroupName': group_name, 'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_attached_group_policies(**params)

    # Inline Policies
    def put_user_policy(self, config: PutUserPolicy):
        self.iam_client.put_user_policy(
            UserName=config.user_name,
            PolicyName=config.policy_name,
            PolicyDocument=config.policy_document
        )
        return True

    def put_role_policy(self, config: PutRolePolicy):
        self.iam_client.put_role_policy(
            RoleName=config.role_name,
            PolicyName=config.policy_name,
            PolicyDocument=config.policy_document
        )
        return True

    def put_group_policy(self, config: PutGroupPolicy):
        self.iam_client.put_group_policy(
            GroupName=config.group_name,
            PolicyName=config.policy_name,
            PolicyDocument=config.policy_document
        )
        return True

    def get_user_policy(self, user_name: str, policy_name: str):
        return self.iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)

    def get_role_policy(self, role_name: str, policy_name: str):
        return self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)

    def get_group_policy(self, group_name: str, policy_name: str):
        return self.iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)

    def list_user_policies(self, user_name: str, marker: str | None = None, max_items: int = 1000):
        params = {'UserName': user_name, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_user_policies(**params)

    def list_role_policies(self, role_name: str, marker: str | None = None, max_items: int = 1000):
        params = {'RoleName': role_name, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_role_policies(**params)

    def list_group_policies(self, group_name: str, marker: str | None = None, max_items: int = 1000):
        params = {'GroupName': group_name, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_group_policies(**params)

    def delete_user_policy(self, user_name: str, policy_name: str):
        self.iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        return True

    def delete_role_policy(self, role_name: str, policy_name: str):
        self.iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        return True

    def delete_group_policy(self, group_name: str, policy_name: str):
        self.iam_client.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
        return True

    # Group Management
    def create_group(self, config: CreateGroup):
        return self.iam_client.create_group(GroupName=config.group_name, Path=config.path)

    def get_group(self, group_name: str, marker: str | None = None, max_items: int = 1000):
        params = {'GroupName': group_name, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.get_group(**params)

    def list_groups(self, path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_groups(**params)

    def delete_group(self, group_name: str):
        self.iam_client.delete_group(GroupName=group_name)
        return True

    def update_group(self, config: UpdateGroup):
        params = {'GroupName': config.group_name}
        if config.new_group_name:
            params['NewGroupName'] = config.new_group_name
        if config.new_path:
            params['NewPath'] = config.new_path
        return self.iam_client.update_group(**params)

    def add_user_to_group(self, config: AddUserToGroup):
        self.iam_client.add_user_to_group(GroupName=config.group_name, UserName=config.user_name)
        return True

    def remove_user_from_group(self, config: RemoveUserFromGroup):
        self.iam_client.remove_user_from_group(GroupName=config.group_name, UserName=config.user_name)
        return True

    def list_groups_for_user(self, user_name: str, marker: str | None = None, max_items: int = 1000):
        params = {'UserName': user_name, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.get_groups_for_user(**params)

    # Login Profile Management
    def create_login_profile(self, config: CreateLoginProfile):
        return self.iam_client.create_login_profile(
            UserName=config.user_name,
            Password=config.password,
            PasswordResetRequired=config.password_reset_required
        )

    def get_login_profile(self, user_name: str):
        return self.iam_client.get_login_profile(UserName=user_name)

    def update_login_profile(self, config: UpdateLoginProfile):
        params = {'UserName': config.user_name}
        if config.password:
            params['Password'] = config.password
        if config.password_reset_required is not None:
            params['PasswordResetRequired'] = config.password_reset_required
        return self.iam_client.update_login_profile(**params)

    def delete_login_profile(self, user_name: str):
        self.iam_client.delete_login_profile(UserName=user_name)
        return True

    # Instance Profile Management
    def create_instance_profile(self, config: CreateInstanceProfile):
        return self.iam_client.create_instance_profile(
            InstanceProfileName=config.instance_profile_name,
            Path=config.path,
            Tags=config.tags
        )

    def get_instance_profile(self, instance_profile_name: str):
        return self.iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)

    def list_instance_profiles(self, path_prefix: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'MaxItems': max_items}
        if path_prefix:
            params['PathPrefix'] = path_prefix
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_instance_profiles(**params)

    def delete_instance_profile(self, instance_profile_name: str):
        self.iam_client.delete_instance_profile(InstanceProfileName=instance_profile_name)
        return True

    def add_role_to_instance_profile(self, config: AddRoleToInstanceProfile):
        self.iam_client.add_role_to_instance_profile(
            InstanceProfileName=config.instance_profile_name,
            RoleName=config.role_name
        )
        return True

    def remove_role_from_instance_profile(self, config: RemoveRoleFromInstanceProfile):
        self.iam_client.remove_role_from_instance_profile(
            InstanceProfileName=config.instance_profile_name,
            RoleName=config.role_name
        )
        return True

    def list_instance_profiles_for_role(self, role_name: str, marker: str | None = None, max_items: int = 1000):
        params = {'RoleName': role_name, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_instance_profiles_for_role(**params)

    # MFA Management
    def create_virtual_mfa_device(self, config: CreateVirtualMFADevice):
        return self.iam_client.create_virtual_mfa_device(
            VirtualMFADeviceName=config.virtual_mfa_device_name,
            Path=config.path,
            Tags=config.tags
        )

    def enable_mfa_device(self, config: EnableMFADevice):
        self.iam_client.enable_mfa_device(
            UserName=config.user_name,
            SerialNumber=config.serial_number,
            AuthenticationCode1=config.authentication_code_1,
            AuthenticationCode2=config.authentication_code_2
        )
        return True

    def deactivate_mfa_device(self, config: DeactivateMFADevice):
        self.iam_client.deactivate_mfa_device(
            UserName=config.user_name,
            SerialNumber=config.serial_number
        )
        return True

    def resync_mfa_device(self, config: ResyncMFADevice):
        self.iam_client.resync_mfa_device(
            UserName=config.user_name,
            SerialNumber=config.serial_number,
            AuthenticationCode1=config.authentication_code_1,
            AuthenticationCode2=config.authentication_code_2
        )
        return True

    def list_mfa_devices(self, user_name: str | None = None, marker: str | None = None, max_items: int = 1000):
        params = {'MaxItems': max_items}
        if user_name:
            params['UserName'] = user_name
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_mfa_devices(**params)

    def list_virtual_mfa_devices(self, assignment_status: tp.Literal["Assigned", "Unassigned", "Any"] = "Any",
                                 marker: str | None = None, max_items: int = 1000):
        params = {'AssignmentStatus': assignment_status, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_virtual_mfa_devices(**params)

    def delete_virtual_mfa_device(self, serial_number: str):
        self.iam_client.delete_virtual_mfa_device(SerialNumber=serial_number)
        return True

    # Identity Providers
    def create_saml_provider(self, config: CreateSAMLProvider):
        return self.iam_client.create_saml_provider(
            SAMLMetadataDocument=config.saml_metadata_document,
            Name=config.name,
            Tags=config.tags
        )

    def get_saml_provider(self, saml_provider_arn: str):
        return self.iam_client.get_saml_provider(SAMLProviderArn=saml_provider_arn)

    def update_saml_provider(self, saml_provider_arn: str, saml_metadata_document: str):
        return self.iam_client.update_saml_provider(
            SAMLProviderArn=saml_provider_arn,
            SAMLMetadataDocument=saml_metadata_document
        )

    def delete_saml_provider(self, saml_provider_arn: str):
        self.iam_client.delete_saml_provider(SAMLProviderArn=saml_provider_arn)
        return True

    def list_saml_providers(self):
        return self.iam_client.list_saml_providers()

    def create_open_id_connect_provider(self, config: CreateOIDCProvider):
        return self.iam_client.create_open_id_connect_provider(
            Url=config.url,
            ClientIDList=config.client_id_list,
            ThumbprintList=config.thumbprint_list,
            Tags=config.tags
        )

    def get_open_id_connect_provider(self, open_id_connect_provider_arn: str):
        return self.iam_client.get_open_id_connect_provider(OpenIDConnectProviderArn=open_id_connect_provider_arn)

    def update_open_id_connect_provider_thumbprint(self, open_id_connect_provider_arn: str, thumbprint_list: tp.List[str]):
        self.iam_client.update_open_id_connect_provider_thumbprint(
            OpenIDConnectProviderArn=open_id_connect_provider_arn,
            ThumbprintList=thumbprint_list
        )
        return True

    def add_client_id_to_open_id_connect_provider(self, open_id_connect_provider_arn: str, client_id: str):
        self.iam_client.add_client_id_to_open_id_connect_provider(
            OpenIDConnectProviderArn=open_id_connect_provider_arn,
            ClientID=client_id
        )
        return True

    def remove_client_id_from_open_id_connect_provider(self, open_id_connect_provider_arn: str, client_id: str):
        self.iam_client.remove_client_id_from_open_id_connect_provider(
            OpenIDConnectProviderArn=open_id_connect_provider_arn,
            ClientID=client_id
        )
        return True

    def delete_open_id_connect_provider(self, open_id_connect_provider_arn: str):
        self.iam_client.delete_open_id_connect_provider(OpenIDConnectProviderArn=open_id_connect_provider_arn)
        return True

    def list_open_id_connect_providers(self):
        return self.iam_client.list_open_id_connect_providers()

    # Service Specific Credentials
    def create_service_specific_credential(self, config: CreateServiceSpecificCredential):
        return self.iam_client.create_service_specific_credential(
            UserName=config.user_name,
            ServiceName=config.service_name
        )

    def delete_service_specific_credential(self, service_specific_credential_id: str, user_name: str):
        self.iam_client.delete_service_specific_credential(
            ServiceSpecificCredentialId=service_specific_credential_id,
            UserName=user_name
        )
        return True

    def describe_service_specific_credentials(self, service_specific_credential_id: str | None = None, user_name: str | None = None, service_name: str | None = None, status: tp.Literal["Active", "Inactive"] | None = None):
        params = {}
        if service_specific_credential_id:
            params['ServiceSpecificCredentialId'] = service_specific_credential_id
        if user_name:
            params['UserName'] = user_name
        if service_name:
            params['ServiceName'] = service_name
        if status:
            params['Status'] = status
        return self.iam_client.describe_service_specific_credentials(**params)

    def list_service_specific_credentials(self, user_name: str | None = None, service_name: str | None = None, status: tp.Literal["Active", "Inactive"] | None = None):
        params = {}
        if user_name:
            params['UserName'] = user_name
        if service_name:
            params['ServiceName'] = service_name
        if status:
            params['Status'] = status
        return self.iam_client.list_service_specific_credentials(**params)

    def update_service_specific_credential(self, service_specific_credential_id: str, status: tp.Literal["Active", "Inactive"], user_name: str | None = None):
        params = {
            'ServiceSpecificCredentialId': service_specific_credential_id,
            'Status': status
        }
        if user_name:
            params['UserName'] = user_name
        self.iam_client.update_service_specific_credential(**params)
        return True

    # Account Alias
    def create_account_alias(self, config: CreateAccountAlias):
        self.iam_client.create_account_alias(AccountAlias=config.account_alias)
        return True

    def delete_account_alias(self, account_alias: str):
        self.iam_client.delete_account_alias(AccountAlias=account_alias)
        return True

    def list_account_aliases(self, marker: str | None = None, max_items: int = 1000):
        params = {'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_account_aliases(**params)

    # Service-linked Roles
    def create_service_linked_role(self, config: CreateServiceLinkedRole):
        params = {
            'AWSServiceName': config.aws_service_name
        }
        if config.description:
            params['Description'] = config.description
        if config.custom_suffix:
            params['CustomSuffix'] = config.custom_suffix
        return self.iam_client.create_service_linked_role(**params)

    def delete_service_linked_role(self, role_name: str):
        return self.iam_client.delete_service_linked_role(RoleName=role_name)

    # Tagging
    def tag_resource(self, config: TagResource):
        self.iam_client.tag_resource(ResourceArn=config.resource_arn, Tags=config.tags)
        return True

    def untag_resource(self, config: UntagResource):
        self.iam_client.untag_resource(ResourceArn=config.resource_arn, TagKeys=config.tag_keys)
        return True

    def list_resource_tags(self, resource_arn: str, marker: str | None = None, max_items: int = 1000):
        params = {'ResourceArn': resource_arn, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.list_resource_tags(**params)

    # Reporting
    def generate_credential_report(self):
        return self.iam_client.generate_credential_report()

    def get_credential_report(self):
        return self.iam_client.get_credential_report()

    def generate_organizations_access_report(self, config: GenerateOrganizationsAccessReport):
        params = {
            'EntityPath': config.entity_path
        }
        if config.organizations_policy_id:
            params['OrganizationsPolicyId'] = config.organizations_policy_id
        return self.iam_client.generate_organizations_access_report(**params)

    def get_organizations_access_report(self, job_id: str, marker: str | None = None, max_items: int = 1000, sort_key: tp.Literal["SERVICE_NAMESPACE_ASCENDING", "SERVICE_NAMESPACE_DESCENDING", "TOTAL_AUTHENTICATIONS_DESCENDING"] | None = None):
        params = {'JobId': job_id, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        if sort_key:
            params['SortKey'] = sort_key
        return self.iam_client.get_organizations_access_report(**params)

    def generate_service_last_accessed_details(self, config: GenerateServiceLastAccessedDetails):
        return self.iam_client.generate_service_last_accessed_details(
            Arn=config.arn,
            Granularity=config.granularity
        )

    def get_service_last_accessed_details(self, job_id: str, marker: str | None = None, max_items: int = 1000):
        params = {'JobId': job_id, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.get_service_last_accessed_details(**params)

    def get_service_last_accessed_details_with_entities(self, job_id: str, service_namespace: str, marker: str | None = None, max_items: int = 1000):
        params = {'JobId': job_id, 'ServiceNamespace': service_namespace, 'MaxItems': max_items}
        if marker:
            params['Marker'] = marker
        return self.iam_client.get_service_last_accessed_details_with_entities(**params)

    # Policy Simulation
    def simulate_principal_policy(self, config: SimulatePrincipalPolicy):
        params = {
            'PolicySourceArn': config.policy_source_arn,
            'ActionNames': config.action_names,
            'MaxItems': config.max_items
        }
        if config.resource_arns:
            params['ResourceArns'] = config.resource_arns
        if config.policy_input_list:
            params['PolicyInputList'] = config.policy_input_list
        if config.context_entries:
            params['ContextEntries'] = config.context_entries
        if config.resource_policy:
            params['ResourcePolicy'] = config.resource_policy
        if config.marker:
            params['Marker'] = config.marker
        return self.iam_client.simulate_principal_policy(**params)

    def simulate_custom_policy(self, action_names: tp.List[str], policy_input_list: tp.List[str], resource_arns: tp.List[str] | None = None, context_entries: tp.List[tp.Dict[str, tp.Any]] | None = None, resource_policy: str | None = None, max_items: int = 1000, marker: str | None = None):
        params = {
            'ActionNames': action_names,
            'PolicyInputList': policy_input_list,
            'MaxItems': max_items
        }
        if resource_arns:
            params['ResourceArns'] = resource_arns
        if context_entries:
            params['ContextEntries'] = context_entries
        if resource_policy:
            params['ResourcePolicy'] = resource_policy
        if marker:
            params['Marker'] = marker
        return self.iam_client.simulate_custom_policy(**params)

    # Password Policy
    def create_account_password_policy(self, config: CreateAccountPasswordPolicy):
        params = {
            'MinimumPasswordLength': config.minimum_password_length,
            'RequireSymbols': config.require_symbols,
            'RequireNumbers': config.require_numbers,
            'RequireUppercaseCharacters': config.require_uppercase_characters,
            'RequireLowercaseCharacters': config.require_lowercase_characters,
            'AllowUsersToChangePassword': config.allow_users_to_change_password,
            'HardExpiry': config.hard_expiry
        }
        if config.max_password_age:
            params['MaxPasswordAge'] = config.max_password_age
        if config.password_reuse_prevention:
            params['PasswordReusePrevention'] = config.password_reuse_prevention
        self.iam_client.update_account_password_policy(**params) # create and update use the same API call
        return True

    def get_account_password_policy(self):
        return self.iam_client.get_account_password_policy()

    def delete_account_password_policy(self):
        self.iam_client.delete_account_password_policy()
        return True


# FastAPI Router
app = APIRouter(prefix="/api/v1/iam")
iam_client = IAMClient() # Initialize IAM client

# Exception Handling for ClientError
def handle_client_error(e: ClientError):
    error_code = e.response.get("Error", {}).get("Code")
    error_message = e.response.get("Error", {}).get("Message")
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error_code": error_code, "message": error_message}
    )

# 
## User Management Endpoints

@app.post("/users", status_code=status.HTTP_201_CREATED)
async def create_iam_user(config: CreateUser):
    """
    Creates a new IAM user.
    """
    try:
        response = iam_client.create_user(config)
        return {"message": "User created successfully", "user": response["User"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/users/{user_name}", status_code=status.HTTP_200_OK)
async def get_iam_user(user_name: str):
    """
    Retrieves information about a specific IAM user.
    """
    try:
        response = iam_client.get_user(user_name=user_name)
        return {"user": response["User"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/users", status_code=status.HTTP_200_OK)
async def list_iam_users(path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all IAM users in the AWS account.
    """
    try:
        response = iam_client.list_users(path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"users": response["Users"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/users/{user_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_user(user_name: str):
    """
    Deletes an IAM user.
    """
    try:
        iam_client.delete_user(user_name=user_name)
        return {"message": "User deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/users", status_code=status.HTTP_200_OK)
async def update_iam_user(config: UpdateUser):
    """
    Updates an IAM user's name or path.
    """
    try:
        iam_client.update_user(config)
        return {"message": "User updated successfully"}
    except ClientError as e:
        handle_client_error(e)


## Access Key Management Endpoints

@app.post("/access-keys", status_code=status.HTTP_201_CREATED)
async def create_iam_access_key(config: CreateAccessKey):
    """
    Creates a new access key for an IAM user.
    """
    try:
        response = iam_client.create_access_key(config)
        return {"message": "Access key created successfully", "access_key": response["AccessKey"]}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/access-keys", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_access_key(config: DeleteAccessKey):
    """
    Deletes an access key for an IAM user.
    """
    try:
        iam_client.delete_access_key(config)
        return {"message": "Access key deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/access-keys", status_code=status.HTTP_200_OK)
async def update_iam_access_key(config: UpdateAccessKey):
    """
    Updates the status of an access key (Active/Inactive).
    """
    try:
        iam_client.update_access_key(config)
        return {"message": "Access key updated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/access-keys", status_code=status.HTTP_200_OK)
async def list_iam_access_keys(user_name: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists access keys for a specific IAM user or all access keys if no user is specified.
    """
    try:
        response = iam_client.list_access_keys(user_name=user_name, marker=marker, max_items=max_items)
        return {"access_keys": response["AccessKeyMetadata"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## Role Management Endpoints

@app.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_iam_role(config: CreateRole):
    """
    Creates a new IAM role.
    """
    try:
        response = iam_client.create_role(config)
        return {"message": "Role created successfully", "role": response["Role"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/roles/{role_name}", status_code=status.HTTP_200_OK)
async def get_iam_role(role_name: str):
    """
    Retrieves information about a specific IAM role.
    """
    try:
        response = iam_client.get_role(role_name=role_name)
        return {"role": response["Role"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/roles", status_code=status.HTTP_200_OK)
async def list_iam_roles(path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all IAM roles in the AWS account.
    """
    try:
        response = iam_client.list_roles(path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"roles": response["Roles"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/roles/{role_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_role(role_name: str):
    """
    Deletes an IAM role.
    """
    try:
        iam_client.delete_role(role_name=role_name)
        return {"message": "Role deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/roles", status_code=status.HTTP_200_OK)
async def update_iam_role(config: UpdateRole):
    """
    Updates an IAM role's description, max session duration, or name.
    """
    try:
        iam_client.update_role(config)
        return {"message": "Role updated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/roles/{role_name}/assume-role-policy", status_code=status.HTTP_200_OK)
async def update_iam_assume_role_policy(role_name: str, policy_document: str):
    """
    Updates the assume role policy for an IAM role.
    """
    try:
        iam_client.update_assume_role_policy(role_name=role_name, policy_document=policy_document)
        return {"message": "Assume role policy updated successfully"}
    except ClientError as e:
        handle_client_error(e)


## Policy Management Endpoints

@app.post("/policies", status_code=status.HTTP_201_CREATED)
async def create_iam_policy(config: CreatePolicy):
    """
    Creates a new IAM managed policy.
    """
    try:
        response = iam_client.create_policy(config)
        return {"message": "Policy created successfully", "policy": response["Policy"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/policies/{policy_arn}", status_code=status.HTTP_200_OK)
async def get_iam_policy(policy_arn: str):
    """
    Retrieves information about a specific IAM managed policy.
    """
    try:
        response = iam_client.get_policy(policy_arn=policy_arn)
        return {"policy": response["Policy"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/policies", status_code=status.HTTP_200_OK)
async def list_iam_policies(scope: tp.Literal["All", "AWS", "Local"] = Query("All"), only_attached: bool = Query(False),
                           path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all IAM managed policies.
    """
    try:
        response = iam_client.list_policies(scope=scope, only_attached=only_attached, path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"policies": response["Policies"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/policies/{policy_arn}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_policy(policy_arn: str):
    """
    Deletes an IAM managed policy.
    """
    try:
        iam_client.delete_policy(policy_arn=policy_arn)
        return {"message": "Policy deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/policy-versions", status_code=status.HTTP_201_CREATED)
async def create_iam_policy_version(config: CreatePolicyVersion):
    """
    Creates a new version of an IAM managed policy.
    """
    try:
        response = iam_client.create_policy_version(config)
        return {"message": "Policy version created successfully", "policy_version": response["PolicyVersion"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/policies/{policy_arn}/versions/{version_id}", status_code=status.HTTP_200_OK)
async def get_iam_policy_version(policy_arn: str, version_id: str):
    """
    Retrieves information about a specific version of an IAM managed policy.
    """
    try:
        response = iam_client.get_policy_version(policy_arn=policy_arn, version_id=version_id)
        return {"policy_version": response["PolicyVersion"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/policies/{policy_arn}/versions", status_code=status.HTTP_200_OK)
async def list_iam_policy_versions(policy_arn: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all versions of an IAM managed policy.
    """
    try:
        response = iam_client.list_policy_versions(policy_arn=policy_arn, marker=marker, max_items=max_items)
        return {"policy_versions": response["Versions"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/policies/{policy_arn}/versions/{version_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_policy_version(policy_arn: str, version_id: str):
    """
    Deletes a specific version of an IAM managed policy.
    """
    try:
        iam_client.delete_policy_version(policy_arn=policy_arn, version_id=version_id)
        return {"message": "Policy version deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/policies/{policy_arn}/default-version", status_code=status.HTTP_200_OK)
async def set_default_iam_policy_version(policy_arn: str, version_id: str):
    """
    Sets the specified version of an IAM managed policy as the default.
    """
    try:
        iam_client.set_default_policy_version(policy_arn=policy_arn, version_id=version_id)
        return {"message": "Default policy version set successfully"}
    except ClientError as e:
        handle_client_error(e)


## Policy Attachment Endpoints

@app.post("/users/attach-policy", status_code=status.HTTP_200_OK)
async def attach_iam_user_policy(config: AttachUserPolicy):
    """
    Attaches a managed policy to an IAM user.
    """
    try:
        iam_client.attach_user_policy(config)
        return {"message": "Policy attached to user successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/users/detach-policy", status_code=status.HTTP_200_OK)
async def detach_iam_user_policy(config: DetachUserPolicy):
    """
    Detaches a managed policy from an IAM user.
    """
    try:
        iam_client.detach_user_policy(config)
        return {"message": "Policy detached from user successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/roles/attach-policy", status_code=status.HTTP_200_OK)
async def attach_iam_role_policy(config: AttachRolePolicy):
    """
    Attaches a managed policy to an IAM role.
    """
    try:
        iam_client.attach_role_policy(config)
        return {"message": "Policy attached to role successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/roles/detach-policy", status_code=status.HTTP_200_OK)
async def detach_iam_role_policy(config: DetachRolePolicy):
    """
    Detaches a managed policy from an IAM role.
    """
    try:
        iam_client.detach_role_policy(config)
        return {"message": "Policy detached from role successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/groups/attach-policy", status_code=status.HTTP_200_OK)
async def attach_iam_group_policy(config: AttachGroupPolicy):
    """
    Attaches a managed policy to an IAM group.
    """
    try:
        iam_client.attach_group_policy(config)
        return {"message": "Policy attached to group successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/groups/detach-policy", status_code=status.HTTP_200_OK)
async def detach_iam_group_policy(config: DetachGroupPolicy):
    """
    Detaches a managed policy from an IAM group.
    """
    try:
        iam_client.detach_group_policy(config)
        return {"message": "Policy detached from group successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/users/{user_name}/attached-policies", status_code=status.HTTP_200_OK)
async def list_attached_iam_user_policies(user_name: str, path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all managed policies attached to an IAM user.
    """
    try:
        response = iam_client.list_attached_user_policies(user_name=user_name, path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"attached_policies": response["AttachedPolicies"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.get("/roles/{role_name}/attached-policies", status_code=status.HTTP_200_OK)
async def list_attached_iam_role_policies(role_name: str, path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all managed policies attached to an IAM role.
    """
    try:
        response = iam_client.list_attached_role_policies(role_name=role_name, path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"attached_policies": response["AttachedPolicies"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.get("/groups/{group_name}/attached-policies", status_code=status.HTTP_200_OK)
async def list_attached_iam_group_policies(group_name: str, path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all managed policies attached to an IAM group.
    """
    try:
        response = iam_client.list_attached_group_policies(group_name=group_name, path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"attached_policies": response["AttachedPolicies"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## Inline Policy Endpoints

@app.put("/users/inline-policy", status_code=status.HTTP_200_OK)
async def put_iam_user_inline_policy(config: PutUserPolicy):
    """
    Attaches an inline policy to an IAM user.
    """
    try:
        iam_client.put_user_policy(config)
        return {"message": "Inline policy put on user successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/roles/inline-policy", status_code=status.HTTP_200_OK)
async def put_iam_role_inline_policy(config: PutRolePolicy):
    """
    Attaches an inline policy to an IAM role.
    """
    try:
        iam_client.put_role_policy(config)
        return {"message": "Inline policy put on role successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/groups/inline-policy", status_code=status.HTTP_200_OK)
async def put_iam_group_inline_policy(config: PutGroupPolicy):
    """
    Attaches an inline policy to an IAM group.
    """
    try:
        iam_client.put_group_policy(config)
        return {"message": "Inline policy put on group successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/users/{user_name}/inline-policy/{policy_name}", status_code=status.HTTP_200_OK)
async def get_iam_user_inline_policy(user_name: str, policy_name: str):
    """
    Retrieves a specific inline policy for an IAM user.
    """
    try:
        response = iam_client.get_user_policy(user_name=user_name, policy_name=policy_name)
        return {"policy_name": response["PolicyName"], "policy_document": json.loads(response["PolicyDocument"])}
    except ClientError as e:
        handle_client_error(e)

@app.get("/roles/{role_name}/inline-policy/{policy_name}", status_code=status.HTTP_200_OK)
async def get_iam_role_inline_policy(role_name: str, policy_name: str):
    """
    Retrieves a specific inline policy for an IAM role.
    """
    try:
        response = iam_client.get_role_policy(role_name=role_name, policy_name=policy_name)
        return {"policy_name": response["PolicyName"], "policy_document": json.loads(response["PolicyDocument"])}
    except ClientError as e:
        handle_client_error(e)

@app.get("/groups/{group_name}/inline-policy/{policy_name}", status_code=status.HTTP_200_OK)
async def get_iam_group_inline_policy(group_name: str, policy_name: str):
    """
    Retrieves a specific inline policy for an IAM group.
    """
    try:
        response = iam_client.get_group_policy(group_name=group_name, policy_name=policy_name)
        return {"policy_name": response["PolicyName"], "policy_document": json.loads(response["PolicyDocument"])}
    except ClientError as e:
        handle_client_error(e)

@app.get("/users/{user_name}/inline-policies", status_code=status.HTTP_200_OK)
async def list_iam_user_inline_policies(user_name: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all inline policies for an IAM user.
    """
    try:
        response = iam_client.list_user_policies(user_name=user_name, marker=marker, max_items=max_items)
        return {"policy_names": response["PolicyNames"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.get("/roles/{role_name}/inline-policies", status_code=status.HTTP_200_OK)
async def list_iam_role_inline_policies(role_name: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all inline policies for an IAM role.
    """
    try:
        response = iam_client.list_role_policies(role_name=role_name, marker=marker, max_items=max_items)
        return {"policy_names": response["PolicyNames"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.get("/groups/{group_name}/inline-policies", status_code=status.HTTP_200_OK)
async def list_iam_group_inline_policies(group_name: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all inline policies for an IAM group.
    """
    try:
        response = iam_client.list_group_policies(group_name=group_name, marker=marker, max_items=max_items)
        return {"policy_names": response["PolicyNames"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/users/{user_name}/inline-policy/{policy_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_user_inline_policy(user_name: str, policy_name: str):
    """
    Deletes a specific inline policy for an IAM user.
    """
    try:
        iam_client.delete_user_policy(user_name=user_name, policy_name=policy_name)
        return {"message": "Inline policy deleted from user successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/roles/{role_name}/inline-policy/{policy_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_role_inline_policy(role_name: str, policy_name: str):
    """
    Deletes a specific inline policy for an IAM role.
    """
    try:
        iam_client.delete_role_policy(role_name=role_name, policy_name=policy_name)
        return {"message": "Inline policy deleted from role successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/groups/{group_name}/inline-policy/{policy_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_group_inline_policy(group_name: str, policy_name: str):
    """
    Deletes a specific inline policy for an IAM group.
    """
    try:
        iam_client.delete_group_policy(group_name=group_name, policy_name=policy_name)
        return {"message": "Inline policy deleted from group successfully"}
    except ClientError as e:
        handle_client_error(e)


## Group Management Endpoints

@app.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_iam_group(config: CreateGroup):
    """
    Creates a new IAM group.
    """
    try:
        response = iam_client.create_group(config)
        return {"message": "Group created successfully", "group": response["Group"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/groups/{group_name}", status_code=status.HTTP_200_OK)
async def get_iam_group(group_name: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Retrieves information about a specific IAM group, including its users.
    """
    try:
        response = iam_client.get_group(group_name=group_name, marker=marker, max_items=max_items)
        return {"group": response["Group"], "users": response["Users"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.get("/groups", status_code=status.HTTP_200_OK)
async def list_iam_groups(path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all IAM groups in the AWS account.
    """
    try:
        response = iam_client.list_groups(path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"groups": response["Groups"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/groups/{group_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_group(group_name: str):
    """
    Deletes an IAM group.
    """
    try:
        iam_client.delete_group(group_name=group_name)
        return {"message": "Group deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.put("/groups", status_code=status.HTTP_200_OK)
async def update_iam_group(config: UpdateGroup):
    """
    Updates an IAM group's name or path.
    """
    try:
        iam_client.update_group(config)
        return {"message": "Group updated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/groups/add-user", status_code=status.HTTP_200_OK)
async def add_iam_user_to_group(config: AddUserToGroup):
    """
    Adds an IAM user to a group.
    """
    try:
        iam_client.add_user_to_group(config)
        return {"message": "User added to group successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/groups/remove-user", status_code=status.HTTP_200_OK)
async def remove_iam_user_from_group(config: RemoveUserFromGroup):
    """
    Removes an IAM user from a group.
    """
    try:
        iam_client.remove_user_from_group(config)
        return {"message": "User removed from group successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/users/{user_name}/groups", status_code=status.HTTP_200_OK)
async def list_iam_groups_for_user(user_name: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all IAM groups a user belongs to.
    """
    try:
        response = iam_client.list_groups_for_user(user_name=user_name, marker=marker, max_items=max_items)
        return {"groups": response["Groups"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## Login Profile Management Endpoints

@app.post("/login-profiles", status_code=status.HTTP_201_CREATED)
async def create_iam_login_profile(config: CreateLoginProfile):
    """
    Creates a login profile for an IAM user, enabling console access.
    """
    try:
        response = iam_client.create_login_profile(config)
        return {"message": "Login profile created successfully", "login_profile": response["LoginProfile"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/login-profiles/{user_name}", status_code=status.HTTP_200_OK)
async def get_iam_login_profile(user_name: str):
    """
    Retrieves the login profile for an IAM user.
    """
    try:
        response = iam_client.get_login_profile(user_name=user_name)
        return {"login_profile": response["LoginProfile"]}
    except ClientError as e:
        handle_client_error(e)

@app.put("/login-profiles", status_code=status.HTTP_200_OK)
async def update_iam_login_profile(config: UpdateLoginProfile):
    """
    Updates the password or password reset requirement for an IAM user's login profile.
    """
    try:
        iam_client.update_login_profile(config)
        return {"message": "Login profile updated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/login-profiles/{user_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_login_profile(user_name: str):
    """
    Deletes the login profile for an IAM user, disabling console access.
    """
    try:
        iam_client.delete_login_profile(user_name=user_name)
        return {"message": "Login profile deleted successfully"}
    except ClientError as e:
        handle_client_error(e)


## Instance Profile Management Endpoints

@app.post("/instance-profiles", status_code=status.HTTP_201_CREATED)
async def create_iam_instance_profile(config: CreateInstanceProfile):
    """
    Creates a new IAM instance profile.
    """
    try:
        response = iam_client.create_instance_profile(config)
        return {"message": "Instance profile created successfully", "instance_profile": response["InstanceProfile"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/instance-profiles/{instance_profile_name}", status_code=status.HTTP_200_OK)
async def get_iam_instance_profile(instance_profile_name: str):
    """
    Retrieves information about a specific IAM instance profile.
    """
    try:
        response = iam_client.get_instance_profile(instance_profile_name=instance_profile_name)
        return {"instance_profile": response["InstanceProfile"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/instance-profiles", status_code=status.HTTP_200_OK)
async def list_iam_instance_profiles(path_prefix: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all IAM instance profiles.
    """
    try:
        response = iam_client.list_instance_profiles(path_prefix=path_prefix, marker=marker, max_items=max_items)
        return {"instance_profiles": response["InstanceProfiles"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/instance-profiles/{instance_profile_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_instance_profile(instance_profile_name: str):
    """
    Deletes an IAM instance profile.
    """
    try:
        iam_client.delete_instance_profile(instance_profile_name=instance_profile_name)
        return {"message": "Instance profile deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/instance-profiles/add-role", status_code=status.HTTP_200_OK)
async def add_iam_role_to_instance_profile(config: AddRoleToInstanceProfile):
    """
    Adds an IAM role to an instance profile.
    """
    try:
        iam_client.add_role_to_instance_profile(config)
        return {"message": "Role added to instance profile successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/instance-profiles/remove-role", status_code=status.HTTP_200_OK)
async def remove_iam_role_from_instance_profile(config: RemoveRoleFromInstanceProfile):
    """
    Removes an IAM role from an instance profile.
    """
    try:
        iam_client.remove_role_from_instance_profile(config)
        return {"message": "Role removed from instance profile successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/roles/{role_name}/instance-profiles", status_code=status.HTTP_200_OK)
async def list_iam_instance_profiles_for_role(role_name: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all instance profiles associated with a specific IAM role.
    """
    try:
        response = iam_client.list_instance_profiles_for_role(role_name=role_name, marker=marker, max_items=max_items)
        return {"instance_profiles": response["InstanceProfiles"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## MFA Management Endpoints

@app.post("/virtual-mfa-devices", status_code=status.HTTP_201_CREATED)
async def create_iam_virtual_mfa_device(config: CreateVirtualMFADevice):
    """
    Creates a new virtual MFA device.
    """
    try:
        response = iam_client.create_virtual_mfa_device(config)
        # Boto3 returns a base64 encoded QR code PNG and a Base32 string,
        # which might need further processing depending on the frontend.
        return {"message": "Virtual MFA device created successfully", "virtual_mfa_device": {
            "SerialNumber": response["VirtualMFADevice"]["SerialNumber"],
            "Base32StringSeed": response["VirtualMFADevice"]["Base32StringSeed"],
            "QRCodePng": response["VirtualMFADevice"]["QRCodePng"].decode('utf-8')  # Decode bytes to string for JSON
        }}
    except ClientError as e:
        handle_client_error(e)

@app.post("/mfa-devices/enable", status_code=status.HTTP_200_OK)
async def enable_iam_mfa_device(config: EnableMFADevice):
    """
    Enables an MFA device for an IAM user.
    """
    try:
        iam_client.enable_mfa_device(config)
        return {"message": "MFA device enabled successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/mfa-devices/deactivate", status_code=status.HTTP_200_OK)
async def deactivate_iam_mfa_device(config: DeactivateMFADevice):
    """
    Deactivates an MFA device for an IAM user.
    """
    try:
        iam_client.deactivate_mfa_device(config)
        return {"message": "MFA device deactivated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/mfa-devices/resync", status_code=status.HTTP_200_OK)
async def resync_iam_mfa_device(config: ResyncMFADevice):
    """
    Resynchronizes an MFA device with AWS.
    """
    try:
        iam_client.resync_mfa_device(config)
        return {"message": "MFA device resynchronized successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/mfa-devices", status_code=status.HTTP_200_OK)
async def list_iam_mfa_devices(user_name: str = Query(None), marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all MFA devices for a specific IAM user or all MFA devices if no user is specified.
    """
    try:
        response = iam_client.list_mfa_devices(user_name=user_name, marker=marker, max_items=max_items)
        return {"mfa_devices": response["MFADevices"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.get("/virtual-mfa-devices", status_code=status.HTTP_200_OK)
async def list_iam_virtual_mfa_devices(assignment_status: tp.Literal["Assigned", "Unassigned", "Any"] = Query("Any"),
                                       marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all virtual MFA devices.
    """
    try:
        response = iam_client.list_virtual_mfa_devices(assignment_status=assignment_status, marker=marker, max_items=max_items)
        return {"virtual_mfa_devices": response["VirtualMFADevices"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/virtual-mfa-devices/{serial_number}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_virtual_mfa_device(serial_number: str):
    """
    Deletes a virtual MFA device.
    """
    try:
        iam_client.delete_virtual_mfa_device(serial_number=serial_number)
        return {"message": "Virtual MFA device deleted successfully"}
    except ClientError as e:
        handle_client_error(e)


## Identity Providers Endpoints

@app.post("/saml-providers", status_code=status.HTTP_201_CREATED)
async def create_iam_saml_provider(config: CreateSAMLProvider):
    """
    Creates a new SAML identity provider.
    """
    try:
        response = iam_client.create_saml_provider(config)
        return {"message": "SAML provider created successfully", "saml_provider_arn": response["SAMLProviderArn"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/saml-providers/{saml_provider_arn}", status_code=status.HTTP_200_OK)
async def get_iam_saml_provider(saml_provider_arn: str):
    """
    Retrieves information about a specific SAML identity provider.
    """
    try:
        response = iam_client.get_saml_provider(saml_provider_arn=saml_provider_arn)
        # Note: SAMLMetadataDocument is a large XML string, may need truncation or specific handling
        return {"saml_provider_arn": saml_provider_arn, "create_date": response["CreateDate"], "valid_until": response["ValidUntil"], "saml_metadata_document": response["SAMLMetadataDocument"]}
    except ClientError as e:
        handle_client_error(e)

@app.put("/saml-providers/{saml_provider_arn}", status_code=status.HTTP_200_OK)
async def update_iam_saml_provider(saml_provider_arn: str, saml_metadata_document: str):
    """
    Updates the SAML metadata document for a SAML identity provider.
    """
    try:
        iam_client.update_saml_provider(saml_provider_arn=saml_provider_arn, saml_metadata_document=saml_metadata_document)
        return {"message": "SAML provider updated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/saml-providers/{saml_provider_arn}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_saml_provider(saml_provider_arn: str):
    """
    Deletes a SAML identity provider.
    """
    try:
        iam_client.delete_saml_provider(saml_provider_arn=saml_provider_arn)
        return {"message": "SAML provider deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/saml-providers", status_code=status.HTTP_200_OK)
async def list_iam_saml_providers():
    """
    Lists all SAML identity providers.
    """
    try:
        response = iam_client.list_saml_providers()
        return {"saml_providers": response["SAMLProviderList"]}
    except ClientError as e:
        handle_client_error(e)

@app.post("/oidc-providers", status_code=status.HTTP_201_CREATED)
async def create_iam_oidc_provider(config: CreateOIDCProvider):
    """
    Creates a new OpenID Connect (OIDC) identity provider.
    """
    try:
        response = iam_client.create_open_id_connect_provider(config)
        return {"message": "OIDC provider created successfully", "open_id_connect_provider_arn": response["OpenIDConnectProviderArn"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/oidc-providers/{open_id_connect_provider_arn}", status_code=status.HTTP_200_OK)
async def get_iam_oidc_provider(open_id_connect_provider_arn: str):
    """
    Retrieves information about a specific OpenID Connect (OIDC) identity provider.
    """
    try:
        response = iam_client.get_open_id_connect_provider(open_id_connect_provider_arn=open_id_connect_provider_arn)
        return {"open_id_connect_provider_arn": open_id_connect_provider_arn, "client_id_list": response["ClientIDList"], "thumbprint_list": response["ThumbprintList"], "create_date": response["CreateDate"]}
    except ClientError as e:
        handle_client_error(e)

@app.put("/oidc-providers/{open_id_connect_provider_arn}/thumbprint", status_code=status.HTTP_200_OK)
async def update_iam_oidc_provider_thumbprint(open_id_connect_provider_arn: str, thumbprint_list: tp.List[str]):
    """
    Updates the list of certificate thumbprints for an OpenID Connect (OIDC) identity provider.
    """
    try:
        iam_client.update_open_id_connect_provider_thumbprint(open_id_connect_provider_arn=open_id_connect_provider_arn, thumbprint_list=thumbprint_list)
        return {"message": "OIDC provider thumbprint updated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/oidc-providers/{open_id_connect_provider_arn}/add-client-id", status_code=status.HTTP_200_OK)
async def add_iam_client_id_to_oidc_provider(open_id_connect_provider_arn: str, client_id: str):
    """
    Adds a new client ID to an OpenID Connect (OIDC) identity provider.
    """
    try:
        iam_client.add_client_id_to_open_id_connect_provider(open_id_connect_provider_arn=open_id_connect_provider_arn, client_id=client_id)
        return {"message": "Client ID added to OIDC provider successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/oidc-providers/{open_id_connect_provider_arn}/remove-client-id", status_code=status.HTTP_200_OK)
async def remove_iam_client_id_from_oidc_provider(open_id_connect_provider_arn: str, client_id: str):
    """
    Removes a client ID from an OpenID Connect (OIDC) identity provider.
    """
    try:
        iam_client.remove_client_id_from_open_id_connect_provider(open_id_connect_provider_arn=open_id_connect_provider_arn, client_id=client_id)
        return {"message": "Client ID removed from OIDC provider successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/oidc-providers/{open_id_connect_provider_arn}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_oidc_provider(open_id_connect_provider_arn: str):
    """
    Deletes an OpenID Connect (OIDC) identity provider.
    """
    try:
        iam_client.delete_open_id_connect_provider(open_id_connect_provider_arn=open_id_connect_provider_arn)
        return {"message": "OIDC provider deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/oidc-providers", status_code=status.HTTP_200_OK)
async def list_iam_oidc_providers():
    """
    Lists all OpenID Connect (OIDC) identity providers.
    """
    try:
        response = iam_client.list_open_id_connect_providers()
        return {"open_id_connect_providers": response["OpenIDConnectProviderList"]}
    except ClientError as e:
        handle_client_error(e)


## Service Specific Credential Endpoints

@app.post("/service-specific-credentials", status_code=status.HTTP_201_CREATED)
async def create_iam_service_specific_credential(config: CreateServiceSpecificCredential):
    """
    Creates a new service-specific credential for an IAM user.
    """
    try:
        response = iam_client.create_service_specific_credential(config)
        return {"message": "Service-specific credential created successfully", "service_specific_credential": response["ServiceSpecificCredential"]}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/service-specific-credentials/{service_specific_credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_service_specific_credential(service_specific_credential_id: str, user_name: str = Query(None)):
    """
    Deletes a service-specific credential.
    """
    try:
        iam_client.delete_service_specific_credential(service_specific_credential_id=service_specific_credential_id, user_name=user_name)
        return {"message": "Service-specific credential deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/service-specific-credentials/describe", status_code=status.HTTP_200_OK)
async def describe_iam_service_specific_credentials(
    service_specific_credential_id: str = Query(None),
    user_name: str = Query(None),
    service_name: str = Query(None),
    status: tp.Literal["Active", "Inactive"] = Query(None)
):
    """
    Retrieves information about service-specific credentials.
    """
    try:
        response = iam_client.describe_service_specific_credentials(
            service_specific_credential_id=service_specific_credential_id,
            user_name=user_name,
            service_name=service_name,
            status=status
        )
        return {"service_specific_credentials": response["ServiceSpecificCredentials"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/service-specific-credentials", status_code=status.HTTP_200_OK)
async def list_iam_service_specific_credentials(
    user_name: str = Query(None),
    service_name: str = Query(None),
    status: tp.Literal["Active", "Inactive"] = Query(None)
):
    """
    Lists service-specific credentials for an IAM user or all service-specific credentials.
    """
    try:
        response = iam_client.list_service_specific_credentials(
            user_name=user_name,
            service_name=service_name,
            status=status
        )
        return {"service_specific_credentials": response["ServiceSpecificCredentials"]}
    except ClientError as e:
        handle_client_error(e)

@app.put("/service-specific-credentials/{service_specific_credential_id}", status_code=status.HTTP_200_OK)
async def update_iam_service_specific_credential(service_specific_credential_id: str, status: tp.Literal["Active", "Inactive"], user_name: str = Query(None)):
    """
    Updates the status of a service-specific credential.
    """
    try:
        iam_client.update_service_specific_credential(
            service_specific_credential_id=service_specific_credential_id,
            status=status,
            user_name=user_name
        )
        return {"message": "Service-specific credential updated successfully"}
    except ClientError as e:
        handle_client_error(e)


## Account Alias Endpoints

@app.post("/account-alias", status_code=status.HTTP_201_CREATED)
async def create_iam_account_alias(config: CreateAccountAlias):
    """
    Creates an alias for your AWS account.
    """
    try:
        iam_client.create_account_alias(config)
        return {"message": "Account alias created successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/account-alias/{account_alias}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_account_alias(account_alias: str):
    """
    Deletes the alias for your AWS account.
    """
    try:
        iam_client.delete_account_alias(account_alias=account_alias)
        return {"message": "Account alias deleted successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/account-aliases", status_code=status.HTTP_200_OK)
async def list_iam_account_aliases(marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists all aliases for your AWS account.
    """
    try:
        response = iam_client.list_account_aliases(marker=marker, max_items=max_items)
        return {"account_aliases": response["AccountAliases"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## Service-linked Role Endpoints

@app.post("/service-linked-roles", status_code=status.HTTP_201_CREATED)
async def create_iam_service_linked_role(config: CreateServiceLinkedRole):
    """
    Creates a service-linked role for a specified AWS service.
    """
    try:
        response = iam_client.create_service_linked_role(config)
        return {"message": "Service-linked role created successfully", "role": response["Role"]}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/service-linked-roles/{role_name}", status_code=status.HTTP_200_OK)
async def delete_iam_service_linked_role(role_name: str):
    """
    Deletes a service-linked role.
    """
    try:
        response = iam_client.delete_service_linked_role(role_name=role_name)
        # Note: The deletion of a service-linked role is asynchronous.
        # The response includes a DeletionTaskId which can be used to check status.
        return {"message": "Service-linked role deletion initiated successfully", "deletion_task_id": response["DeletionTaskId"]}
    except ClientError as e:
        handle_client_error(e)


## Tagging Endpoints

@app.post("/tags", status_code=status.HTTP_200_OK)
async def tag_iam_resource(config: TagResource):
    """
    Adds tags to an IAM user, role, policy, or instance profile.
    """
    try:
        iam_client.tag_resource(config)
        return {"message": "Resource tagged successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.post("/untag", status_code=status.HTTP_200_OK)
async def untag_iam_resource(config: UntagResource):
    """
    Removes tags from an IAM user, role, policy, or instance profile.
    """
    try:
        iam_client.untag_resource(config)
        return {"message": "Resource untagged successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/resources/{resource_arn}/tags", status_code=status.HTTP_200_OK)
async def list_iam_resource_tags(resource_arn: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Lists the tags that are attached to an IAM user, role, policy, or instance profile.
    """
    try:
        response = iam_client.list_resource_tags(resource_arn=resource_arn, marker=marker, max_items=max_items)
        return {"tags": response["Tags"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## Reporting Endpoints

@app.post("/credential-report/generate", status_code=status.HTTP_200_OK)
async def generate_iam_credential_report():
    """
    Generates a credential report for your AWS account.
    """
    try:
        response = iam_client.generate_credential_report()
        return {"message": "Credential report generation initiated", "state": response["State"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/credential-report", status_code=status.HTTP_200_OK)
async def get_iam_credential_report():
    """
    Retrieves the credential report for your AWS account.
    """
    try:
        response = iam_client.get_credential_report()
        # Report is returned as a CSV string
        return {"content": response["Content"].decode('utf-8'), "report_format": response["ReportFormat"], "generated_time": response["GeneratedTime"]}
    except ClientError as e:
        handle_client_error(e)

@app.post("/organizations-access-report/generate", status_code=status.HTTP_200_OK)
async def generate_iam_organizations_access_report(config: GenerateOrganizationsAccessReport):
    """
    Generates a report that includes details about the last attempted access to the AWS services by a principal in your AWS Organizations entity.
    """
    try:
        response = iam_client.generate_organizations_access_report(config)
        return {"message": "Organizations access report generation initiated", "job_id": response["JobId"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/organizations-access-report/{job_id}", status_code=status.HTTP_200_OK)
async def get_iam_organizations_access_report(
    job_id: str,
    marker: str = Query(None),
    max_items: int = Query(1000),
    sort_key: tp.Literal["SERVICE_NAMESPACE_ASCENDING", "SERVICE_NAMESPACE_DESCENDING", "TOTAL_AUTHENTICATIONS_DESCENDING"] = Query(None)
):
    """
    Retrieves the status of your AWS Organizations access report.
    """
    try:
        response = iam_client.get_organizations_access_report(job_id=job_id, marker=marker, max_items=max_items, sort_key=sort_key)
        return {"job_status": response["JobStatus"], "report_status": response["AccessKeyLastUsed"] if "AccessKeyLastUsed" in response else None, "error_details": response.get("ErrorDetails"), "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.post("/service-last-accessed-details/generate", status_code=status.HTTP_200_OK)
async def generate_iam_service_last_accessed_details(config: GenerateServiceLastAccessedDetails):
    """
    Generates a report that includes details about when the specified policy, user, role, or group was last used to access an AWS service.
    """
    try:
        response = iam_client.generate_service_last_accessed_details(config)
        return {"message": "Service last accessed details generation initiated", "job_id": response["JobId"]}
    except ClientError as e:
        handle_client_error(e)

@app.get("/service-last-accessed-details/{job_id}", status_code=status.HTTP_200_OK)
async def get_iam_service_last_accessed_details(job_id: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Retrieves the status of the service last accessed report.
    """
    try:
        response = iam_client.get_service_last_accessed_details(job_id=job_id, marker=marker, max_items=max_items)
        return {"job_status": response["JobStatus"], "job_completion_date": response["JobCompletionDate"], "services_last_accessed": response["ServicesLastAccessed"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.get("/service-last-accessed-details-with-entities/{job_id}", status_code=status.HTTP_200_OK)
async def get_iam_service_last_accessed_details_with_entities(job_id: str, service_namespace: str, marker: str = Query(None), max_items: int = Query(1000)):
    """
    Retrieves the details of entities that last accessed the specified AWS service.
    """
    try:
        response = iam_client.get_service_last_accessed_details_with_entities(job_id=job_id, service_namespace=service_namespace, marker=marker, max_items=max_items)
        return {"job_status": response["JobStatus"], "entity_details_list": response["EntityDetailsList"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## Policy Simulation Endpoints

@app.post("/simulate-principal-policy", status_code=status.HTTP_200_OK)
async def simulate_iam_principal_policy(config: SimulatePrincipalPolicy):
    """
    Simulates the results of a permissions policy for a principal (user, role, or group).
    """
    try:
        response = iam_client.simulate_principal_policy(config)
        return {"evaluation_results": response["EvaluationResults"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)

@app.post("/simulate-custom-policy", status_code=status.HTTP_200_OK)
async def simulate_iam_custom_policy(
    action_names: tp.List[str],
    policy_input_list: tp.List[str],
    resource_arns: tp.List[str] | None = None,
    context_entries: tp.List[tp.Dict[str, tp.Any]] | None = None,
    resource_policy: str | None = None,
    max_items: int = Query(1000),
    marker: str = Query(None)
):
    """
    Simulates the results of a set of IAM policies.
    """
    try:
        response = iam_client.simulate_custom_policy(
            action_names=action_names,
            policy_input_list=policy_input_list,
            resource_arns=resource_arns,
            context_entries=context_entries,
            resource_policy=resource_policy,
            max_items=max_items,
            marker=marker
        )
        return {"evaluation_results": response["EvaluationResults"], "is_truncated": response["IsTruncated"], "marker": response.get("Marker")}
    except ClientError as e:
        handle_client_error(e)


## Password Policy Endpoints

@app.post("/account-password-policy", status_code=status.HTTP_200_OK)
async def create_or_update_iam_account_password_policy(config: CreateAccountPasswordPolicy):
    """
    Creates or updates the password policy for your AWS account.
    """
    try:
        iam_client.create_account_password_policy(config)
        return {"message": "Account password policy created/updated successfully"}
    except ClientError as e:
        handle_client_error(e)

@app.get("/account-password-policy", status_code=status.HTTP_200_OK)
async def get_iam_account_password_policy():
    """
    Retrieves the password policy for your AWS account.
    """
    try:
        response = iam_client.get_account_password_policy()
        return {"password_policy": response["PasswordPolicy"]}
    except ClientError as e:
        handle_client_error(e)

@app.delete("/account-password-policy", status_code=status.HTTP_204_NO_CONTENT)
async def delete_iam_account_password_policy():
    """
    Deletes the password policy for your AWS account.
    """
    try:
        iam_client.delete_account_password_policy()
        return {"message": "Account password policy deleted successfully"}
    except ClientError as e:
        handle_client_error(e)