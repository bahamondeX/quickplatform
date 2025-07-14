import os


import pytest
from boto3 import Session
from botocore.exceptions import ClientError, EndpointConnectionError
from dotenv import load_dotenv


load_dotenv()

ENDPOINT_URL = "https://aws.oscarbahamonde.com"
SERVICES = (
    "apigateway",
    "sqs",
    "sns",
    "stepfunctions",
    "events",
    "ec2",
    "lambda",
    "s3",
    "cloudformation",
    "cloudwatch",
    "ssm",
    "acm",
    "secretsmanager",
    "kms",
    "iam",
    "ses",
    "transcribe",
    "dynamodb",
    "kinesis",
    "opensearch",
    "route53",
    "redshift",
    "kinesis",
    "sts",
    "opensearch",
)

REGION = "us-east-1"

# Mapa de operaciones mínimas por servicio
TEST_CALLS = {
    "s3": lambda client: client.list_buckets(),
    "sqs": lambda client: client.list_queues(),
    "sns": lambda client: client.list_topics(),
    "stepfunctions": lambda client: client.list_state_machines(),
    "events": lambda client: client.list_event_buses(),
    "ec2": lambda client: client.describe_instances(),
    "lambda": lambda client: client.list_functions(),
    "cloudformation": lambda client: client.list_stacks(),
    "cloudwatch": lambda client: client.list_dashboards(),
    "ssm": lambda client: client.describe_parameters(),
    "acm": lambda client: client.list_certificates(),
    "secretsmanager": lambda client: client.list_secrets(),
    "kms": lambda client: client.list_keys(),
    "iam": lambda client: client.list_users(),
    "ses": lambda client: client.list_identities(),
    "transcribe": lambda client: client.list_transcription_jobs(),
    "dynamodb": lambda client: client.list_tables(),
    "apigateway": lambda client: client.get_rest_apis(),
    "opensearch": lambda client: client.list_domain_names(),
    "cognito-idp": lambda client: client.list_user_pools(),
    "sts": lambda client: client.get_caller_identity(),
    "redshift": lambda client: client.describe_clusters(),
    "kinesis": lambda client: client.list_streams(),
    "route53": lambda client: client.list_hosted_zones(),
}


@pytest.mark.parametrize("service", SERVICES)
def test_service_availability(service):
    session = Session()
    try:
        client = session.client(service, endpoint_url=ENDPOINT_URL, region_name=REGION)
    except EndpointConnectionError:
        pytest.fail(f"❌ {service}: endpoint not reachable")

    call = TEST_CALLS.get(service)
    if not call:
        pytest.skip(f"⚠️  {service}: no test defined")

    try:
        call(client)
    except ClientError as e:
        pytest.fail(f"⚠️  {service}: API error - {e.response['Error']['Message']}")
    except Exception as e:
        pytest.fail(f"❌ {service}: unknown error - {str(e)}")
