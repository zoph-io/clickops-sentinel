# SPDX-License-Identifier: Apache-2.0
"""Default suppression list for events that should not trigger alerts.

Entries use the format "service:EventName" where service is the eventSource
host with ".amazonaws.com" stripped (for example "ec2.amazonaws.com" becomes
"ec2").

The list combines two battle-tested sources:

- Arkadiy Tetelman, "Detecting Manual AWS Actions: An Update" (2024):
  actions that CloudTrail mislabels as mutating, plus operational actions
  that cannot or should not live in infrastructure as code.
- cloudandthings/terraform-aws-clickops-notifier issue tracker: noise
  discovered by real users of the equivalent Terraform module.
"""

DEFAULT_SUPPRESSED_ACTIONS = frozenset(
    {
        # Mislabeled as mutating or purely operational (arkadiyt 2024 list).
        "access-analyzer:StartPolicyGeneration",
        "airflow:CreateWebLoginToken",
        "bedrock:GetFoundationModelAvailability",
        "bedrock:ListFoundationModelAgreementOffers",
        "billingconsole:AWSPaymentPortalService.DescribePaymentsDashboard",
        "billingconsole:AWSPaymentPortalService.GetAccountPreferences",
        "billingconsole:AWSPaymentPortalService.GetPaymentsDue",
        "billingconsole:AWSPaymentPreferenceGateway.Get",
        "billingconsole:FindPaymentInstruments",
        "billingconsole:GetAllowedPaymentMethods",
        "billingconsole:GetBillingNotifications",
        "billingconsole:GetPaymentInstrument",
        "billingconsole:GetPaymentPreference",
        "billingconsole:GetTaxInvoicesMetadata",
        "billingconsole:ListCostAllocationTags",
        "ce:CreateReport",
        "ce:ListCostAllocationTags",
        "ce:StartSavingsPlansPurchaseRecommendationGeneration",
        "cloudwatch:TestEventPattern",
        "cloudwatch:TestMetricFilter",
        "cloudwatch:TestScheduleExpression",
        "config:SelectAggregateResourceConfig",
        "config:SelectResourceConfig",
        "dms:RefreshSchemas",
        "dms:TestConnection",
        "dynamodb:DescribeContributorInsights",
        "dynamodb:DescribeExport",
        "dynamodb:DescribeImport",
        "dynamodb:DescribeKinesisStreamingDestination",
        "dynamodb:ListContributorInsights",
        "dynamodb:ListExports",
        "dynamodb:ListImports",
        "ec2:SearchTransitGatewayRoutes",
        # PutImage arrives at the end of an upload, layer events are noise.
        "ecr:BatchGetRepositoryScanningConfiguration",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeRepositoryCreationTemplates",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "eks:ListInsights",
        "events:DescribeEndpoint",
        "glue:BatchGetCrawlers",
        "glue:BatchGetJobs",
        "glue:BatchGetTriggers",
        "glue:CancelStatement",
        "glue:CreateSession",
        "glue:ListCustomEntityTypes",
        "glue:RunStatement",
        "glue:StopSession",
        "guardduty:DescribeMalwareScans",
        "guardduty:GetRemainingFreeTrialDays",
        "iam:GenerateOrganizationsAccessReport",
        "iam:GenerateServiceLastAccessedDetails",
        "inspector2:CreateFindingsReport",
        "kinesisanalytics:CreateApplicationPresignedUrl",
        "logs:StartLiveTail",
        "logs:StartQuery",
        "logs:StopLiveTail",
        "logs:StopQuery",
        # Amazon Q usage from the console is not a resource change.
        "networkmanager-chat:CreateConversation",
        "networkmanager-chat:SendConversationMessage",
        "networkmanager:GetConnectPeerAssociations",
        "pipes:ListPipes",
        "sagemaker:StartPipelineExecution",
        "sagemaker:StopPipelineExecution",
        "secretsmanager:ReplicateSecretToRegions",
        "securityhub:GetUsage",
        # Sign-in and federation events are handled by the dedicated
        # ConsoleLogin rule, not the change-detection path.
        "signin:CheckMfa",
        "signin:ConsoleLogin",
        "signin:GetSigninToken",
        "signin:SwitchRole",
        "signin:UserAuthentication",
        "sso-directory:SearchGroups",
        "sso-directory:SearchUsers",
        "sso:Authenticate",
        "sso:Federate",
        "sso:Logout",
        "sts:AssumeRole",
        # Support cases are operational, they cannot live in IaC.
        "support:AddAttachmentsToSet",
        "support:AddCommunicationToCase",
        "support:CreateCase",
        "support:ResolveCase",
        "trustedadvisor:CreateExcelReport",
        "trustedadvisor:DescribeAccount",
        "trustedadvisor:DescribeAccountAccess",
        "trustedadvisor:DescribeCheckItems",
        "trustedadvisor:DescribeCheckRefreshStatuses",
        "trustedadvisor:DescribeChecks",
        "trustedadvisor:DescribeCheckSummaries",
        "trustedadvisor:DescribeOrganization",
        "trustedadvisor:DescribeReports",
        "trustedadvisor:DescribeRisk",
        "trustedadvisor:DescribeRiskResources",
        "trustedadvisor:DescribeRisks",
        "trustedadvisor:GetExcelReport",
        "trustedadvisor:RefreshCheck",
        # From the cloudandthings issue tracker.
        # Amazon Q chat in the console (issue 85).
        "q:StartConversation",
        "q:SendMessage",
        "q:GetConversation",
        "q:PassRequest",
        # Arrives with userIdentity.type Unknown, not ClickOps (issue 101).
        "iot:RegisterCertificate",
        # Emitted during console browsing of registered domains (PR 72).
        "route53domains:TransferDomain",
        # Grafana workspace login events (PR 68).
        "grafana:CreateWorkspaceApiKey",
        "grafana:DeleteWorkspaceApiKey",
        # RDS log browsing in the console.
        "rds:DownloadDBLogFilePortion",
        # CloudTrail event history browsing.
        "cloudtrail:LookupEvents",
        # KMS decrypt happens implicitly all over the console.
        "kms:Decrypt",
    }
)

# Event name prefixes that indicate read-only operations. Defense in depth:
# the EventBridge rule already requires readOnly false, but a few services
# mislabel reads as writes.
READONLY_PREFIXES = ("Get", "List", "Describe", "Head", "Search", "Lookup")


def build_suppression_set(extra_csv: str) -> frozenset:
    """Merge the default list with a comma-separated operator-provided list."""
    extra = {item.strip() for item in extra_csv.split(",") if item.strip()}
    return DEFAULT_SUPPRESSED_ACTIONS | frozenset(extra)


def service_from_event_source(event_source: str) -> str:
    """Reduce an eventSource host to its service prefix.

    "ec2.amazonaws.com" becomes "ec2". Unrecognized values pass through.
    """
    return (event_source or "").removesuffix(".amazonaws.com")


def is_suppressed(record: dict, suppressed: frozenset) -> bool:
    """Return True when the CloudTrail record must not produce an alert."""
    event_name = record.get("eventName", "")
    service = service_from_event_source(record.get("eventSource", ""))
    if f"{service}:{event_name}" in suppressed:
        return True
    return event_name.startswith(READONLY_PREFIXES)
