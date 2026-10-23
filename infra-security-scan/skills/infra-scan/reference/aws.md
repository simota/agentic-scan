# AWS — where each perspective looks

**Read when:** REVIEW of a unit with AWS resources. Terraform resource types are
listed; the CloudFormation equivalents (`AWS::S3::Bucket`…) carry the same
properties in PascalCase.

Benchmark citations in `controls` name the benchmark and the section title, with
the edition only when the requester names one (e.g. `CIS AWS Foundations v3.0 — Ensure no security groups allow
ingress from 0.0.0.0/0 to remote server administration ports`). Control numbers
change between editions: copy the number only from the edition the requester
uses, never from memory.

## Network exposure

| Look at | Attribute | Unsound |
|---|---|---|
| `aws_security_group`, `aws_vpc_security_group_ingress_rule`, `aws_security_group_rule` | `cidr_blocks`, `ipv6_cidr_blocks`, `cidr_ipv4`, `from_port`/`to_port`, `protocol = "-1"` | `0.0.0.0/0` / `::/0` on 22, 3389, 3306, 5432, 1433, 1521, 6379, 9200, 27017, 2375/2376, 6443, or all ports |
| `aws_network_acl_rule` | `cidr_block`, `rule_action`, ports | Allow from `0.0.0.0/0` on admin ports (NACLs are stateless: check egress too) |
| `aws_instance`, `aws_launch_template` | `associate_public_ip_address`, subnet with `map_public_ip_on_launch` | Public address on a workload that is not an edge |
| `aws_db_instance`, `aws_rds_cluster_instance`, `aws_redshift_cluster`, `aws_elasticsearch_domain` / `aws_opensearch_domain` | `publicly_accessible`, `vpc_options` absent | Public data store |
| `aws_lb_listener` | `protocol`, `ssl_policy`, default action | HTTP without redirect; TLS policy older than TLS 1.2 |
| `aws_eks_cluster` | `vpc_config.endpoint_public_access`, `public_access_cidrs` | Public endpoint open to `0.0.0.0/0` |
| `aws_vpc_endpoint` | `policy` | `*` principal and action where the endpoint is the private path to a crown jewel |
| `aws_default_security_group` | ingress / egress | Default SG with rules (it is attached by default) |

## Identity and privilege

- `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`,
  `aws_iam_group_policy`, `aws_iam_policy_document` data sources,
  `jsonencode({...})` bodies, `*_policy_attachment` with AWS managed policies
  (`AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess`)
- Escalation permissions (perspectives IP2): `iam:PassRole` on `*`,
  `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`,
  `iam:Attach{User,Group,Role}Policy`, `iam:Put{User,Group,Role}Policy`,
  `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`,
  `iam:UpdateAssumeRolePolicy`, `iam:AddUserToGroup`, `sts:AssumeRole` on `*`,
  `lambda:UpdateFunctionCode` / `lambda:CreateFunction` + PassRole,
  `ec2:RunInstances` + PassRole, `cloudformation:CreateStack` + PassRole,
  `glue:UpdateDevEndpoint`, `ssm:SendCommand` on privileged instances
- `NotAction` / `NotResource` with `Allow` — almost always broader than meant
- `aws_iam_user`, `aws_iam_access_key`, `aws_iam_user_login_profile` — humans
  should come through IAM Identity Center
- `permissions_boundary` on roles created by delegated admins

## Trust and federation

| Look at | Unsound |
|---|---|
| `aws_iam_role.assume_role_policy` | `Principal: "*"` or `{"AWS": "*"}`; another account's root without `sts:ExternalId` for a third party; no `aws:PrincipalOrgID` where org-only is meant; a condition every caller meets (`ForAllValues:` or `…IfExists` on a key the request can lack, an `aws:PrincipalArn` pattern with a wildcard account under `ArnLike` or `ArnEquals`, which expands wildcards too, `aws:PrincipalOrgID` like `o-*`, a key the caller sets itself such as `aws:PrincipalTag/*`, `aws:RequestTag/*` or `sts:RoleSessionName`) |
| GitHub OIDC (`aws_iam_openid_connect_provider` for `token.actions.githubusercontent.com`, referenced by any name, or a GitHub Enterprise issuer `…/<enterprise>`) | Trust without `token.actions.githubusercontent.com:sub`, or `StringLike` with `repo:*`, `repo:org/*` when one repo is meant; `aud` not `sts.amazonaws.com` |
| EKS IRSA / Pod Identity | Trust without `oidc…:sub` = `system:serviceaccount:<ns>:<sa>` |
| Resource policies (`aws_s3_bucket_policy`, `aws_kms_key.policy`, `aws_kms_key_policy`, `aws_sqs_queue_policy`, `aws_sns_topic_policy`, `aws_ecr_repository_policy`, `aws_secretsmanager_secret_policy`, `aws_lambda_permission`) | `Principal: "*"` without a narrowing condition; external accounts not in `decisions` |

## Data protection

- S3: `aws_s3_bucket_public_access_block` and
  `aws_s3_account_public_access_block` (all four flags `true`),
  `aws_s3_bucket_acl` (`public-read`, `public-read-write`,
  `authenticated-read`; also `acl` on `aws_s3_object`), `aws_s3_bucket_ownership_controls`
  (`BucketOwnerEnforced` disables ACLs), bucket policies, `aws:SecureTransport`
  deny, `aws_s3_bucket_server_side_encryption_configuration`
- Snapshots and images: `aws_ebs_snapshot` / `aws_db_snapshot` sharing,
  `aws_ami_launch_permission` with `group = "all"`,
  `aws_ebs_encryption_by_default`
- RDS / Aurora: `storage_encrypted`, `kms_key_id`, parameter group
  `rds.force_ssl` / `require_secure_transport`
- ElastiCache: `transit_encryption_enabled`, `at_rest_encryption_enabled`,
  `auth_token`
- KMS key policies: `kms:*` to `*` principal; `Decrypt` granted broadly

## Compute and workload

- `metadata_options { http_tokens = "required" }` on `aws_instance` and
  `aws_launch_template`; `http_put_response_hop_limit` 1 (2 for containers on
  EC2), account default `aws_ec2_instance_metadata_defaults`
- `user_data`, ECS `container_definitions` `environment`, Lambda
  `environment.variables`: literal secrets (use `secrets` / Secrets Manager
  references)
- Instance profiles and task roles of internet-facing workloads
- ECS `privileged`, `readonlyRootFilesystem`; ECR `image_tag_mutability`,
  `scan_on_push`

## Serverless and API edge

- `aws_lambda_function_url.authorization_type = "NONE"`
- `aws_lambda_permission` with `principal = "*"` and no `source_arn` /
  `source_account`
- `aws_api_gateway_method.authorization = "NONE"`, `api_key_required` used
  alone; `aws_apigatewayv2_route.authorization_type`
- CloudFront: `origin_access_control` for S3 origins, `viewer_protocol_policy`,
  `minimum_protocol_version`, WAF `web_acl_id`; whether the ALB origin accepts
  traffic from anywhere (origin bypass)

## Logging and detection

- `aws_cloudtrail`: `is_multi_region_trail`, `is_organization_trail`,
  `enable_log_file_validation`, `kms_key_id`, `include_global_service_events`,
  data events for crown-jewel buckets
- `aws_flow_log` per VPC; S3 `aws_s3_bucket_logging`; ALB `access_logs`
- `aws_guardduty_detector` (+ organization admin), `aws_securityhub_account`,
  `aws_config_configuration_recorder`, `aws_accessanalyzer_analyzer`
- CloudWatch `retention_in_days`; log bucket object lock

## Resilience and recovery

- `backup_retention_period`, `deletion_protection`, `skip_final_snapshot`,
  `aws_backup_plan` / `aws_backup_vault_lock_configuration`,
  S3 `versioning` and `object_lock_configuration`, `force_destroy`,
  `lifecycle { prevent_destroy }`

## Governance and pipeline

- `aws_organizations_policy` (SCP, RCP) and attachments: deny leaving the org,
  disabling CloudTrail / GuardDuty, public S3, regions
- State backend `backend "s3"`: `encrypt`, `kms_key_id`, `dynamodb_table` or
  `use_lockfile`, the state bucket's own public access block, versioning and
  policy
- `provider "aws"` with `access_key` / `secret_key` / `profile` hardcoded;
  `assume_role` chains to the apply role
