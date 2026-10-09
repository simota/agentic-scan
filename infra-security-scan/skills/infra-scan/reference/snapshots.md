# Snapshots — deployed configuration the requester exports

**Read when:** RECON, when the requester wants the deployed state compared with
the IaC, or asks for "live" confirmation; REPORT, to describe snapshot inputs.

This skill never authenticates to a cloud. When deployed configuration is
needed, give the requester the commands below to run **themselves**, with
read-only credentials (AWS `SecurityAudit` or `ReadOnlyAccess`; GCP
`roles/iam.securityReviewer` plus `roles/viewer`, or `roles/cloudasset.viewer`
for the asset export). Ask them to place the output in a directory outside the
repository and pass that path.

Before reading a snapshot, tell the requester it may contain secret values
(function environment variables, user data) and that those values will be
reported by location only.

## AWS (per account and region in scope)

```sh
aws sts get-caller-identity
aws ec2 describe-security-groups            > aws-sg.json
aws ec2 describe-instances                  > aws-instances.json
aws ec2 describe-snapshots --owner-ids self > aws-ebs-snapshots.json
aws s3control get-public-access-block --account-id <account-id> > aws-account-pab.json
aws s3api list-buckets                      > aws-buckets.json
# per bucket:
aws s3api get-bucket-policy --bucket <bucket>          > aws-bucket-<bucket>-policy.json
aws s3api get-public-access-block --bucket <bucket>    > aws-bucket-<bucket>-pab.json
aws iam get-account-authorization-details   > aws-iam.json
aws rds describe-db-instances               > aws-rds.json
aws lambda list-function-url-configs --function-name <fn> > aws-lambda-<fn>-url.json
aws cloudtrail describe-trails              > aws-cloudtrail.json
aws organizations list-policies --filter SERVICE_CONTROL_POLICY > aws-scps.json
```

`get-account-authorization-details` is the single most useful export: every
user, group, role, trust policy and policy version.

## GCP (per project; org-level commands need org-level read)

```sh
gcloud projects get-iam-policy <project> --format=json               > gcp-iam.json
gcloud compute firewall-rules list --project <project> --format=json > gcp-firewall.json
gcloud compute instances list --project <project> --format=json      > gcp-instances.json
gcloud sql instances list --project <project> --format=json          > gcp-sql.json
gcloud storage buckets list --project <project> --format=json        > gcp-buckets.json
gcloud container clusters list --project <project> --format=json     > gcp-gke.json
gcloud run services list --project <project> --format=json           > gcp-run.json
gcloud org-policies list --project <project> --format=json           > gcp-org-policies.json
# whole organization in one export (needs Cloud Asset API):
gcloud asset search-all-iam-policies --scope=organizations/<org-id> --format=json > gcp-iam-all.json
```

## Kubernetes

```sh
kubectl get clusterrolebindings,rolebindings -A -o json > k8s-rbac.json
kubectl get pods -A -o json                             > k8s-pods.json
kubectl get networkpolicies -A -o json                  > k8s-netpol.json
kubectl get ns -o json                                  > k8s-namespaces.json
```

Do not export `secrets`.

## Reading snapshots

- Pass the export directory to the same baseline run as the repository:
  `scripts/iac_scan.py <repo> --snapshots <exports> --out <out>/iac.json --into <out>/findings.json`.
  Each run replaces the whole `I-*` baseline, so a separate run on the exports
  alone would drop the repository's hits. Snapshot files are reported as
  `@snapshots/<dir>/<file>` and never excerpted in the reports
- `iac_scan.py` applies its rules to snapshot shapes it recognises
  (`SecurityGroups`, IAM policy `bindings`, firewall lists, bucket policy
  `Statement`, and Kubernetes objects or `List`s from `kubectl … -o json`);
  others are read by hand
- Record a snapshot's capture time in its `meta.inputs[].note`; an input
  entry holds only `kind`, `path` and `note`
- Exports saved by Windows PowerShell (`>` writes UTF-16) are read; other
  encodings are listed in `not_run`
- Match each snapshot resource to an IaC resource by ID, name or tag. Unmatched
  snapshot resources are drift (perspective *Coverage and drift*, CD2) and are
  reviewed like any other resource
- A snapshot shows one moment; its capture time goes in `meta.inputs[].note`
- A finding confirmed by a snapshot but absent from the IaC is still a
  finding; its fix includes bringing the resource under IaC
