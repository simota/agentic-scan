# Fixture: sound counterparts of aws/main.tf. iac_scan must report nothing here.
terraform {
  backend "s3" {
    bucket  = "example-state"
    key     = "app/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}

provider "aws" {
  region = "us-east-1"
}

module "vpc_pinned" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
}

module "net" {
  source = "./modules/net"
}

module "pinned_git" {
  source = "git::https://example.com/org/modules.git//net?ref=v1.4.0"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = "example-logs"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = "example-logs"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example-logs/*"
      Condition = { StringEquals = { "aws:SourceVpce" = "vpce-1234" } }
    }]
  })
}

data "aws_iam_policy_document" "app_read" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-logs/*"]
  }
}

resource "aws_iam_role_policy" "app" {
  role   = "app"
  policy = data.aws_iam_policy_document.app_read.json
}

resource "aws_iam_role" "github_pinned" {
  name = "github-pinned"
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:example-org/app:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_db_instance" "app" {
  engine              = "postgres"
  publicly_accessible = false
  storage_encrypted   = true
  password            = var.db_password
  backup_retention_period = 7
}

resource "aws_lambda_function_url" "app" {
  function_name      = "app"
  authorization_type = "AWS_IAM"
}

resource "aws_lambda_permission" "apigw" {
  action        = "lambda:InvokeFunction"
  function_name = "app"
  principal     = "apigateway.amazonaws.com"
}

resource "aws_ebs_volume" "app" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
}

resource "aws_cloudtrail" "org" {
  name                       = "org"
  s3_bucket_name             = "trail"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}

resource "aws_kms_key" "app" {
  description         = "app"
  enable_key_rotation = true
}

resource "aws_eks_cluster" "app" {
  name     = "app"
  role_arn = "arn:aws:iam::111122223333:role/eks"
  vpc_config {
    subnet_ids             = ["subnet-1"]
    endpoint_public_access = false
  }
}
