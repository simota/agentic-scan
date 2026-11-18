# Fixture: deliberately weak AWS configuration for iac_scan tests. Not deployable.
terraform {
  backend "s3" {
    bucket = "example-state"
    key    = "app/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = var.access_key
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}

module "legacy" {
  source = "git::https://example.com/org/modules.git//net"
}

resource "aws_security_group" "ssh" {
  name        = "ssh-${var.env}" /* a comment with a { brace */
  description = "allow {all} admins"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] // open to the world
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "example-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.data.arn}/*"
    }]
  })
}

resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}
EOF
}

data "aws_iam_policy_document" "deployer" {
  statement {
    actions   = ["iam:PassRole", "ec2:RunInstances"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deployer" {
  role   = aws_iam_role.github.id
  policy = data.aws_iam_policy_document.deployer.json
}

resource "aws_iam_role" "github" {
  name = "github-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
      }
    }]
  })
}

resource "aws_iam_role" "vendor" {
  name = "vendor"
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = "*" } }]
  })
}

resource "aws_iam_access_key" "ci" {
  user = "ci"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
  password            = "example-literal-not-real"
  backup_retention_period = 0
}

resource "aws_lambda_function_url" "api" {
  function_name      = "api"
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "any" {
  action        = "lambda:InvokeFunction"
  function_name = "api"
  principal     = "*"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
}

resource "aws_cloudtrail" "main" {
  name                  = "main"
  s3_bucket_name        = "trail"
  is_multi_region_trail = false
}

resource "aws_kms_key" "data" {
  description = "data"
}

resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::111122223333:role/eks"
  vpc_config {
    subnet_ids             = ["subnet-1"]
    endpoint_public_access = true
  }
}

resource "aws_ami_launch_permission" "public" {
  image_id = "ami-12345678"
  group    = "all"
}

resource "aws_cloudfront_distribution" "site" {
  enabled = true
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
