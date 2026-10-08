# Fixture: deliberately weak GCP configuration for iac_scan tests. Not deployable.
resource "google_compute_firewall" "ssh" {
  name    = "allow-ssh"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22", "8000-8100"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = "example-assets"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_project_iam_member" "owner" {
  project = "example-project"
  role    = "roles/owner"
  member  = "user:dev@example.com"
}

resource "google_project_iam_binding" "token" {
  project = "example-project"
  role    = "roles/iam.serviceAccountTokenCreator"
  members = ["group:dev@example.com"]
}

resource "google_service_account_key" "ci" {
  service_account_id = google_service_account.ci.name
}

resource "google_storage_bucket" "data" {
  name                        = "example-data"
  location                    = "US"
  uniform_bucket_level_access = false
}

resource "google_sql_database_instance" "main" {
  name             = "main"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  metadata = {
    "serial-port-enable" = "true"
  }
  service_account {
    scopes = ["cloud-platform"]
  }
}

resource "google_container_cluster" "main" {
  name               = "main"
  location           = "us-central1"
  enable_legacy_abac = true
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
