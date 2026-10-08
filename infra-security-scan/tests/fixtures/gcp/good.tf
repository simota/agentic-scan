# Fixture: sound counterparts of gcp/main.tf. iac_scan must report nothing here.
resource "google_compute_firewall" "web" {
  name    = "allow-https"
  network = "app"
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "iap_ssh" {
  name    = "allow-iap-ssh"
  network = "app"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
}

resource "google_storage_bucket_iam_member" "reader" {
  bucket = "example-data"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:app@example-project.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "viewer" {
  project = "example-project"
  role    = "roles/viewer"
  member  = "group:dev@example.com"
}

resource "google_storage_bucket" "data" {
  name                        = "example-data"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_sql_database_instance" "main" {
  name             = "main"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/example-project/global/networks/app"
    }
  }
}

resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  metadata = {
    "block-project-ssh-keys" = "true"
  }
  service_account {
    email  = "app@example-project.iam.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
}

resource "google_container_cluster" "main" {
  name     = "main"
  location = "us-central1"
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "10.0.0.0/8"
    }
  }
  workload_identity_config {
    workload_pool = "example-project.svc.id.goog"
  }
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "github"
  attribute_condition                = "assertion.repository_owner == 'example-org'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
