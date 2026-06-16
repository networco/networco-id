terraform {
  required_version = ">= 1.6.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token"
  type        = string
  sensitive   = true
}

variable "vps_nodes" {
  description = "List of VPS nodes to provision"
  type = list(object({
    name       = string
    ip         = string
    ssh_user   = string
    role       = string
    datacenter = string
  }))
  default = [
    {
      name       = "srv01"
      ip         = "217.170.206.215"
      ssh_user   = "root"
      role       = "server"
      datacenter = "oslo-stw"
    },
    {
      name       = "srv02"
      ip         = "85.136.80.232"
      ssh_user   = "root"
      role       = "server"
      datacenter = "oslo-stw"
    },
    {
      name       = "srv03"
      ip         = "104.233.9.174"
      ssh_user   = "root"
      role       = "server"
      datacenter = "oslo-stw"
    },
    {
      name       = "srv04"
      ip         = "104.233.9.235"
      ssh_user   = "root"
      role       = "server"
      datacenter = "oslo-stw"
    }
  ]
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

data "cloudflare_zone" "networco" {
  name = "networco.no"
}

# NetworcoID subdomain - creates one A record per server
resource "cloudflare_record" "networcoid" {
  for_each = { for idx, node in var.vps_nodes : node.name => node if node.ip != "" }

  zone_id = data.cloudflare_zone.networco.id
  name    = "id.networco"
  type    = "A"
  content = each.value.ip
  ttl     = 300
  proxied = false

  comment = "NetworcoID OIDC Provider - ${each.value.name}"
}

output "networcoid_ips" {
  value = [for record in cloudflare_record.networcoid : record.content]
}

output "networcoid_url" {
  value = "https://id.networco.no"
}
