# Rancher Let's Encrypt Service

## Let's Encrypt verification

Let's Encrypt has two methods of verifying ownership of domains. The first is through the addition of a custom DNS record (say acme-12321313.subdomain.domain.com). This is what https://github.com/janeczku/rancher-letsencrypt does. That service creates Let's Encrypt challenges via DNS resolution. The other way of proving ownership of domains is through a webserver webroot over HTTP. 

## Our Service

With our environment, we wanted to do webroot verification for Let's Encrypt and Rancher. We wanted a service that would manage TLS certificates automatically, and renew them as needed. We also wanted this tightly integrated with Rancher for complete automation. This way load balancers (and other services) could automatically pick up certs through the Rancher API. Also, when we update a cert in Rancher, the load balancers will receive the updated cert with zero downtime. We also did not want to give keys for updating DNS records for our entire domain to every rancher environment for security purposes (isolation is best!)

## How it Works

The service launches two containers:
- `letsencrypt-nginx`
- `letsencrypt-python`

The `letsencrypt-nginx` container is stock nginx, but shares the webroot with the `letsencrypt-python` service container. This way the `letsencrypt-python` container can add ACME challenges to the `<host>/.well-known/acme-challenge/` directory on the webserver for verification. The python container is a sidekick of the nginx container. The containers are launched as a Rancher Service Account, so special environment variables containing the Rancher server API url, and access keys are passed into the container at runtime. 

## Requirements

- DNS control of domain names (ability to create host.subdomain.domain.com records to point to Rancher IP)
- Front-end load balancer exposing port 80 to the internet for Let's Encrypt verification
- This Rancher service

## How to use

Create a front end load balancer (or use the one in `traffic-manager` directory). If you are making one, you need to make sure it is a L7 HTTP load balancer on port 80. This way the load balancer can redirect /.well-known/\* traffic to the `letsencrypt-nginx` container for verification. You can then route all other traffic to your normal HTTP services. This way only during verification does traffic get directed to the `letsencrypt-nginx` container. Use `rancher-compose up` to launch the stack in rancher. **In order to get a Let's Encrypt Production certificate, you must set the environment variable STAGING=False**. This will then tell the service to use the production Let's Encrypt api instead of the staging api.

# Certificate Workflows

"staging" refers to Let's Encrypt staging API.
"production" refers to Let's Encrypt production API.

This flowchart/execution diagram shows all the cases the service deals with, and how it responds to different stages.

- get certs from rancher API
    - local copy of cert
        - cert in rancher
            - upgrade staging cert to production
                - create cert
                - push to rancher
            - upgrade self signed cert to production
                - create cert
                - push to rancher
            - rancher cert expired
                - local cert expired
                    - create cert (renew)
                    - push to rancher
                - local cert not expired
                    - push to rancher
        - cert not in rancher
            - local cert expired
                - create cert
                - push to rancher
            - local cert not expired
                - push to rancher
    - no local copy of cert
        - create cert
        - push to rancher
