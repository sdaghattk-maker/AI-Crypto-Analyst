Cloudflare Gateway deployment bundle — V6.3.2.3

This is a separate deployment bundle, not the original Flutter application ZIP.

Files:
- ai-gateway/worker.js: copied from the V6.3.2.3 project archive without modification.
- ai-gateway/wrangler.toml: copied from the V6.3.2.3 project archive without modification.
- .github/workflows/deploy-cloudflare-gateway.yml: new manual-only GitHub Actions workflow.

IMPORTANT:
1. Add these files to a separate GitHub branch, not main.
2. Keep the existing build-apk-from-zip.yml unchanged.
3. Before deployment, independently verify that the Cloudflare RATE_LIMITER namespace ID really is 1001. If it differs, STOP; do not deploy this config.
4. Add CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID as GitHub Actions secrets. Never send these secrets to anyone.
5. The workflow is workflow_dispatch only. Adding it to the repository does not deploy anything. Running it initiates a Worker deployment and must only be done after explicit review and authorization.
6. After deployment, manually verify /health and confirm providerCircuitBreakerHealth.bindingConfigured=true and status=HEALTHY.

No deployment has been performed by creating this bundle.
