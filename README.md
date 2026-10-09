# Splitflap ESP32-S3 firmware

Public signed firmware releases for a four-digit ESP-IDF countdown. Source is maintained separately.

Install the signed `firmware.sfu` from Releases through the authenticated device web panel. Confirm ESP32-S3 hardware and wiring before first serial flash. Releases include software build/test evidence; physical mechanics, Wi-Fi and OTA behavior require device verification.

Do not connect motors directly to the PCF8575; external drivers are required. No universal Wi-Fi or panel passwords are included.

## Automated releases

The private source repository tests, builds and signs firmware. A dedicated SSH deploy key can write only to this public repository; its private part is an encrypted Actions secret in the private repository. Only approved ready-made assets and delivery metadata are pushed to `delivery`. Firmware source and the signing private key remain private.

The public `Publish delivered firmware` workflow validates checksums, the RSA signature, manifest and actual ESP32-S3 application version, then publishes using this repository's short-lived `GITHUB_TOKEN`. Existing releases are never overwritten: identical asset bytes and notes are an idempotent success; any difference fails. Verification mode cannot create a release or change `latest`.

For a future version, run **Publish signed firmware** in the private source repository with its new canonical version, or push a matching `vMAJOR.MINOR.PATCH` source tag. Wait for both the private delivery workflow and this public publishing workflow to succeed. Retrying a completed delivery is safe. An interrupted new release upload may leave a draft for manual inspection; the workflow refuses to overwrite that draft.

The deploy key is restricted to one repository, not one branch. Its workflow only pushes prepared delivery files. Revoke or rotate it in this repository's Settings → Deploy keys and replace `FIRMWARE_DEPLOY_KEY` in the private repository when needed. No personal token is required in either CI workflow.
