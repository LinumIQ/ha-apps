# Agent Instructions for mTLS Caddy Add-On

## Project Overview
- This is a Home Assistant Add-on built using Docker.
- Key components: `config.yaml` (metadata), `Dockerfile` (build), `run.sh` (entrypoint).

## Home Assistant Add-on Rules
- Always refer to the [official HA Add-on documentation](https://developers.home-assistant.io/docs/add-ons/)
- Configuration MUST follow the `config.yaml` schema; options must be defined there to be accessible via `/data/options.json`.
- All persistent data MUST be stored in `/data`.
- If Ingress is used, ensure `ingress: true` is set in `config.yaml` and the server listens on the correct port.

## Testing Instructions
- Validate `config.yaml` against the official schema before suggesting changes.
- Test the `run.sh` script locally using a mock `/data/options.json` file.