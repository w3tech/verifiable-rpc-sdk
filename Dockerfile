# --- builder -----------------------------------------------------------------
FROM node:24-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS builder
WORKDIR /build
RUN npm i -g pnpm@11.8.0
# Layer-cache friendly: manifests first, then sources. ALL FIVE workspace package
# manifests are required — the lockfile has five importers and the
# --frozen-lockfile check validates the whole workspace.
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json tsconfig.json ./
COPY packages/core/package.json packages/core/
COPY packages/dstack-verify/package.json packages/dstack-verify/
COPY packages/ethers/package.json packages/ethers/
COPY packages/viem/package.json packages/viem/
COPY packages/proxy/package.json packages/proxy/
# Full workspace install (NOT a proxy-filtered subtree): tsup is a ROOT
# devDependency — a filtered install omits the root importer and has no tsup.
RUN pnpm install --frozen-lockfile
# Only the sources the bundle needs (ethers/viem stay manifest-only above).
COPY packages/core/ packages/core/
COPY packages/dstack-verify/ packages/dstack-verify/
COPY packages/proxy/ packages/proxy/
# Workspace deps first: their `exports` resolve to ./dist, so core and
# dstack-verify must be built before the bundler can resolve them.
RUN pnpm --filter "@w3tech.io/vrpc-proxy^..." run build
RUN pnpm --filter @w3tech.io/vrpc-proxy run build:docker

# --- runtime -----------------------------------------------------------------
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:af85d11ce7ef10172855a6e3649e3e8125b1b9e3ca41849ec2918036f05cb212
COPY --from=builder /build/packages/proxy/dist-docker/cli.js /app/cli.js
# Container default: bind all interfaces (see header). CLI flags still override.
ENV VRPC_PROXY_LISTEN=0.0.0.0:8969
EXPOSE 8969
USER nonroot:nonroot
# Array form so `docker run <image> --upstream ... --chain-id ...` appends args.
# No HEALTHCHECK: the proxy has no health endpoint and distroless has no shell.
ENTRYPOINT ["/nodejs/bin/node", "/app/cli.js"]
