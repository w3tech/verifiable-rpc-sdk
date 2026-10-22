# --- builder -----------------------------------------------------------------
FROM node:26-slim@sha256:36793bcbb160a6a16cede1e62b93f84e26b78a972a8a4c0b879c1c12f22761ec AS builder
WORKDIR /build
RUN npm i -g pnpm@11.8.0
# Layer-cache friendly: manifests first, then sources. The five published package manifests
# are enough: --frozen-lockfile accepts the uncopied test-support and examples importers.
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
FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:3a6f4e6fd37efe00042667d06fd52240f2589ed09b0694fbb3b1bf860030a839
COPY --from=builder /build/packages/proxy/dist-docker/cli.js /app/cli.js
# Container default: bind all interfaces (see header). CLI flags still override.
ENV VRPC_PROXY_LISTEN=0.0.0.0:8969
EXPOSE 8969
USER nonroot:nonroot
# Array form so `docker run <image> --upstream ... --chain-id ...` appends args.
# No HEALTHCHECK: the proxy has no health endpoint and distroless has no shell.
ENTRYPOINT ["/nodejs/bin/node", "/app/cli.js"]
