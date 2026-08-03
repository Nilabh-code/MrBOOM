# DrDOOM harness — code-protected Docker image
# Multi-stage:
#   pd-builder  -> compiles ProjectDiscovery Go tools (native, open source)
#   nuitka      -> compiles app.py + deps to a native standalone binary (NO .py ships)
#   runtime     -> slim image with only the compiled binary + data + PD tools

# ---- Stage 1: ProjectDiscovery tools ----
FROM golang:1.26 AS pd-builder
ENV GOPATH=/go GOFLAGS=-buildvcs=false
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
 && go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest \
 && go install github.com/projectdiscovery/uncover/cmd/uncover@latest

# ---- Stage 2: Nuitka compile (no source survives to runtime) ----
FROM python:3.12-slim AS nuitka
ENV PIP_NO_CACHE_DIR=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc g++ python3-dev patchelf \
 && rm -rf /var/lib/apt/lists/*
RUN pip install nuitka \
 && pip install -r requirements.txt

WORKDIR /build
COPY app.py requirements.txt stealth.py clientside.py cvemap.py /build/

# --standalone: native binary + minimal python lib bundle in app.dist/
# --nofollow-import-to: keep only runtime-needed stdlib; bundled modules resolved by name
RUN python -m nuitka --standalone \
      --enable-plugin=no-qt \
      --include-module=uvicorn \
      --include-module=fastapi \
      --include-module=pydantic \
      --include-package=starlette \
      --include-package=uvicorn \
      --include-module=stealth \
      --include-module=clientside \
      --include-module=cvemap \
      --output-dir=/out \
      app.py

# ---- Stage 3: runtime ----
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      dnsutils netcat-openbsd whois ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*

# PD tools (open-source, fine to ship)
COPY --from=pd-builder /go/bin/* /usr/local/bin/

# Compiled app only — the Python source lives in app.py but never ships.
COPY --from=nuitka /out/app.dist/ /app/

# Runtime data assets
COPY frontend.html /app/frontend.html
COPY marked.min.js /app/marked.min.js
COPY wordlists/ /app/wordlists/
RUN mkdir -p /app/skills /app/scan_history

ENV DRDOOM_DATA_DIR=/app
ENV PATH="/usr/local/bin:${PATH}"

EXPOSE 8085
CMD ["/app/app.bin"]
