# Copyright (C) 2024 Alexandre Nicolaie (xunleii@users.noreply.github.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------
#

# ┌───────────────────────────────────────────────────────────────────────────┐
# │ <machine-id>: Generate a machine-id for the container.                    │
# |                                                                           │
# │ NOTE: This image will be cached (and the machine-id too) in               │
# │       order to have a persistent machine-id even if the                   │
# │       image is rebuilt.                                                   │
# └───────────────────────────────────────────────────────────────────────────┘
FROM docker.io/library/alpine:3.20.1 as machine-id
RUN apk add --no-cache dbus \
    && dbus-uuidgen > /etc/machine-id

# ┌───────────────────────────────────────────────────────────────────────────┐
# │ <devcontainer>: Create a slim development container with Golang.          │
# └───────────────────────────────────────────────────────────────────────────┘
FROM mcr.microsoft.com/devcontainers/rust:bookworm

# Install mise package manager
COPY --from=docker.io/jdxcode/mise:v2024.7.3@sha256:d284e59e73c14b5d06074e277f91d80da58909a614ef38f02386adf47e2483d3 /usr/local/bin/mise /usr/local/bin/mise
RUN mise settings set experimental true

# Copy generated machine-id
COPY --from=machine-id /etc/machine-id /etc/machine-id

# Configure lazygit
COPY --chown=vscode:vscode config/home.vscode..config.lazygit.config.yaml /home/vscode/.config/lazygit/config.yml
