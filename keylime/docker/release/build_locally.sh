#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Thore Sommer

# Build Docker container locally

VERSION=${1:-latest}
KEYLIME_DIR=${2:-"../../"}

./generate-files.sh ${VERSION} gitlab.ilabt.imec.be:4567/edge-keylime/deploy-keylime-cloud/
for part in base registrar verifier tenant; do
  docker buildx build -t gitlab.ilabt.imec.be:4567/edge-keylime/deploy-keylime-cloud/keylime_${part}:${VERSION} -f ${part}/Dockerfile $KEYLIME_DIR --progress plain ${@:3}
  rm -f ${part}/Dockerfile
done
