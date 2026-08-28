#!/bin/bash
set -e

PATCH='[
  {"op":"replace","path":"/metadata/labels/delivery-gear.gardener.cloud~1claimed","value":"False"},
  {"op":"remove","path":"/metadata/annotations/delivery-gear.gardener.cloud~1claimed-by"},
  {"op":"remove","path":"/metadata/annotations/delivery-gear.gardener.cloud~1claimed-at"}
]'

for item in $(kubectl get backlogitems \
  -l 'delivery-gear.gardener.cloud/claimed=True' \
  -o jsonpath='{.items[*].metadata.name}'); do
  echo "Unclaiming $item"
  kubectl patch backlogitems "$item" --type=json -p="$PATCH"
done
