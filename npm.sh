#!/bin/bash

if [[ ! "$1" =~ ^(major|minor|patch)$ ]]; then
  echo "./publish.sh [major|minor|patch]"
  exit 1
fi

cd js;

echo "Incrementing version: $1..."
npm version "$1"


npm publish

echo "pkg published on npm"