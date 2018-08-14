#!/usr/bin/env bash
set -o errexit

cd ..
npm install
npm run test

npm run build
npm run minimize

echo "Subresource Integrity"
npm run srisum
