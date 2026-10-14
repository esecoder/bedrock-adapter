#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-test}" in
  test) python3 test_bedrock.py ;;
  demo) python3 -c "
import bedrock as B, json
m = B.MODELS['claude-3-5-sonnet']
h, p = B.build_url(m, 'us-east-1')
print('  host :', h)
print('  path :', p)
print('  body :', json.dumps(json.loads(B.build_body(m, 'hello')), indent=2))
" ;;
  *) sed -n '2,5p' "$0" ;;
esac
