#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

phase=""
strict=1

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$tool" >&2
    exit 1
  fi
}

usage() {
  cat <<'EOF'
usage: bash scripts/rearchitecture/phase_gate_check.sh --phase <phase-name> [--strict|--no-strict]
       bash scripts/rearchitecture/phase_gate_check.sh <phase-name>

Supported phases:
  phase0 phase1 phase2 phase3 phase4 phase5 phase6

Exit codes:
  0  requested gate passed
  1  requested gate failed in strict mode
  2  invalid arguments or unsupported phase
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)
      if [[ $# -lt 2 ]]; then
        printf 'missing value for --phase\n\n' >&2
        usage >&2
        exit 2
      fi
      phase="$2"
      shift 2
      ;;
    --strict)
      strict=1
      shift
      ;;
    --no-strict)
      strict=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    phase0|phase1|phase2|phase3|phase4|phase5|phase6)
      if [[ -n "$phase" ]]; then
        printf 'phase specified multiple times\n\n' >&2
        usage >&2
        exit 2
      fi
      phase="$1"
      shift
      ;;
    *)
      printf 'unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$phase" ]]; then
  usage >&2
  exit 2
fi

check_file() {
  local file="$1"
  if [[ ! -s "$file" ]]; then
    printf 'missing-or-empty: %s\n' "$file" >&2
    return 1
  fi
}

require_no_matches() {
  local label="$1"
  shift

  local output
  set +e
  output="$($@ 2>/dev/null)"
  local status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    if [[ -n "$output" ]]; then
      printf 'gate-failed [%s]: unexpected matches\n%s\n' "$label" "$output" >&2
      return 1
    fi
    printf 'gate-ok [%s]\n' "$label"
    return 0
  fi

  if [[ "$status" -eq 1 ]]; then
    printf 'gate-ok [%s]\n' "$label"
    return 0
  fi

  printf 'gate-error [%s]: command failed with exit %d\n' "$label" "$status" >&2
  return "$status"
}

phase0_required=(
  "plans/phase0/baselines/cli-baseline-matrix.md"
  "plans/phase0/baselines/config-baseline-matrix.md"
  "plans/phase0/baselines/failure-baseline-matrix.md"
  "plans/phase0/baselines/performance-baseline-matrix.md"
  "plans/phase0/architecture/final-directory-tree-final.md"
  "plans/phase0/architecture/layer-responsibilities-final.md"
  "plans/phase0/architecture/dependency-directions-final.md"
  "plans/phase0/architecture/ports-catalog-final.md"
  "plans/phase0/architecture/architecture-guard-rules-final.md"
  "plans/phase0/architecture/transitional-code-rules-final.md"
  "plans/phase0/models/config-model-final.md"
  "plans/phase0/models/state-model-final.md"
  "plans/phase0/models/plugin-model-final.md"
  "plans/phase0/migration/path-mapping-final.md"
  "plans/phase0/migration/removal-schedule-final.md"
  "plans/phase0/migration/legacy-freeze-rules-final.md"
  "plans/phase0/reviews/phase0-import-audit-baseline.md"
  "plans/phase0/reviews/phase-gate-template.md"
  "plans/phase0/reviews/phase0-completion-review.md"
  "plans/phase0/reviews/phase1-input-package.md"
  "scripts/rearchitecture/import_audit.sh"
  "scripts/rearchitecture/transitional_code_audit.sh"
  "scripts/rearchitecture/phase_gate_check.sh"
  ".github/workflows/rearchitecture-guard.yml"
)

phase_common_required=(
  "plans/20260415-complete-rearchitecture-plan.md"
  "plans/20260417-code-execution-plan.md"
)

phase1_required=(
  "plans/20260415-phase1-execution-backlog.md"
  "plans/20260417-phase1-code-execution-plan.md"
  "plans/phase0/reviews/phase1-input-package.md"
)

phase2_required=(
  "plans/20260415-phase2-execution-backlog.md"
  "plans/20260417-phase2-code-execution-plan.md"
)

phase3_required=(
  "plans/20260415-phase3-execution-backlog.md"
  "plans/20260417-phase3-code-execution-plan.md"
)

phase4_required=(
  "plans/20260415-phase4-execution-backlog.md"
  "plans/20260417-phase4-code-execution-plan.md"
)

phase5_required=(
  "plans/20260415-phase5-execution-backlog.md"
  "plans/20260417-phase5-code-execution-plan.md"
)

phase6_required=(
  "plans/20260415-phase6-execution-backlog.md"
  "plans/20260417-phase6-code-execution-plan.md"
  "internal/ports/config.go"
  "internal/ports/datapath.go"
  "internal/ports/plugin.go"
  "internal/ports/runtime.go"
  "internal/ports/observability.go"
  "internal/ports/storage.go"
)

check_required_files() {
  local files=("$@")
  for file in "${phase_common_required[@]}"; do
    check_file "$file"
  done
  for file in "${files[@]}"; do
    check_file "$file"
  done
}

printf '== Phase Gate Check ==\n'
printf 'phase: %s\n\n' "$phase"

case "$phase" in
  phase0)
    check_required_files "${phase0_required[@]}"
    bash scripts/rearchitecture/import_audit.sh --strict >/tmp/netxfw-phase0-import-audit.txt
    bash scripts/rearchitecture/transitional_code_audit.sh --strict >/tmp/netxfw-phase0-transitional-audit.txt
    printf 'phase0 gate passed\n'
    ;;
  phase1)
    check_required_files "${phase1_required[@]}"
    printf 'phase1 gate passed\n'
    ;;
  phase2)
    check_required_files "${phase2_required[@]}"
    require_no_matches \
      "phase2:no-configtypes-production-imports" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal cmd pkg --include '*.go' --exclude '*_test.go' --pattern 'internal/configtypes'
    printf 'phase2 gate passed\n'
    ;;
  phase3)
    check_required_files "${phase3_required[@]}"
    require_no_matches \
      "phase3:no-backend-imports-app-daemon-domain" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal/app internal/daemon internal/domain --include '*.go' --exclude '*_test.go' --pattern '^\s*(backendxdp\s+)?"github.com/netxfw/netxfw/internal/datapath/xdp/backend"'
    printf 'phase3 gate passed\n'
    ;;
  phase4)
    check_required_files "${phase4_required[@]}"
    require_no_matches \
      "phase4:no-plugin-backend-imports" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal/datapath/xdp/plugins internal/app/plugin internal/app/ops_xdp.go --include '*.go' --exclude '*_test.go' --pattern 'internal/datapath/xdp/backend'
    printf 'phase4 gate passed\n'
    ;;
  phase5)
    check_required_files "${phase5_required[@]}"
    bash scripts/rearchitecture/import_audit.sh --strict >/tmp/netxfw-phase5-import-audit.txt
    require_no_matches \
      "phase5:no-configtypes-or-xdpbackend-outside-facades" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal/app internal/daemon internal/domain internal/metrics internal/optimizer internal/plugins cmd --include '*.go' --exclude '*_test.go' --pattern 'internal/adapters/datapath/xdpbackend|internal/configtypes'
    printf 'phase5 gate passed\n'
    ;;
  phase6)
    check_required_files "${phase6_required[@]}"
    bash scripts/rearchitecture/import_audit.sh --strict >/tmp/netxfw-phase6-import-audit.txt
    bash scripts/rearchitecture/transitional_code_audit.sh --strict >/tmp/netxfw-phase6-transitional-audit.txt
    require_no_matches \
      "phase6:no-domain-sdk-imports" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal/domain --include '*.go' --pattern 'github.com/netxfw/netxfw/pkg/sdk'
    require_no_matches \
      "phase6:no-production-config-centers" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal cmd pkg --include '*.go' --exclude '*_test.go' --pattern 'internal/configtypes|internal/config\b'
    require_no_matches \
      "phase6:no-xdpbackend-bridge-imports" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal cmd pkg --include '*.go' --exclude '*_test.go' --pattern 'internal/adapters/datapath/xdpbackend|statsbridge|healthbridge|syncbridge|mapbridge'
    require_no_matches \
      "phase6:no-runtime-legacy-plugin-center-imports" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal/app internal/adapters internal/daemon internal/domain internal/datapath cmd pkg --include '*.go' --exclude '*_test.go' --pattern 'internal/plugins(?!/(logengine|metricsplugin|webplugin))|GetRuntimePlugins'
    require_no_matches \
      "phase6:no-production-transitional-markers" \
      python3 scripts/rearchitecture/python_scan.py content --roots internal/app internal/adapters internal/api internal/daemon internal/datapath internal/domain internal/metrics internal/optimizer internal/plugins internal/runtime internal/utils cmd pkg --include '*.go' --exclude '*_test.go' --pattern 'legacy|compat|migration|transitional'
    printf 'phase6 gate passed\n'
    ;;
  *)
    printf 'unsupported phase gate: %s\n' "$phase" >&2
    exit 2
    ;;
esac

if [[ "$strict" != "1" ]]; then
  exit 0
fi

