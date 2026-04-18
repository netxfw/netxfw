#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

phase=""
strict=1

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
    printf 'phase2 gate passed\n'
    ;;
  phase3)
    check_required_files "${phase3_required[@]}"
    printf 'phase3 gate passed\n'
    ;;
  phase4)
    check_required_files "${phase4_required[@]}"
    printf 'phase4 gate passed\n'
    ;;
  phase5)
    check_required_files "${phase5_required[@]}"
    printf 'phase5 gate passed\n'
    ;;
  phase6)
    check_required_files "${phase6_required[@]}"
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
