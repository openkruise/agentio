#!/usr/bin/env bash
# Verifies every Go source file added or modified relative to a base ref follows
# the logging convention recorded in AGENTS.md: one stack per process, klog and
# the stdlib logger bridged only at the entrypoints, no console diagnostics, no
# process exit outside main, no verbosity decoration on logr Error, and one
# error vocabulary.
# Runs in CI on PRs and pushes. macOS bash 3.2 compatible.
set -euo pipefail

BASE="${1:-${BASE_REF:-}}"
if [[ -z "${BASE}" ]]; then
  if git rev-parse --verify -q origin/main >/dev/null 2>&1; then
    BASE="$(git merge-base origin/main HEAD)"
  elif git rev-parse --verify -q origin/master >/dev/null 2>&1; then
    BASE="$(git merge-base origin/master HEAD)"
  else
    BASE="HEAD~1"
  fi
fi

FILES=()
while IFS= read -r line; do
  [[ -n "${line}" ]] && FILES+=("${line}")
done < <(
  {
    git diff --name-only --diff-filter=ACM "${BASE}" -- '*.go' || true
    git ls-files --others --exclude-standard -- '*.go' || true
  } | sort -u
)

ec=0
checked=0

report() {
  echo "::error file=${1},line=${2}::${3}"
  ec=1
}

# scan reports every line of a file matching an extended regular expression.
scan() {
  local file="$1" pattern="$2" message="$3" ln
  while IFS= read -r ln; do
    [[ -n "${ln}" ]] || continue
    report "${file}" "${ln}" "${message}"
  done < <(grep -nE "${pattern}" "${file}" 2>/dev/null | cut -d: -f1 || true)
}

is_test() {
  case "$1" in
    *_test.go) return 0 ;;
    *) return 1 ;;
  esac
}

for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "${f}" ]] || continue
  case "${f}" in
    vendor/* | */testdata/*) continue ;;
  esac
  if head -n 20 "${f}" | grep -qE 'Code generated .* DO NOT EDIT'; then
    continue
  fi
  checked=$((checked + 1))

  # 1. The two stacks are split by process. agentiod logs through pkg/log, EPE
  #    through controller-runtime's logr. Neither imports the other's stack.
  case "${f}" in
    extensions/*)
      case "${f}" in
        # This test asserts the bridge that routes pkg/log records into EPE's
        # zap core, so it must import both sides.
        extensions/epe/cmd/epe/logging_test.go) ;;
        *)
          scan "${f}" '"github\.com/openkruise/agentio/pkg/log"' \
            "extensions/ logs through logr; pkg/log belongs to the agentiod process"
          ;;
      esac
      ;;
    *)
      scan "${f}" '"github\.com/go-logr/(logr|zapr)"|"go\.uber\.org/zap|controller-runtime/pkg/log' \
        "logr and zap belong to the EPE process; log through github.com/openkruise/agentio/pkg/log"
      ;;
  esac

  # 2. klog and the stdlib logger are owned by process entrypoints. Tests are
  #    exempt because the ones that assert a bridge must call it.
  if ! is_test "${f}"; then
    case "${f}" in
      cmd/agentiod/logging.go | extensions/epe/cmd/epe/main.go | test/fixtures/extproc/main.go) ;;
      *)
        scan "${f}" '(^|[^[:alnum:]_."])klog\.' \
          "klog is bridged once in the process entrypoint; use the package logger"
        scan "${f}" '^[[:space:]]*("log"|log "log")$' \
          "the stdlib log package is bridged once in the process entrypoint; use the package logger"
        ;;
    esac
  fi

  # 3. Console output is a CLI surface, not a diagnostics channel.
  if ! is_test "${f}"; then
    case "${f}" in
      cmd/* | test/e2e/* | tools/* | pkg/server/env.go) ;;
      *)
        scan "${f}" 'fmt\.Print|fmt\.Fprint(f|ln)?\(os\.Std(out|err)' \
          "use the package logger; fmt.Print is only for CLI surfaces and the e2e harness"
        ;;
    esac
  fi

  # 4. Only main decides that the process should stop.
  if ! is_test "${f}"; then
    case "${f}" in
      cmd/*/main.go | extensions/*/cmd/*/main.go | test/e2e/cmd/*/main.go | tools/*/main.go) ;;
      *)
        scan "${f}" 'os\.Exit\(' \
          "os.Exit belongs in main; return the error and let the entrypoint log it"
        ;;
    esac
  fi

  # 5. logr applies verbosity to Info only, so V(...) on Error reads as a
  #    suppressible log but is not one.
  scan "${f}" '\.V\([^)]*\)\.Error\(' \
    "logr ignores V() on Error; drop the verbosity decoration"

  # 6. One key for the error value, and the value itself rather than its string.
  #    Passing nil as logr's first argument is not checked: some call sites
  #    legitimately have no error value in scope, so that is a review judgement.
  scan "${f}" '"err",' \
    'attach the error as "error", err (agentiod) or logger.Error(err, msg) (EPE)'
  scan "${f}" '"(err|error|reason)", *[[:alnum:]_.]+\.Error\(\)' \
    'attach the error value under "error"; a stringified error loses the type'
done

if [[ ${ec} -ne 0 ]]; then
  echo ""
  echo "Logging check FAILED. See the AGENTS.md 'Logging' section for the convention."
  exit 1
fi
echo "Logging check passed (${checked} changed source file(s) verified against ${BASE})."
