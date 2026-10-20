#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
"$PYTHON" -m stac_attack_lab.attack_program.r4_real_diagnosis_cli "$@"
