#!/usr/bin/env bash

set -euo pipefail

accordlock_find_system_tool() {
    local tool_name="$1"
    local wrapper_path="$2"
    local path_entry
    local resolved_directory
    local candidate
    local -a path_entries=()

    IFS=':' read -r -a path_entries <<< "${PATH-}"
    for path_entry in "${path_entries[@]}"; do
        case "${path_entry}" in
            /*) ;;
            *) continue ;;
        esac

        resolved_directory="$(cd -P -- "${path_entry}" 2>/dev/null && pwd -P)" || continue
        candidate="${resolved_directory}/${tool_name}"
        if [[ ! -f "${candidate}" || ! -x "${candidate}" ]]; then
            continue
        fi
        if [[ "${candidate}" -ef "${wrapper_path}" ]]; then
            continue
        fi

        printf '%s\n' "${candidate}"
        return 0
    done

    return 1
}

accordlock_exec_system_tool() {
    local tool_name="$1"
    local wrapper_path="$2"
    local executable
    shift 2

    if ! executable="$(accordlock_find_system_tool "${tool_name}" "${wrapper_path}")"; then
        printf '%s\n' \
            "[AccordLock] ${tool_name} is required but was not found outside the application bundle." \
            "Install it through your organization's approved system provisioning, then restart AccordLock." \
            >&2
        return 127
    fi

    exec "${executable}" "$@"
}
