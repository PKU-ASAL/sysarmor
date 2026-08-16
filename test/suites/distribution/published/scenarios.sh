#!/usr/bin/env bash

release_scenarios() {
  printf '%s\n' web-runtime-shell download-by-lolbin reverse-shell suspicious-exec-connect payload-lifecycle
}

scenario_rule() {
  case "$1" in
    web-runtime-shell) printf '%s\n' web_runtime_spawns_shell ;;
    download-by-lolbin) printf '%s\n' download_by_lolbin ;;
    reverse-shell) printf '%s\n' reverse_shell_pattern ;;
    suspicious-exec-connect) printf '%s\n' suspicious_exec_connect ;;
    payload-lifecycle) printf '%s\n' payload_lifecycle ;;
    *) return 1 ;;
  esac
}

scenario_severity() {
  case "$1" in
    web-runtime-shell|suspicious-exec-connect|payload-lifecycle) printf '%s\n' high ;;
    download-by-lolbin) printf '%s\n' medium ;;
    reverse-shell) printf '%s\n' critical ;;
    *) return 1 ;;
  esac
}

scenario_behaviors() {
  case "$1" in
    web-runtime-shell) printf '%s\n' process.exec ;;
    download-by-lolbin) printf '%s\n' network.connect ;;
    reverse-shell) printf '%s\n' network.connect ;;
    suspicious-exec-connect) printf '%s\n' 'process.exec network.connect' ;;
    payload-lifecycle) printf '%s\n' 'file.write process.exec network.connect' ;;
    *) return 1 ;;
  esac
}

scenario_ports() {
  case "$1" in
    web-runtime-shell) return 0 ;;
    download-by-lolbin) printf '%s\n' 8080 ;;
    reverse-shell|suspicious-exec-connect) printf '%s\n' 8443 ;;
    payload-lifecycle) printf '%s\n' 8443 ;;
    *) return 1 ;;
  esac
}

scenario_attack() {
  case "$1" in
    web-runtime-shell) printf '%s\n' web-runtime-shell.sh ;;
    download-by-lolbin) printf '%s\n' download-by-lolbin.sh ;;
    reverse-shell) printf '%s\n' reverse-shell.sh ;;
    suspicious-exec-connect) printf '%s\n' suspicious-exec-connect.sh ;;
    payload-lifecycle) printf '%s\n' payload-lifecycle.sh ;;
    *) return 1 ;;
  esac
}

scenario_stage() {
  case "$1" in
    reverse-shell) printf '%s\n' SIGNAL_STAGE_CONCLUSION ;;
    web-runtime-shell|download-by-lolbin|suspicious-exec-connect|payload-lifecycle) printf '%s\n' SIGNAL_STAGE_CANDIDATE ;;
    *) return 1 ;;
  esac
}
