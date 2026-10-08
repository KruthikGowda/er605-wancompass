#!/usr/bin/env bash
# Read a v1/v2c community into a private temporary Net-SNMP config, never argv.

snmp_community_setup() {
    read -r -s -p "SNMP read-only community: " NP_SNMP_COMMUNITY
    echo
    if [[ -z $NP_SNMP_COMMUNITY ]]; then
        echo "The community cannot be empty." >&2
        return 2
    fi
    if [[ $NP_SNMP_COMMUNITY == *$'\r'* ]]; then
        unset NP_SNMP_COMMUNITY
        echo "The community cannot contain a carriage return." >&2
        return 2
    fi

    umask 077
    NP_SNMP_TMP_DIR=$(mktemp -d) || {
        unset NP_SNMP_COMMUNITY
        echo "Could not create a private temporary directory." >&2
        return 1
    }
    chmod 700 "$NP_SNMP_TMP_DIR"

    # Net-SNMP parses quoted values and treats backslash as a quote escape.
    local escaped=${NP_SNMP_COMMUNITY//\\/\\\\}
    escaped=${escaped//\"/\\\"}
    if ! printf 'defCommunity "%s"\n' "$escaped" > "$NP_SNMP_TMP_DIR/snmp.conf"; then
        snmp_community_cleanup
        echo "Could not write private Net-SNMP configuration." >&2
        return 1
    fi
    chmod 600 "$NP_SNMP_TMP_DIR/snmp.conf"
    unset NP_SNMP_COMMUNITY escaped
}

snmp_community_cleanup() {
    unset NP_SNMP_COMMUNITY escaped
    if [[ -n ${NP_SNMP_TMP_DIR:-} ]]; then
        rm -rf -- "$NP_SNMP_TMP_DIR"
        unset NP_SNMP_TMP_DIR
    fi
}

snmp_community_walk() {
    local system_config_path="/etc/snmp:/usr/local/etc/snmp:/usr/local/share/snmp:/usr/local/lib/snmp"
    SNMPCONFPATH="$system_config_path:$NP_SNMP_TMP_DIR" snmpwalk -v2c "$@"
}
