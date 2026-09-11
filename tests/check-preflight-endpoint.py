#!/usr/bin/env python3
"""Exercise daemon preflight configuration through the real client parser.

Usage: python3 tests/check-preflight-endpoint.py --libusbmuxd-source /path/to/libusbmuxd-2.1.1
The client source is an existing pinned build input; this test never downloads it.
Socket stubs record routing and prohibit all connections, including to the system
daemon. Production functions are compiled with allocation/environment failure
injection and address/undefined-behavior sanitizers.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


def extract_function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--libusbmuxd-source', required=True, type=Path)
    parser.add_argument('--daemon-source', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'src/main.c')
    args = parser.parse_args()
    daemon = args.daemon_source.read_text()
    client = (args.libusbmuxd_source / 'src/libusbmuxd.c').read_text()
    configure = extract_function(daemon, 'static int configure_preflight_socket(void)')
    connect = extract_function(client, 'static int connect_usbmuxd_socket()')
    # Check the real startup path uses the helper before creating preflight state.
    startup = daemon[daemon.index('int main(int argc, char *argv[])'):]
    assert startup.index('create_socket()') < startup.index('configure_preflight_socket()')
    assert startup.index('configure_preflight_socket()') < startup.index('config_get_config_dir()')

    harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *socket_path = "/var/run/usbmuxd";
static const char *listen_addr;
static int fail_allocation, fail_environment;
static void *test_malloc(size_t size)
{
    if (fail_allocation) { errno = ENOMEM; return NULL; }
    return malloc(size);
}
static int test_setenv(const char *key, const char *value, int overwrite)
{
    assert(strcmp(key, "USBMUXD_SOCKET_ADDRESS") == 0);
    assert(overwrite == 1);
    if (fail_environment) { errno = ENOMEM; return -1; }
    return setenv(key, value, overwrite);
}
#define malloc test_malloc
#define setenv test_setenv
''' + configure + r'''
#undef malloc
#undef setenv

static const char *expected_address;
static uint16_t expected_port;
static int calls, connection_fails;
static int socket_connect_unix(const char *address)
{
    /* No actual socket calls: an unexpected fallback fails before any I/O. */
    calls++;
    assert(expected_port == 0);
    assert(strcmp(address, expected_address) == 0);
    if (connection_fails) { errno = ECONNREFUSED; return -1; }
    return 41;
}
static int socket_connect(const char *address, uint16_t port)
{
    calls++;
    assert(expected_port != 0 && port == expected_port);
    assert(strcmp(address, expected_address) == 0);
    if (connection_fails) { errno = ECONNREFUSED; return -1; }
    return 42;
}
#define USBMUXD_SOCKET_FILE "/var/run/usbmuxd"
''' + connect + r'''

static void check_route(const char *selected, const char *environment,
                        const char *address, uint16_t port)
{
    listen_addr = selected;
    expected_address = address;
    expected_port = port;
    assert(setenv("USBMUXD_SOCKET_ADDRESS", "inherited-invalid-value", 1) == 0);
    assert(configure_preflight_socket() == 0);
    assert(strcmp(getenv("USBMUXD_SOCKET_ADDRESS"), environment) == 0);
    calls = 0;
    assert(connect_usbmuxd_socket() == (port ? 42 : 41));
    assert(calls == 1);
    connection_fails = 1;
    calls = 0;
    assert(connect_usbmuxd_socket() == -ECONNREFUSED);
    assert(calls == 1); /* Failed private endpoints must never fall back. */
    connection_fails = 0;
}

int main(void)
{
    check_route(NULL, "UNIX:/var/run/usbmuxd", "/var/run/usbmuxd", 0);
    check_route("/private/tmp/preflight-test.sock", "UNIX:/private/tmp/preflight-test.sock",
                "/private/tmp/preflight-test.sock", 0);
    check_route("relative socket.sock", "UNIX:relative socket.sock", "relative socket.sock", 0);
    check_route("127.0.0.1:4242", "127.0.0.1:4242", "127.0.0.1", 4242);
    check_route("::1:4242", "::1:4242", "::1", 4242);

    listen_addr = "/private/tmp/preflight-test.sock";
    assert(setenv("USBMUXD_SOCKET_ADDRESS", "unchanged", 1) == 0);
    fail_allocation = 1;
    assert(configure_preflight_socket() == -1 && errno == ENOMEM);
    assert(strcmp(getenv("USBMUXD_SOCKET_ADDRESS"), "unchanged") == 0);
    fail_allocation = 0;
    fail_environment = 1;
    assert(configure_preflight_socket() == -1 && errno == ENOMEM);
    assert(strcmp(getenv("USBMUXD_SOCKET_ADDRESS"), "unchanged") == 0);
    listen_addr = "127.0.0.1:4242";
    assert(configure_preflight_socket() == -1 && errno == ENOMEM);
    assert(strcmp(getenv("USBMUXD_SOCKET_ADDRESS"), "unchanged") == 0);
    puts("PASS: Unix/default/TCP routing, inherited override, no fallback, allocation/environment failures");
}
'''
    with tempfile.TemporaryDirectory(prefix='usbmuxd-preflight-test-') as directory:
        root = Path(directory)
        source, binary = root / 'test.c', root / 'test'
        source.write_text(harness)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-g', '-O1',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(source), '-o', str(binary)], check=True, timeout=30)
        subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == '__main__':
    main()
