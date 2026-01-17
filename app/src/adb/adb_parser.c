#include "adb_parser.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util/log.h"
#include "util/str.h"

// Known device states from "adb devices" output
static const char *const DEVICE_STATES[] = {
    "device",
    "offline",
    "unauthorized",
    "authorizing",
    "connecting",
    "unknown",
    NULL
};

static bool
is_device_state(const char *token) {
    for (size_t i = 0; DEVICE_STATES[i]; ++i) {
        if (!strcmp(token, DEVICE_STATES[i])) {
            return true;
        }
    }
    return false;
}

static bool
sc_adb_parse_device(char *line, struct sc_adb_device *device) {
    // One device line looks like:
    // "0123456789abcdef	device usb:2-1 product:MyProduct model:MyModel "
    //     "device:MyDevice transport_id:1"

    if (line[0] == '*') {
        // Garbage lines printed by adb daemon while starting start with a '*'
        return false;
    }

    if (!strncmp("adb server", line, sizeof("adb server") - 1)) {
        // Ignore lines starting with "adb server":
        //   adb server version (41) doesn't match this client (39); killing...
        return false;
    }

    char *s = line;

    // Serials can contain spaces (e.g., mDNS names), so we can't simply split
    // on the first space. Instead, find the device state (a known keyword) and
    // treat everything before it as the serial.
    // After the serial (which may contain spaces, e.g. mDNS device names):
    //  - "adb devices" writes a tab before the state
    //  - "adb devices -l" writes space(s) before the state
    // We identify the state by its known value (device, offline, etc.)
    // and treat everything before it as the serial.

    // Find the state by tokenizing and looking for a known state keyword
    char *state_start = NULL;
    char *state_end = NULL;
    char state_end_char = '\0';  // Save the character after state for eol check
    char *p = s;

    while (*p) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        // Found start of a token
        char *token_start = p;

        // Find end of token
        while (*p && *p != ' ' && *p != '\t') p++;

        // Check if this token is a known state
        char saved = *p;
        *p = '\0';

        if (is_device_state(token_start)) {
            state_start = token_start;
            state_end = p;
            state_end_char = saved;  // Save for eol check
            // Don't restore *p here - state must remain null-terminated
            break;
        }

        *p = saved;
    }

    if (!state_start) {
        // No valid state found
        return false;
    }

    // Everything before state_start is the serial
    // Find the end of the serial (trim trailing whitespace before state)
    char *serial_end = state_start;
    while (serial_end > s && (serial_end[-1] == ' ' || serial_end[-1] == '\t')) {
        serial_end--;
    }

    size_t serial_len = serial_end - s;
    if (!serial_len) {
        // empty serial
        return false;
    }

    *serial_end = '\0';
    char *serial = s;

    // state_start already points to the state, null-terminated by tokenization
    char *state = state_start;

    // Position s after the state for property parsing
    // Use state_end (saved position) instead of strlen since state is null-terminated
    s = state_end;
    bool eol = (state_end_char == '\0');  // Check saved character, not current
    if (!eol) {
        s++;  // Skip past the null terminator we placed
        s += strspn(s, " \t");  // Skip separators
    }

    char *model = NULL;
    if (!eol) {
        // Iterate over all properties "key:value key:value ..."
        for (;;) {
            size_t token_len = strcspn(s, " ");
            if (!token_len) {
                break;
            }
            eol = s[token_len] == '\0';
            s[token_len] = '\0';
            char *token = s;

            if (!strncmp("model:", token, sizeof("model:") - 1)) {
                model = &token[sizeof("model:") - 1];
                // We only need the model
                break;
            }

            if (eol) {
                break;
            } else {
                s+= token_len + 1;
            }
        }
    }

    device->serial = strdup(serial);
    if (!device->serial) {
        return false;
    }

    device->state = strdup(state);
    if (!device->state) {
        free(device->serial);
        return false;
    }

    if (model) {
        device->model = strdup(model);
        if (!device->model) {
            LOG_OOM();
            // model is optional, do not fail
        }
    } else {
        device->model = NULL;
    }

    device->selected = false;

    return true;
}

bool
sc_adb_parse_devices(char *str, struct sc_vec_adb_devices *out_vec) {
#define HEADER "List of devices attached"
#define HEADER_LEN (sizeof(HEADER) - 1)
    bool header_found = false;

    size_t idx_line = 0;
    while (str[idx_line] != '\0') {
        char *line = &str[idx_line];
        size_t len = strcspn(line, "\n");

        // The next line starts after the '\n' (replaced by `\0`)
        idx_line += len;

        if (str[idx_line] != '\0') {
            // The next line starts after the '\n'
            ++idx_line;
        }

        if (!header_found) {
            if (!strncmp(line, HEADER, HEADER_LEN)) {
                header_found = true;
            }
            // Skip everything until the header, there might be garbage lines
            // related to daemon starting before
            continue;
        }

        // The line, but without any trailing '\r'
        size_t line_len = sc_str_remove_trailing_cr(line, len);
        line[line_len] = '\0';

        struct sc_adb_device device;
        bool ok = sc_adb_parse_device(line, &device);
        if (!ok) {
            continue;
        }

        ok = sc_vector_push(out_vec, device);
        if (!ok) {
            LOG_OOM();
            LOGE("Could not push adb_device to vector");
            sc_adb_device_destroy(&device);
            // continue anyway
            continue;
        }
    }

    assert(header_found || out_vec->size == 0);
    return header_found;
}

static char *
sc_adb_parse_device_ip_from_line(char *line) {
    // One line from "ip route" looks like:
    // "192.168.1.0/24 dev wlan0  proto kernel  scope link  src 192.168.1.x"

    // Get the location of the device name (index of "wlan0" in the example)
    ssize_t idx_dev_name = sc_str_index_of_column(line, 2, " ");
    if (idx_dev_name == -1) {
        return NULL;
    }

    // Get the location of the ip address (column 8, but column 6 if we start
    // from column 2). Must be computed before truncating individual columns.
    ssize_t idx_ip = sc_str_index_of_column(&line[idx_dev_name], 6, " ");
    if (idx_ip == -1) {
        return NULL;
    }
    // idx_ip is searched from &line[idx_dev_name]
    idx_ip += idx_dev_name;

    char *dev_name = &line[idx_dev_name];
    size_t dev_name_len = strcspn(dev_name, " \t");
    dev_name[dev_name_len] = '\0';

    char *ip = &line[idx_ip];
    size_t ip_len = strcspn(ip, " \t");
    ip[ip_len] = '\0';

    // Only consider lines where the device name starts with "wlan"
    if (strncmp(dev_name, "wlan", sizeof("wlan") - 1)) {
        LOGD("Device ip lookup: ignoring %s (%s)", ip, dev_name);
        return NULL;
    }

    return strdup(ip);
}

char *
sc_adb_parse_device_ip(char *str) {
    size_t idx_line = 0;
    while (str[idx_line] != '\0') {
        char *line = &str[idx_line];
        size_t len = strcspn(line, "\n");
        bool is_last_line = line[len] == '\0';

        // The same, but without any trailing '\r'
        size_t line_len = sc_str_remove_trailing_cr(line, len);
        line[line_len] = '\0';

        char *ip = sc_adb_parse_device_ip_from_line(line);
        if (ip) {
            // Found
            return ip;
        }

        if (is_last_line) {
            break;
        }

        // The next line starts after the '\n'
        idx_line += len + 1;
    }

    return NULL;
}
