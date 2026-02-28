// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
/* Ported from AgentSight (https://github.com/eunomia-bpf/agentsight)
 *
 * Modified for matchlock guest VM:
 * - Output JSONL over vsock (CID 2, port 5003) instead of stdout
 * - Retry vsock connection with exponential backoff
 * - Removed bash_readline handling
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "process.h"
#include "process.skel.h"
#include "process_utils.h"
#include "process_filter.h"

/* vsock support */
#include <linux/vm_sockets.h>

#define VSOCK_HOST_CID  2
#define VSOCK_EBPF_PORT 5003
#define VSOCK_MAX_RETRIES 30
#define VSOCK_INITIAL_BACKOFF_MS 100

#define MAX_COMMAND_LIST 256
#define FILE_DEDUP_WINDOW_NS 60000000000ULL  /* 60 seconds in nanoseconds */
#define MAX_FILE_HASHES 1024

/* Rate limiting per second */
#define MAX_PID_LIMITS 256
#define MAX_DISTINCT_FILES_PER_SEC 30

/* Output buffer for building JSON lines */
#define OUTPUT_BUF_SIZE 4096

struct per_second_limit {
    pid_t pid;
    uint64_t current_second;
    uint32_t distinct_file_count;
    bool should_warn_next;
};

/* Simple hash table for FILE_OPEN deduplication */
struct file_hash_entry {
    uint64_t hash;
    uint64_t timestamp_ns;
    uint32_t count;
    pid_t pid;
    char comm[TASK_COMM_LEN];
    char filepath[MAX_FILENAME_LEN];
    int flags;
};

static struct file_hash_entry file_hashes[MAX_FILE_HASHES];
static int hash_count = 0;

static struct per_second_limit pid_limits[MAX_PID_LIMITS];
static int pid_limit_count = 0;

/* vsock connection fd */
static int vsock_fd = -1;

static struct env {
	bool verbose;
	long min_duration_ms;
	char *command_list[MAX_COMMAND_LIST];
	int command_count;
	enum filter_mode filter_mode;
	pid_t pid;
} env = {
	.verbose = false,
	.min_duration_ms = 0,
	.command_count = 0,
	.filter_mode = FILTER_MODE_ALL,  /* Default to ALL for guest VM tracing */
	.pid = 0
};

/* Global PID tracker for userspace filtering */
static struct pid_tracker pid_tracker;

const char *argp_program_version = "ebpf-tracer 1.0";
const char *argp_program_bug_address = "<>";
const char argp_program_doc[] =
"eBPF process & file operations tracer for matchlock guest VMs.\n"
"\n"
"Traces process lifecycle (exec/exit) and file operations (open/openat)\n"
"and streams JSONL events over vsock to the host.\n"
"\n"
"USAGE: ./ebpf-tracer [-d <min-duration-ms>] [-m <mode>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{ "mode", 'm', "FILTER-MODE", 0, "Filter mode: 0=all (default), 1=proc, 2=filter" },
	{ "filter-mode", 'f', "FILTER-MODE", OPTION_ALIAS, NULL },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
	case 'f':
		errno = 0;
		{
			int mode = strtol(arg, NULL, 10);
			if (errno || mode < 0 || mode > 2) {
				/* Try string names */
				if (strcmp(arg, "all") == 0)
					mode = FILTER_MODE_ALL;
				else if (strcmp(arg, "proc") == 0)
					mode = FILTER_MODE_PROC;
				else if (strcmp(arg, "filter") == 0)
					mode = FILTER_MODE_FILTER;
				else {
					fprintf(stderr, "Invalid filter mode: %s (use 0/all, 1/proc, 2/filter)\n", arg);
					argp_usage(state);
				}
			}
			env.filter_mode = (enum filter_mode)mode;
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

/* --- vsock connection --- */

static int connect_vsock(void)
{
	int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "ebpf-tracer: socket(AF_VSOCK) failed: %s\n", strerror(errno));
		return -1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VSOCK_HOST_CID,
		.svm_port = VSOCK_EBPF_PORT,
	};

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	fprintf(stderr, "ebpf-tracer: connected to host vsock CID %d port %d\n",
		VSOCK_HOST_CID, VSOCK_EBPF_PORT);
	return fd;
}

static int connect_vsock_with_retry(void)
{
	int backoff_ms = VSOCK_INITIAL_BACKOFF_MS;

	for (int attempt = 0; attempt < VSOCK_MAX_RETRIES; attempt++) {
		int fd = connect_vsock();
		if (fd >= 0)
			return fd;

		if (env.verbose || attempt % 5 == 0) {
			fprintf(stderr, "ebpf-tracer: vsock connect attempt %d/%d failed, retrying in %dms...\n",
				attempt + 1, VSOCK_MAX_RETRIES, backoff_ms);
		}

		usleep(backoff_ms * 1000);
		if (backoff_ms < 5000)
			backoff_ms = backoff_ms * 3 / 2;  /* 1.5x exponential backoff */
	}

	fprintf(stderr, "ebpf-tracer: failed to connect vsock after %d attempts\n", VSOCK_MAX_RETRIES);
	return -1;
}

/* Write a complete JSONL line to vsock. Falls back to stdout if vsock is not connected. */
static void emit_line(const char *line, size_t len)
{
	if (vsock_fd >= 0) {
		ssize_t written = 0;
		while ((size_t)written < len) {
			ssize_t n = write(vsock_fd, line + written, len - written);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				fprintf(stderr, "ebpf-tracer: vsock write failed: %s\n", strerror(errno));
				close(vsock_fd);
				vsock_fd = -1;
				break;
			}
			written += n;
		}
		if (vsock_fd >= 0) {
			write(vsock_fd, "\n", 1);
		}
	}
	/* Also write to stdout for debugging when verbose */
	if (vsock_fd < 0 || env.verbose) {
		fwrite(line, 1, len, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}
}

/* --- Rate limiting --- */

static bool should_rate_limit_file(const struct event *e, uint64_t timestamp_ns, bool *add_warning) {
    uint64_t current_second = timestamp_ns / 1000000000ULL;
    *add_warning = false;

    struct per_second_limit *limit = NULL;
    for (int i = 0; i < pid_limit_count; i++) {
        if (pid_limits[i].pid == e->pid) {
            limit = &pid_limits[i];
            break;
        }
    }

    if (!limit && pid_limit_count < MAX_PID_LIMITS) {
        limit = &pid_limits[pid_limit_count++];
        limit->pid = e->pid;
        limit->current_second = current_second;
        limit->distinct_file_count = 0;
        limit->should_warn_next = false;
    }

    if (!limit) return false;

    if (limit->current_second != current_second) {
        if (limit->should_warn_next) {
            *add_warning = true;
            limit->should_warn_next = false;
        }
        limit->current_second = current_second;
        limit->distinct_file_count = 0;
    }

    limit->distinct_file_count++;

    if (limit->distinct_file_count > MAX_DISTINCT_FILES_PER_SEC) {
        limit->should_warn_next = true;
        return true;
    }

    return false;
}

/* --- FILE_OPEN output --- */

static void emit_file_open_event(const struct event *e, uint64_t timestamp_ns, uint32_t count, const char *extra_fields)
{
	char buf[OUTPUT_BUF_SIZE];
	int n;

	if (extra_fields && strlen(extra_fields) > 0) {
		n = snprintf(buf, sizeof(buf),
			"{\"timestamp\":%llu,\"event\":\"FILE_OPEN\",\"comm\":\"%s\","
			"\"pid\":%d,\"count\":%u,\"filepath\":\"%s\",\"flags\":%d,%s}",
			(unsigned long long)timestamp_ns, e->comm, e->pid, count,
			e->file_op.filepath, e->file_op.flags, extra_fields);
	} else {
		n = snprintf(buf, sizeof(buf),
			"{\"timestamp\":%llu,\"event\":\"FILE_OPEN\",\"comm\":\"%s\","
			"\"pid\":%d,\"count\":%u,\"filepath\":\"%s\",\"flags\":%d}",
			(unsigned long long)timestamp_ns, e->comm, e->pid, count,
			e->file_op.filepath, e->file_op.flags);
	}

	if (n > 0 && n < (int)sizeof(buf))
		emit_line(buf, n);
}

/* --- FILE_OPEN deduplication --- */

static uint64_t hash_file_open(const struct event *e)
{
	uint64_t hash = 5381;
	hash = ((hash << 5) + hash) + e->pid;

	const char *str = e->file_op.filepath;
	while (*str) {
		hash = ((hash << 5) + hash) + *str++;
	}

	return hash;
}

static uint32_t get_file_open_count(const struct event *e, uint64_t timestamp_ns, char *warning_msg, size_t warning_msg_size)
{
	if (e->type != EVENT_TYPE_FILE_OPERATION || !e->file_op.is_open) {
		return 1;
	}

	warning_msg[0] = '\0';

	bool add_warning = false;
	if (should_rate_limit_file(e, timestamp_ns, &add_warning)) {
		return 0;
	}

	if (add_warning) {
		snprintf(warning_msg, warning_msg_size, "\"rate_limit_warning\":\"Previous second exceeded %d file limit\"", MAX_DISTINCT_FILES_PER_SEC);
	}

	uint64_t hash = hash_file_open(e);

	/* Clean up expired entries */
	for (int i = 0; i < hash_count; i++) {
		if (timestamp_ns - file_hashes[i].timestamp_ns > FILE_DEDUP_WINDOW_NS) {
			if (file_hashes[i].count > 1) {
				struct event fake_event = {
					.type = EVENT_TYPE_FILE_OPERATION,
					.pid = file_hashes[i].pid,
					.ppid = 0,
					.exit_code = 0,
					.duration_ns = 0,
					.exit_event = false,
					.file_op = {
						.fd = -1,
						.flags = file_hashes[i].flags,
						.is_open = true
					}
				};
				strncpy(fake_event.comm, file_hashes[i].comm, TASK_COMM_LEN - 1);
				fake_event.comm[TASK_COMM_LEN - 1] = '\0';
				strncpy(fake_event.file_op.filepath, file_hashes[i].filepath, MAX_FILENAME_LEN - 1);
				fake_event.file_op.filepath[MAX_FILENAME_LEN - 1] = '\0';
				emit_file_open_event(&fake_event, timestamp_ns, file_hashes[i].count, "\"window_expired\":true");
			}

			file_hashes[i] = file_hashes[hash_count - 1];
			hash_count--;
			i--;
		}
	}

	/* Check for existing hash */
	for (int i = 0; i < hash_count; i++) {
		if (file_hashes[i].hash == hash) {
			file_hashes[i].count++;
			file_hashes[i].timestamp_ns = timestamp_ns;
			return 0;  /* Duplicate, skip */
		}
	}

	/* Add new entry */
	if (hash_count < MAX_FILE_HASHES) {
		file_hashes[hash_count].hash = hash;
		file_hashes[hash_count].timestamp_ns = timestamp_ns;
		file_hashes[hash_count].count = 1;
		file_hashes[hash_count].pid = e->pid;
		strncpy(file_hashes[hash_count].comm, e->comm, TASK_COMM_LEN - 1);
		file_hashes[hash_count].comm[TASK_COMM_LEN - 1] = '\0';
		strncpy(file_hashes[hash_count].filepath, e->file_op.filepath, MAX_FILENAME_LEN - 1);
		file_hashes[hash_count].filepath[MAX_FILENAME_LEN - 1] = '\0';
		file_hashes[hash_count].flags = e->file_op.flags;
		hash_count++;
	}

	return 1;
}

static void flush_pid_file_opens(pid_t pid, uint64_t timestamp_ns)
{
	for (int i = 0; i < hash_count; i++) {
		if (file_hashes[i].pid == pid && file_hashes[i].count > 1) {
			struct event fake_event = {
				.type = EVENT_TYPE_FILE_OPERATION,
				.pid = file_hashes[i].pid,
				.ppid = 0,
				.exit_code = 0,
				.duration_ns = 0,
				.exit_event = false,
				.file_op = {
					.fd = -1,
					.flags = file_hashes[i].flags,
					.is_open = true
				}
			};
			strncpy(fake_event.comm, file_hashes[i].comm, TASK_COMM_LEN - 1);
			fake_event.comm[TASK_COMM_LEN - 1] = '\0';
			strncpy(fake_event.file_op.filepath, file_hashes[i].filepath, MAX_FILENAME_LEN - 1);
			fake_event.file_op.filepath[MAX_FILENAME_LEN - 1] = '\0';
			emit_file_open_event(&fake_event, timestamp_ns, file_hashes[i].count, "\"reason\":\"process_exit\"");
		}
	}

	/* Remove entries for this PID */
	for (int i = 0; i < hash_count; i++) {
		if (file_hashes[i].pid == pid) {
			file_hashes[i] = file_hashes[hash_count - 1];
			hash_count--;
			i--;
		}
	}
}

/* --- Signal handler --- */

static void sig_handler(int sig)
{
	exiting = true;
}

/* --- Populate initial PIDs --- */

static int populate_initial_pids(struct pid_tracker *tracker)
{
	DIR *proc_dir;
	struct dirent *entry;
	pid_t pid, ppid;
	char comm[TASK_COMM_LEN];
	int tracked_count = 0;

	proc_dir = opendir("/proc");
	if (!proc_dir) {
		fprintf(stderr, "Failed to open /proc directory\n");
		return -1;
	}

	while ((entry = readdir(proc_dir)) != NULL) {
		if (strspn(entry->d_name, "0123456789") != strlen(entry->d_name))
			continue;

		pid = (pid_t)strtol(entry->d_name, NULL, 10);
		if (pid <= 0)
			continue;

		if (read_proc_comm(pid, comm, sizeof(comm)) != 0)
			continue;

		if (read_proc_ppid(pid, &ppid) != 0)
			continue;

		if (should_track_process(tracker, comm, pid, ppid)) {
			if (pid_tracker_add(tracker, pid, ppid))
				tracked_count++;
		}
	}

	closedir(proc_dir);
	return tracked_count;
}

/* --- Event handler --- */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct pid_tracker *tracker = (struct pid_tracker *)ctx;
	uint64_t timestamp_ns = e->timestamp_ns;
	char buf[OUTPUT_BUF_SIZE];
	int n;

	switch (e->type) {
		case EVENT_TYPE_PROCESS:
			if (e->exit_event) {
				bool is_tracked = pid_tracker_is_tracked(tracker, e->pid);
				pid_tracker_remove(tracker, e->pid);

				if (!is_tracked && tracker->filter_mode == FILTER_MODE_FILTER)
					break;

				n = snprintf(buf, sizeof(buf),
					"{\"timestamp\":%llu,\"event\":\"EXIT\",\"comm\":\"%s\","
					"\"pid\":%d,\"ppid\":%d,\"exit_code\":%u",
					(unsigned long long)timestamp_ns, e->comm, e->pid, e->ppid, e->exit_code);

				if (e->duration_ns && n < (int)sizeof(buf) - 64) {
					n += snprintf(buf + n, sizeof(buf) - n,
						",\"duration_ms\":%llu",
						(unsigned long long)(e->duration_ns / 1000000));
				}

				/* Check for pending rate limit warning */
				for (int i = 0; i < pid_limit_count; i++) {
					if (pid_limits[i].pid == e->pid && pid_limits[i].should_warn_next) {
						if (n < (int)sizeof(buf) - 80) {
							n += snprintf(buf + n, sizeof(buf) - n,
								",\"rate_limit_warning\":\"Process had %d+ file ops per second\"",
								MAX_DISTINCT_FILES_PER_SEC);
						}
						pid_limits[i] = pid_limits[--pid_limit_count];
						break;
					}
				}

				if (n < (int)sizeof(buf) - 1) {
					buf[n++] = '}';
					buf[n] = '\0';
					emit_line(buf, n);
				}

				flush_pid_file_opens(e->pid, timestamp_ns);
			} else {
				/* EXEC event */
				if (should_track_process(tracker, e->comm, e->pid, e->ppid)) {
					pid_tracker_add(tracker, e->pid, e->ppid);
				} else if (tracker->filter_mode == FILTER_MODE_FILTER) {
					break;
				} else if (tracker->filter_mode == FILTER_MODE_PROC) {
					pid_tracker_add(tracker, e->pid, e->ppid);
				}

				n = snprintf(buf, sizeof(buf),
					"{\"timestamp\":%llu,\"event\":\"EXEC\",\"comm\":\"%s\","
					"\"pid\":%d,\"ppid\":%d,\"filename\":\"%s\",\"full_command\":\"%s\"}",
					(unsigned long long)timestamp_ns, e->comm, e->pid, e->ppid,
					e->filename, e->full_command);

				if (n > 0 && n < (int)sizeof(buf))
					emit_line(buf, n);
			}
			break;

		case EVENT_TYPE_FILE_OPERATION:
			if (!e->file_op.is_open)
				break;

			if (!should_report_file_ops(tracker, e->pid))
				break;

			{
				char warning_msg[128];
				uint32_t count = get_file_open_count(e, timestamp_ns, warning_msg, sizeof(warning_msg));

				if (count == 0)
					break;

				emit_file_open_event(e, timestamp_ns, count, strlen(warning_msg) > 0 ? warning_msg : NULL);
			}
			break;

		default:
			break;
	}

	return 0;
}

/* --- Main --- */

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct process_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	fprintf(stderr, "ebpf-tracer: starting (filter_mode=%d, min_duration_ms=%ld)\n",
		env.filter_mode, env.min_duration_ms);

	/* Initialize userspace PID tracker */
	pid_tracker_init(&pid_tracker, env.command_list, env.command_count, env.filter_mode, env.pid);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Signal handling */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Connect to host via vsock */
	vsock_fd = connect_vsock_with_retry();
	if (vsock_fd < 0) {
		fprintf(stderr, "ebpf-tracer: WARNING: vsock not available, falling back to stdout\n");
	}

	/* Load and verify BPF application */
	skel = process_bpf__open();
	if (!skel) {
		fprintf(stderr, "ebpf-tracer: failed to open BPF skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* Parameterize BPF code with minimum duration */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = process_bpf__load(skel);
	if (err) {
		fprintf(stderr, "ebpf-tracer: failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Populate initial PIDs */
	int tracked_count = populate_initial_pids(&pid_tracker);
	if (tracked_count < 0) {
		fprintf(stderr, "ebpf-tracer: failed to populate initial PIDs\n");
		goto cleanup;
	}
	fprintf(stderr, "ebpf-tracer: initially tracking %d processes\n", tracked_count);

	/* Attach tracepoints */
	err = process_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "ebpf-tracer: failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &pid_tracker, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "ebpf-tracer: failed to create ring buffer\n");
		goto cleanup;
	}

	fprintf(stderr, "ebpf-tracer: tracing started, streaming events...\n");

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ebpf-tracer: error polling ring buffer: %d\n", err);
			break;
		}
	}

	fprintf(stderr, "ebpf-tracer: shutting down\n");

cleanup:
	ring_buffer__free(rb);
	if (skel)
		process_bpf__destroy(skel);

	if (vsock_fd >= 0)
		close(vsock_fd);

	for (int i = 0; i < env.command_count; i++)
		free(env.command_list[i]);

	hash_count = 0;
	pid_limit_count = 0;

	return err < 0 ? -err : 0;
}
