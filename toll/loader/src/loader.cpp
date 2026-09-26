#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "../include/module.skel.h"

#define WHITELIST_ARRIVALS_PATH "../rsrc/whitelist_arrivals.txt"
#define WHITELIST_DEPARTURES_PATH "../rsrc/whitelist_departures.txt"

#define MAX_IPS 64

static volatile sig_atomic_t stop;
static void on_sigint(int sig) { stop = 1; }

static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;

    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';

    return s;
}

static int load_whitelist(__u32 *whitelist, __u32 *count, const char *path)
{
    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "cannot open %s\n", path);
        return 1;
    }

    char buf[128];
    int ret = 0;

    while (fgets(buf, sizeof(buf), file)) {
        char *line = trim(buf);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (*count >= MAX_IPS) {
            fprintf(stderr, "%s: more than %d IPs\n", path, MAX_IPS);
            ret = 1;
            break;
        }
        if (inet_pton(AF_INET, line, &whitelist[*count]) != 1) {
            fprintf(stderr, "%s: invalid IP '%s'\n", path, line);
            ret = 1;
            break;
        }
        (*count)++;
    }

    fclose(file);
    return ret;
}

int main()
{
    struct module_bpf* skel = module_bpf__open_and_load();   // load + verify
    if (!skel)
    {
        fprintf(stderr, "failed to open/load BPF program\n");
        return 1;
    }

    load_whitelist(
        skel->bss->whitelisted_arrivals, 
        &skel->bss->whitelisted_arrivals_count, 
        WHITELIST_ARRIVALS_PATH
    );
    
    load_whitelist(
        skel->bss->whitelisted_departures, 
        &skel->bss->whitelisted_departures_count, 
        WHITELIST_DEPARTURES_PATH
    );

    int ifindex = if_nametoindex("enp5s0"); // Select port
    
    skel->links.on_arrival = bpf_program__attach_tcx(skel->progs.on_arrival, ifindex, NULL); // attach
    if (!skel->links.on_arrival)
    {
        fprintf(stderr, "failed to attach on_arrival BPF program\n");
        return 1;
    }

    skel->links.on_departure = bpf_program__attach_tcx(skel->progs.on_departure, ifindex, NULL); // attach
    if (!skel->links.on_departure)
    {
        fprintf(stderr, "failed to attach on_departure BPF program\n");
        return 1;
    }

    signal(SIGINT, on_sigint);
    printf("Running. In another terminal: sudo cat /sys/kernel/tracing/trace_pipe\n");

    while (!stop)
        sleep(1);

    module_bpf__destroy(skel); // detach + unload
    return 0;
}