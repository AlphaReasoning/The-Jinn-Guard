// Minimal libbpf loader: open + load + attach an LSM object (default mini.bpf.o,
// or argv[1]), then stay alive (the LSM stays attached only while the bpf_link
// is held) until signalled.
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

static volatile int stop = 0;
static void onsig(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
    const char *obj_path = argc > 1 ? argv[1] : "mini.bpf.o";
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) { fprintf(stderr, "open fail\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load fail\n"); return 1; }
    struct bpf_program *p = bpf_object__next_program(obj, NULL);
    struct bpf_link *l = bpf_program__attach(p);
    if (!l) { fprintf(stderr, "attach fail\n"); return 1; }
    printf("ATTACHED ok\n");
    fflush(stdout);
    signal(SIGINT, onsig);
    signal(SIGTERM, onsig);
    while (!stop) sleep(1);
    bpf_link__destroy(l);
    return 0;
}
