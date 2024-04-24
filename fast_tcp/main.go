package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native bpf ./bpf.c -- -I./headers -I. -Wall

func main() {
	if len(os.Args) != 2 {
		log.Printf("Usage: %s [comm]\ne.g. run \"%s curl\" to bpf_msg_redirect local TCP segment from curl", os.Args[0], os.Args[0])
		os.Exit(1)
	}

	comm := os.Args[1]
	if len(comm) > 16 {
		log.Fatalf("comm must be less than 16 characters")
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Failed to load BPF: %v\n", err)
	}

	c := [16]byte{}
	copy(c[:], comm)
	if err := spec.RewriteConstants(map[string]interface{}{
		"CFG": struct {
			comm [16]byte
		}{
			comm: c,
		},
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %v\n", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}

	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Program: objs.TcpSockops,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup: %w", err)
	}
	defer cg.Close()

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.FastSock.FD(),
		Program: objs.SkMsgFastRedirect,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		log.Fatalf("failed to attach sk_skb stream verdict: %w", err)
	}

	defer func() {
		link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.FastSock.FD(),
			Program: objs.SkMsgFastRedirect,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
	}()

	println("Press CTRL+C to stop")
	f, _ := os.OpenFile("/sys/kernel/debug/tracing/trace_pipe", os.O_RDONLY, os.ModePerm)
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		fmt.Println(string(line))
	}
}
