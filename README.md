# bpf_msg_redirect_bug_reproducer

This repo provides minimal steps to reproduce an issue when `splice(2)` is used with `sockmap`+`bpf_msg_redirect`.

I first found it on 6.5.0-28-generic, then managed to reproduce on bpf-next-20240419(6.9.0-rc1-g462e5e2a5938), so I presume the issue exists among all versions of kernel.

## Build

```shell
cd fast_tcp/
go generate . && go build .
cd ..

cd tcp_splice/
go build .
cd ..
```

If nothing gone wrong, we'll have two binaries: `./fast_tcp/fast_tcp` and `./tcp_splice/tcp_splice`.

## Reproducing Steps

### 1. Setup a local TCP service

Python's HTTP simple server will listen on :8000.

```shell
python3 -mhttp.server
```

### 2. Run tcp_splice without bpf engaged

```shell
./tcp_splice/tcp_splice localhost:8000
```

We should see output like:

```
TTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.12
Date: Wed, 24 Apr 2024 18:33:38 GMT
Content-type: text/html; charset=utf-8
Content-Length: 481

Splice reads 156 bytes
```

### 3. Setup bpf

```shell
sudo ./fast_tcp/fast_tcp tcp_splice
```

The command line argument `tcp_splice` is telling bpf to only accelerate traffic sent from process whose comm is "tcp_splice".

### 4. Run tcp_splice again with bpf

```shell
./tcp_splice/tcp_splice localhost:8000
```

This time we will get:

```
Splice reads 0 bytes
```

In the meantime, we can confirm bpf_msg_redirect seems to be called properly by checking fast_tcp's output:

```
# sudo ./fast_tcp/fast_tcp tcp_splice
Press CTRL+C to stop
           <...>-547     [003] ...11   143.469291: bpf_trace_printk: v4 fast_sock added: 127.0.0.1:32984 -> 127.0.0.1:8000
      tcp_splice-547     [003] ..s31   143.469325: bpf_trace_printk: v4 fast_sock added: 127.0.0.1:8000 -> 127.0.0.1:32984
      tcp_splice-545     [000] ...11   143.469365: bpf_trace_printk: v4 tcp fast redirect: size=18 127.0.0.1:32984 -> 127.0.0.1:8000
           <...>-549     [001] ...11   143.469995: bpf_trace_printk: v4 tcp fast redirect: size=155 127.0.0.1:8000 -> 127.0.0.1:32984
           <...>-549     [001] ...11   143.470016: bpf_trace_printk: v4 tcp fast redirect: size=394 127.0.0.1:8000 -> 127.0.0.1:32984
```

It looks like a kernel bug.
