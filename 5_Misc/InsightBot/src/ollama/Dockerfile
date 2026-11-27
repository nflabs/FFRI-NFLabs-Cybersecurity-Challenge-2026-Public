FROM ollama/ollama:latest

RUN bash -c 'ollama serve & \
    serve_pid=$!; \
    for i in $(seq 1 60); do ollama list >/dev/null 2>&1 && break; sleep 1; done; \
    ollama pull qwen2.5-coder:3b-instruct; \
    rc=$?; \
    kill "$serve_pid" 2>/dev/null; \
    wait "$serve_pid" 2>/dev/null; \
    exit $rc'
