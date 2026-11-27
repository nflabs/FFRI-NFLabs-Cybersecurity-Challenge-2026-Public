FROM python:3.12-slim

# non-root
RUN useradd -m -u 10001 ctf
WORKDIR /app

COPY challenge_data.py server.py handout.md ./

ENV HOST=0.0.0.0 \
    PORT=25001 \
    TIME_LIMIT=10 \
    SHUFFLE=0
# Override the flag at deploy time:  docker run -e FLAG='flag{...}' ...
ENV FLAG=flag{untrusted_fields_are_not_instructions}

USER ctf
EXPOSE 25001
CMD ["python3", "-u", "server.py"]
