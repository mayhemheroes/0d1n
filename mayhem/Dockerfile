FROM ubuntu:22.04 as builder
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcurl4 build-essential libcurl4-openssl-dev clang
COPY ./bin/0d1n /

COPY . /repo
WORKDIR /repo
RUN make
RUN rm /repo/0d1n.o
RUN clang++ /repo/mayhem/fuzz_deadspace.cpp -fsanitize=fuzzer,address /repo/*.o -lcurl -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libcurl4
COPY --from=builder /0d1n /
COPY --from=builder /fuzz /fuzz_deadspace