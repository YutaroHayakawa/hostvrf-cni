FROM golang:1.24.3-bookworm

# Install dependencies
RUN apt update && apt install -y iproute2 nftables
RUN go install github.com/containernetworking/cni/cnitool@v1.2.3
RUN go install github.com/containernetworking/plugins/plugins/ipam/static@v1.6.1

# Create CNI path
RUN mkdir -p /etc/cni/net.d

# Create testing network ns and sleep process bound to it. This is for
# accessing testing NS later from host through /proc/<sleep's PID in host PID
# ns>/ns/net. For the moment, this was the easiest way to execute test code
# within the nested network namespace.
ENTRYPOINT ["sh", "-c", "ip netns add testing && ip netns exec testing sleep 1d"]
