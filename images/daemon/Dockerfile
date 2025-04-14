FROM golang:1.24.1 AS build

WORKDIR /app
COPY . ./
RUN go mod download
RUN cd plugins/hostvrf && CGO_ENABLED=0 go build
RUN CGO_ENABLED=0 go build -o hostvrf-cni

FROM scratch
COPY --from=build /app/hostvrf-cni /bin/hostvrf-cni
ENTRYPOINT ["/bin/hostvrf-cni"]
