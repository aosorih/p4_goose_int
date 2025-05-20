### p4_goose_int
## Goose with in-band network telemetry in programable data plain
# This project calculates the processing time inside a BMv2 switch using P4, i.e. subtracts the egress_timestamp from the ingress_timestamp. The timestamps are sent in an ethernet packet using the concept of in-band telemetry. The collector file receives the packets, extracts the fields and calculates the preprocessing latency.
