FROM scratch
ADD rootfs.tar.gz /
WORKDIR /opt/nockapp/research/zkid
ENTRYPOINT ["/usr/bin/python3.14", "-I", "-B", "-S", "/opt/nockapp/research/zkid/public_renewal_runtime_entrypoint_v1.py"]
