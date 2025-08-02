# fatrace

`fatrace` reports file access events from all running processes. Its main purpose is to find processes which keep waking up the disk unnecessarily and thus prevent some power saving.

## Testing

Like `fatrace` itself, the integration tests have to run as root:

```sh
sudo python3 -m unittest -v
```

You can also run them in a privileged root container, with giving it an image
name of a Debian-ish (`apt`) or Fedora-ish (`dnf`) distribution:

```sh
sudo tests/run-container registry.fedoraproject.org/fedora:latest
sudo tests/run-container docker.io/amd64/debian:sid
```

By default, it runs in latest Fedora.

Run the test with `DEBUG=1` to sleep on failures. You can then attach to the container and inspect it:

```sh
sudo podman exec -itl bash
```
