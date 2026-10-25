# UAT (User Address Translation)

NAT (Network Address Translation) is commonly responsible for masquerading lan
addresses under single public ip address thereby isolating different lan
networks. UAT does the same thing but for different users on the system.

## Aya

This project makes use of [aya]((https://aya-rs.dev/book/)) for building eBPF
program with only rust code. If you encounter any difficulty, you may find
their [documentation]((https://aya-rs.dev/book/)) helpful.

## Prerequisites

Follow aya's instructions at [Development
Environment](https://aya-rs.dev/book/start/development.html). There is no need
to install `cargo-generate` since you are not generating a new project.

## Installation

This project provides a convenient Makefile that bundle together both the
compilation and installation step:

```shell
$ make && sudo make install
```

Alternatively, it is also possible compile the project directly with cargo and
perform the installation on your own:

```shell
$ cargo build --profile release
```

## Usage

```shell
$ sudo uat
```

By default, this will create a network interface with addresses set to
`192.168.33.0/24`, which can be overridden with `--net`, for local
communication. For example, using netcat:

```shell
$ nc -l 192.168.33.1 80 # server
$ nc 192.168.33.1 80 # client
```

The address is per-user so that it is possible to communicate over the same
address as another user such as root:

```shell
$ sudo nc -l 192.168.33.1 80 # server
$ sudo nc 192.168.33.1 80 # client
```

Under the hood, a port mapping `(uid, address, port) <-> (address, port)` is
dynamically built. It is easy to see that this mapping can never be injective.
Because of this and limitation of eBPF program, it is possible for the port
mapping process to fail, in which case the primary ip address (`192.168.33.0`)
is substituted in. It is thus important not to communicate over this primary ip
address.

Range of reserved port, which defaults to `61000-65535`, can also be specified
using `--min-port` and `--max-port` options. Mapped ports are selected from the
range of reserved port and the default range is chosen to avoid collision with:
 - Low ports commonly used for system and user service.
 - Range for ephemeral port allocation by kernel as specified in
   `/proc/sys/net/ipv4/ip_local_port_range` (default: 32768-60999).
It is important to keep the above in mind when picking an alternative range of
reserved ports.

In order to avoid trivial bypass by binding to INADDR_ANY, attempts to bind to
reserved ports with INADDR_ANY will be blocked.

## Design

In principle, it is possible to create a blackhole route for the ip address
(`192.168.33.0`). In practice, this is not done because such a route will not
be removed automatically when the created network interface is removed. This is
because there is no reference to the created network interface in the route. A
design decision made for this program is that no matter how the program
terminate, all created objects are removed. This is also why we use a tun
interface instead of a dummy interface.
