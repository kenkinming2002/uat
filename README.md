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
$ sudo uat <NET>
```

This will create a network interface with address set to specified by `NET`,
which should be an ipv4 network in CIDR notation. Relevant routes will also be
setup so that you could listen on and send message over the network interface
address. For simplicity of explanation, lets say `NET` is selected to be
`192.168.33.0/24`. You can setup tcp connection over addresses in `NET` except
the actual ip address (`192.168.33.0`) using netcat:

```shell
$ nc -l 192.168.33.1 80 # server
$ nc 192.168.33.1 80 # client
```

Notice that it is also possible to bind to privilege port. Under the hood, a
eBPF program is used to dynamically allocate and remap ports. Because the
allocation is per user, it is possible to communicate over the same address and
port pair as another user such as root:

```shell
$ sudo nc -l 192.168.33.1 80 # server
$ sudo nc 192.168.33.1 80 # client
```

To put it simply, a port mapping `(uid, port) <-> port` is dynamically built
under the hood. It is easy to see that this mapping can never be injective.
Because of this and limitation of eBPF program, it is possible for the port
mapping process to fail. In such a case, we may use the ip address
(`192.168.33.0`) as a placeholder which is why it is important to not actually
use this address.

## Design

In principle, it is possible to create a blackhole route for the ip address
(`192.168.33.0`). In practice, this is not done because such a route will not
be removed automatically when the created network interface is removed. This is
because there is no reference to the created network interface in the route. A
design decision made for this program is that no matter how the program
terminate, all created objects are removed. This is also why we use a tun
interface instead of a dummy interface.
