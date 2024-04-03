# Peridio.RAT

Peridio Remote Access Tullens.

## Installation

Add the dependency to your mix project

```elixir
{:peridio_rat, github: "peridio/peridio-rat"}
```

## System Dependencies

Peridio RAT is designed to operate on Linux based systems and requires the following system utilities and dependencies to function properly.

* Linux Kernel with Wireguard enabled.
* `wireguard-tools`: Tools for wg-quick.
* `ss`: For scanning local ports
