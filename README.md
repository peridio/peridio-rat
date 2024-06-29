# Peridio.RAT

Peridio Remote Access Tunnels.

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

## Looking up a tunnel server via interface id

You can use `Registry.select` to look up `Peridio.RAT.Tunnel` servers by interface using a match spec. Match spec's are so easy!

```elixir
Registry.select(:tunnels, [{{:"$1", :"$2", :"$3"}, [{:==, {:map_get, :id, :"$3"}, "peridio-RSLO2KQ"}], [{{:"$1", :"$2", :"$3"}}]}])
[
  {"5167cecf-64e6-4eef-b694-5b8f490dc429",
   #PID<0.1319.0>,
   %Peridio.RAT.WireGuard.Interface{
     id: "peridio-RSLO2KQ",
     ip_address: %Peridio.RAT.Network.IP{address: 3232235544},
     port: 49677,
     private_key: "...",
     public_key: "..."
   }}
]
```
