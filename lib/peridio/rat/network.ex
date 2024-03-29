defmodule Peridio.RAT.Network do

  alias Peridio.RAT.Network.CIDR

  @default_cidrs [
    "172.16.0.0/12",
    "192.168.0.0/16",
    "10.0.0.0/8"
  ] |> Enum.map(&CIDR.from_string!/1)

  @default_ports []

  def default_ip_address_cidrs(), do: @default_cidrs
  def default_port_ranges(), do: @default_ports

  def available_cidrs(cidrs \\ @default_cidrs) do
    reserved_cidrs = reserved_cidrs()
    Enum.map(cidrs, fn(cidr) ->
      reserved_cidrs
      |> Enum.filter(&CIDR.contains?(cidr, &1))
      |> Enum.map(&CIDR.difference(&1, cidr))
      |> List.flatten()
    end)
    |> List.flatten()
  end

  def reserved_cidrs() do
    case :inet.getifaddrs() do
      {:ok, addrs} ->
        resp =
          Enum.reduce(addrs, [], fn(inets_interface, acc) ->
            case CIDR.from_inets_interface(inets_interface) do
              {:ok, cidr} -> [cidr | acc]
              _e -> acc
            end
          end)
        resp
      _error -> :error
    end
  end
end
