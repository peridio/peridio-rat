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

    {reserved, available} =
      Enum.reduce(cidrs, {[], []}, fn(cidr, {reserved, available}) ->
        case Enum.filter(reserved_cidrs, &CIDR.contains?(cidr, &1)) do
          [] -> {reserved, [cidr | available]}
          reservations -> {Enum.map(reservations, &{&1, cidr}) ++ reserved, available}
        end
      end)

    available_from_reserved =
      Enum.map(reserved, fn({reservation, cidr}) ->
        CIDR.difference(reservation, cidr) |> List.flatten()
      end)

    List.flatten(available ++ available_from_reserved)
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
