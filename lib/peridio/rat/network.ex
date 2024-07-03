defmodule Peridio.RAT.Network do
  alias Peridio.RAT.Tunnel
  alias Peridio.RAT.Network.CIDR

  # RFC 1918 - Private Address Space
  # https://datatracker.ietf.org/doc/html/rfc1918#section-3
  @default_cidrs [
                   "172.16.0.0/12",
                   "192.168.0.0/16",
                   "10.0.0.0/8"
                 ]
                 |> Enum.map(&CIDR.from_string!/1)

  # RFC 6335 - Dynamic Port Range
  # https://datatracker.ietf.org/doc/html/rfc6335#page-11
  @default_ports 49152..65535

  def default_ip_address_cidrs(), do: @default_cidrs
  def default_port_ranges(), do: @default_ports

  def available_cidrs(cidrs \\ @default_cidrs) do
    reserved_cidrs = reserved_cidrs()

    {reserved, available} =
      Enum.reduce(cidrs, {[], []}, fn cidr, {reserved, available} ->
        case Enum.filter(reserved_cidrs, &CIDR.contains?(cidr, &1)) do
          [] -> {reserved, [cidr | available]}
          reservations -> {Enum.map(reservations, &{&1, cidr}) ++ reserved, available}
        end
      end)

    available_from_reserved =
      Enum.map(reserved, fn {reservation, cidr} ->
        CIDR.difference(reservation, cidr) |> List.flatten()
      end)

    List.flatten(available ++ available_from_reserved)
  end

  def available_ports(port_range \\ @default_ports) do
    with {:ok, reserved} <- reserved_ports(port_range) do
      split_range(port_range, reserved)
    end
  end

  def reserved_cidrs() do
    case :inet.getifaddrs() do
      {:ok, addrs} ->
        resp =
          Enum.reduce(addrs, tunnel_interface_cidrs(), fn inets_interface, acc ->
            case CIDR.from_inets_interface(inets_interface) do
              {:ok, cidr} -> [cidr | acc]
              _e -> acc
            end
          end)

        resp

      _error ->
        :error
    end
  end

  def tunnel_interface_cidrs() do
    Peridio.RAT.DynamicSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.map(&elem(&1, 1))
    |> Enum.map(&Tunnel.get_state/1)
    |> Enum.map(& &1.interface.ip_address.address)
    |> Enum.map(&CIDR.from_ip_range(&1..&1))
    |> List.flatten()
  end

  def reserved_ports(port_start..port_end//_) do
    case System.cmd("ss", [
           "-tauH",
           "sport",
           "\>",
           ":#{port_start}",
           "and",
           "sport",
           "\<",
           ":#{port_end}"
         ]) do
      {result, 0} ->
        reserved =
          result
          |> String.split("\n", trim: true)
          |> Enum.map(&parse_port!/1)
          |> Enum.sort()

        {:ok, reserved}

      {error, _} ->
        {:error, error}
    end
  end

  def parse_port!(line) do
    line = String.trim(line)

    Regex.split(~r{\s+}, line)
    |> Enum.at(4)
    |> String.split(":")
    |> List.last()
    |> Integer.parse()
    |> elem(0)
  end

  def split_range(_start.._stop//_ = range, numbers_to_remove) do
    numbers_to_remove = Enum.sort(numbers_to_remove)
    do_split_range(range, numbers_to_remove)
  end

  defp do_split_range(_range, _remove, _acc \\ [])

  defp do_split_range(start..stop//_, [], acc) do
    if start > stop do
      acc
    else
      List.flatten([acc, [start..stop]])
    end
  end

  # Number is outside range
  defp do_split_range(start..stop//_, [head | _tail], acc)
       when start > stop or head > stop do
    do_split_range(start..stop, [], acc)
  end

  # Remove first in range
  defp do_split_range(start..stop//_, [start | tail], acc) do
    do_split_range((start + 1)..stop, tail, acc)
  end

  # Remove last in range
  defp do_split_range(start..stop//_, [stop | _tail], acc) do
    do_split_range(start..(stop - 1), [], acc)
  end

  # In range
  defp do_split_range(start..stop//_, [head | tail], acc) do
    new_range = start..(head - 1)
    do_split_range((head + 1)..stop, tail, [new_range | acc])
  end
end
