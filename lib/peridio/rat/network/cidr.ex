defmodule Peridio.RAT.Network.CIDR do
  defstruct ip_start: nil,
            ip_end: nil,
            addresses: nil,
            length: nil,
            range: nil

  alias Peridio.RAT.Network.IP

  import Bitwise

  def contains?(%__MODULE__{range: cidr1}, %__MODULE__{range: cidr2}) do
    not Range.disjoint?(cidr1, cidr2)
  end

  def from_inets_interface!(inet_if) do
    {:ok, cidr} = from_inets_interface(inet_if)
    cidr
  end

  def from_inets_interface({_if_name, if_opts}) do
    with {:ok, {_, _, _, _} = addr} <- Keyword.fetch(if_opts, :addr),
         {:ok, {_, _, _, _} = mask} <- Keyword.fetch(if_opts, :netmask) do
      ip = IP.new(addr)
      mask = IP.tuple_to_integer(mask)
      ip_start = find_start_address(ip.address, mask)

      cidr_length = mask_to_length(mask)
      addresses = addresses(cidr_length)
      ip_end = ip_start + (addresses - 1)

      cidr =
        %__MODULE__{
          ip_start: IP.integer_to_tuple(ip_start),
          ip_end: IP.integer_to_tuple(ip_end),
          addresses: addresses,
          length: cidr_length,
          range: ip_start..ip_end
        }

      {:ok, cidr}
    else
      e -> {:error, e}
    end
  end

  def from_string!(cidr_string) do
    {:ok, cidr} = from_string(cidr_string)
    cidr
  end

  def from_string(cidr_string) do
    with [ip_string, length_str] <- String.split(cidr_string, "/", parts: 2),
         char_list <- String.to_charlist(ip_string),
         {:ok, ip_start_tuple} <- :inet.parse_address(char_list),
         {cidr_length, _} <- Integer.parse(length_str) do
      ip_start = IP.tuple_to_integer(ip_start_tuple)
      addresses = addresses(cidr_length)
      ip_end = ip_start + (addresses - 1)

      cidr =
        %__MODULE__{
          ip_start: ip_start_tuple,
          ip_end: IP.integer_to_tuple(ip_end),
          addresses: addresses,
          length: cidr_length,
          range: ip_start..ip_end
        }

      {:ok, cidr}
    end
  end

  def from_ip_tuple_range({_, _, _, _} = ip_start, {_, _, _, _} = ip_end) do
    from_ip_range(IP.tuple_to_integer(ip_start)..IP.tuple_to_integer(ip_end))
  end

  def from_ip_range(_, acc \\ [])
  def from_ip_range(s_ip..e_ip//_ = range, []) when s_ip == e_ip, do: [do_from_ip_range(range)]
  def from_ip_range(s_ip..e_ip//_, acc) when s_ip >= e_ip, do: acc

  def from_ip_range(_ip_start..ip_end//_ = range, acc) do
    cidr = do_from_ip_range(range)
    cidr_ip_end = IP.tuple_to_integer(cidr.ip_end)
    from_ip_range((cidr_ip_end + 1)..ip_end, [cidr | acc])
  end

  def find_start_address({_, _, _, _} = addr, {_, _, _, _} = mask) do
    ip_int = IP.tuple_to_integer(addr)
    mask_int = IP.tuple_to_integer(mask)
    find_start_address(ip_int, mask_int)
  end

  def find_start_address(ip_int, mask_int), do: mask_int &&& ip_int

  def mask_to_length({a, b, c, d}) do
    <<mask_int::unsigned-integer-size(32)>> = <<a, b, c, d>>
    mask_to_length(mask_int)
  end

  def mask_to_length(mask_int) do
    msb_position =
      mask_int
      |> bxor(0xFFFFFFFF)

    case msb_position do
      0 ->
        32

      pos ->
        pos =
          pos
          |> :math.log2()
          |> floor()
          |> round()

        32 - (pos + 1)
    end
  end

  def to_string(%__MODULE__{ip_start: ip_start, length: length}) do
    "#{:inet.ntoa(ip_start)}/#{length}"
  end

  # l:   [###]
  # r:   [###]
  # ret: []
  def difference(%__MODULE__{range: range}, %__MODULE__{range: range}), do: []

  # l:   [####]
  # r:    [##]
  # ret: []
  def difference(%__MODULE__{range: l_start..l_end//_}, %__MODULE__{range: r_start..r_end//_})
      when l_start < r_start and l_end > r_end do
    []
  end

  # l: [###]
  # r:  [###]
  # ret:  [#]
  def difference(%__MODULE__{range: l_start..l_end//_}, %__MODULE__{range: r_start..r_end//_})
      when l_end < r_end and l_start <= r_start do
    [(l_end + 1)..r_end] |> Enum.map(&from_ip_range/1) |> List.flatten()
  end

  # l:    [###]
  # r:   [###]
  # ret: [#]
  def difference(%__MODULE__{range: l_start..l_end//_}, %__MODULE__{range: r_start..r_end//_})
      when l_end > r_end and l_start >= r_start do
    [(r_end + 1)..l_end] |> Enum.map(&from_ip_range/1) |> List.flatten()
  end

  # l:    [##]
  # r:   [####]
  # ret: [#][#]
  def difference(%__MODULE__{range: l_start..l_end//_}, %__MODULE__{range: r_start..r_end//_})
      when l_start > r_start and l_end < r_end do
    [r_start..(l_start - 1), (l_end + 1)..r_end] |> Enum.map(&from_ip_range/1) |> List.flatten()
  end

  def ip_prefix_length(ip_int) do
    first_lsb = first_set_lsb_position(ip_int)

    (:math.pow(2, first_lsb) - 1)
    |> round()
    |> bxor(0xFFFFFFFF)
    |> mask_to_length()
  end

  defp do_from_ip_range(ip_start.._ip_end//_ = range) do
    max_range_prefix =
      Range.size(range)
      |> :math.log2()
      |> :math.floor()
      |> round()

    max_range_prefix = 32 - max_range_prefix
    min_ip_prefix = ip_prefix_length(ip_start)
    cidr_prefix = max(max_range_prefix, min_ip_prefix)
    addresses = addresses(cidr_prefix)
    cidr_ip_end = (ip_start + (addresses - 1)) |> round()

    %__MODULE__{
      ip_start: IP.integer_to_tuple(ip_start),
      ip_end: IP.integer_to_tuple(cidr_ip_end),
      addresses: addresses,
      length: cidr_prefix,
      range: ip_start..cidr_ip_end
    }
  end

  defp addresses(cidr_length) when is_integer(cidr_length), do: 0x100000000 >>> cidr_length

  defp first_set_lsb_position(x) when x > 0 do
    lowest_set_bit = x &&& -x
    :math.log2(lowest_set_bit) |> floor() |> round
  end

  defp first_set_lsb_position(0), do: nil
end
