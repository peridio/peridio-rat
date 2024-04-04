defmodule Peridio.RAT.Network.IP do
  def tuple_to_integer({a, b, c, d}) do
    <<ipv4_int::unsigned-integer-size(32)>> = <<a, b, c, d>>
    ipv4_int
  end

  def integer_to_tuple(ipv4_int) do
    <<a, b, c, d>> = <<ipv4_int::unsigned-integer-size(32)>>
    {a, b, c, d}
  end
end
