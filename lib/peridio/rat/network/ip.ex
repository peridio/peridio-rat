defmodule Peridio.RAT.Network.IP do
  defstruct [
    address: nil
  ]

  @type address :: non_neg_integer()

  @type t :: %__MODULE__{
    address: address()
  }

  defimpl String.Chars, for: __MODULE__ do
    def to_string(%{address: address}) do
      {a, b, c, d} = Peridio.RAT.Network.IP.integer_to_tuple(address)
      "#{a}.#{b}.#{c}.#{d}"
    end
  end

  def new({_, _, _, _} = ipv4) do
    %__MODULE__{
      address: tuple_to_integer(ipv4),
    }
  end

  def tuple_to_integer({a, b, c, d}) do
    <<ipv4_int::unsigned-integer-size(32)>> = <<a, b, c, d>>
    ipv4_int
  end

  def integer_to_tuple(ipv4_int) do
    <<a, b, c, d>> = <<ipv4_int::unsigned-integer-size(32)>>
    {a, b, c, d}
  end
end
