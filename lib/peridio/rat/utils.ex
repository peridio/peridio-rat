defmodule Peridio.RAT.Utils do
  def generate_random_string(length) do
    length
    |> :crypto.strong_rand_bytes()
    |> Base.encode32(padding: false)
  end
end
