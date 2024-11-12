defmodule Peridio.RAT.Utils do
  def generate_random_string(length) do
    length
    |> :crypto.strong_rand_bytes()
    |> Base.encode32(padding: false)
  end

  def write_file_sync(filename, data) do
    with {:ok, file} <- File.open(filename, [:write, :sync]),
         :ok <- IO.binwrite(file, data),
         :ok <- File.close(file) do
      :ok
    end
  end
end
