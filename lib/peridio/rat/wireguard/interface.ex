defmodule Peridio.RAT.WireGuard.Interface do
  defstruct [
    :name,
    :ip_address,
    :port,
    :port_forward,
    :private_key,
    :public_key
  ]
end
