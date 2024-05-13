defmodule Peridio.RAT.WireGuard.Interface do
  @moduledoc """
   The Wireguard [Interface] definition for the local machine
  """

  alias Peridio.RAT.Utils
  alias Peridio.RAT.Network
  alias Peridio.RAT.Network.IP

  defstruct [
    :id,
    :ip_address,
    :port,
    :private_key,
    :public_key
  ]

  @typedoc """
  The Wireguard Interface definition for the local machine

  - `:id` - The local Interface name.
  - `:ip_address` - The ip address of the local interface in Erlang tuple form {_, _, _, _}.
  - `:port` - The local port the interface is listening on.
  - `:private_key` - The private key of the wireguard interface.
  - `:public_key` - The public key of the wireguard interface.
  """

  @type t :: %__MODULE__{
          id: String.t(),
          ip_address: IP.t(),
          port: non_neg_integer(),
          private_key: String.t(),
          public_key: String.t()
        }

  @ifprefix "peridio-"

  def new(%{private_key: private_key, public_key: public_key}) do
    id = @ifprefix <> Utils.generate_random_string(4)
    port_range = Network.available_ports()
    port = port_range |> Enum.random() |> Enum.random()

    %__MODULE__{
      id: id,
      port: port,
      public_key: public_key,
      private_key: private_key
    }
  end

  def used_interfaces() do
    with {:ok, interfaces} <- :inet.getifaddrs() do
      interfaces
      |> Enum.map(&elem(&1, 0))
      |> Enum.map(&to_string/1)
      |> Enum.filter(&String.starts_with?(&1, @ifprefix))
    end
  end
end
