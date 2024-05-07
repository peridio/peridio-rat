defmodule Peridio.RAT.WireGuard.Peer do
  @moduledoc """
   The Wireguard [Peer] definition for the remote machine
  """

  defstruct [
    :ip_address,
    :endpoint,
    :port,
    :public_key,
    :persistent_keepalive
  ]

  @typedoc """
  - `:ip_address` - The local ip address of the remote peer.
  - `:endpoint` - The remote ip address of the remote peer.
  - `:port` - The remote port the peer is listening on.
  - `:public_key` - The public key of the wireguard peer.
  - `:persistent_keepalive` - Optionally set for NAT keepalive .
  """

  @type t :: %__MODULE__{
          ip_address: String.t(),
          endpoint: String.t(),
          port: non_neg_integer(),
          public_key: String.t(),
          persistent_keepalive: non_neg_integer()
        }
end
