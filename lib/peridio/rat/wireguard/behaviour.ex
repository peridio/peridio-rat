defmodule Peridio.RAT.WireGuard.WireGuardBehaviour do
  # Setup and Configuration
  alias Peridio.RAT.WireGuard.{Interface, Peer}

  @callback create_interface(String.t()) :: {String.t(), integer()}
  @callback configure_interface_endpoints(String.t(), String.t(), String.t()) ::
              {String.t(), integer()}
  @callback configure_wireguard(Interface.t(), Peer.t(), Keyword.t()) :: :ok | {:error, any()}
  @callback bring_up_interface(String.t(), Keyword.t()) :: {String.t(), integer()}
  @callback teardown_interface(String.t(), Keyword.t()) :: {String.t(), integer()}
  @callback generate_key_pair() :: %{atom() => String.t(), atom() => String.t()}

  # Monitoring and Stats
  @callback rx_packet_stats(String.t()) :: {integer(), integer()}
  @callback tx_packet_stats(String.t()) :: {integer(), integer()}
  @callback wg_latest_handshakes(String.t()) :: {integer(), integer()}
end
