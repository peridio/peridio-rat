defmodule Peridio.RAT.WireGuard.Mock do
  alias Peridio.RAT.WireGuard.WireGuardBehaviour

  @behaviour WireGuardBehaviour

  # Setup and Configuration
  @impl WireGuardBehaviour
  def create_interface("failure") do
    {"", 255}
  end

  @impl WireGuardBehaviour
  def create_interface(_) do
    {"", 0}
  end

  @impl WireGuardBehaviour
  def configure_interface_endpoints(_interface_name, _our_ip, _peer_ip) do
    {"good", 0}
  end

  @impl WireGuardBehaviour
  def configure_wireguard(_interface, _args, _conf_hooks) do
    :ok
  end

  @impl WireGuardBehaviour
  def bring_up_interface("failure", _opts) do
    {"fail", 1}
  end

  @impl WireGuardBehaviour
  def bring_up_interface(_, _opts) do
    {"", 0}
  end

  @impl WireGuardBehaviour
  def teardown_interface("failure", _opts) do
    {"fail", 1}
  end

  @impl WireGuardBehaviour
  def teardown_interface(_, _opts) do
    {"success", 0}
  end

  @impl WireGuardBehaviour
  def generate_key_pair() do
    %{
      public_key: "SfHcet4JVMU6QVhs9hVFiAWZOa8YcBpnSdEK1Nyy6nY=",
      private_key: "gKP7GseJqWS4H0ZgP7z2kySaJPvhmKjxc+NnhfhdJmM="
    }
  end

  # Monitoring and Statistics
  @impl WireGuardBehaviour
  def rx_packet_stats(_) do
    {27, 0}
  end

  @impl WireGuardBehaviour
  def tx_packet_stats(_) do
    {8, 0}
  end

  @impl WireGuardBehaviour
  def wg_latest_handshakes(_) do
    {1_656_345_389, 0}
  end
end
