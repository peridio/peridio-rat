defmodule Peridio.RAT.WireGuard do
  @client Application.compile_env(:peridio_rat, :wireguard_client)

  # Setup and Configuration
  def create_interface(interface_name) do
    @client.create_interface(interface_name)
  end

  def configure_interface_endpoints(interface_name, our_ip, peer_ip) do
    @client.configure_interface_endpoints(interface_name, our_ip, peer_ip)
  end

  def configure_wireguard(interface, peer, opts \\ []) do
    @client.configure_wireguard(interface, peer, opts)
  end

  def bring_up_interface(interface_id, opts \\ []) do
    @client.bring_up_interface(interface_id, opts)
  end

  def teardown_interface(interface_name, opts \\ []) do
    @client.teardown_interface(interface_name, opts)
  end

  def generate_key_pair() do
    @client.generate_key_pair()
  end

  # Monitoring and Statistics
  def rx_packet_stats(interface_name) do
    @client.rx_packet_stats(interface_name)
  end

  def tx_packet_stats(interface_name) do
    @client.tx_packet_stats(interface_name)
  end

  def wg_latest_handshakes(interface_name) do
    @client.wg_latest_handshakes(interface_name)
  end
end
