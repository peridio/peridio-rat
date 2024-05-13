defmodule Peridio.RAT.WireGuard.Default do
  alias Peridio.RAT.WireGuard.{WireGuardBehaviour, Interface, Peer}

  @behaviour WireGuardBehaviour

  # Setup and Configuration
  @impl WireGuardBehaviour
  def create_interface(interface_name) do
    System.cmd("ip", ["link", "add", "dev", interface_name, "type", "wireguard"])
  end

  @impl WireGuardBehaviour
  def configure_interface_endpoints(interface_name, our_ip, peer_ip) do
    System.cmd("ip", ["address", "add", "dev", interface_name, our_ip, "peer", peer_ip])
  end

  @impl WireGuardBehaviour
  def configure_wireguard(%Interface{} = interface, %Peer{} = peer, opts \\ []) do
    # System.cmd("bash", [
    #   "-c",
    #   "wg set #{inspect(args.interface_name)} listen-port #{inspect(args.listen_port)} private-key <(echo #{inspect(args.private_key)}) peer #{inspect(args.peer)} allowed-ips #{inspect(args.allowed_ips)} endpoint #{inspect(args.endpoint_ip)}:#{inspect(args.endpoint_port)} persistent-keepalive #{inspect(args.keep_alive_timeout)}"
    # ])
    # This is peer configuration to give to the interface
    # peer = EEx.eval_file("priv/wg_conf_peer_template.eex", peer: peer)
    # File.write("priv/#{wg_interface}_peer.conf", peer)

    opts = default_wireguard_opts(opts)
    priv_dir = Application.app_dir(:peridio_rat, "priv")

    # wireguard interface configuration
    conf_interface =
      EEx.eval_file("#{priv_dir}/wg_conf_interface_template.eex", interface: interface)

    # wireguard peer configuration
    conf_peer = EEx.eval_file("#{priv_dir}/wg_conf_peer_template.eex", peer: peer)

    opts[:work_dir]
    |> Path.join("#{interface.id}.conf")
    |> File.write(conf_interface <> "\n" <> opts[:hooks] <> "\n" <> conf_peer)
  end

  @impl WireGuardBehaviour
  def bring_up_interface(interface_name, opts \\ []) do
    # System.cmd("ip", ["link", "set", "up", "dev", interface_name])
    opts = default_wireguard_opts(opts)
    conf_file = Path.join([opts[:work_dir], "#{interface_name}.conf"])
    System.cmd("wg-quick", ["up", conf_file])
  end

  @impl WireGuardBehaviour
  def teardown_interface(interface_name, opts \\ []) do
    # System.cmd("ip", ["link", "del", "dev", interface_name])
    opts = default_wireguard_opts(opts)
    conf_file = Path.join([opts[:work_dir], "#{interface_name}.conf"])
    result = System.cmd("wg-quick", ["down", conf_file])

    if result == {"", 0} do
      File.rm(conf_file)
    end

    result
  end

  @impl WireGuardBehaviour
  # @spec generate_key_pair :: %{private_key: binary, public_key: binary}
  def generate_key_pair() do
    {private_key, 0} = System.cmd("wg", ["genkey"])
    private_key = String.trim(private_key)
    {public_key, 0} = System.shell("echo #{private_key} | wg pubkey")
    public_key = String.trim(public_key)
    %{private_key: private_key, public_key: public_key}
  end

  # Monitoring and Statistics
  @impl WireGuardBehaviour
  def rx_packet_stats(interface_name) do
    # This returns the number of packets coming in over the interface. If it's static/unchanging, that _could_ mean it's stale,
    # but it's not definitive proof by itself.

    case System.cmd("cat", ["/sys/class/net/#{interface_name}/statistics/rx_packets"]) do
      {packets, 0} ->
        {String.replace(packets, "\n", ""), 0}

      error_tuple ->
        error_tuple
    end
  end

  @impl WireGuardBehaviour
  def tx_packet_stats(interface_name) do
    # This returns the number of packets going out over the interface. If it's static/unchanging, that _could_ mean it's stale,
    # but it's not definitive proof by itself.

    case System.cmd("cat", ["/sys/class/net/#{interface_name}/statistics/tx_packets"]) do
      {packets, 0} ->
        {String.replace(packets, "\n", ""), 0}

      error_tuple ->
        error_tuple
    end
  end

  @impl WireGuardBehaviour
  def wg_latest_handshakes(interface_name) do
    # This returns the epoch time of the last key exchange handshake.
    # If this is less than the keep alive timeout, we don't have a live tunnel.

    case System.cmd("wg", ["show", interface_name, "latest-handshakes"]) do
      {"", 0} ->
        {"0", 0}

      {return_value, 0} ->
        [_, epoch_time, _] = String.split(return_value, ~r/\s/)
        {epoch_time, 0}

      error_tuple ->
        error_tuple
    end
  end

  def default_wireguard_opts(opts) do
    opts
    |> Keyword.put_new(:hooks, "")
    |> Keyword.put_new(:work_dir, default_work_dir())
  end

  def default_work_dir() do
    Application.get_env(:peridio_rat, :work_dir, System.tmp_dir!())
  end
end
