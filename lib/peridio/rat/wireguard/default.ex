defmodule Peridio.RAT.WireGuard.Default do
  alias Peridio.RAT.WireGuard.{WireGuardBehaviour, Interface, Peer, QuickConfig}

  @behaviour WireGuardBehaviour

  # Setup and Configuration
  @impl WireGuardBehaviour
  def create_interface(interface_name) do
    System.cmd("ip", ["link", "add", "dev", interface_name, "type", "wireguard"],
      stderr_to_stdout: true
    )
  end

  @impl WireGuardBehaviour
  def configure_interface_endpoints(interface_name, our_ip, peer_ip) do
    System.cmd("ip", ["address", "add", "dev", interface_name, our_ip, "peer", peer_ip],
      stderr_to_stdout: true
    )
  end

  @impl WireGuardBehaviour
  def configure_wireguard(%Interface{} = interface, %Peer{} = peer, opts \\ []) do
    opts = default_wireguard_opts(opts)
    filepath = Path.join(opts[:data_dir], "#{interface.id}.conf")

    extra = opts[:extra] || %{}
    config = QuickConfig.new(interface, peer, extra)
    QuickConfig.write(filepath, config)
  end

  @impl WireGuardBehaviour
  def bring_up_interface(interface_name, opts \\ []) do
    opts = default_wireguard_opts(opts)
    conf_file = Path.join([opts[:data_dir], "#{interface_name}.conf"])
    System.cmd("wg-quick", ["up", conf_file], stderr_to_stdout: true)
  end

  require Logger
  @impl WireGuardBehaviour
  def teardown_interface(interface_name, opts \\ []) do
    opts = default_wireguard_opts(opts)
    conf_file = Path.join([opts[:data_dir], "#{interface_name}.conf"])

    result = System.cmd("wg-quick", ["down", conf_file], stderr_to_stdout: true)
    Logger.debug("Tearing down interface #{interface_name}")
    File.rm(conf_file)

    result
  end

  @impl WireGuardBehaviour
  def list_interfaces(opts \\ []) do
    opts = default_wireguard_opts(opts)

    opts[:data_dir]
    |> Path.join("*.conf")
    |> Path.wildcard()
    |> Stream.map(&Path.expand/1)
    |> Enum.map(&QuickConfig.read/1)
    |> Enum.filter(&match?({:ok, _}, &1))
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

    case System.cmd("cat", ["/sys/class/net/#{interface_name}/statistics/rx_packets"],
           stderr_to_stdout: true
         ) do
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

    case System.cmd("cat", ["/sys/class/net/#{interface_name}/statistics/tx_packets"],
           stderr_to_stdout: true
         ) do
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

    case System.cmd("wg", ["show", interface_name, "latest-handshakes"], stderr_to_stdout: true) do
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
    |> Keyword.put_new(:data_dir, default_data_dir())
  end

  def default_data_dir() do
    Application.get_env(:peridio_rat, :data_dir, System.tmp_dir!())
  end
end
