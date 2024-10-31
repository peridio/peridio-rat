defmodule Peridio.RAT.WireGuard.QuickConfig do
  alias Peridio.RAT.WireGuard.{Interface, Peer}
  alias Peridio.RAT.Network.IP
  alias Peridio.RAT.Utils

  require Logger

  defstruct interface: %{},
            peer: %{},
            extra: %{}

  @conf_keys %{
    "Interface" => [
      "Address",
      "DNS",
      "MTU",
      "Table",
      "ListenPort",
      "PrivateKey",
      "PreUp",
      "PreDown",
      "PostUp",
      "PostDown",
      "SaveConfig"
    ],
    "Peer" => ["AllowedIPs", "PublicKey", "Endpoint", "PersistentKeepalive", "PresharedKey"]
  }
  @interface_keys ["ID", "Address", "ListenPort", "PrivateKey", "PublicKey"]
  @peer_keys ["AllowedIPs", "PublicKey", "Endpoint", "PersistentKeepalive"]

  def new(%Interface{} = interface, %Peer{} = peer, extra \\ %{}) do
    %__MODULE__{
      interface: interface,
      peer: peer,
      extra: extra
    }
  end

  def write(filepath, %__MODULE__{} = config) do
    content = encode(config)
    File.write(filepath, content)
  end

  def read(filepath) do
    case File.read(filepath) do
      {:ok, conf} -> {:ok, decode_conf(conf)}
      error -> error
    end
  end

  def read!(filepath) do
    {:ok, quick_config} = read(filepath)
    quick_config
  end

  def conf_parse(content) when is_binary(content) do
    content
    |> String.split("\n")
    |> Stream.map(&String.trim/1)
    |> Stream.map(&String.replace_prefix(&1, "# ", ""))
    |> Enum.reject(&(String.length(&1) == 0 || String.starts_with?(&1, ";")))
    |> conf_parse_lines(%{}, nil)
  end

  defp conf_parse_lines([], acc, _current_section), do: acc

  defp conf_parse_lines([line | rest], acc, current_section) do
    cond do
      # Section header
      String.match?(line, ~r/^\[(.*)\]$/) ->
        [_, section] = Regex.run(~r/^\[(.*)\]$/, line)
        conf_parse_lines(rest, Map.put_new(acc, section, %{}), section)

      # Key-value pair
      String.match?(line, ~r/^(.+?)=(.*)$/) ->
        [_, key, value] = Regex.run(~r/^(.+?)=(.*)$/, line)
        key = String.trim(key)
        value = String.trim(value)

        new_acc =
          if current_section do
            Map.update!(acc, current_section, fn section ->
              Map.put(section, key, value)
            end)
          else
            Map.put(acc, key, value)
          end

        conf_parse_lines(rest, new_acc, current_section)

      true ->
        conf_parse_lines(rest, acc, current_section)
    end
  end

  def conf_to_string(data) do
    conf_sections = Map.keys(@conf_keys)

    data
    |> Enum.map(fn
      {section, values} when is_map(values) ->
        section_str =
          if section in conf_sections do
            "[#{section}]\n"
          else
            "# [#{section}]\n"
          end

        section_keys = @conf_keys[section] || []

        values_str =
          values
          |> Enum.map(fn
            {k, v} ->
              case k in section_keys do
                true -> "#{k} = #{v}"
                false -> "# #{k} = #{v}"
              end
          end)
          |> Enum.join("\n")

        section_str <> values_str

      {key, value} ->
        "# #{key} = #{value}"
    end)
    |> Enum.join("\n\n")
  end

  def encode(%Interface{} = interface) do
    %{
      "Address" => to_string(interface.ip_address),
      "ListenPort" => to_string(interface.port),
      "PrivateKey" => interface.private_key,
      "ID" => interface.id,
      "PublicKey" => interface.public_key
    }
  end

  def encode(%Peer{} = peer) do
    %{
      "AllowedIPs" => "#{peer.ip_address}/32",
      "PublicKey" => peer.public_key,
      "Endpoint" => "#{peer.endpoint}:#{peer.port}",
      "PersistentKeepalive" => to_string(peer.persistent_keepalive)
    }
  end

  def encode(%__MODULE__{} = config) do
    %{
      "Interface" => encode(config.interface),
      "Peer" => encode(config.peer)
    }
    |> Utils.deep_merge(config.extra)
    |> Utils.sort_by_keys(["Interface", "Peer"])
    |> conf_to_string()
  end

  def decode_conf(conf) do
    conf = conf_parse(conf)
    interface = decode_interface(conf["Interface"])
    peer = decode_peer(conf["Peer"])
    extra = decode_extra(conf)
    %__MODULE__{interface: interface, peer: peer, extra: extra}
  end

  def decode_interface(interface_section) when is_map(interface_section) do
    %Interface{
      ip_address: IP.new(interface_section["Address"]),
      port: String.to_integer(interface_section["ListenPort"]),
      private_key: interface_section["PrivateKey"],
      id: interface_section["ID"],
      public_key: interface_section["PublicKey"]
    }
  end

  def decode_peer(peer_section) when is_map(peer_section) do
    [peer_endpoint, peer_port] = String.split(peer_section["Endpoint"], ":")
    peer_port = String.to_integer(peer_port)
    [peer_ip | _] = String.split(peer_section["AllowedIPs"], "/")

    %Peer{
      ip_address: peer_ip,
      endpoint: peer_endpoint,
      port: peer_port,
      public_key: peer_section["PublicKey"],
      persistent_keepalive: String.to_integer(peer_section["PersistentKeepalive"])
    }
  end

  def decode_extra(conf) do
    interface_extra = Map.drop(conf["Interface"], @interface_keys)
    peer_extra = Map.drop(conf["Peer"], @peer_keys)

    Map.drop(conf, ["Interface", "Peer"])
    |> put_interface_extra(interface_extra)
    |> put_peer_extra(peer_extra)
  end

  def put_interface_extra(extra, interface_extra) when map_size(interface_extra) == 0, do: extra

  def put_interface_extra(extra, interface_extra) do
    Map.put(extra, "Interface", interface_extra)
  end

  def put_peer_extra(extra, peer_extra) when map_size(peer_extra) == 0, do: extra

  def put_peer_extra(extra, peer_extra) do
    Map.put(extra, "Peer", peer_extra)
  end
end
