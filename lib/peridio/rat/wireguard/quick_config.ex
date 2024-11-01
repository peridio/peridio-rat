defmodule Peridio.RAT.WireGuard.QuickConfig do
  alias Peridio.RAT.WireGuard.{Interface, Peer}
  alias Peridio.RAT.Network.IP

  require Logger

  defstruct interface: [],
            peer: [],
            extra: []

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

  def new(%Interface{} = interface, %Peer{} = peer, extra \\ []) do
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

  def get_in_extra(%__MODULE__{extra: extra}, [section | rest]) do
    case Enum.find(extra, fn {name, _values} -> name == section end) do
      {_section, values} -> do_get_in_extra(values, rest)
      nil -> []
    end
  end

  def conf_parse(content) when is_binary(content) do
    content
    |> String.split("\n")
    |> Stream.map(&String.trim/1)
    |> Stream.map(&String.replace_prefix(&1, "# ", ""))
    |> Enum.reject(&(String.length(&1) == 0 || String.starts_with?(&1, ";")))
    |> conf_parse_lines([], nil)
  end

  def conf_to_string(data) do
    conf_sections = Map.keys(@conf_keys)

    data
    |> Enum.map(fn
      {section, values} when is_list(values) ->
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

            _ ->
              raise "QuickConfig values must be in the form of {\"key\", value}"
          end)
          |> Enum.join("\n")

        section_str <> values_str

      {key, value} ->
        "# #{key} = #{value}"
    end)
    |> Enum.join("\n\n")
  end

  def encode(%Interface{} = interface) do
    [
      {"Address", to_string(interface.ip_address)},
      {"ListenPort", to_string(interface.port)},
      {"PrivateKey", interface.private_key},
      {"ID", interface.id},
      {"PublicKey", interface.public_key}
    ]
  end

  def encode(%Peer{} = peer) do
    [
      {"AllowedIPs", "#{peer.ip_address}/32"},
      {"PublicKey", peer.public_key},
      {"Endpoint", "#{peer.endpoint}:#{peer.port}"},
      {"PersistentKeepalive", to_string(peer.persistent_keepalive)}
    ]
  end

  def encode(%__MODULE__{} = config) do
    [
      {"Interface", encode(config.interface)},
      {"Peer", encode(config.peer)}
    ]
    |> merge_extra(config.extra)
    |> conf_to_string()
  end

  def decode_conf(conf) do
    conf_list = conf_parse(conf)
    interface = get_section_and_decode(conf_list, "Interface", &decode_interface/1)
    peer = get_section_and_decode(conf_list, "Peer", &decode_peer/1)
    extra = decode_extra(conf_list)
    %__MODULE__{interface: interface, peer: peer, extra: extra}
  end

  def decode_interface(interface_kvs) do
    values = Enum.into(interface_kvs, %{})

    %Interface{
      ip_address: IP.new(values["Address"]),
      port: String.to_integer(values["ListenPort"]),
      private_key: values["PrivateKey"],
      id: values["ID"],
      public_key: values["PublicKey"]
    }
  end

  def decode_peer(peer_kvs) do
    values = Enum.into(peer_kvs, %{})
    [peer_endpoint, peer_port] = String.split(values["Endpoint"], ":")
    peer_port = String.to_integer(peer_port)
    [peer_ip | _] = String.split(values["AllowedIPs"], "/")

    %Peer{
      ip_address: peer_ip,
      endpoint: peer_endpoint,
      port: peer_port,
      public_key: values["PublicKey"],
      persistent_keepalive: String.to_integer(values["PersistentKeepalive"])
    }
  end

  def decode_extra(conf_list) do
    conf_list
    |> Enum.reduce([], fn
      {"Interface", kvs}, acc ->
        case filter_extra_kvs(kvs, @interface_keys) do
          [] -> acc
          extra_kvs -> [{"Interface", extra_kvs} | acc]
        end

      {"Peer", kvs}, acc ->
        case filter_extra_kvs(kvs, @peer_keys) do
          [] -> acc
          extra_kvs -> [{"Peer", extra_kvs} | acc]
        end

      other, acc ->
        [other | acc]
    end)
    |> Enum.reverse()
  end

  defp filter_extra_kvs(kvs, keys_to_remove) do
    kvs
    |> Enum.reject(fn {key, _} -> key in keys_to_remove end)
  end

  defp do_get_in_extra(values, []) when is_list(values), do: values

  defp do_get_in_extra(values, [key]) when is_list(values) do
    values |> Enum.filter(fn {k, _v} -> k == key end)
  end

  defp do_get_in_extra(values, [key | rest]) when is_list(values) do
    values
    |> Enum.filter(fn {k, _} -> k == key end)
    |> Enum.flat_map(fn {_, v} ->
      case v do
        v when is_list(v) -> do_get_in_extra(v, rest)
        _ -> []
      end
    end)
  end

  defp get_section_and_decode(conf_list, section, decoder) do
    conf_list
    |> Enum.find(fn {name, _} -> name == section end)
    |> elem(1)
    |> decoder.()
  end

  defp merge_extra(base, extra) do
    extra
    |> Enum.reduce(base, fn
      {section, values}, acc when is_list(values) ->
        case List.keytake(acc, section, 0) do
          {{^section, existing_values}, remaining} ->
            [{section, values ++ existing_values} | remaining]

          nil ->
            acc ++ [{section, values}]
        end

      _, _ ->
        raise "QuickConfig Extra values must be passed as a list"
    end)
  end

  defp conf_parse_lines([], acc, _current_section), do: acc

  defp conf_parse_lines([line | rest], acc, current_section) do
    cond do
      # Section header
      String.match?(line, ~r/^\[(.*)\]$/) ->
        [_, section] = Regex.run(~r/^\[(.*)\]$/, line)
        conf_parse_lines(rest, [{section, []} | acc], section)

      # Key-value pair
      String.match?(line, ~r/^(.+?)=(.*)$/) ->
        [_, key, value] = Regex.run(~r/^(.+?)=(.*)$/, line)
        key = String.trim(key)
        value = String.trim(value)

        new_acc =
          if current_section do
            update_section_values(acc, current_section, key, value)
          else
            [{key, value} | acc]
          end

        conf_parse_lines(rest, new_acc, current_section)

      true ->
        conf_parse_lines(rest, acc, current_section)
    end
  end

  defp update_section_values(acc, section, key, value) do
    Enum.map(acc, fn
      {^section, values} -> {section, [{key, value} | values]}
      other -> other
    end)
  end
end
