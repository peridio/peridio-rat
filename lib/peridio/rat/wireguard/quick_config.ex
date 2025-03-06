defmodule Peridio.RAT.WireGuard.QuickConfig do
  alias Peridio.RAT.WireGuard.{Interface, Peer}
  alias Peridio.RAT.Network.IP
  alias Peridio.RAT.Utils

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
    Utils.write_file_sync(filepath, content)
  end

  def read(filepath) do
    with {:ok, content} <- File.read(filepath),
         {:ok, _} <- validate_content(content),
         {:ok, decoded} <- decode_conf(content) do
      {:ok, decoded}
    else
      {:error, :enoent} ->
        {:error, :file_not_found}

      {:error, :empty_file} ->
        {:error, :empty_file}

      {:error, :invalid_content} ->
        {:error, :invalid_config}

      {:error, reason} when is_atom(reason) ->
        {:error, reason}

      error ->
        Logger.error("Unexpected error reading WireGuard config: #{inspect(error)}")
        {:error, :invalid_config}
    end
  end

  def read!(filepath) do
    case read(filepath) do
      {:ok, config} -> config
      {:error, reason} -> raise "Failed to read WireGuard config: #{reason}"
    end
  end

  defp validate_content(""), do: {:error, :empty_file}
  defp validate_content(nil), do: {:error, :empty_file}
  defp validate_content(content) when is_binary(content), do: {:ok, content}
  defp validate_content(_), do: {:error, :invalid_content}

  def decode_conf(nil), do: {:error, :nil_config}

  def decode_conf(conf) do
    try do
      conf_list = conf_parse(conf)

      with {:ok, interface} <-
             safe_get_section_and_decode(conf_list, "Interface", &safe_decode_interface/1),
           {:ok, peer} <- safe_get_section_and_decode(conf_list, "Peer", &safe_decode_peer/1) do
        extra = decode_extra(conf_list)
        {:ok, %__MODULE__{interface: interface, peer: peer, extra: extra}}
      else
        {:error, reason} -> {:error, reason}
      end
    rescue
      e ->
        Logger.error("Error decoding config: #{inspect(e)}")
        {:error, :decode_error}
    end
  end

  defp safe_get_section_and_decode(conf_list, section, decoder) do
    case Enum.find(conf_list, fn {name, _} -> name == section end) do
      {^section, values} when is_list(values) ->
        decoder.(values)

      nil ->
        {:error, :"#{String.downcase(section)}_section_missing"}

      _ ->
        {:error, :"invalid_#{String.downcase(section)}_section"}
    end
  end

  def safe_decode_interface(interface_kvs) do
    required_keys = ["Address", "ListenPort", "PrivateKey", "ID", "PublicKey"]

    with {:ok, values} <- validate_required_keys(interface_kvs, required_keys),
         {:ok, port} <- safe_to_integer(values["ListenPort"]) do
      try do
        interface = %Interface{
          ip_address: IP.new(values["Address"]),
          port: port,
          private_key: values["PrivateKey"],
          id: values["ID"],
          public_key: values["PublicKey"]
        }

        {:ok, interface}
      rescue
        _ -> {:error, :invalid_interface_values}
      end
    end
  end

  def safe_decode_peer(peer_kvs) do
    required_keys = ["AllowedIPs", "Endpoint", "PublicKey", "PersistentKeepalive"]

    with {:ok, values} <- validate_required_keys(peer_kvs, required_keys),
         {:ok, endpoint, port} <- parse_endpoint(values["Endpoint"]),
         {:ok, keepalive} <- safe_to_integer(values["PersistentKeepalive"]),
         {:ok, ip} <- parse_allowed_ips(values["AllowedIPs"]) do
      try do
        peer = %Peer{
          ip_address: ip,
          endpoint: endpoint,
          port: port,
          public_key: values["PublicKey"],
          persistent_keepalive: keepalive
        }

        {:ok, peer}
      rescue
        _ -> {:error, :invalid_peer_values}
      end
    end
  end

  defp validate_required_keys(kvs, required_keys) do
    values = Enum.into(kvs, %{})
    missing_keys = Enum.filter(required_keys, &(not Map.has_key?(values, &1)))

    case missing_keys do
      [] -> {:ok, values}
      missing -> {:error, {:missing_required_keys, missing}}
    end
  end

  defp safe_to_integer(nil), do: {:error, :value_missing}

  defp safe_to_integer(str) when is_binary(str) do
    try do
      {:ok, String.to_integer(str)}
    rescue
      _ -> {:error, :invalid_integer}
    end
  end

  defp safe_to_integer(_), do: {:error, :invalid_integer}

  defp parse_endpoint(nil), do: {:error, :endpoint_missing}

  defp parse_endpoint(endpoint) do
    case String.split(endpoint, ":") do
      [host, port_str] ->
        case safe_to_integer(port_str) do
          {:ok, port} -> {:ok, host, port}
          {:error, reason} -> {:error, {:invalid_port, reason}}
        end

      _ ->
        {:error, :invalid_endpoint_format}
    end
  end

  defp parse_allowed_ips(nil), do: {:error, :allowed_ips_missing}

  defp parse_allowed_ips(ips) do
    case String.split(ips, "/") do
      [ip | _] -> {:ok, ip}
      _ -> {:error, :invalid_allowed_ips_format}
    end
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
    conf = [
      {"Address", to_string(interface.ip_address)},
      {"ListenPort", to_string(interface.port)},
      {"PrivateKey", interface.private_key},
      {"ID", interface.id},
      {"PublicKey", interface.public_key},
      {"Table", to_string(interface.table)}
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
