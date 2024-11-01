defmodule Peridio.UtilsTest do
  use ExUnit.Case
  doctest Peridio.RAT.WireGuard.QuickConfig

  alias Peridio.RAT.WireGuard.{Interface, Peer, QuickConfig}
  alias Peridio.RAT.Network.IP

  @config """
  [Interface]
  Address = 10.0.0.1
  ListenPort = 8080
  PrivateKey = 2PSyTqm+3rXzUK+T8jBhgZp9UHjFkgVZv4bXncWMyXY=
  # ID = peridio-56X4U4Q
  # PublicKey = Pu7ymHtDqF4X9VNjVj9mYFBh/z7LGxY6VQJAGiSEgTM=

  [Peer]
  AllowedIPs = 10.0.0.3/32
  PublicKey = h2W8fjxUwZH+G8/Qp/H7kzn4SQz/EJIhOVFMh6mmtX4=
  Endpoint = 10.0.0.2:8081
  PersistentKeepalive = 25

  # [Peridio]
  # TunnelID = prn:1:be4d30b4-de6b-47cd-85ea-a75e23fd63ef:tunnel:b3f1f699-3bc8-4c77-bda2-b974595d5e3f
  # A = B
  # A = C
  """

  describe "conf" do
    test "parse" do
      parsed_config = QuickConfig.conf_parse(@config)
      {"Interface", interface_section} = Enum.find(parsed_config, &(elem(&1, 0) == "Interface"))
      {"Peer", peer_section} = Enum.find(parsed_config, &(elem(&1, 0) == "Peer"))
      {"Peridio", peridio_section} = Enum.find(parsed_config, &(elem(&1, 0) == "Peridio"))

      assert {"Address", "10.0.0.1"} = Enum.find(interface_section, &(elem(&1, 0) == "Address"))
      assert {"ListenPort", "8080"} = Enum.find(interface_section, &(elem(&1, 0) == "ListenPort"))

      assert {"PrivateKey", "2PSyTqm+3rXzUK+T8jBhgZp9UHjFkgVZv4bXncWMyXY="} =
               Enum.find(interface_section, &(elem(&1, 0) == "PrivateKey"))

      assert {"ID", "peridio-56X4U4Q"} = Enum.find(interface_section, &(elem(&1, 0) == "ID"))

      assert {"PublicKey", "Pu7ymHtDqF4X9VNjVj9mYFBh/z7LGxY6VQJAGiSEgTM="} =
               Enum.find(interface_section, &(elem(&1, 0) == "PublicKey"))

      assert {"AllowedIPs", "10.0.0.3/32"} =
               Enum.find(peer_section, &(elem(&1, 0) == "AllowedIPs"))

      assert {"PublicKey", "h2W8fjxUwZH+G8/Qp/H7kzn4SQz/EJIhOVFMh6mmtX4="} =
               Enum.find(peer_section, &(elem(&1, 0) == "PublicKey"))

      assert {"Endpoint", "10.0.0.2:8081"} = Enum.find(peer_section, &(elem(&1, 0) == "Endpoint"))

      assert {"PersistentKeepalive", "25"} =
               Enum.find(peer_section, &(elem(&1, 0) == "PersistentKeepalive"))

      assert {"TunnelID",
              "prn:1:be4d30b4-de6b-47cd-85ea-a75e23fd63ef:tunnel:b3f1f699-3bc8-4c77-bda2-b974595d5e3f"} =
               Enum.find(peridio_section, &(elem(&1, 0) == "TunnelID"))

      a_values = Enum.filter(peridio_section, &(elem(&1, 0) == "A"))
      assert {"A", "B"} = Enum.find(a_values, &(elem(&1, 1) == "B"))
      assert {"A", "C"} = Enum.find(a_values, &(elem(&1, 1) == "C"))
    end

    test "read/write" do
      interface =
        %Interface{
          id: "peridio-56X4U4Q",
          ip_address: IP.new("10.0.0.1"),
          port: 8080,
          public_key: "Pu7ymHtDqF4X9VNjVj9mYFBh/z7LGxY6VQJAGiSEgTM=",
          private_key: "2PSyTqm+3rXzUK+T8jBhgZp9UHjFkgVZv4bXncWMyXY="
        }

      peer =
        %Peer{
          ip_address: "10.0.0.3",
          endpoint: "10.0.0.2",
          port: 8081,
          public_key: "h2W8fjxUwZH+G8/Qp/H7kzn4SQz/EJIhOVFMh6mmtX4=",
          persistent_keepalive: 25
        }

      extra = [
        {"Peridio",
         [
           {"TunnelID",
            "prn:1:be4d30b4-de6b-47cd-85ea-a75e23fd63ef:tunnel:b3f1f699-3bc8-4c77-bda2-b974595d5e3f"}
         ]},
        {"Interface",
         [
           {"PreUp", "foo"},
           {"PreUp", "bar"}
         ]},
        {"Peridio", [{"Other", "Value"}]}
      ]

      config = QuickConfig.new(interface, peer, extra)
      encoded_config = QuickConfig.encode(config)
      decoded_conf = QuickConfig.decode_conf(encoded_config)
      assert config.interface == decoded_conf.interface
      assert config.peer == decoded_conf.peer
    end

    test "get_in_extra all values" do
      config = QuickConfig.new(%Interface{}, %Peer{}, [{"A", [{"B", "C"}, {"B", "D"}]}])
      extra_find = QuickConfig.get_in_extra(config, ["A", "B"])
      assert {"B", "C"} = Enum.find(extra_find, &(elem(&1, 0) == "B" and elem(&1, 1) == "C"))
      assert {"B", "D"} = Enum.find(extra_find, &(elem(&1, 0) == "B" and elem(&1, 1) == "D"))
    end

    test "malformed extra fails" do
      assert_raise RuntimeError, fn ->
        QuickConfig.new(%Interface{}, %Peer{}, [{"Interface", "foo"}]) |> QuickConfig.encode()
      end

      assert_raise RuntimeError, fn ->
        QuickConfig.new(%Interface{}, %Peer{}, [{"Interface", ["foo"]}]) |> QuickConfig.encode()
      end
    end
  end
end
