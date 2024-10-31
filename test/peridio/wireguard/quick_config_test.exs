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
  """

  describe "conf" do
    test "parse" do
      assert %{
               "Interface" => %{
                 "Address" => "10.0.0.1",
                 "ListenPort" => "8080",
                 "PrivateKey" => "2PSyTqm+3rXzUK+T8jBhgZp9UHjFkgVZv4bXncWMyXY=",
                 "ID" => "peridio-56X4U4Q",
                 "PublicKey" => "Pu7ymHtDqF4X9VNjVj9mYFBh/z7LGxY6VQJAGiSEgTM="
               },
               "Peer" => %{
                 "AllowedIPs" => "10.0.0.3/32",
                 "PublicKey" => "h2W8fjxUwZH+G8/Qp/H7kzn4SQz/EJIhOVFMh6mmtX4=",
                 "Endpoint" => "10.0.0.2:8081",
                 "PersistentKeepalive" => "25"
               },
               "Peridio" => %{
                 "TunnelID" =>
                   "prn:1:be4d30b4-de6b-47cd-85ea-a75e23fd63ef:tunnel:b3f1f699-3bc8-4c77-bda2-b974595d5e3f"
               }
             } = QuickConfig.conf_parse(@config)
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

      extra = %{
        "Interface" => %{
          "TunnelID" =>
            "prn:1:be4d30b4-de6b-47cd-85ea-a75e23fd63ef:tunnel:b3f1f699-3bc8-4c77-bda2-b974595d5e3f"
        }
      }

      config = QuickConfig.new(interface, peer, extra)
      assert config == config |> QuickConfig.encode() |> QuickConfig.decode_conf()
    end
  end
end
