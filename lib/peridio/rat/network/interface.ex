defmodule Peridio.RAT.Network.Interface do
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
end
