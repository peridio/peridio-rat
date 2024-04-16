defmodule Peridio.RAT do
  alias Peridio.RAT.Tunnel

  # What is needed to open a tunnel?
  # We need the peer and interface information structs
  def open_tunnel(interface, peer, opts \\ []) do
    state = %Tunnel.State{
      interface: interface,
      peer: peer,
      expires_at: opts[:expires_at],
      opts: opts
    }
    resp = DynamicSupervisor.start_child(Peridio.RAT.DynamicSupervisor, Peridio.RAT.Tunnel.child_spec(state))
    case resp do
      {:ok, _pid} -> {:ok, state}
      error -> error
    end
  end

  def close_tunnel(id) do
    case GenServer.whereis(Tunnel.generate_via_tuple(id)) do
      nil ->
        {:error, :not_running}

      pid ->
        GenServer.stop(pid)
    end
  end
end
