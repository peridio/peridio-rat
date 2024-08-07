defmodule Peridio.RAT do
  alias Peridio.RAT.Tunnel

  # What is needed to open a tunnel?
  # We need the peer and interface information structs
  def open_tunnel(id, interface, peer, opts \\ []) do
    state = %Tunnel.State{
      id: id,
      interface: interface,
      peer: peer,
      expires_at: opts[:expires_at],
      opts: opts
    }

    resp =
      DynamicSupervisor.start_child(
        Peridio.RAT.DynamicSupervisor,
        Peridio.RAT.Tunnel.child_spec(state)
      )

    case resp do
      {:ok, _pid} -> {:ok, state}
      error -> error
    end
  end

  @spec close_tunnel(any()) :: :ok | {:error, :not_running}
  def close_tunnel(id) do
    case GenServer.whereis(Tunnel.generate_via_tuple(id)) do
      nil ->
        {:error, :not_running}

      pid ->
        GenServer.stop(pid)
    end
  end

  def extend_tunnel(id, expires_at) do
    case GenServer.whereis(Tunnel.generate_via_tuple(id)) do
      nil ->
        {:error, :not_running}

      pid ->
        GenServer.cast(pid, {:extend, expires_at})
    end
  end

  def list_tunnels() do
    Peridio.RAT.DynamicSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.map(&elem(&1, 1))
    |> Enum.map(&{&1, Tunnel.get_state(&1)})
    |> Enum.map(fn {pid, %Tunnel.State{id: id, interface: interface}} ->
      {pid, id, interface}
    end)
  end

  def get_tunnel_by_interface_id(interface_id) do
    case Registry.select(:tunnels, [
           {{:"$2", :"$1", :"$3"}, [{:==, {:map_get, :id, :"$3"}, interface_id}],
            [{{:"$1", :"$2", :"$3"}}]}
         ]) do
      [] -> nil
      [tunnel] -> tunnel
    end
  end
end
