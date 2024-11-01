defmodule Peridio.RAT.Tunnel do
  @moduledoc """
  ## Overview:
  The pattern we are using here is to have a single GenServer process take responsibility for establishing,
  configuring, monitoring, and tearing down a single network interface and WireGuard tunnel pair.

  We'll register the name of that process at initialization using the interface id to ensure
  there is one unique process per device.

  We'll gather all the rest of the data we'll need inside a "handle_continue" callback to
  provide some shielding against race conditions.

  We setup the ttl_timeout with an expiration so that the tunnel can clean up after itself.

  ## The Purpose of Processes:
  The semantics of processes in the BEAM mean that we can have strong guarantees about uniqueness via the Elixir
  Registry. Process mailboxes provide ordering guarantees, and the "handle_continue" callback ensures that we
  control the very first message in the processes mailbox.

  ## Uniqueness:
  This application starts a new process registry in the application.ex file. The key we're using is ":tunnels".
  We've configured it to make each process PID map to a single, unique interface ID.

  The Registry requires a three tuple commonly called a "via tuple" for that name. The naming happens at process
  initialization, which is very, very fast. Once initialization is complete, no other process can start with that
  same via tuple.

  Every via tuple will use the interface id, which is unique. The via tuple looks like this:
  {:via, Registry, {:tunnels, state.interface.id}} where the state.interface.id is a generated name.

  ## Race Conditions:
  We will potentially have multiple tunnel requests coming in. Each of those request will want to start up a new process,
  and each time a new process starts, it's going to try to do some configuration.

  Process registration ensures that we'll only have one process no matter how many requests come in. The "handle_continue"
  clause ensures that data manipulation happens in the order we want.

  ## Stale Connection Checks:
  Another benefit of using one BEAM process per tunnel is that each process can handle periodically checking
  to see if the connection is stale, just by periodically sending itself a message. There's a built in function
  called "send_after" that takes the PID of the process we want to message, the message we want to send, and the
  number of milliseconds to wait before it sends the message.

  Here we check for staleness by sending ourselves a ":check_status" message every minute. There's a "handle_info"
  clause to determine if the connection is stale, and if it is, to shut the process down and clean up. Otherwise, it
  sends itself another message in a minute.

  We don't need a centralized mechanism to periodically run through all the active tunnels and check their freshness.
  Each process handles that for itself.

  ## Process Termination and Cleanup:
  Every time one of these processes shuts down, the BEAM executes the "terminate" function. This is where we clean up
  any tunnels.

  It is possible that the BEAM shuts down really abruptly, and there isn't time to run "terminate" on each process.
  """
  use GenServer

  require Logger

  alias Peridio.RAT.WireGuard

  @status_check_interval 1000 * 60
  # should happen after keepalive_timeout
  @initial_status_check_interval 1000 * 60 * 10
  # handshake times older than this many seconds are to be considered stale
  @connection_timeout 60 * 5
  @interface_check_timeout 10_000

  defmodule State do
    defstruct id: nil,
              interface: nil,
              peer: nil,
              expires_at: nil,
              exit_reason: :normal,
              status: :start,
              interface_timeout_ref: nil,
              opts: []
  end

  # Public Functions
  def generate_via_tuple(id), do: {:via, Registry, {:tunnels, id}}
  def generate_via_tuple(id, interface), do: {:via, Registry, {:tunnels, id, interface}}

  def child_spec(args) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [args]},
      restart: :temporary
    }
  end

  def get_state(pid) do
    GenServer.call(pid, :get_state)
  end

  def extend(pid, expires_at) do
    GenServer.cast(pid, {:extend, expires_at})
  end

  def start_link(%State{} = state) do
    GenServer.start_link(__MODULE__, state, name: generate_via_tuple(state.id, state.interface))
  end

  def stop(pid, reason \\ :normal) do
    GenServer.cast(pid, {:stop, reason})
  end

  # Server Process Callbacks
  def init(state) do
    Process.send_after(self(), :check_status, @initial_status_check_interval)
    ttl = DateTime.diff(state.expires_at, DateTime.utc_now(), :millisecond)
    timer_ref = Process.send_after(self(), :ttl_timeout, ttl)

    hooks = state.opts[:hooks] || []
    extra = state.opts[:extra] || []

    extra = [{"Interface", hooks}, {"Peridio", [{"TunnelID", state.id}]} | extra]

    opts =
      state.opts
      |> Keyword.put(:timeout, timer_ref)
      |> Keyword.put(:extra, extra)
      |> Keyword.put(:exit_reason, :normal)

    {:ok, %{state | opts: opts}, {:continue, nil}}
  end

  def handle_continue(nil, state) do
    interfaces = WireGuard.list_interfaces(state.opts)

    interface_config =
      Enum.find(interfaces, fn interface ->
        [{"TunnelID", tunnel_id}] =
          WireGuard.QuickConfig.get_in_extra(interface, ["Peridio", "TunnelID"])

        String.equivalent?(tunnel_id, state.id)
      end)

    network_interfaces = Peridio.RAT.WireGuard.Interface.network_interfaces()

    cond do
      is_nil(interface_config) ->
        Logger.debug("Tunnel #{state.id} configuring interface")

        case WireGuard.configure_wireguard(
               state.interface,
               state.peer,
               state.opts
             ) do
          :ok ->
            Logger.debug("Tunnel #{state.id} bringing up interface #{state.interface.id}")
            interface_up(state)

          _error ->
            {:stop, :normal, %{state | exit_reason: "device_error_interface_configure"}}
        end

      interface_config.interface.id in network_interfaces ->
        Logger.debug(
          "Tunnel #{state.id} interface #{interface_config.interface.id} already up, resuming"
        )

        {:noreply, state}

      true ->
        Logger.debug("Tunnel #{state.id} config already exists, bringing up interface")
        interface_up(state)
    end
  end

  def handle_cast({:extend, expires_at}, state) do
    Process.cancel_timer(state.opts[:timeout])
    ttl = DateTime.diff(expires_at, DateTime.utc_now(), :millisecond)
    timer_ref = Process.send_after(self(), :ttl_timeout, ttl)
    opts = Keyword.put(state.opts, :timeout, timer_ref)
    {:noreply, %{state | expires_at: expires_at, opts: opts}}
  end

  def handle_cast({:stop, reason}, state) do
    {:stop, :normal, %{state | exit_reason: reason}}
  end

  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  def handle_info(:ttl_timeout, state) do
    Logger.info("Tunnel #{state.id} ttl timeout")
    {:stop, :normal, %{state | exit_reason: :ttl_timeout}}
  end

  def handle_info(:interface_timeout, state) do
    Logger.error("Tunnel #{state.id} failed to bring up interface #{state.interface.id}")
    {:stop, :normal, %{state | exit_reason: :interface_timeout}}
  end

  def handle_info(:check_interface, %{status: :start} = state) do
    exists? =
      WireGuard.Interface.network_interfaces()
      |> Enum.any?(&String.equivalent?(&1, state.interface.id))

    case exists? do
      true ->
        Logger.info("Tunnel #{state.id} interface #{state.interface.id} up")
        Process.cancel_timer(state.interface_timeout_ref)
        {:noreply, %{state | interface_timeout_ref: nil, status: :up}}

      false ->
        Process.send_after(self(), :check_interface, 1000)
        {:noreply, state}
    end
  end

  def handle_info(:check_status, state) do
    case stale?(state.interface.id) do
      # true -> {:stop, :normal, state}  # FIXME setup a more graceful way to toggle for development
      true ->
        Logger.warning("Tunnel #{state.id} reported inactive")
        Process.send_after(self(), :check_status, @status_check_interval)
        {:noreply, state}

      false ->
        Process.send_after(self(), :check_status, @status_check_interval)
        {:noreply, state}
    end
  end

  def terminate(_reason, state) do
    if Map.has_key?(state, :interface) do
      {_, _} = WireGuard.teardown_interface(state.interface.id, state.opts)
    end

    if Keyword.has_key?(state.opts, :on_exit) do
      on_exit(state.exit_reason, state.opts[:on_exit])
    end

    Logger.debug("Tunnel #{state.id} terminated reason: #{state.exit_reason}")
    :ok
  end

  defp stale?(interface) do
    {rx, _} = WireGuard.rx_packet_stats(interface)
    {tx, _} = WireGuard.tx_packet_stats(interface)
    {time, _} = WireGuard.wg_latest_handshakes(interface)
    rx = String.to_integer(rx)
    tx = String.to_integer(tx)
    time = String.to_integer(time)
    current_time = :os.system_time(:seconds)

    case {rx, tx, time} do
      # Still setting up
      {0, 0, 0} -> false
      # Sending, but not receiving, so first check should fail
      {0, _tx, 0} -> true
      # Started handshakes, but they went cold
      {_, _, time} when current_time <= time + @connection_timeout -> false
      _ -> true
    end
  end

  defp interface_up(state) do
    case WireGuard.bring_up_interface(state.interface.id, state.opts) do
      {result, 0} ->
        Logger.debug("Tunnel Interface Up Output: #{inspect(result)}")
        Process.send_after(self(), :check_interface, 1000)

        interface_timeout_ref =
          Process.send_after(self(), :interface_timeout, @interface_check_timeout)

        {:noreply, %{state | interface_timeout_ref: interface_timeout_ref}}

      error ->
        Logger.error("Tunnel Interface Up Error: #{inspect(error)}")
        {:stop, :normal, %{state | exit_reason: "device_error_interface_up"}}
    end
  end

  defp on_exit(_reason, nil), do: :noop
  defp on_exit(reason, fun), do: spawn(fn -> fun.(reason) end)
end
