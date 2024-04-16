defmodule Peridio.RAT.Tunnel do
  @moduledoc """
  Overview:
  The pattern we are using here is to have a single GenServer process take responsibility for establishing,
  configuring, monitoring, and tearing down a single network interface and WireGuard tunnel pair. When we get a POST
  request asking to create a new session, we'll start one of these GenServer processes with the data we receive.

  We'll register the name of that process at initialization using the device id from the HTTP request to ensure
  there is one unique process per device.

  We'll gather all the rest of the data we'll need inside a "handle_continue" callback to
  provide some shielding against race conditions.

  Then whenever we need to take action with the network interface/tunnel for a specific device via HTTP request,
  the controller action will address the individual process for that device session to do the work. This includes
  tearing down the tunnel entirely.

  The Purpose of Processes:
  The semantics of processes in the BEAM mean that we can have strong guarantees about uniqueness via the Elixir
  Registry. Process mailboxes provide ordering guarantees, and the "handle_continue" callback ensures that we
  control the very first message in the processes mailbox.


  Uniqueness:
  This application starts a new process registry in the application.ex file. The key we're using is ":tunnel_servers".
  We've configured it to make each process PID map to a single, unique name.

  The Registry requires a three tuple commonly called a "via tuple" for that name. The naming happens at process
  initialization, which is very, very fast. Once initialization is complete, no other process can start with that
  same via tuple.

  Every via tuple will use the device id, which is unique. The via tuple looks like this:
  {:via, Registry, {:tunnel_servers, device_id}} where the device_id is a UUID.


  Race Conditions:
  We will potentially have multiple HTTP requests coming in to start a new ssh session for a device. Each of those
  requests will want to start up a new process, and each time a new process starts, it's going to try to do some data
  manipulation in both ETS and in MariaDB.

  Process registration ensures that we'll only have one process no matter how many requests come in. The "handle_continue"
  clause ensures that data manipulation happens in the order we want.


  Data Stores:
  We use two data stores for different purposes.

  There is a persistent table in MariaDB useful for reporting.

  There is also a table in ETS (Erlang Term Storage) for ephemeral data. ETS is an in-memory key-value storage
  mechanism that exists in the running BEAM itself. It's exceedingly fast, but the data gets lost whenever the
  BEAM restarts.

  This ETS table is intended to solve the problem of finding unused interface names, ports, and IP address
  which are available to use for new ssh sessions.

  When the application starts up, it pre-populates rows in this table with all the initial data we will need to
  create a network interface as well as initialize a WireGuard tunnel. The shape of that data is a six-tuple:
  {wg_interface, status, port_number, internal_net_address, our_ip, peer_ip}

  The status can be either ":available" or ":checked_out".

  Note that none of these network interfaces or tunnels actually exist when we fill the table. This is only
  metadata for the time being.

  Part of initializing a new process is "checking out" one of these rows from ETS and storing the resulting data
  in the GenServer's state. Checking out a row means switching its state from ":available" to ":checked_out."
  Part of tearing down a process involves checking the interface back in by reversion the status change.

  During the lifetime of the session, the GenServer will use the metadata it got from ETS to create an actual
  network interface as well as initialize and configure an actual WireGuard tunnel. The reverse is also true.
  When needed, the process will use this metadata to tear down the actual network interface and WireGuard tunnel.


  Stale Connection Checks:
  Another benefit of using one BEAM process per device tunnel is that each process can handle periodically checking
  to see if the connection is stale, just by periodically sending itself a message. There's a built in function
  called "send_after" that takes the PID of the process we want to message, the message we want to send, and the
  number of milliseconds to wait before it sends the message.

  Here we check for staleness by sending ourselves a ":check_status" message every minute. There's a "handle_info"
  clause to determine if the connection is stale, and if it is, to shut the process down and clean up. Otherwise, it
  sends itself another message in a minute.

  We don't need a centralized mechanism to periodically run through all the active tunnels and check their freshness.
  Each process handles that for itself.


  Process Termination and Cleanup:
  Every time one of these processes shuts down, the BEAM executes the "terminate" function. This is where we clean up
  any data we've maniuplated in ETS or MariaDB.

  It is possible that the BEAM shuts down really abruptly, and there isn't time to run "terminate" on each process.
  That will leave inconsistent state across the two data stores. There are checks in the "handle_continue" clause
  to fix up inconsistenties as best we can.
  """
  use GenServer

  alias Peridio.RAT.WireGuard

  @status_check_interval 1000 * 60
  # should happen after keepalive_timeout
  @initial_status_check_interval 1000 * 60 * 10
  # handshake times older than this many seconds are to be considered stale
  @connection_timeout 60 * 5

  defmodule State do
    defstruct [
      interface: nil,
      peer: nil,
      expires_at: nil,
      opts: []
    ]
  end

  # Public Functions
  def generate_via_tuple(id), do: {:via, Registry, {:tunnels, id}}

  def child_spec(args) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [args]},
      restart: :transient,
    }
  end

  def start_link(%State{} = state) do
    GenServer.start_link(__MODULE__, state, name: generate_via_tuple(state.interface.id))
  end

  # Server Process Callbacks
  def init(state) do
    Process.send_after(self(), :check_status, @initial_status_check_interval)
    ttl = DateTime.diff(state.expires_at, DateTime.utc_now())
    Process.send_after(self(), :ttl_timeout, ttl)
    {:ok, state, {:continue, :further_setup}}
  end

  def handle_continue(:further_setup, state) do
    with :ok <-
           WireGuard.configure_wireguard(
             state.interface,
             state.peer,
             state.opts
           ),
         {_, 0} <- WireGuard.bring_up_interface(state.interface.id, state.opts) do
      {:noreply, state}
    else
      _ -> {:stop, :normal, state}
    end
  end

  def handle_info(:ttl_timeout, state) do
    # Just stop the process here and rely on the terminate callback to do the work.
    {:stop, :normal, state}
  end

  def handle_info(:check_status, state) do
    # assuming we have a WireGuard.stale?(state.wg_interface)
    # depending on the reply, we can either keep going and check again
    # or terminate and clean up
    case stale?(state.wg_interface) do
      # true -> {:stop, :normal, state}  # FIXME setup a more graceful way to toggle for development
      true ->
        IO.puts("Stale connection!")
        Process.send_after(self(), :check_status, @status_check_interval)
        {:noreply, state}

      false ->
        Process.send_after(self(), :check_status, @status_check_interval)
        {:noreply, state}
    end
  end

  def terminate(_reason, state) do
    if Map.has_key?(state, :wg_interface) do
      {_, _} = WireGuard.teardown_interface(state.wg_interface)
    end
  end

  defp stale?(wg_interface) do
    {rx, _} = WireGuard.rx_packet_stats(wg_interface)
    {tx, _} = WireGuard.tx_packet_stats(wg_interface)
    {time, _} = WireGuard.wg_latest_handshakes(wg_interface)
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
end
