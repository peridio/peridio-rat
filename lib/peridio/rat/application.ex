defmodule Peridio.RAT.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the process registry for WireGuard tunnel GenServers
      {Registry, keys: :unique, name: :tunnels},
      {Registry, keys: :unique, name: :mocks},
      # Start the supervisor which will monitor WireGuard tunnel GenServers
      {DynamicSupervisor, strategy: :one_for_one, name: Peridio.RAT.DynamicSupervisor}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Peridio.RAT.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
