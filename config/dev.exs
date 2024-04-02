import Config

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# In case you don't want to run real system commands against WireGuard,
# uncomment the following line and recompile.
# config :peridio_rat, wireguard_client: Peridio.RAT.WireGuard.Mock
# config :peridio_rat, mock_device_wireguard_client: MockDevice.WireGuard.Mock
