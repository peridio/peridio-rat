import Config

# Print only warnings and errors during test
config :logger, level: :warning

config :peridio_rat, wireguard_client: Peridio.RAT.WireGuard.Mock
config :peridio_rat, mock_device_wireguard_client: MockDevice.WireGuard.Mock
