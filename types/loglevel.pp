# @summary A ufw logging level (`ufw logging LEVEL`)
#
# `on` turns logging on at its last level (`low` if it was off).
type Ufw::LogLevel = Enum['off', 'on', 'low', 'medium', 'high', 'full']
