# @summary A network interface name, as ufw accepts it
type Ufw::Interface = Pattern[/\A(?!\.\.?\z)[a-zA-Z0-9_\-.+,=%@]{1,15}\z/]
