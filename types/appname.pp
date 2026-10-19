# @summary The name of a ufw application profile (`ufw app list`)
type Ufw::AppName = Pattern[/\A[^'"\n\r\/]+\z/]
