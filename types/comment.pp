# @summary A ufw rule comment (ufw rejects `'`)
type Ufw::Comment = Pattern[/\A[^'\n\r]*\z/]
