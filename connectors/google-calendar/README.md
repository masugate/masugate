# MasuGate Google Calendar connector

This narrow connector profile has one intentionally narrow
surface: create and cancel one non-recurring event in one configured calendar.
It uses only the public `masugate-connector-sdk` contract and the Python standard
library. The package accepts an OAuth access token only through the worker's
secret handle; it never emits credential bytes in connector evidence.

The trusted worker deployment provides `MASUGATE_GOOGLE_CALENDAR_ID`,
`MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF`, and the exact
`MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE=https://www.googleapis.com/auth/calendar.events`.
The secret reference names its mounted worker-only secret. One terminal LF or
CRLF from a mounted secret file is accepted; other whitespace is rejected.
Requests are fixed to `https://www.googleapis.com` and the Calendar v3 event
endpoints. No redirect or alternate origin is accepted.

The optional live-sandbox contract is deliberately not implied by installing
this package. It requires a dedicated disposable Google test calendar and an
OAuth test credential to execute create, GET recovery, duplicate create, and
cancel.
