# MasuGate Stripe PaymentIntent connector

This package is an exact **test-mode** Stripe PaymentIntent profile for the
existing `spend.purchase` provider. It uses only `masugate-connector-sdk` and the
standard library. The worker supplies the sole `sk_test_...` secret; connector
evidence contains no credential, customer payment method, or Stripe account
value.

Trusted deployment configuration fixes the USD currency, one Connect connected
account, a platform `sk_test_...` credential authorized to act on it, one test
customer and payment method in that connected account, API version, merchant
allowlist, and secret reference. The model supplies only the existing governed
`amount_cents`, `merchant_id`, and `request_ref` arguments. It cannot select
PaymentIntent IDs, API keys, payment credentials, currency, metadata, return
URLs, a Connect account, or live mode.

The connector uses the MasuGate provider idempotency key for PaymentIntent creation
and retains Stripe's returned `pi_...` ID as the external operation ID. Before
that ID is available, reconciliation performs an idempotent retry only inside
the profile's conservative Stripe v1 retention window. Outside that window it
returns an ambiguous outcome for MasuGate to quarantine rather than risk a new
charge.

Live credentials, refunds, subscriptions, payouts, arbitrary products, and
Stripe Connect selection are outside this profile.
