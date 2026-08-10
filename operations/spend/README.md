# MasuGate spend operation pack

This pack projects the existing governed `spend.purchase` provider into the
operation-pack format. It does not define a second payment policy:
budget reservation, approval, the durable provider outbox, and MasuGate receipts
remain owned by the existing spend provider.

The published Stripe profile is limited to one exact test-mode PaymentIntent
configuration. Test evidence earns `reference-effect` maturity only. Live
charges, refunds, subscriptions, payouts, arbitrary products, and Connect
account selection are unsupported.
