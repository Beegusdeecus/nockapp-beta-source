# Retained ticket status after an offer migration

The new primary wallet can be uninitialized while the old wallet still holds
assigned tickets. Initialization, pending status and totals must describe the
same set of wallets. The previous projection combined old counts with a false
initialization flag; the strict browser validator correctly rejected it.

The two-source native overlay fixes that contradiction and reuses the original
terminal nonpayment proof for purchase readiness. It does not initialize wallets,
move/decrypt/export owner data, clear pending records, sign or spend. The browser
keeps exact schema validation, avoids repeating a failed initial read, names its
loading stages and hides new-buy controls while an earlier purchase blocks them.
Existing tickets remain usable. Apply the two source members to the recorded
parent; binaries/configuration/permissions are unchanged. For the synthetic
Python regression, compose the review/two-offer-v5 fixture closure with these two
updated modules and this test file. The browser fixture is generated from actual
native status constructors with synthetic wallets, not owner records. Full
Chrome/private payment, historical badge and recovery acceptance remain separate.
