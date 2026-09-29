# Project Sessionkey x402 Payment

Agent-to-agent x402 payer for Project Vegetables.

- Buyer: sessionkey.base.eth — ERC-8004 Agent #95962
- Buyer wallet: 0xAB05Ea86008615F8808d18f966109527BbB99981
- Seller: vegetables.base.eth — ERC-8004 Agent #95581
- Network: Base Sepolia (`eip155:84532`)
- Payment: 0.01 test USDC, as challenged by the seller
- Transport: Cloudflare Service Binding `VEGETABLES_SERVICE`

## Security
The private key is never stored in this repository. It is read only from the
Cloudflare secret `SESSIONKEY_PRIVATE_KEY`.

`/signer-check` verifies the configured signer.
`/binding-check` tests the direct Worker-to-Worker route without paying.
`/pay-vegetables` intentionally performs the x402-aware paid request.
