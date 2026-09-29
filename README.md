# Project Sessionkey x402 Client

x402 payer/client for the Project Vegetables proof of concept.

- Buyer: sessionkey.base.eth — ERC-8004 Agent #95962
- Buyer wallet: 0xAB05Ea86008615F8808d18f966109527BbB99981
- Seller: vegetables.base.eth — ERC-8004 Agent #95581
- Network: Base Sepolia (`eip155:84532`)
- Target: Project Vegetables `/premium`

## Security
The private key is never stored in this repository. It is read only from the
Cloudflare secret `SESSIONKEY_PRIVATE_KEY`.

`/signer-check` verifies the secret derives the expected Sessionkey wallet.
`/pay-vegetables` intentionally performs the x402 paid request.
