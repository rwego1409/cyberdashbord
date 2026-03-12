import crypto from "node:crypto";

function pseudoChainRegister(target, validUntilIso) {
  const seed = `${target}:${validUntilIso}:${Date.now()}`;
  const txHash = `0x${crypto.createHash("sha256").update(seed).digest("hex")}`;
  return { txHash, network: "hardhat-local-sim" };
}

async function registerConsentViaGateway() {
  const apiBase = process.env.TCIO_API_BASE_URL ?? "http://localhost:8000/api/v1";
  const target = process.env.CONTRACT_TARGET ?? "203.0.113.30";
  const validUntil = process.env.CONTRACT_VALID_UNTIL ?? new Date(Date.now() + 5 * 24 * 3600 * 1000).toISOString();

  const chain = pseudoChainRegister(target, validUntil);

  const response = await fetch(`${apiBase}/consent/grants/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Debug-Role": "analyst",
    },
    body: JSON.stringify({
      requester_name: "SmartContractGateway",
      requester_email: "gateway@tcio.local",
      target,
      source: "smart_contract",
      blockchain_tx_hash: chain.txHash,
      allowed_scanners: ["nmap", "openvas", "vulners"],
      valid_until: validUntil,
    }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(`Consent gateway failed: ${response.status} ${JSON.stringify(payload)}`);
  }

  return {
    service: "contracts-gateway",
    status: "completed",
    chain,
    consent: payload,
  };
}

registerConsentViaGateway()
  .then((payload) => {
    console.log(payload);
  })
  .catch((err) => {
    console.error({ service: "contracts-gateway", status: "failed", error: err.message });
    process.exitCode = 1;
  });

