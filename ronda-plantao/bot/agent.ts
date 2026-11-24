import { defineAgent } from "@grok/agent-sdk";

export default defineAgent({
  name: "Ronda Plantão",
  description:
    "Plantão defensivo da Ronda: lê o briefing, prioriza vulnerabilidades altas e críticas e lembra a triagem e as correções publicadas.",
  model: {
    id: "grok-4.7",
    params: [
      { id: "reasoning_effort", value: "high" },
      { id: "fast", value: "true" },
    ],
  },
});
