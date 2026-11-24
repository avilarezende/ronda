import { defineEval } from "@grok/agent-sdk/evals";

export default defineEval({
  tags: ["smoke"],
  description: "O briefing de exemplo devolve a coleta sintética e não grava triagem.",
  async test(t) {
    await t.send("Use ler_briefing com usarExemplo true e diga quantas altas ou críticas a coleta de exemplo tem.");
    t.succeeded();
    t.calledTool("ler_briefing", {
      input: { usarExemplo: true },
      output: { fonte: "exemplo", contagem: { altasCriticas: 2 } },
    });
    t.notCalledTool("lembrar_triagem");
  },
});
