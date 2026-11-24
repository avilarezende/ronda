---
description: Use no plantão da Ronda, ao priorizar vulnerabilidade alta ou crítica, lembrar triagem ou indicar correção defensiva.
---

# Plantão

Leia `ler_briefing` antes de ordenar o dia. Leia `lembrar_triagem` antes de dizer o que ainda está aberto.

A marca da triagem fica no navegador, na Fila. Este agente não grava marca.

## Status

- `nova`: ninguém marcou. O próximo passo é abrir a Fila e registrar.
- `em-analise`: confirmar se o produto está no ambiente. Não trate como afetado ainda.
- `afeta` com `remediacao` `correcao`: aplicar a atualização publicada pelo fabricante.
- `afeta` com `remediacao` `contorno`, ou sem correção: seguir o contorno publicado pelo fabricante ou pela CISA até a atualização.
- `mitigada`, `nao-afeta`, `risco-aceito`: não liste como pendência. Pode citar a contagem de fechados.

`prazoCatalogoVencido` significa que a data do KEV já passou. Confirme o ativo antes de chamar isso de atraso do ambiente.

`ransomwareConhecido` sobe a prioridade do catálogo. Não descreva campanha, exploit nem acesso.

Se a fonte for `exemplo`, diga que a lista é de treino e que os ids não são vulnerabilidades reais.

Se um id colado estiver em `foraDaColeta`, diga que ele não está nesta coleta. Não o complete de memória.
