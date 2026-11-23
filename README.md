# Ronda

Bancada diária para o acompanhamento de vulnerabilidades. A Ronda junta três fontes públicas, cruza o resultado com os ativos que você cadastrar e organiza a triagem do plantão.

- **CISA KEV**: vulnerabilidades com uso conhecido, dos últimos 120 dias.
- **NIST NVD**: publicações recentes de severidade alta ou crítica.
- **OSV.dev**: confirma o pacote afetado e se há versão corrigida. A busca da fila também consulta o OSV.dev pelo pacote ou pelo CVE.
- **VulDB**: registros recentes de severidade alta ou crítica, e a busca por produto ou CVE. Precisa da chave `VULDB_API_KEY` no servidor. Sem a chave, as outras fontes seguem e Fontes explica a ausência.
- **CERT.br**: novidades do centro.

A lista de ativos e a triagem ficam neste navegador. A orientação de cada item é confirmar se o produto está no ambiente e aplicar a atualização publicada pelo fabricante.

## Uso

1. Abra o briefing. Ele resume o que entrou no KEV, o que conversa com seus ativos e o que ainda não foi triado.
2. Em **Ativos**, apague os exemplos que não existem no seu ambiente e cadastre os produtos que você opera. A correspondência usa a frase inteira da palavra-chave.
3. Em **Fila**, busque um produto ou um CVE. A busca olha a fila local, o NIST, o OSV.dev e o VulDB. Abra um item, registre a triagem e uma nota.
4. **Correções** reúne o que tem atualização do fabricante ou contorno publicado pela CISA. Essas marcas também aparecem na prioridade do briefing.
5. A coleta renova às 2h, 8h, 14h e 20h, horário de Fortaleza. Com o painel aberto, ela atualiza sozinha nesses horários. **Atualizar fontes** busca de novo antes disso.

## Rodar localmente

```bash
npm install
npm test
npm run dev
```

O servidor de desenvolvimento sobe em http://localhost:3847. O mesmo endereço em 127.0.0.1 também abre o plantão.

## Página no GitHub

O GitHub Pages publica a coleta pronta. Ele não executa o servidor da Ronda. A Action `.github/workflows/pages.yml` monta a página ao enviar o código para `main` e de novo às 2h, 8h, 14h e 20h, horário de Fortaleza. Essa coleta lê o secret `VULDB_API_KEY` do repositório. A busca da fila, na página publicada, consulta NIST e OSV.dev direto do navegador; o VulDB dessa página é o da coleta.

No repositório `avilarezende/ronda`, com Pages apontando para GitHub Actions, o endereço fica https://avilarezende.github.io/ronda/.
