# Ronda

Bancada diária para o acompanhamento de vulnerabilidades. A Ronda junta três fontes públicas, cruza o resultado com os ativos que você cadastrar e organiza a triagem do plantão.

- **CISA KEV**: vulnerabilidades com uso conhecido, dos últimos 120 dias.
- **NIST NVD**: publicações recentes de severidade alta ou crítica. A busca da fila também consulta o NIST pelo produto ou pelo identificador CVE.
- **CERT.br**: novidades do centro.

A lista de ativos e a triagem ficam neste navegador. A orientação de cada item é confirmar se o produto está no ambiente e aplicar a atualização publicada pelo fabricante.

## Uso

1. Abra o briefing. Ele resume o que entrou no KEV, o que conversa com seus ativos e o que ainda não foi triado.
2. Em **Ativos**, apague os exemplos que não existem no seu ambiente e cadastre os produtos que você opera. A correspondência usa a frase inteira da palavra-chave.
3. Em **Fila**, busque um produto ou um CVE. A busca olha a fila local e o NIST. Abra um item, registre a triagem e uma nota.
4. **Atualizar fontes** busca de novo. A consulta fica em cache por cerca de 10 minutos.

## Rodar localmente

```bash
npm install
npm test
npm run dev
```

O servidor de desenvolvimento sobe em http://localhost:3847. O mesmo endereço em 127.0.0.1 também abre o plantão.
