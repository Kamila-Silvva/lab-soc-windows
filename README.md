# SOC Windows Logon Lab

Montei este laboratório para investigar falhas de senha seguidas de um login bem-sucedido no Windows. Fiz testes locais com `runas` e acessos SMB a partir do Kali, usando a conta `SocLab`.

## Problema e hipótese

Uma falha isolada pode ser um erro de digitação. Quis verificar se conseguiria identificar uma sequência de três falhas antes do sucesso e distingui-la de um controle com apenas uma falha.

Para cada evento **4624**, contei eventos **4625** com `SubStatus = 0xc000006a` nos 60 segundos anteriores, mantendo computador, domínio, usuário, tipo de logon e origem iguais. Com três ou mais falhas, o script retorna `Alerta = True`.

## Ambiente

Usei Kali Linux e uma VM Windows 11 no VirtualBox, ligados por uma rede host-only. A VM tinha 6 GB de RAM e duas CPUs virtuais; o notebook, 12 GB de RAM.

Escolhi exportar os EVTX para continuar a análise sem manter a VM ligada. Usei PowerShell no Windows, Python para ler os arquivos no Kali e Elastic Cloud para consultar os eventos SMB convertidos em NDJSON.

## Resultados

| Teste | Três falhas e sucesso | Uma falha e sucesso |
|---|---|---|
| Local, tipo 2 | `True` | `False` |
| SMB, tipo 3 | `True` | `False` |

O script reproduziu os dois resultados SMB. No teste local, associei o login à criação de `cmd.exe` pelo Sysmon. No Elastic, a consulta EQL retornou uma sequência do caso positivo e nenhuma do controle, entre os seis eventos importados.

Confira o [dashboard](docs/dashboard-elastic.png) e o [relatório com os comandos e as evidências](docs/relatorio.md).

## Como executar

No Windows, com PowerShell 5.1 ou posterior, execute a partir da raiz do projeto e ajuste o caminho do EVTX:

```powershell
.\scripts\analisar-logons.ps1 -ArquivoEVTX 'C:\Users\Ka\Lab\Evidencias\03-smb\Security-SMB.evtx' | Format-List
```

Para outra conta, acrescente `-Usuario 'NomeDaConta'`. Os arquivos brutos ficam no acervo local; o script apenas lê os eventos.

## Escopo e próximos passos

São quatro testes controlados, com uma conta e um host. A janela de 60 segundos foi escolhida para o lab e pode deixar tentativas espaçadas de fora. O resultado indica uma sequência para investigar, não confirma comprometimento.

O [Sigma](rules/detect_brute_force.yml) está experimental: validei sua estrutura e referências; a EQL foi escrita separadamente. O Elastic foi usado para análise histórica manual.
