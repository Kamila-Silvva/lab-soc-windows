# Laboratório SOC — correlação de falhas de logon locais e via SMB

**Autora:** Kamila Silva  
**Datas dos exercícios:** 08 e 10/11/2026  
**Ambiente:** Kali Linux e uma VM Windows 11 Enterprise Evaluation no VirtualBox.  
**Fontes:** log Security e Microsoft-Windows-Sysmon/Operational.  
**Análise:** Visualizador de Eventos, consultas PowerShell e script reutilizável sobre arquivos EVTX exportados.

## Objetivo e resultado

O exercício investigou falhas de senha seguidas de autenticação bem-sucedida em dois contextos: acesso local com `runas` e acesso pela rede via SMB a partir do Kali. A mesma regra foi avaliada com três falhas e com uma falha em cada contexto. Na etapa local, a sessão criada também foi relacionada à execução de `cmd.exe` usando o Sysmon.

| Caso | Tipo de logon | Origem | Falhas nos 60 s anteriores ao sucesso | Alerta observado |
|---|---:|---|---:|---|
| Local — três falhas e sucesso | 2 | `::1` | 3 | `True` |
| Local — controle com uma falha e sucesso | 2 | `::1` | 1 | `False` |
| SMB — três falhas e sucesso | 3 | `192.168.56.1` | 3 | `True` |
| SMB — controle com uma falha e sucesso | 3 | `192.168.56.1` | 1 | `False` |

Os quatro resultados corresponderam ao comportamento definido para a regra. Todos os casos foram produzidos intencionalmente no laboratório. Após as consultas interativas, os dois casos SMB foram reanalisados pelo arquivo `analisar-logons.ps1`, usando os EVTX salvos; os resultados de três falhas/alerta e uma falha/sem alerta foram confirmados novamente na VM.

## Ambiente utilizado

O laboratório foi executado em um notebook com 12 GB de RAM, usando o Kali como sistema hospedeiro. A VM `Windows-SOC` estava configurada com 6 GB de RAM e duas CPUs virtuais. O computador Windows é `DESKTOP-EJJMRGB`, com a conta principal `Ka` e a conta local de teste `SocLab`.

Na etapa SMB, o adaptador da VM foi conectado à rede host-only `vboxnet0`:

| Componente | Endereço e função |
|---|---|
| Kali / `vboxnet0` | `192.168.56.1/24`; cliente SMB |
| Windows-SOC | `192.168.56.101/24`; servidor SMB, sem gateway padrão nesse adaptador |
| DHCP host-only | Servidor `192.168.56.100`, faixa `192.168.56.101–254` |
| Compartilhamento de teste | `LabSOC`, diretório `C:\LabSMB`, arquivo `teste.txt` |

O compartilhamento concedeu leitura à conta `SocLab`, com permissão NTFS de leitura e execução. A regra de firewall `LabSOC-SMB-Kali` foi criada para permitir TCP/445 no endereço `192.168.56.101`, tendo `192.168.56.1` como origem. Essa descrição se refere à regra criada, não a uma auditoria de todas as regras do firewall. Os endereços são os observados durante o teste; a VM recebeu seu endereço por DHCP.

## Etapa local — 08/11/2026

O computador analisado foi `DESKTOP-EJJMRGB`. A conta `Ka` solicitou a execução de `cmd.exe` com as credenciais da conta local `SocLab`:

```text
runas /user:DESKTOP-EJJMRGB\SocLab cmd.exe
```

Nos eventos do cenário com três falhas, o tipo de logon foi `2` (interativo), a origem foi `::1` (loopback) e o substatus das falhas foi `0xC000006A` (senha incorreta). O status geral foi `0xC000006D`.

### Linha do tempo do cenário com três falhas

Horários locais de Brasília, UTC−3, em 08/11/2026. Os registros XML usam UTC.

| Hora local | Fonte / evento | EventRecordID | Observação |
|---|---|---:|---|
| 16:49:30 | Security / 4625 | 14004 | Primeira falha de senha para `SocLab` |
| 16:49:33 | Security / 4625 | 14005 | Segunda falha de senha para `SocLab` |
| 16:49:36 | Security / 4625 | 14006 | Terceira falha de senha para `SocLab` |
| 16:49:44 | Security / 4648 | 14007 | Tentativa com credenciais explícitas de `SocLab` |
| 16:49:44 | Security / 4624 | 14008 | Criação da sessão de `SocLab` |
| 16:49:44 | Sysmon / 1 | 1506 | Criação de `cmd.exe` como `SocLab` |

Da primeira falha ao sucesso transcorreram aproximadamente **13,93 segundos**, calculados pelos timestamps dos XMLs. O evento 4648 registra a tentativa com credenciais explícitas; a confirmação da sessão vem do 4624.

### Correlação entre autenticação e processo

O evento 4624 contém `TargetLogonId = 0x14bfc2d`. O evento Sysmon 1 contém o mesmo valor em `LogonId`, no mesmo computador e para a mesma conta.

| Campo do Sysmon | Valor observado |
|---|---|
| Processo | `C:\Windows\System32\cmd.exe` |
| PID | `10196` |
| Usuário | `DESKTOP-EJJMRGB\SocLab` |
| LogonId | `0x14bfc2d` |
| ProcessGuid | `{eadcf747-d258-6af0-f603-000000000600}` |
| Processo pai | `C:\Windows\System32\runas.exe` |
| PID do pai | `8644` |
| Usuário do pai | `DESKTOP-EJJMRGB\Ka` |
| Linha de comando do pai | `runas.exe /user:DESKTOP-EJJMRGB\SocLab cmd.exe` |
| Integridade | `Medium` |

A integridade `Medium` é coerente com o campo `Token Elevado: Não` do 4624. A associação usa computador, conta e identificador de sessão, além da proximidade temporal. Os identificadores de sessão devem ser interpretados no contexto do host e do período analisado.

### Controle local

No controle, a coleta foi delimitada entre **19:42:12.779 e 19:43:09.596 de 08/11/2026**, no horário local. Foi conferida a presença de um 4625 seguido de um 4624 para `SocLab`. A consulta manteve os mesmos critérios e retornou **uma falha relacionada ao sucesso e `Alerta = False`**. A ausência de alerta veio acompanhada da confirmação de que os eventos foram coletados e processados.

## Etapa SMB — 10/11/2026

No terminal do Kali, a conexão ao compartilhamento foi iniciada com:

```bash
smbclient //192.168.56.101/LabSOC -p 445 -W DESKTOP-EJJMRGB -U SocLab
```

A senha foi informada no prompt interativo. Uma conexão inicial com a senha correta permitiu listar `teste.txt` com `ls` e encerrar com `quit`.

### Acesso inicial confirmado

O evento Security 4624 de referência apresentou:

| Campo | Valor observado |
|---|---|
| Hora local | `2026-11-10 19:27:18` |
| EventRecordID | `14175` |
| Conta | `DESKTOP-EJJMRGB\SocLab` |
| Tipo de logon | `3` — rede |
| Endereço de origem | `192.168.56.1` |
| Estação de trabalho | `KALI-KAH` |
| Pacote de autenticação | `NTLM` |
| Nome do pacote NTLM | `NTLM V2` |
| TargetLogonId | `0x271012` |

O tipo 3, a origem e o contexto do cliente SMB sustentam a identificação desse acesso pela rede. Esse evento de referência foi usado como marco para separar as tentativas seguintes.

### Caso com três falhas e sucesso

Foram feitas três tentativas com senha incorreta e, em seguida, uma com a senha correta. A consulta ao Security confirmou três eventos 4625 seguidos de um 4624 para `SocLab`, originados do Kali. A regra retornou:

```text
Conta     : DESKTOP-EJJMRGB\SocLab
Sucesso   : 2026-11-10 19:32:22.840
Origem    : 192.168.56.1
TipoLogon : 3
Sessao    : 0x33016c
Falhas60s : 3
Alerta    : True
```

O sucesso ocorreu às `22:32:22.840 UTC`. As três falhas contabilizadas corresponderam aos critérios da regra, incluindo o substatus de senha incorreta e a janela de 60 segundos anterior ao sucesso.

### Controle SMB

Em uma execução separada, foi feita uma tentativa com senha incorreta seguida de uma com a senha correta. A mesma regra retornou **`Falhas60s = 1` e `Alerta = False`**. Os eventos e o resultado foram exportados separadamente do caso com três falhas.

A análise desta etapa trata de autenticação e acesso ao compartilhamento. O logon SMB não demonstra execução remota de `cmd.exe`. A correlação entre autenticação e criação de processo via Sysmon foi realizada na etapa local com `runas`.

## Regra avaliada

Para cada evento de sucesso 4624, a consulta conta eventos 4625 com substatus `0xc000006a` no intervalo **[sucesso − 60 segundos, sucesso)**. As falhas precisam corresponder ao sucesso em quatro campos:

- Computador.
- Conta, incluindo domínio.
- Tipo de logon.
- Endereço de origem.

A decisão é `Alerta = (quantidade de falhas >= 3)`. O limite de três falhas e a janela de 60 segundos foram escolhidos para o exercício.

No primeiro cenário local, a consulta retornou `DESKTOP-EJJMRGB\SocLab`, três falhas, sucesso às `16:49:44.043`, origem `::1` e sessão `0x14bfc2d`. A mesma lógica foi aplicada ao logon tipo 3, com a origem do Kali.

## Repetição da análise a partir dos EVTX

O arquivo `analisar-logons.ps1` lê o EVTX exportado, interpreta os campos XML pelo nome e aplica a regra a cada sucesso 4624 da conta indicada. A conta padrão é `SocLab`. A saída inclui a conta, o host, o horário local e UTC do sucesso, os identificadores dos registros, a origem, o tipo de logon, a sessão, a contagem de falhas e a decisão de alerta.

O script usa `Get-WinEvent` e requer PowerShell no Windows, versão 5.1 ou posterior. Ele analisa os eventos Security 4624/4625; a associação com Sysmon descrita neste relatório foi feita separadamente. A leitura não altera os EVTX e o script não exporta arquivos automaticamente.

Com o script salvo em `C:\Users\Ka\Lab`, os comandos usados na VM foram:

```powershell
Set-Location 'C:\Users\Ka\Lab'

.\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\03-smb\Security-SMB.evtx' | Format-List

.\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\04-smb-controle\Security-SMB-controle.evtx' | Format-List
```

| Arquivo analisado pelo script | Falhas60s | Alerta | Validação |
|---|---:|---|---|
| `Security-SMB.evtx` | 3 | `True` | Execução confirmada na VM |
| `Security-SMB-controle.evtx` | 1 | `False` | Execução confirmada na VM |

A política de execução inicialmente impediu a abertura do `.ps1`. Para executar o script criado localmente, foi aplicada a política abaixo apenas ao processo PowerShell em uso:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
```

Essa alteração é temporária e termina com o encerramento da sessão e de seus processos filhos. Os dois comandos de análise foram executados após esse ajuste. A validação do arquivo reutilizável nesta etapa abrange os dois EVTX SMB; os resultados locais foram validados anteriormente por consultas interativas.

## Evidências organizadas na VM

Diretório base: `C:\Users\Ka\Lab\Evidencias`.

| Pasta | Arquivos do procedimento |
|---|---|
| `01-logon` | `Security-1649.evtx`, `Sysmon-1649.evtx`, `alerta-correlacao.csv`, `hashes-evidencias.csv` |
| `02-controle` | `Security-controle.evtx`, `Sysmon-controle.evtx`, `resultado-controle.csv`, `hashes-evidencias.csv` |
| `03-smb` | `Security-SMB.evtx`, `resultado-smb.csv`, `hashes-evidencias.csv` |
| `04-smb-controle` | `Security-SMB-controle.evtx`, `resultado-controle-smb.csv`, `hashes-evidencias.csv` |

Os manifestos SHA-256 permitem comparar os arquivos com a referência calculada após a exportação. Nas pastas SMB, cada manifesto cobre o EVTX e o CSV de resultado correspondente. Os valores dos hashes ficam nos CSVs da VM; não são reproduzidos aqui. O hash permite verificar mudanças em relação à referência, mas não comprova sozinho a autenticidade da coleta.

Os EVTX SMB foram exportados do primeiro registro selecionado até o registro de sucesso, inclusive, preservando também os outros eventos Security existentes nesse intervalo. São recortes dos testes. Este relatório referencia as evidências mantidas na VM; os arquivos EVTX não estão incorporados a ele.

## Conclusão e limites

A regra sinalizou três falhas seguidas de sucesso e permaneceu sem alerta no controle com uma falha, tanto no acesso local quanto no acesso via SMB. O script reutilizável reproduziu os dois resultados SMB a partir das evidências exportadas. A análise manual da etapa local também relacionou a sessão de `SocLab` à criação de `cmd.exe` por meio de `runas`.

A classificação do caso é **atividade controlada de laboratório**. Em uma investigação real, falhas seguidas de sucesso exigiriam verificar o contexto antes de concluir que houve comprometimento.

Esta validação cobre quatro casos controlados, uma conta-alvo e um computador Windows, com logon local e pela rede. Ela não determina taxas de falsos positivos ou negativos em produção. O controle mostra que uma falha não atinge o limite escolhido; não demonstra que toda atividade legítima ficará sem alerta.

A regra exige um sucesso posterior e não foi avaliada com tentativas distribuídas entre contas ou origens, nem fora da janela definida. Ela conta somente os eventos presentes no arquivo: um recorte incompleto pode omitir falhas. A leitura dos EVTX é pontual; não há monitoramento contínuo, bloqueio automático nem implantação de SIEM neste exercício.

## Referências técnicas

- [Microsoft — evento 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft — evento 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft — evento 4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648)
- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft — Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1)
- [Microsoft — políticas de execução do PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1)
- [Microsoft — wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [Microsoft — Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1)
- [Samba — smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [Oracle VirtualBox — redes virtuais](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)

Relatório baseado nos eventos, nas saídas de comandos e nas confirmações apresentados durante o exercício. Os resultados dos dois comandos de reanálise SMB foram confirmados na VM pela autora. Os testes utilizaram contas e dados do próprio laboratório.
