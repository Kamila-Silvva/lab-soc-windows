# Notas de investigação - logons locais e via SMB

> Correlacionei falhas 4625 seguidas de sucesso 4624 em logon local (tipo 2) e SMB (tipo 3).  
> Nos dois cenários, três falhas nos 60 segundos anteriores ao sucesso retornaram `Alerta = True`; o controle com uma falha retornou `False`.  
> O script reproduziu os dois casos SMB; a EQL encontrou uma sequência do positivo e nenhuma do controle. O Sigma continua experimental.

Fiz os testes em 08 e 10/11/2026 para acompanhar o caminho entre uma senha incorreta, o login bem-sucedido e a atividade da sessão. Usei a conta local `SocLab`, primeiro com `runas` e depois pelo SMB a partir do Kali.

Minha hipótese era que a correlação encontraria três falhas antes do sucesso e deixaria de sinalizar o controle com apenas uma falha. Conferi os quatro casos por consultas interativas. Depois repeti os dois casos SMB com o script e levei seus eventos para o Elastic.

## Ambiente que usei

O notebook tem 12 GB de RAM. A VM `Windows-SOC`, com Windows 11 Enterprise Evaluation, recebeu 6 GB e duas CPUs virtuais no VirtualBox. O Kali foi o hospedeiro e cliente SMB. No Windows, trabalhei com o log Security e o canal `Microsoft-Windows-Sysmon/Operational`.

Escolhi exportar os eventos para continuar a análise com a VM desligada.

Na etapa SMB, usei a rede host-only `vboxnet0`:

- Kali: `192.168.56.1/24`.
- Windows: `192.168.56.101/24`, sem gateway nesse adaptador. O DHCP estava em `192.168.56.100`, com faixa de `192.168.56.101–254`.
- Compartilhamento `LabSOC`: pasta `C:\LabSMB`, contendo `teste.txt`; leitura para `SocLab` no compartilhamento e leitura/execução no NTFS.

Criei a regra `LabSOC-SMB-Kali` para permitir TCP/445 no IP da VM, com origem em `192.168.56.1`. Registrei a configuração dessa regra; não fiz uma auditoria completa do firewall. O computador Windows foi identificado como `DESKTOP-EJJMRGB`, e a conta principal era `Ka`.

## Critério usado na análise

Para cada sucesso **4624**, contei falhas **4625** com `SubStatus = 0xc000006a` no intervalo **[sucesso − 60 segundos, sucesso)**. Exigi os mesmos valores de `Computer`, `TargetDomainName`, `TargetUserName`, `LogonType` e `IpAddress`.

Com três ou mais falhas, o PowerShell retorna `Alerta = True`. Escolhi esse limite para o exercício e usei uma falha seguida de sucesso como controle.

## 08/11 - login local e criação de processo
Executei, a partir da conta `Ka`:

```text
runas /user:DESKTOP-EJJMRGB\SocLab cmd.exe
```
Errei a senha três vezes de propósito e depois informei a correta. Nas falhas, observei logon tipo `2` — interativo —, origem `::1`, status `0xC000006D` e substatus `0xC000006A`.

A sequência abaixo usa horário de Brasília, UTC−3. Os horários dos XMLs estão em UTC.

| Hora local | Fonte / evento | EventRecordID | Observação |
|---|---|---:|---|
| 16:49:30 | Security / 4625 | 14004 | Primeira falha de senha para `SocLab` |
| 16:49:33 | Security / 4625 | 14005 | Segunda falha |
| 16:49:36 | Security / 4625 | 14006 | Terceira falha |
| 16:49:44 | Security / 4648 | 14007 | Tentativa com credenciais explícitas |
| 16:49:44 | Security / 4624 | 14008 | Criação da sessão de `SocLab` |
| 16:49:44 | Sysmon / 1 | 1506 | Criação de `cmd.exe` como `SocLab` |

Pelos timestamps completos, passaram aproximadamente **13,93 segundos** entre a primeira falha e o sucesso, registrado às `16:49:44.043` no horário local. Usei o 4624 para confirmar a criação da sessão; o 4648 registra a tentativa com credenciais explícitas.

Para ligar o login ao processo, comparei `TargetLogonId` do 4624 com `LogonId` do Sysmon 1: ambos eram `0x14bfc2d`, no mesmo host e para `SocLab`.

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

Conferi também o horário e o processo pai. A integridade `Medium` era coerente com `Token Elevado: Não` no 4624. Essa foi a associação de processo observada no teste local.

No controle, delimitei a coleta entre **19:42:12.779 e 19:43:09.596**, no mesmo dia e fuso. Confirmei um 4625 antes de um 4624. A consulta retornou **uma falha e `Alerta = False`**.

## 10/11 - acesso ao compartilhamento pelo Kali

Usei o comando abaixo e informei a senha no prompt:

```bash
smbclient //192.168.56.101/LabSOC -p 445 -W DESKTOP-EJJMRGB -U SocLab
```

Na conexão inicial com a senha correta, consegui listar `teste.txt` com `ls` e sair com `quit`. O 4624 correspondente foi o registro `14175`, às `19:27:18` locais: conta `SocLab`, logon tipo `3`, origem `192.168.56.1`, estação `KALI-KAH`, autenticação `NTLM`/`NTLM V2` e sessão `0x271012`.

Usei esse acesso como referência e fiz as próximas tentativas separadamente. Depois de três senhas incorretas e uma correta, imprimi o resultado da consulta interativa:

```powershell
$resultadoSMB | Format-List
```

Saída registrada:

```text
Conta     : DESKTOP-EJJMRGB\SocLab
Sucesso   : 2026-11-10 19:32:22.840
Origem    : 192.168.56.1
TipoLogon : 3
Sessao    : 0x33016c
Falhas60s : 3
Alerta    : True
```

Em outra execução, fiz apenas uma tentativa incorreta antes da correta. O resultado foi `Falhas60s = 1` e `Alerta = False`. Salvei cada caso em sua própria pasta.

A leitura dos EVTX no Kali confirmou estes seis registros. Todos pertencem a `SocLab`, com logon tipo `3` e origem `192.168.56.1`:

| Caso | Horário UTC em 10/11/2026 | Evento | EventRecordID |
|---|---|---:|---:|
| Três falhas | 22:32:03.303637 | 4625 | 14182 |
| Três falhas | 22:32:08.465334 | 4625 | 14183 |
| Três falhas | 22:32:14.257408 | 4625 | 14184 |
| Sucesso | 22:32:22.840467 | 4624 | 14185 |
| Controle: falha | 22:46:53.591682 | 4625 | 14192 |
| Controle: sucesso | 22:46:59.615614 | 4624 | 14193 |

As quatro falhas têm `SubStatus = 0xc000006a`. No caso positivo, a primeira falha precede o sucesso em **19,536830 segundos**. O acesso SMB confirmou autenticação pela rede; a execução de `cmd.exe` pertence à etapa local com `runas`.

### Repetindo a leitura com o script

O [analisar-logons.ps1](../scripts/analisar-logons.ps1) lê os campos XML pelo nome e retorna um objeto por sucesso da conta indicada, incluindo os IDs dos registros usados na correlação. Na VM, executei:

```powershell
Set-Location 'C:\Users\Ka\Lab'
.\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\03-smb\Security-SMB.evtx' | Format-List
.\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\04-smb-controle\Security-SMB-controle.evtx' | Format-List
```

Obtive novamente três falhas/`True` no primeiro arquivo e uma falha/`False` no controle. O script requer Windows com PowerShell 5.1 ou posterior, usa `Get-WinEvent` e apenas lê os EVTX. A conta padrão é `SocLab`; outra pode ser indicada com `-Usuario`.

Na primeira tentativa, a política de execução bloqueou o `.ps1`.

## Sigma e Elastic

Escrevi o [arquivo Sigma](../rules/detect_brute_force.yml) em quatro blocos: seleção das falhas, seleção dos sucessos, contagem com `event_count` e sequência com `temporal_ordered`. Ao carregar o YAML e resolver as referências no pySigma, obtive:

```text
OK: 4 blocos carregados.
Referencias entre as regras resolvidas.
```

Para consultar os dados no Elastic, escrevi a EQL separadamente. No Kali, li os dois EVTX SMB com `python-evtx` e processei os XMLs com `defusedxml`. Selecionei os eventos 4624/4625 de `SocLab` e gerei `logons-smb.ndjson`.

Mantive os nomes dos campos Windows e acrescentei `@timestamp` em UTC, `lab.caso`, `lab.arquivo` e `lab.evtx_sha256`. A importação manual criou o índice e a data view `lab-soc-smb`, com quatro documentos de `smb-positivo` e dois de `smb-controle`.

### Dashboard

Montei um gráfico de contagem por minuto e uma tabela em ordem cronológica. O período da imagem é de **19:31 a 19:49 de 10/11/2026**, em Brasília.

![Falhas e sucessos SMB no Elastic, com os seis eventos do teste e do controle](dashboard-elastic.png)

O primeiro grupo mostra três falhas e um sucesso; o segundo, uma falha e um sucesso. Guardei a configuração na pasta [dashboards](../dashboards/). Os dados do índice precisam ser importados separadamente ao reconstruir a visualização.

### Consulta EQL e resultado

Executei este bloco no Console do Kibana:

```http
GET lab-soc-smb/_eql/search
{
  "timestamp_field": "@timestamp",
  "tiebreaker_field": "EventRecordID",
  "size": 10,
  "query": """
    sequence by Computer, TargetDomainName, TargetUserName, LogonType, IpAddress
    with maxspan=60s

      [any where
        EventID == 4625 and
        TargetUserName : "SocLab" and
        SubStatus : "0xc000006a"
      ] with runs=3

      [any where
        EventID == 4624 and
        TargetUserName : "SocLab"
      ]
  """
}
```

`sequence by` agrupa os eventos pelos campos indicados, `with runs=3` repete o critério de falha e `maxspan=60s` limita a duração desde o primeiro evento da sequência. Usei `any` porque os documentos não têm `event.category`.

A resposta trouxe **`hits.total.value = 1`**, com `is_partial`, `is_running` e `timed_out` iguais a `false`. Os registros retornados foram `14182`, `14183`, `14184` e `14185`: as três falhas e o sucesso do caso positivo.

Conferi as chaves: computador e domínio `DESKTOP-EJJMRGB`, usuário `SocLab`, logon tipo `3` e origem `192.168.56.1`. Os eventos do controle estavam no mesmo índice e não formaram uma sequência correspondente.

## Evidências preservadas

Organizei os arquivos na VM em `C:\Users\Ka\Lab\Evidencias`:

| Pasta | Arquivos |
|---|---|
| `01-logon` | `Security-1649.evtx`, `Sysmon-1649.evtx`, `alerta-correlacao.csv`, `hashes-evidencias.csv` |
| `02-controle` | `Security-controle.evtx`, `Sysmon-controle.evtx`, `resultado-controle.csv`, `hashes-evidencias.csv` |
| `03-smb` | `Security-SMB.evtx`, `resultado-smb.csv`, `hashes-evidencias.csv` |
| `04-smb-controle` | `Security-SMB-controle.evtx`, `resultado-controle-smb.csv`, `hashes-evidencias.csv` |

Os recortes SMB vão do primeiro registro selecionado até o sucesso, inclusive, com os outros eventos Security presentes nesse intervalo. Calculei os manifestos SHA-256 após a exportação; nas pastas SMB eles cobrem o EVTX e o CSV correspondente.

Reuni as evidências e a cópia do script usada na VM em `evidencias-soc-final.zip`. No Kali, guardei o pacote em `~/Documentos/evidencias-soc/`. O SHA-256 coincidiu com o valor registrado no Windows:

```text
20cbc0fff6b88e625e50b94c8b51e9325516c618b523d081c9d2259aab07f29d
```

O `unzip -t` verificou os 15 arquivos sem erros. Os arquivos brutos ficaram no acervo local. O hash serve para comparar a cópia com a referência registrada após a exportação.

## Relação com MITRE ATT&CK

Usei o ATT&CK para relacionar os comportamentos estudados às técnicas:

- **T1110 / T1110.001 - Brute Force / Password Guessing:** tentativas repetidas com senhas incorretas.
- **T1078 / T1078.003 - Valid Accounts / Local Accounts:** uso da conta local `SocLab` no sucesso.
- **T1059.003 - Windows Command Shell, Execution:** criação local de `cmd.exe`, registrada no Sysmon.

O alvo desta regra é o padrão de tentativas de senha associado a **T1110.001**, dentro de T1110. T1078 e T1059.003 ajudam a contextualizar o acesso e a execução local, mas não são alvos de detecções específicas neste projeto.

Todos os acessos foram feitos no laboratório com credenciais conhecidas. Esse mapeamento descreve os comportamentos; não demonstra obtenção de senha por força bruta ou abuso real da conta.

## O que ficou pendente

**Minha prioridade é repetir a análise com um conjunto maior de logons legítimos da conta de teste, intercalando os cenários controlados.** Essa mistura aproxima o exercício de uma rotina de autenticação e permite avaliar correspondências benignas antes de ajustar o limiar e automatizar a detecção.

A validação cobre quatro casos, uma conta e um host. Para ampliar o teste, preciso avaliar tentativas mais espaçadas, contas e origens diferentes e recortes incompletos. A regra depende de um sucesso posterior; os 60 segundos não cobrem todo padrão de tentativa de senha.

No Sigma, validei a estrutura e as referências. As duas correlações de 60 segundos encadeadas ainda precisam ser testadas no backend escolhido: elas não garantem a janela única anterior ao sucesso usada pelo script. Por isso, mantenho essa versão experimental.

A EQL encontrou o resultado esperado nos dois conjuntos SMB. Ainda faltam testes de limite — timestamps iguais, ocorrências exatamente em 60 segundos e vários sucessos próximos — antes de afirmar equivalência com o PowerShell.

O Elastic recebeu dados históricos por upload manual. Para uma próxima etapa, posso estudar coleta contínua e regras agendadas. 

## Referências técnicas

- [Microsoft - evento 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft - evento 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft - evento 4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648)
- [Microsoft Sysinternals - Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft - Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1)
- [Microsoft - Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1)
- [Samba - smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [Sigma - especificação das regras de correlação](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
- [pySigma - documentação](https://sigmahq-pysigma.readthedocs.io/en/latest/)
- [python-evtx - leitor de arquivos EVTX](https://github.com/williballenthin/python-evtx)
- [Elastic - sintaxe EQL](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)
- [Elastic - objetos salvos e exportação](https://www.elastic.co/docs/explore-analyze/find-and-organize/saved-objects)
- [MITRE ATT&CK - T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK - T1078.003: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)
- [MITRE ATT&CK - T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
