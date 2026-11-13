# Lab SOC

Montei este laboratório para entender como as tentativas de login aparecem nos logs do Windows e como relacionar falhas de senha a um acesso bem-sucedido.

Comecei com autenticações locais usando `runas`. Depois, usei o Kali para acessar um compartilhamento SMB na VM Windows. Nos dois cenários, fiz três tentativas com senha incorreta seguidas de um acerto e comparei com um controle de apenas uma falha antes do sucesso.

Também usei o Sysmon para relacionar o login local à abertura de `cmd.exe` e um script PowerShell para repetir a análise dos arquivos EVTX da etapa SMB.

## Resultados

A regra foi sinalizar **três ou mais falhas de senha nos 60 segundos anteriores a um login bem-sucedido**, para a mesma conta, computador, origem e tipo de logon.

| Teste | Tipo de logon | Origem | Falhas em 60 s | Alerta |
|---|---:|---|---:|---|
| Local: três falhas e sucesso | 2 | `::1` | 3 | `True` |
| Local: uma falha e sucesso | 2 | `::1` | 1 | `False` |
| SMB: três falhas e sucesso | 3 | `192.168.56.1` | 3 | `True` |
| SMB: uma falha e sucesso | 3 | `192.168.56.1` | 1 | `False` |

Os quatro testes retornaram o resultado previsto pela regra. Depois, executei o `analisar-logons.ps1` sobre os dois EVTX SMB salvos e obtive novamente três falhas com alerta e uma falha sem alerta.

## Ambiente

A análise foi feita com o Visualizador de Eventos, consultas PowerShell e os logs:

- `Security`, para os eventos de autenticação.
- `Microsoft-Windows-Sysmon/Operational`, para a criação de processo na etapa local.

Para o teste SMB, conectei a VM à rede host-only `vboxnet0`:

| Componente | Configuração |
|---|---|
| Kali | `192.168.56.1/24`, cliente SMB |
| Windows-SOC | `192.168.56.101/24`, servidor SMB, sem gateway padrão nesse adaptador |
| DHCP | Servidor `192.168.56.100`, faixa `192.168.56.101–254` |
| Compartilhamento | `LabSOC`, na pasta `C:\LabSMB`, com o arquivo `teste.txt` |

Dei à conta `SocLab` permissão de leitura no compartilhamento e de leitura e execução no NTFS. Criei a regra de firewall `LabSOC-SMB-Kali` para permitir TCP/445 no endereço da VM, com origem no Kali (`192.168.56.1`). Esses eram os endereços usados no teste; o IP da VM foi recebido por DHCP.

## 1. Logon local com runas

```text
runas /user:DESKTOP-EJJMRGB\SocLab cmd.exe
```

Fiz três tentativas com senha incorreta e depois informei a senha correta. Os eventos de falha mostraram tipo de logon `2` (interativo), origem `::1` (loopback), status `0xC000006D` e substatus `0xC000006A`, que indica senha incorreta.

### Sequência dos eventos

| Hora local | Log / evento | EventRecordID | O que foi registrado |
|---|---|---:|---|
| 16:49:30 | Security / 4625 | 14004 | Primeira falha de senha |
| 16:49:33 | Security / 4625 | 14005 | Segunda falha de senha |
| 16:49:36 | Security / 4625 | 14006 | Terceira falha de senha |
| 16:49:44 | Security / 4648 | 14007 | Tentativa com credenciais explícitas de `SocLab` |
| 16:49:44 | Security / 4624 | 14008 | Criação da sessão de `SocLab` |
| 16:49:44 | Sysmon / 1 | 1506 | Criação de `cmd.exe` como `SocLab` |

Entre a primeira falha e o sucesso passaram aproximadamente **14 segundos**, considerando os timestamps completos dos XMLs. O 4648 registra o uso de credenciais explícitas; o 4624 confirma o login bem-sucedido.

### Ligando o login ao processo

Comparei o `TargetLogonId` do evento 4624 com o `LogonId` do Sysmon 1. Os dois tinham o valor **`0x14bfc2d`**, no mesmo computador e para a conta.

| Campo do Sysmon | Valor |
|---|---|
| Processo | `C:\Windows\System32\cmd.exe` |
| PID | `10196` |
| Usuário | `DESKTOP-EJJMRGB\SocLab` |
| LogonId | `0x14bfc2d` |
| ProcessGuid | `{eadcf747-d258-6af0-f603-000000000600}` |
| Processo pai | `C:\Windows\System32\runas.exe` |
| PID do pai | `8644` |
| Usuário do pai | `DESKTOP-EJJMRGB\Ka` |
| Comando do pai | `runas.exe /user:DESKTOP-EJJMRGB\SocLab cmd.exe` |
| Integridade | `Medium` |

Isso permitiu associar a sessão à abertura do prompt. A conferência considerou conta, computador, sessão e horário. O processo estava com integridade `Medium`, e o evento 4624 mostrava `Token Elevado: Não`.

### Controle com uma falha

Repeti o teste com uma senha incorreta antes da correta. A coleta ficou entre **19:42:12.779 e 19:43:09.596**, no mesmo dia, em horário local.

Conferi os eventos 4625 e 4624 e apliquei os mesmos critérios. O resultado foi **uma falha e `Alerta = False`**, abaixo do limite de três definido para o exercício.

## 2. Acesso SMB a partir do Kali

Usei o `smbclient` para acessar o compartilhamento da VM:

```bash
smbclient //192.168.56.101/LabSOC -p 445 -W DESKTOP-EJJMRGB -U SocLab
```

Informei a senha no prompt. Primeiro fiz uma conexão com a senha correta, listei o arquivo `teste.txt`.

Esse acesso inicial gerou um evento 4624 com os seguintes dados:

| Campo | Valor |
|---|---|
| Hora local | `2026-11-10 19:27:18` |
| EventRecordID | `14175` |
| Conta | `DESKTOP-EJJMRGB\SocLab` |
| Tipo de logon | `3` - rede |
| Origem | `192.168.56.1` |
| Estação de trabalho | `KALI-KAH` |
| Pacote de autenticação | `NTLM` |
| Nome do pacote NTLM | `NTLM V2` |
| TargetLogonId | `0x271012` |

Usei esse evento como referência para separar a conexão inicial das tentativas seguintes.

### Três falhas e um sucesso

Depois de três tentativas com senha incorreta, fiz uma conexão com a senha correta. A consulta encontrou três eventos 4625 antes do 4624:

```text
Conta     : DESKTOP-EJJMRGB\SocLab
Sucesso   : 2026-11-10 19:32:22.840
Origem    : 192.168.56.1
TipoLogon : 3
Sessao    : 0x33016c
Falhas60s : 3
Alerta    : True
```

As três falhas estavam dentro da janela de 60 segundos e atendiam aos filtros de conta, computador, origem, tipo de logon e senha incorreta.

### Controle SMB

Fiz outra execução com apenas uma senha incorreta antes do acerto. A mesma consulta retornou **`Falhas60s = 1` e `Alerta = False`**. Salvei os eventos e o resultado em uma pasta separada.

Nesta etapa, observei a autenticação pela rede e o acesso ao compartilhamento. A abertura de `cmd.exe` mostrada no Sysmon pertence ao teste local com `runas`; o login SMB, por si só, não comprova execução remota de comandos.

## Como a regra funciona

Para cada sucesso 4624, a análise procura falhas 4625 com substatus `0xc000006a` nos 60 segundos anteriores. Uma falha só entra na contagem quando corresponde ao sucesso em:

- Computador.
- Conta e domínio.
- Tipo de logon.
- Endereço de origem.

A janela inclui o instante de 60 segundos antes do sucesso e termina antes do próprio sucesso: **[sucesso − 60 s, sucesso)**.

Com três ou mais falhas, o resultado é `Alerta = True`. Escolhi esse limite e essa janela para o laboratório.

## Reanalisando os EVTX com PowerShell

O `analisar-logons.ps1` lê os eventos 4624 e 4625 de um EVTX exportado do Security. Ele busca os campos pelo nome no XML e aplica a regra a cada sucesso da conta indicada.

A saída traz conta, computador, origem, tipo de logon, sessão, horários local e UTC, quantidade de falhas e resultado do alerta. Também inclui os IDs dos registros para facilitar a conferência nos eventos originais.

O script requer Windows e PowerShell 5.1 ou posterior.

```powershell
Set-Location 'C:\Users\Ka\Lab'

.\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\03-smb\Security-SMB.evtx' | Format-List

.\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\04-smb-controle\Security-SMB-controle.evtx' | Format-List
```

| Arquivo | Falhas60s | Alerta |
|---|---:|---|
| `Security-SMB.evtx` | 3 | `True` |
| `Security-SMB-controle.evtx` | 1 | `False` |

Na primeira execução, a política do PowerShell bloqueou o `.ps1`. Ajustei a política apenas para a sessão em uso:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
```

Depois disso, consegui executar as duas análises. O ajuste vale para aquele processo PowerShell; não altera a política permanentemente.

O script apenas lê os EVTX e retorna os resultados. A correlação com o Sysmon foi feita separadamente. Os testes locais foram conferidos por consultas interativas, e os dois casos SMB também foram validados com o script salvo.

## Organização das evidências

Salvei os arquivos, separados por teste:

| Pasta | Arquivos |
|---|---|
| `01-logon` | `Security-1649.evtx`, `Sysmon-1649.evtx`, `alerta-correlacao.csv`, `hashes-evidencias.csv` |
| `02-controle` | `Security-controle.evtx`, `Sysmon-controle.evtx`, `resultado-controle.csv`, `hashes-evidencias.csv` |
| `03-smb` | `Security-SMB.evtx`, `resultado-smb.csv`, `hashes-evidencias.csv` |
| `04-smb-controle` | `Security-SMB-controle.evtx`, `resultado-controle-smb.csv`, `hashes-evidencias.csv` |

Calculei hashes SHA-256 após as exportações e guardei os valores nos CSVs. Nas pastas SMB, os hashes cobrem o EVTX e o CSV de resultado. Eles servem como referência para conferir se os arquivos foram alterados depois da exportação.

Os EVTX SMB vão do primeiro registro selecionado até o sucesso, incluindo os outros eventos Security desse intervalo. São recortes dos testes, mantidos com as evidências na VM.

## O que aprendi e os limites do teste

A parte mais útil foi acompanhar a sequência completa: a falha, o sucesso e, no caso local, o processo criado naquela sessão. O `LogonId` ajudou a ligar o Security ao Sysmon, enquanto o tipo de logon e o endereço de origem ajudaram a distinguir o acesso local do acesso pela rede.

O controle com uma falha também foi importante. Ele confirmou que a análise estava lendo os eventos e respeitando o limite escolhido, mesmo quando o resultado era `False`.

Todos os acessos foram feitos por mim no laboratório. Uma sequência de falhas seguida de sucesso é um ponto para investigar, mas não basta para concluir que houve um ataque. Estes quatro casos também não medem a taxa de falsos positivos ou negativos em um ambiente real.

A regra depende de um sucesso posterior, de tentativas que atendam aos mesmos filtros e dos eventos disponíveis no arquivo. Um recorte incompleto pode deixar falhas de fora. O projeto faz análise pontual dos EVTX, sem monitoramento contínuo, bloqueio automático ou SIEM.
