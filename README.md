# SOC Windows Logon Lab

Laboratório de análise e correlação de eventos de autenticação no Windows, com testes locais e acessos SMB a partir do Kali Linux.

**Autora:** Kamila Silva  
**Execução dos testes:** 8 e 10 de novembro de 2026

## Objetivo

Identificar três ou mais falhas de senha seguidas de sucesso em até 60 segundos, relacionando computador, domínio/conta, tipo de logon e endereço de origem. Comparar o resultado com um controle de uma falha seguida de sucesso.

## Ambiente

- Kali Linux como hospedeiro e cliente SMB.
- VM Windows 11 Enterprise Evaluation no VirtualBox, com 6 GB de RAM e duas CPUs virtuais.
- Rede host-only: Kali `192.168.56.1`; Windows `192.168.56.101`.
- Conta local de teste: `SocLab`; compartilhamento de leitura `LabSOC`.
- Windows Security, Sysmon, PowerShell e smbclient.

## Resultados observados

| Caso | Tipo de logon | Origem | Falhas na janela | Alerta |
|---|---:|---|---:|---|
| Local: três falhas e sucesso | 2 | `::1` | 3 | True |
| Local: uma falha e sucesso | 2 | `::1` | 1 | False |
| SMB: três falhas e sucesso | 3 | `192.168.56.1` | 3 | True |
| SMB: uma falha e sucesso | 3 | `192.168.56.1` | 1 | False |

Os quatro casos foram validados por consultas interativas. Os dois casos SMB também foram reanalisados pelo script reutilizável, a partir dos EVTX exportados, com os mesmos resultados confirmados na VM.

No caso local, o `TargetLogonId` do evento Security 4624 foi relacionado ao `LogonId` do Sysmon 1 para identificar a criação de `cmd.exe` como `SocLab`, com `runas.exe` como processo pai.

## Regra de correlação

Para cada sucesso **4624**, contar falhas **4625** com `SubStatus = 0xc000006a` (senha incorreta) no intervalo **[sucesso − 60 segundos, sucesso)**, exigindo:

- Mesmo computador.
- Mesmo usuário e domínio.
- Mesmo tipo de logon.
- Mesmo endereço de origem.

O resultado é `Alerta = True` a partir de três falhas correspondentes.

## Arquivos

- [Script de análise](scripts/analisar-logons.ps1): leitura dos EVTX Security e aplicação da regra.
- [Relatório técnico](docs/relatorio.md): ambiente, linha do tempo local, evidências, resultados e limitações.
- [Guia de finalização](docs/guia-finalizacao.md): transferência das evidências e publicação do projeto.

## Como executar a análise

Requisitos: Windows com PowerShell 5.1 ou posterior e um EVTX exportado do log Security contendo os eventos do teste. Os EVTX devem estar disponíveis localmente; eles não integram este pacote.

A partir da raiz deste projeto, no PowerShell:

```powershell
.\scripts\analisar-logons.ps1 -ArquivoEVTX 'C:\Users\Ka\Lab\Evidencias\03-smb\Security-SMB.evtx' | Format-List
.\scripts\analisar-logons.ps1 -ArquivoEVTX 'C:\Users\Ka\Lab\Evidencias\04-smb-controle\Security-SMB-controle.evtx' | Format-List
```

Para outra conta, acrescente `-Usuario 'NomeDaConta'`. O script devolve um objeto por sucesso encontrado e inclui os IDs dos registros usados na correlação. Ele não altera os EVTX, não escreve arquivos e não se conecta à rede.

Se a política de execução bloquear este script local, a configuração utilizada no laboratório foi limitada à sessão:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
```

## Evidências

Na VM, os recortes EVTX, resultados CSV e manifestos SHA-256 foram organizados nas pastas `01-logon`, `02-controle`, `03-smb` e `04-smb-controle`, sob `C:\Users\Ka\Lab\Evidencias`.

Os hashes são referências calculadas após a exportação. Os arquivos brutos permanecem no acervo local do laboratório. O relatório descreve os resultados observados; não inclui cópias dos EVTX.

## Limitações

- Trata-se de quatro casos controlados em uma conta-alvo e um computador Windows; não há medição de precisão em produção.
- O alerta sinaliza uma sequência definida pela regra; não comprova comprometimento ou intenção maliciosa.
- Uma falha não atingir o limite não demonstra que toda atividade legítima ficará sem alerta.
- A regra exige sucesso posterior e conta somente os eventos presentes no arquivo. Recortes incompletos podem omitir falhas.
- O script analisa autenticações Security. A correlação com Sysmon foi feita separadamente na etapa local.
- Acesso SMB não demonstra execução remota de processos.
- A análise é pontual e não implementa SIEM ou monitoramento contínuo.

As referências oficiais usadas estão no [relatório técnico](docs/relatorio.md).

