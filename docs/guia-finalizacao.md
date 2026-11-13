# Guia de finalização do laboratório

Execute os passos em ordem. Os testes de autenticação já estão concluídos; aqui estão as tarefas restantes de apresentação, preservação e publicação. Os comandos abaixo são instruções para o notebook e a VM da autora, não ações já executadas.

## 1. Preparar a pasta no Kali

Baixe `soc-windows-logon-lab.zip` em `~/Downloads`. No terminal do Kali:

```bash
mkdir -p "$HOME/projetos"
unzip -n "$HOME/Downloads/soc-windows-logon-lab.zip" -d "$HOME/projetos"
```

A pasta resultante é `~/projetos/soc-windows-logon-lab`. Ela contém README.md, .gitignore, scripts/analisar-logons.ps1, docs/relatorio.md e este guia. Se o navegador tiver acrescentado um sufixo ao nome do ZIP, ajuste o caminho do comando.

## 2. Exibir os dois resultados para a imagem do projeto

Na mesma janela do PowerShell da VM Windows:

```powershell
Set-Location 'C:\Users\Ka\Lab'
$resultadosLab = @(
    .\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\03-smb\Security-SMB.evtx'
    .\analisar-logons.ps1 -ArquivoEVTX '.\Evidencias\04-smb-controle\Security-SMB-controle.evtx'
)
$resultadosLab | Format-Table Arquivo,Origem,TipoLogon,Falhas60s,Alerta -AutoSize
```

Se a sessão anterior foi fechada e a execução estiver bloqueada:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
```

Depois repita o bloco da tabela. O esperado é:

| Arquivo | Origem | TipoLogon | Falhas60s | Alerta |
|---|---|---:|---:|---|
| Security-SMB.evtx | 192.168.56.1 | 3 | 3 | True |
| Security-SMB-controle.evtx | 192.168.56.1 | 3 | 1 | False |

Capture a janela com a tabela usando a ferramenta de captura do Kali e salve em `~/projetos/soc-windows-logon-lab/docs/resultados-smb.png`. Essa etapa apenas reapresenta os arquivos salvos, sem gerar novas tentativas de senha.

## 3. Compactar as evidências na VM Windows

No PowerShell:

```powershell
$itensLab = @('C:\Users\Ka\Lab\Evidencias', 'C:\Users\Ka\Lab\analisar-logons.ps1')
Compress-Archive -LiteralPath $itensLab -DestinationPath 'C:\LabSMB\evidencias-soc.zip' -ErrorAction Stop
Get-FileHash -LiteralPath 'C:\LabSMB\evidencias-soc.zip' -Algorithm SHA256 | Format-List Algorithm,Hash
```

Anote o hash mostrado. O ZIP reúne as evidências e a cópia do script usada na VM, mantendo os originais. Se esse ZIP já existir, confira se é a cópia que você acabou de criar; o comando não foi configurado para sobrescrevê-lo.

## 4. Baixar as evidências para o Kali

Mantenha a VM ligada e conectada à rede host-only. No terminal do Kali:

```bash
mkdir -p "$HOME/Documentos/evidencias-soc"
cd "$HOME/Documentos/evidencias-soc"
smbclient //192.168.56.101/LabSOC -p 445 -W DESKTOP-EJJMRGB -U SocLab
```

Informe a senha correta da conta SocLab quando solicitada. Dentro do prompt `smb: \>`, execute um comando por vez:

```text
get evidencias-soc.zip
quit
```

De volta ao terminal do Kali:

```bash
sha256sum evidencias-soc.zip
unzip -t evidencias-soc.zip
```

O SHA-256 deve ser igual ao exibido no Windows, desconsiderando maiúsculas/minúsculas. A verificação do ZIP deve terminar sem erros. O ZIP permanece em `~/Documentos/evidencias-soc`, fora da pasta destinada ao GitHub. Mantenha também os originais na VM.

Se houver erro de conexão, confirme o IPv4 com `ipconfig` no Windows: o endereço utilizado no exercício foi 192.168.56.101. Se houver erro de autenticação, confirme que está usando a senha correta de SocLab.

## 5. Publicar o projeto no GitHub pelo navegador

1. Acesse https://github.com/new com sua conta.
2. Nome sugerido: `soc-windows-logon-lab`.
3. Descrição: `Laboratório de correlação de logons Windows com Security, Sysmon e PowerShell: testes locais e via SMB a partir do Kali.`
4. Selecione Public para o portfólio público. Deixe desmarcada a criação automática de README; o pacote já contém esse arquivo. Não é necessário escolher uma licença para concluir esta etapa.
5. Crie o repositório.
6. Na tela inicial do repositório vazio, escolha a opção para enviar um arquivo existente. Se já houver arquivos, use Add file → Upload files.
7. Abra `~/projetos/soc-windows-logon-lab` no gerenciador de arquivos. Arraste o conteúdo da pasta: README.md, scripts, docs e .gitignore. Use Ctrl+H para exibir .gitignore se necessário.
8. Confira se o README está na raiz e se as pastas scripts e docs aparecem corretamente. O ZIP de evidências guardado em Documentos fica fora desse envio.
9. Mensagem de commit sugerida: `Adiciona laboratório de correlação de logons locais e SMB`.
10. Confirme o commit. Confira o README renderizado e abra os links do script e do relatório.

A interface web aceita arquivos e pastas. O .gitignore é útil em futuros commits com Git, mas não impede que arquivos selecionados manualmente sejam enviados pelo navegador.

## 6. Publicar no LinkedIn

Use a imagem da tabela dos dois resultados e acrescente o link real do repositório ao texto abaixo.

---

Depois de explorar detecção de comportamentos no Linux com o PurpleCheck, levei o estudo para autenticações no Windows.

Montei um laboratório com Kali Linux e uma VM Windows 11 para investigar falhas de senha seguidas de um logon bem-sucedido.

Trabalhei com dois cenários: autenticação local usando runas e acesso via SMB a partir do Kali. Analisei os eventos 4625 e 4624 do Windows Security e, na etapa local, relacionei a sessão à criação de um processo usando o Sysmon.

A regra avaliada sinaliza três ou mais falhas de senha nos 60 segundos anteriores ao sucesso, considerando a mesma conta, computador, origem e tipo de logon. Também usei um controle com uma falha seguida de sucesso, que ficou sem alerta conforme o limite definido.

Organizei as evidências em EVTX, registrei hashes SHA-256 e usei um script PowerShell para repetir a análise dos dois casos SMB.

O principal aprendizado foi correlacionar os eventos e conferir o contexto antes de interpretar um alerta como ataque. Os resultados são de testes controlados de laboratório.

Código e documentação: [cole o link do repositório]

#Cybersecurity #SOC #BlueTeam #PowerShell #Sysmon

---

## 7. Encerrar a sessão de laboratório

Depois de confirmar a cópia no Kali, desligue o Windows pelo menu Iniciar → Energia → Desligar. A VM continua disponível para futuras análises.

## Referências dos procedimentos

- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive?view=powershell-5.1
- https://www.samba.org/samba/docs/current/man-html/smbclient.1.html
- https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository

