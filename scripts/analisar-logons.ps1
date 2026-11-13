[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ArquivoEVTX,

    [ValidateNotNullOrEmpty()]
    [string]$Usuario = 'SocLab'
)

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Execute este script no PowerShell do Windows.'
}

$arquivo = Get-Item -LiteralPath $ArquivoEVTX

if ($arquivo.PSIsContainer -or $arquivo.Extension -ne '.evtx') {
    throw 'Informe um arquivo .evtx exportado do log Security.'
}

$filtroLogons = "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4625)]]"
$registros = @(Get-WinEvent -Path $arquivo.FullName -FilterXPath $filtroLogons -Oldest)

$eventos = @(foreach ($registro in $registros) {
    $xml = [xml]$registro.ToXml()
    $dados = @{}

    foreach ($campo in $xml.Event.EventData.Data) {
        $dados[$campo.GetAttribute('Name')] = [string]$campo.InnerText
    }

    if ($dados['TargetUserName'] -ine $Usuario) {
        continue
    }

    [pscustomobject]@{
        Momento    = $registro.TimeCreated
        Registro   = $registro.RecordId
        Evento     = $registro.Id
        Computador = $registro.MachineName
        Conta      = [string]$dados['TargetUserName']
        Dominio    = [string]$dados['TargetDomainName']
        Tipo       = [string]$dados['LogonType']
        Origem     = [string]$dados['IpAddress']
        Substatus  = [string]$dados['SubStatus']
        Sessao     = [string]$dados['TargetLogonId']
    }
})

$logonsComSucesso = @(
    $eventos |
        Where-Object Evento -eq 4624 |
        Sort-Object Momento, Registro
)

if ($logonsComSucesso.Count -eq 0) {
    throw "Nenhum sucesso 4624 para '$Usuario' foi encontrado."
}

foreach ($sucesso in $logonsComSucesso) {
    $inicioDaJanela = $sucesso.Momento.AddSeconds(-60)

    $falhas = @($eventos | Where-Object {
        $_.Evento -eq 4625 -and
        $_.Substatus -eq '0xc000006a' -and
        $_.Computador -eq $sucesso.Computador -and
        $_.Conta -eq $sucesso.Conta -and
        $_.Dominio -eq $sucesso.Dominio -and
        $_.Tipo -eq $sucesso.Tipo -and
        $_.Origem -eq $sucesso.Origem -and
        $_.Momento -ge $inicioDaJanela -and
        $_.Momento -lt $sucesso.Momento
    })

    $idsDasFalhas = ($falhas |
        Sort-Object Momento, Registro |
        ForEach-Object { $_.Registro }) -join ','

    [pscustomobject]@{
        Arquivo         = $arquivo.Name
        Computador      = $sucesso.Computador
        Conta           = "$($sucesso.Dominio)\$($sucesso.Conta)"
        Sucesso         = $sucesso.Momento.ToString('yyyy-MM-dd HH:mm:ss.fff')
        SucessoUTC      = $sucesso.Momento.ToUniversalTime().ToString('o')
        RegistroSucesso = $sucesso.Registro
        Origem          = $sucesso.Origem
        TipoLogon       = $sucesso.Tipo
        Sessao          = $sucesso.Sessao
        Falhas60s       = $falhas.Count
        Alerta          = ($falhas.Count -ge 3)
        RegistrosFalha  = $idsDasFalhas
    }
}

