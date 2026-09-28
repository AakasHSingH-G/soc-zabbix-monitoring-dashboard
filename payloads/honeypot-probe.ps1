param(
    [string]$TargetHost = "127.0.0.1"
)

$targetPorts = @(2222, 2323, 8081)

function Send-HoneypotProbe {
    param(
        [string]$HostName,
        [int]$Port,
        [byte[]]$Payload
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.ConnectAsync($HostName, $Port).Wait(2000) | Out-Null
        if (-not $client.Connected) {
            Write-Host "[-] No connection to ${HostName}:$Port"
            return
        }

        $stream = $client.GetStream()
        $stream.Write($Payload, 0, $Payload.Length)
        Write-Host "[+] Sent probe to ${HostName}:$Port"
    }
    catch {
        Write-Host "[-] ${HostName}:$Port - $($_.Exception.Message)"
    }
    finally {
        if ($stream) { $stream.Dispose() }
        $client.Dispose()
    }
}

Write-Host "[*] Probing honeypot at $TargetHost"

foreach ($port in $targetPorts) {
    Send-HoneypotProbe $TargetHost $port ([Text.Encoding]::ASCII.GetBytes("HONEYPOT-TEST tcp`r`n"))
}

Send-HoneypotProbe $TargetHost 2222 ([Text.Encoding]::ASCII.GetBytes("SSH-2.0-Honeypot-Test`r`n"))

$httpRequest = "GET /honeypot-test HTTP/1.1`r`nHost: honeypot-test`r`nUser-Agent: honeypot-probe/1.0`r`nConnection: close`r`n`r`n"
Send-HoneypotProbe $TargetHost 8081 ([Text.Encoding]::ASCII.GetBytes($httpRequest))

$tlsSignature = [byte[]](0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00)
Send-HoneypotProbe $TargetHost 2323 $tlsSignature

Write-Host "[*] Probe complete. Check /api/security/honeyports for events."