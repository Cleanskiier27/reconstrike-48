# networkbusteros PowerShell Service Loader
# Imports all .psm1 modules in the workspace

$modulePaths = @(
    "WinHttpProxy/WinHttpProxy.psm1",
    "WindowsUpdate/WindowsUpdateLog.psm1",
    "Microsoft.PowerShell.ODataUtils/Microsoft.PowerShell.ODataUtils.psm1",
    "ISE/ise.psm1",
    "Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psm1",
    "Dism/Dism.psm1",
    "BitsTransfer/BitsTransfer.psm1",
    "ConfigDefenderPerformance/MSFT_MpPerformanceRecording.psm1",
    "NetAdapter/NetAdapter.Format.Helper.psm1",
    "NetAdapter/MSFT_NetAdapterQos.Format.Helper.psm1",
    "NetAdapter/MSFT_NetAdapterPowerManagement.Format.Helper.psm1",
    "NetQos/MSFT_NetQosPolicy.Format.Helper.psm1",
    "DeliveryOptimization/DeliveryOptimizationVerboseLogs.psm1",
    "DeliveryOptimization/DeliveryOptimizationStatus.psm1",
    "DeliveryOptimization/DeliveryOptimizationSettings.psm1",
    "Microsoft.PowerShell.Archive/Microsoft.PowerShell.Archive.psm1",
    "HostNetworkingService/HostNetworkingService.psm1",
    "Appx/Appx.psm1",
    "BitLocker/BitLocker.psm1",
    "PSWorkflow/PSWorkflow.psm1"
    # ...add all other .psm1 files found
)

foreach ($path in $modulePaths) {
    $fullPath = Join-Path $PSScriptRoot $path
    if (Test-Path $fullPath) {
        Import-Module $fullPath -ErrorAction SilentlyContinue
    }
}

Write-Host "networkbusteros PowerShell services loaded."
