param(
    [string]$Config = "configs/lab.yaml",
    [string]$Output = "artifacts"
)

python "$PSScriptRoot/../hidewg" verify --config $Config --output $Output
