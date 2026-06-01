param(
    [string]$Config = "configs/client.yaml"
)

python "$PSScriptRoot/../hidewg" run --role client --config $Config
