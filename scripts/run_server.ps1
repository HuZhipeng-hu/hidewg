param(
    [string]$Config = "configs/server.yaml"
)

python "$PSScriptRoot/../hidewg" run --role server --config $Config
