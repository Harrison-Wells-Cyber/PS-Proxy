# PS-Proxy agent entrypoint.
# The mature implementation packages a precompiled C# agent DLL into a single PS1
# and loads it with [System.Reflection.Assembly]::Load(byte[]) instead of Add-Type.
# Build release/agent.ps1 on Windows with: powershell -ExecutionPolicy Bypass -File tools/build-agent.ps1
throw "This source checkout contains the agent source and loader template. Use release/agent.ps1 from a packaged release, or run tools/build-agent.ps1 on Windows to generate it."
