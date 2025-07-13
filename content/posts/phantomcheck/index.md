---
date: '2025-07-13T12:30:30+03:00'
draft: false
title: 'Operation Blackout 2025: Phantom Check'
summary: 'In this post we are looking at Windows event logs'
params:
  author: Axonym
tags:
- DFIR
- HTB

cover:
  image: "phantomcheck.png"
  alt: "Photo of Phantom Check logo from HTB"
  caption: "Credit: [HTB](https://app.hackthebox.com/sherlocks/Operation%20Blackout%202025:%20Phantom%20Check)"

---

## Info

- Status: Retired

- Difficulty: Very Easy

## Sherlock Scenario

Talion suspects that the threat actor carried out anti-virtualization checks to avoid detection in sandboxed environments. Your task is to analyze the event logs and identify the specific techniques used for virtualization detection. Byte Doctor requires evidence of the registry checks or processes the attacker executed to perform these checks.

## Files given

We are given a `.zip` file which contains the following structure:

```bash
|-- Microsoft-Windows-Powershell.evtx
|-- Windows-Powershell-Operational.evtx
```

## Beginning

In the zip file we have two evtx event logs:

Microsoft-Windows-Powershell.evtx and Windows-Powershell-Operational.evtx

These are the files we have to do analysis on.

This time I used [KAPE](https://github.com/EricZimmerman/KapeFiles?tab=readme-ov-file) (kinda overkill I know) to analyze the files even though I could have just used [EvtxECmd](https://github.com/EricZimmerman/evtx).

## Tasks

### Task 1

Which WMI class did the attacker use to retrieve model and manufacturer information for virtualization detection?

To retrieve what WMI class the attacker used we need to analyze the given evtx files.

I used KAPE with the following command

```powershell
.\KAPE.exe --msource "PhantomCheck" --mdest "Parsed" --module EvtxECmd
```

This then gave me csv file which combined both of the evtx files. I then searched through it for "WMI and found this class **"Win32_ComputerSystem"** which gives information about computer and in return can give information about used virtualization platforms.

**Answer:** Win32_ComputerSystem

### Task 2

Which WMI query did the attacker execute to retrieve the current temperature value of the machine?

Searching through the CSV file for temperature I found this line:

```powershell
{"EventData":{"Data":"Get-WmiObject -Query \"SELECT * FROM MSAcpi_ThermalZoneTemperature\" -ErrorAction SilentlyContinue, \tDetailSequence=1\n\tDetailTotal=1\n\n\tSequenceNumber=53\n\n\tUserId=DESKTOP-M3AKJSD\\User\n\tHostName=ConsoleHost\n\tHostVersion=5.1.26100.2161\n\tHostId=0fad0cf8-6cb6-4657-86f7-655ec22eed9f\n\tHostApplication=C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe\n\tEngineVersion=5.1.26100.2161\n\tRunspaceId=2aeeba59-d0f6-4ce7-b41c-e07625b3beec\n\tPipelineId=21\n\tScriptName=\n\tCommandLine=Get-WmiObject -Query \"SELECT * FROM MSAcpi_ThermalZoneTemperature\" -ErrorAction SilentlyContinue, CommandInvocation(Get-WmiObject): \"Get-WmiObject\"\nParameterBinding(Get-WmiObject): name=\"Query\"; value=\"SELECT * FROM MSAcpi_ThermalZoneTemperature\"\nParameterBinding(Get-WmiObject): name=\"ErrorAction\"; value=\"SilentlyContinue\"\nNonTerminatingError(Get-WmiObject): \"Invalid class \"MSAcpi_ThermalZoneTemperature\"\"\n","Binary":""}}
```

And the attacker used this **"SELECT * FROM MSAcpi_ThermalZoneTemperature"** WMI querty to get the current temperature value.

**Answer:** SELECT * FROM MSAcpi_ThermalZoneTemperature

### Task 3

The attacker loaded a PowerShell script to detect virtualization. What is the function name of the script?

Searching through the CSV file for "function" I was able to find the following information.

```powershell
ScriptBlockText: function Check-VM, {, <# , .SYNOPSIS , Nishang script which detects whether it is in a known virtual machine.,  , .DESCRIPTION , This script uses known parameters or 'fingerprints' of Hyper-V, VMWare, Virtual PC, Virtual Box,, Xen and QEMU for detecting the environment., .EXAMPLE , PS > Check-VM,  , .LINK , http://www.labofapenetrationtester.com/2013/01/quick-post-check-if-your-payload-is.html, https://github.com/samratashok/nishang, .NOTES , The script draws heavily from checkvm.rb post module from msf., https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/checkvm.rb, #> ,     [CmdletBinding()] Param(),     $ErrorActionPreference = "SilentlyContinue",     #Hyper-V,     $hyperv = Get-ChildItem HKLM:\SOFTWARE\Microsoft,     if (($hyperv -match "Hyper-V") -or ($hyperv -match "VirtualMachine")),         {,             $hypervm = $true,         },     if (!$hypervm),         {,             $hyperv = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion,             if ($hyperv -match "vrtual"),                 {,                     $hypervm = $true,                 },         },     ,     if (!$hypervm),         {,             $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT,             if ($hyperv -match "vrtual"),                 {,                     $hypervm = $true,                 },         },             ,     if (!$hypervm),         {,             $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT,             if ($hyperv -match "vrtual"),                 {,                     $hypervm = $true,                 },         },     if (!$hypervm),         {,             $hyperv = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services,             if (($hyperv -match "vmicheartbeat") -or ($hyperv -match "vmicvss") -or ($hyperv -match "vmicshutdown") -or ($hyperv -match "vmiexchange")),                 {,                     $hypervm = $true,                 },         },    ,     if ($hypervm),         {,     ,              "This is a Hyper-V machine.",     ,         },     #VMWARE,     $vmware = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services,     if (($vmware -match "vmdebug") -or ($vmware -match "vmmouse") -or ($vmware -match "VMTools") -or ($vmware -match "VMMEMCTL")),         {,             $vmwarevm = $true,         },     if (!$vmwarevm),         {,             $vmware = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System\BIOS -Name SystemManufacturer,             if ($vmware -match "vmware"),                 {,                     $vmwarevm = $true,                 },         },     ,     if (!$vmwarevm),         {,             $vmware = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier,             if ($vmware -match "vmware"),                 {,                     $vmwarevm = $true,                 },         },     if (!$vmwarevm),         {,             $vmware = Get-Process,             if (($vmware -eq "vmwareuser.exe") -or ($vmware -match "vmwaretray.exe")),                 {,                     $vmwarevm = $true,                 },         },     if ($vmwarevm),         {,     ,              "This is a VMWare machine.",     ,         },     ,     #Virtual PC,     $vpc = Get-Process,     if (($vpc -eq "vmusrvc.exe") -or ($vpc -match "vmsrvc.exe")),         {,         $vpcvm = $true,         },     if (!$vpcvm),         {,             $vpc = Get-Process,             if (($vpc -eq "vmwareuser.exe") -or ($vpc -match "vmwaretray.exe")),                 {,                     $vpcvm = $true,                 },         },     if (!$vpcvm),         {,             $vpc = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services,             if (($vpc -match "vpc-s3") -or ($vpc -match "vpcuhub") -or ($vpc -match "msvmmouf")),                 {,                     $vpcvm = $true,                 },         },     if ($vpcvm),         {,     ,          "This is a Virtual PC.",     ,         },     #Virtual Box,     $vb = Get-Process,     if (($vb -eq "vboxservice.exe") -or ($vb -match "vboxtray.exe")),         {,     ,         $vbvm = $true,     ,         },     if (!$vbvm),         {,             $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT,             if ($vb -match "vbox_"),                 {,                     $vbvm = $true,                 },         },     if (!$vbvm),         {,             $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT,             if ($vb -match "vbox_"),                 {,                     $vbvm = $true,                 },         },     ,     if (!$vbvm),         {,             $vb = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier,             if ($vb -match "vbox"),                 {,                     $vbvm = $true,                 },         },     if (!$vbvm),         {,             $vb = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion,             if ($vb -match "vbox"),                 {,                      $vbvm = $true,                 },         },   ,     if (!$vbvm),         {,             $vb = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services,             if (($vb -match "VBoxMouse") -or ($vb -match "VBoxGuest") -or ($vb -match "VBoxService") -or ($vb -match "VBoxSF")),                 {,                     $vbvm = $true,                 },         },     if ($vbvm),         {,     ,          "This is a Virtual Box.",     ,         },     #Xen,     $xen = Get-Process,     if ($xen -eq "xenservice.exe"),         {,     ,         $xenvm = $true,     ,         },     ,     if (!$xenvm),         {,             $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT,             if ($xen -match "xen"),                 {,                     $xenvm = $true,                 },         },     if (!$xenvm),         {,             $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\DSDT,             if ($xen -match "xen"),                 {,                     $xenvm = $true,                 },         },     ,     if (!$xenvm),         {,             $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT,             if ($xen -match "xen"),                 {,                     $xenvm = $true,                 },         },     ,     if (!$xenvm),         {,            $xen = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services,             if (($xen -match "xenevtchn") -or ($xen -match "xennet") -or ($xen -match "xennet6") -or ($xen -match "xensvc") -or ($xen -match "xenvdb")),                 {,                     $xenvm = $true,                 },         },     if ($xenvm),         {,     ,          "This is a Xen Machine.",     ,         },     #QEMU,     $qemu = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier,     if ($qemu -match "qemu"),         {,     ,             $qemuvm = $true,     ,         },     ,     if (!$qemuvm),         {,         $qemu = Get-ItemProperty hklm:HARDWARE\DESCRIPTION\System\CentralProcessor\0 -Name ProcessorNameString,         if ($qemu -match "qemu"),             {,                 $qemuvm = $true,             },         }    ,     if ($qemuvm),         {,     ,          "This is a Qemu machine.",     ,         }, }
```

The function's name was obtained and is **"Check-VM"**

**Answer:** Check-VM

### Task 4

Which registry key did the above script query to retrieve service details for virtualization detection?

I was able to find the registry key from the above script by looking at the script for "service"

The query used **"HKLM:\SYSTEM\ControlSet001\Services"** registry key to retrieve service details for virtualization detection. 

**Answer:** HKLM:\SYSTEM\ControlSet001\Services

### Task 5

The VM detection script can also identify VirtualBox. Which processes is it comparing to determine if the system is running VirtualBox?

```bash
grep -i ".exe" EvtxECmd_Output.csv | grep -v powershell.exe | grep -i ".exe"
```

Using this I was able to find the **"vboxservice.exe, vboxtray.exe"** which are used to compare if system is running VirtualBox.

**Answer:** vboxservice.exe, vboxtray.exe

### Task 6

The VM detection script prints any detection with the prefix 'This is a'. Which two virtualization platforms did the script detect?

I searched from the CSV file for "This is a" and I was able to find the following:

```powershell
{"EventData":{"Data":"\tDetailSequence=1\n\tDetailTotal=1\n\n\tSequenceNumber=145\n\n\tUserId=DESKTOP-M3AKJSD\\User\n\tHostName=ConsoleHost\n\tHostVersion=5.1.26100.2161\n\tHostId=0fad0cf8-6cb6-4657-86f7-655ec22eed9f\n\tHostApplication=C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe\n\tEngineVersion=5.1.26100.2161\n\tRunspaceId=2aeeba59-d0f6-4ce7-b41c-e07625b3beec\n\tPipelineId=43\n\tScriptName=\n\tCommandLine=, CommandInvocation(Out-Default): \"Out-Default\"\nParameterBinding(Out-Default): name=\"InputObject\"; value=\"This is a Hyper-V machine.\"\nParameterBinding(Out-Default): name=\"InputObject\"; value=\"This is a VMWare machine.\"\n","Binary":""}}
```

And especially this value was important: "**This is a Hyper-V machine.\"\nParameterBinding(Out-Default): name=\"InputObject\"; value=\"This is a VMWare machine.**" Indicating that the script detected "**Hyper-V**" and "**VMWare**" virtualization platforms.

**Answer:** Hyper-V, Vmware

## Further analysis

### Indicators of attack (IOAs)

- PowerShell command: `Get-WmiObject -Query "SELECT * FROM Win32_ComputerSystem"`

- PowerShell command: `Get-WmiObject -Query "SELECT * FROM MSAcpi_ThermalZoneTemperature"`

- Use of [Nishang](https://github.com/samratashok/nishang/blob/master/Gather/Check-VM.ps1) PowerShell script

### Observations

Attacker is performing environment awareness by trying to detect virtualization platforms and this could mean that the attacker hasn't ready ran any malware (if the malware doesn't contain the script in it) 

So potentially this could be an useful rule or detection point when to flag certain IP, user etc. if they are running this kind of script.

## Conclusion

This challenge demonstrates what attackers could use to detect virtualization platforms and which kind of script they might use. The challenge also demonstrates what to look for in event logs.

Even though this Phantom Check Sherlock challenge demonstrates what to look for in event logs for certain script's commands, it accomplishes to what to look for when trying to detect attacker's IOAs.

https://labs.hackthebox.com/achievement/sherlock/2339218/935
