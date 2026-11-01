Title: Aquantia atlAccess.sys physical memory map

Vendor: Aquantia Corp.
Product: atlAccess
Component: atlAccess.sys
SHA-256: 0b57569aaa0f4789d9642dd2189b0a82466b80ad32ff35f88127210ed105fe57
MD5: 08001b0cdb0946433366032827d7a187
SHA-1: 6b54b8f7edca5fb25a8ef1a1d31e14b9738db579
Size: 15672 bytes
PE timestamp: 2020-03-31 07:35:36 UTC
Authenticode status: Valid
Signer: CN=Aquantia Corp., OU=IT, O=Aquantia Corp., L=San Jose, S=California, C=US
Thumbprint: 89C637766CD42D843E07E9655A7BBADE87A80C70
Device: \\.\atlAccess
PDB: c:\w\workspace\build_tools_windows_driver\objchk_win7_amd64\amd64\atlAccess.pdb

CVE:

Description:
atlAccess.sys IOCTL 0x7B592418 is METHOD_BUFFERED. The caller supplies a physical address and a length. The driver passes that address to MmMapIoSpace with the cache type fixed to non-cached, then maps the range into the calling process and returns the user-mode address. VERSIONINFO on this file is the Windows 7 DDK template: CompanyName Windows (R) Win 7 DDK provider, ProductName Windows (R) Win 7 DDK driver, FileDescription Simple PCI access driver, FileVersion 6.1.7600.16385 built by: WinDDK, ProductVersion 6.1.7600.16385, OriginalFilename atlAccess.sys. The Authenticode signer is Aquantia Corp. Local account aida-low sent this IOCTL. That account wrote its own bytes through the returned mapping into a page an administrator was holding.

Access:
On 2026-11-02, on an isolated Windows 10 virtual machine, an administrator loaded this file. The service started. The running image is the file identified above: SHA-256 0b57569aaa0f4789d9642dd2189b0a82466b80ad32ff35f88127210ed105fe57, 15672 bytes. On that machine the Authenticode status was Valid. The device security descriptor was:

O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW)

Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA. Local account aida-low belongs to Users and is not in Administrators. That account opened \\.\atlAccess and sent IOCTL 0x7B592418. The administrator locked one of its own pages, resolved that page, and watched the first byte. The administrator did not send the IOCTL.

Map result:
On 2026-11-02 the administrator held physical address 0x3e095000. aida-low sent IOCTL 0x7B592418 for that address and wrote 0x5A, then 0xA5, through the mapping returned to its process. Its result showed administrators_sid=absent, marker=0x5a map=0x5a, marker=0xa5 map=0xa5, and IOCTL PASS. The administrator's result showed saw page=0x5a and saw page=0xa5. The test did not show a crash.

Other reports:
CVE-2021-43975 describes the Linux atlantic NIC driver. It does not describe this Windows atlAccess.sys image or IOCTL 0x7B592418. A search of the 2026-11-02 CVE list found no atlAccess.sys and no IOCTL 0x7B592418. This note identifies the tested file by the hashes above.

Suggested fix: on this IOCTL, map only a physical address chosen inside the driver, and limit access to \\.\atlAccess to Administrators and SYSTEM.
