identifyexecutorscript = """
getgenv().identifyexecutor = function()
return "Synapse X Revive", "v1.0"
end
"""

print("CONSOLE:")
print("Loading..")
import pyperclip
from win10toast import ToastNotifier 
from tkinter import filedialog, messagebox
import sys
import os
import re
import ctypes
import random
import string
import pymem
import time
from datetime import datetime
import json
import psutil
import threading
import requests
import subprocess
import webview
import os
import time
import subprocess
import socket
import re
from urllib.request import urlopen 
import ssl  # this part is not recommended, however it's the only fix I could find.
from ctypes import windll
from ctypes import c_int
from ctypes import c_uint
from ctypes import c_ulong
from ctypes import POINTER
from ctypes import byref
def check_if_process_running(process_name):
    for process in psutil.process_iter(['name']):
        if process.info['name'] == process_name:
            return True
    return False
n = ToastNotifier() 
  

def sendNotif(text, dur):
    n.show_toast("Synapse X Revive", text, duration = dur)
if not check_if_process_running("RobloxPlayerBeta.exe"):
    sendNotif("Please Open Roblox!", 3)
    exit()
if check_if_process_running("RobloxCrashHandler.exe"):
 os.system('taskkill /f /im RobloxCrashHandler.exe')
 print("Ended Crash Handler")
LightingScript = "496E6A656374????????????????????06"
RobloxPlayer = ["RobloxPlayerBeta.exe", "Windows10Universal.exe", "RobloxCrashHandler.exe"]
SpoofName = False
target = False
Injecting = False
Injected = False
NameOffset = 0x48
ChildrenOffset = 0x50
ParentOffset = 0x60
ctypes.windll.kernel32.SetConsoleTitleW("Synapse X Revive CONSOLE")
DataModelMethods = ["RenderView", "GuiRoot"]
LocalDebuggers = ["x64dbg.exe", "RobloxCrashHandler.exe", "ida64.exe", "wireshark.exe", "ollydbg.exe", "windbg.exe", "gdb.exe", "immunitydebugger.exe", "radare2.exe", "cheatengine.exe", "devenv.exe", "procmon.exe", "procexp.exe", "hxd.exe", "tcpview.exe", "apimonitor.exe", "sandboxie.exe", "sysinternalsuite.exe", "reshacker.exe", "resourcehacker.exe", "peid.exe", "x32dbg.exe", "ghidra.exe", "lordpe.exe", "pestudio.exe", "dnspy.exe", "binaryninja.exe", "exescope.exe", "scylla.exe", "reclass.exe", "tracerpt.exe", "fiddler.exe", "charles.exe", "httprequester.exe", "appverif.exe", "malwarebytes.exe", "glasswire.exe", "debugview.exe", "hijackthis.exe", "regmon.exe"]
for debugger in LocalDebuggers:
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'].lower() == debugger.lower():
                proc.terminate()
                proc.wait(timeout=3)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def GetNameAddress(Instance: int) -> int:
           try:
                ExpectedAddress = InjectorClass.DRP(Instance + NameOffset, True)
                return ExpectedAddress
           except TypeError as e:
                exit() 
def GetName(Instance: int) -> str:
        ExpectedAddress = GetNameAddress(Instance)
        return ReadRobloxString(ExpectedAddress)
def GetChildren(Instance: int) -> str:
        ChildrenInstance = []
        InstanceAddress = Instance
        if not InstanceAddress:
            return False
        ChildrenStart = InjectorClass.DRP(InstanceAddress + ChildrenOffset, True)
        if ChildrenStart == 0:
            return []
        ChildrenEnd = InjectorClass.DRP(ChildrenStart + 8, True)
        OffsetAddressPerChild = 0x10
        CurrentChildAddress = InjectorClass.DRP(ChildrenStart, True)
        try:
            for i in range(0, 9000):
                if i == 8999:
                    raise ValueError("[X]: 208")
                    
                if CurrentChildAddress == ChildrenEnd:
                    break
                ChildrenInstance.append(InjectorClass.Pymem.read_longlong(CurrentChildAddress))
                CurrentChildAddress += OffsetAddressPerChild
            return ChildrenInstance
        except ValueError as e:
            exit()
def GetParent(Instance: int) -> int:
        return InjectorClass.DRP(Instance + ParentOffset, True)
def FindFirstChild(Instance: int, ChildName: str) -> int:
        ChildrenOfInstance = GetChildren(Instance)
        for i in ChildrenOfInstance:
            if GetName(i) == ChildName:
                return i
def FindFirstChildOfClass(Instance: int, ClassName: str) -> int:
        ChildrenOfInstance = GetChildren(Instance)
        for i in ChildrenOfInstance:
            if GetClassName(i) == ClassName:
                return i
def GetDescendants(Instance: int) -> list:
        descendants = []
        def _get_descendants_recursive(current_instance: int):
            children = GetChildren(current_instance)
            descendants.extend(children)
            for child in children:
                _get_descendants_recursive(child)
        _get_descendants_recursive(Instance)
        return descendants
class toInstance:
        def __init__(self, address: int = 0):
            self.Address = address
            self.Self = address
            self.Name = GetName(address)
            self.ClassName = GetClassName(address)
            self.Parent = GetParent(address)
        def getChildren(self):
            return GetChildren(self.Address)
        def findFirstChild(self, ChildName):
            return FindFirstChild(self.Address, ChildName)
        def findFirstClass(self, ChildClass):
            return FindFirstChildOfClass(self.Address, ChildClass)
        def setParent(self, Parent):
            setParent(self.Address, Parent)
        def GetChildren(self):
            return GetChildren(self.Address)
        def GetDescendants(self):
            return GetDescendants(self.Address)
        def FindFirstChild(self, ChildName):
            return FindFirstChild(self.Address, ChildName)
        def FindFirstClass(self, ChildClass):
            return FindFirstChildOfClass(self.Address, ChildClass)
        def SetParent(self, Parent):
            setParent(self.Address, Parent, ParentOffset, ChildrenOffset)
class InjectorClass:
    def __init__(self, program_name):
        self.program_name = program_name

    def SimpleGetProcesses(self):
        return [proc.name() for proc in psutil.process_iter(["name"])]

    def SetParent(self, Instance, Parent, parentOffset):
        InjectorClass.Pymem.write_longlong(Instance + parentOffset, Parent)

    def __init__(self, ProgramName=None):
        self.ProgramName = ProgramName
        self.Pymem = pymem.Pymem()
        self.Addresses = {}
        self.Handle = None
        self.is64bit = True
        self.ProcessID = None
        self.PID = self.ProcessID
        if type(ProgramName) == str:
            self.Pymem = pymem.Pymem(ProgramName)
            self.Handle = self.Pymem.process_handle
            self.is64bit = pymem.process.is_64_bit(self.Handle)
            self.ProcessID = self.Pymem.process_id
            self.PID = self.ProcessID
        elif type(ProgramName) == int:
            self.Pymem.open_process_from_id(ProgramName)
            self.Handle = self.Pymem.process_handle
            self.is64bit = pymem.process.is_64_bit(self.Handle)
            self.ProcessID = self.Pymem.process_id
            self.PID = self.ProcessID  

    def h2d(self, hz: str, bit: int = 16) -> int:
        if type(hz) == int:
            return hz
        return int(hz, bit)

    def d2h(self, dc: int, UseAuto=None) -> str:
        if type(dc) == str:
            return dc
        if UseAuto:
            if UseAuto == 32:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
        else:
            if abs(dc) > 4294967295:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
        if len(dc) > 8:
            while len(dc) < 16:
                dc = "0" + dc
        if len(dc) < 8:
            while len(dc) < 8:
                dc = "0" + dc
        return dc

    def PLAT(self, aob: str):
        if type(aob) == bytes:
            return aob
        trueB = bytearray(b"")
        aob = aob.replace(" ", "")
        PLATlist = []
        for i in range(0, len(aob), 2):
            PLATlist.append(aob[i : i + 2])
        for i in PLATlist:
            if "?" in i:
                trueB.extend(b".")
            if "?" not in i:
                trueB.extend(re.escape(bytes.fromhex(i)))
        return bytes(trueB)

    def AOBSCANALL(self, AOB_HexArray, xreturn_multiple=False):
        try:
            InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(
                0x1F0FFF,
                False, 
                InjectorClass.Pymem.process_id,
            )
            PAGE_EXECUTE_READWRITE = 0x40
            ntdll = ctypes.windll.ntdll
            NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
            NtProtectVirtualMemory.restype = ctypes.c_long
            base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
            old_protect = ctypes.c_ulong()
            size = ctypes.c_size_t(0x1000)
            NtProtectVirtualMemory(
                InjectorClass.Pymem.process_handle,
                ctypes.byref(ctypes.c_void_p(base_address)),
                ctypes.byref(size),
                PAGE_EXECUTE_READWRITE,
                ctypes.byref(old_protect),
            )
            base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
            NtProtectVirtualMemory(
                InjectorClass.Pymem.process_handle,
                ctypes.byref(ctypes.c_void_p(base_address)),
                ctypes.byref(size),
                old_protect,
                ctypes.byref(ctypes.c_ulong()),
            )
            return pymem.pattern.pattern_scan_all(
                self.Pymem.process_handle,
                self.PLAT(AOB_HexArray),
                return_multiple=xreturn_multiple,
            )
        except Exception as e:
            try:
                InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(
                    0x1F0FFF,
                    False, 
                    InjectorClass.Pymem.process_id,
                )
                PAGE_EXECUTE_READWRITE = 0x40
                ntdll = ctypes.windll.ntdll
                NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
                NtProtectVirtualMemory.restype = ctypes.c_long
                base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
                old_protect = ctypes.c_ulong()
                size = ctypes.c_size_t(0x1000)
                NtProtectVirtualMemory(
                    InjectorClass.Pymem.process_handle,
                    ctypes.byref(ctypes.c_void_p(base_address)),
                    ctypes.byref(size),
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect),
                )
                base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
                NtProtectVirtualMemory(
                    InjectorClass.Pymem.process_handle,
                    ctypes.byref(ctypes.c_void_p(base_address)),
                    ctypes.byref(size),
                    old_protect,
                    ctypes.byref(ctypes.c_ulong()),
                )
                return pymem.pattern.pattern_scan_all(
                    self.Pymem.process_handle,
                    self.PLAT(AOB_HexArray),
                    return_multiple=xreturn_multiple,
                )
            except WindowsError as we:
                if we.winerror == 5:
                    InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(
                        0x1F0FFF,
                        False,
                        InjectorClass.Pymem.process_id,
                    )
                PAGE_EXECUTE_READWRITE = 0x40
                ntdll = ctypes.windll.ntdll
                NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
                NtProtectVirtualMemory.restype = ctypes.c_long
                base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
                old_protect = ctypes.c_ulong()
                size = ctypes.c_size_t(0x1000)
                NtProtectVirtualMemory(
                    InjectorClass.Pymem.process_handle,
                    ctypes.byref(ctypes.c_void_p(base_address)),
                    ctypes.byref(size),
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect),
                )
                base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
                NtProtectVirtualMemory(
                    InjectorClass.Pymem.process_handle,
                    ctypes.byref(ctypes.c_void_p(base_address)),
                    ctypes.byref(size),
                    old_protect,
                    ctypes.byref(ctypes.c_ulong()),
                )
                return pymem.pattern.pattern_scan_all(
                    self.Pymem.process_handle,
                    self.PLAT(AOB_HexArray),
                    return_multiple=xreturn_multiple,
                )
            except Exception as e:
                pass
    def gethexc(self, hex: str):
        hex = hex.replace(" ", "")
        hxlist = []
        for i in range(0, len(hex), 2):
            hxlist.append(hex[i : i + 2])
        return len(hxlist)

    def hex2le(self, hex: str):
        lehex = hex.replace(" ", "")
        lelist = []
        if len(lehex) > 8:
            while len(lehex) < 16:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)
        if len(lehex) < 9:
            while len(lehex) < 8:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)
    def calcjmpop(self, des, cur):
        jmpopc = (self.h2d(des) - self.h2d(cur)) - 5
        jmpopc = hex(jmpopc & (2**32 - 1)).replace("0x", "")
        if len(jmpopc) % 2 != 0:
            jmpopc = "0" + str(jmpopc)
        return jmpopc
    def isProgramGameActive(self):
        try:
            self.Pymem.read_char(self.Pymem.base_address)
            return True
        except:
            return False
    def DRP(self, Address: int, is64Bit: bool = None) -> int:
        Address = Address
        if type(Address) == str:
            Address = self.h2d(Address)
        if is64Bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        if self.is64bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        return int.from_bytes(self.Pymem.read_bytes(Address, 4), "little")
    def isValidPointer(self, Address: int, is64Bit: bool = None) -> bool:
        try:
            if type(Address) == str:
                Address = self.h2d(Address)
            self.Pymem.read_bytes(self.DRP(Address, is64Bit), 1)
            return True
        except:
            return False
    def GetModules(self) -> list:
        return list(self.Pymem.list_modules())
    def getAddressFromName(self, Address: str) -> int:
        if type(Address) == int:
            return Address
        AddressBase = 0
        AddressOffset = 0
        for i in self.GetModules():
            if i.name in Address:
                AddressBase = i.lpBaseOfDll
                AddressOffset = self.h2d(Address.replace(i.name + "+", ""))
                AddressNamed = AddressBase + AddressOffset
                return AddressNamed
            exit() 
        return Address
    def getNameFromAddress(self, Address: int) -> str:
        memoryInfo = pymem.memory.virtual_query(self.Pymem.process_handle, Address)
        BaseAddress = memoryInfo.BaseAddress
        NameOfDLL = ""
        AddressOffset = 0
        for i in self.GetModules():
            if i.lpBaseOfDll == BaseAddress:
                NameOfDLL = i.name
                AddressOffset = Address - BaseAddress
                break
        if NameOfDLL == "":
            return Address
        NameOfAddress = NameOfDLL + "+" + self.d2h(AddressOffset)
        return NameOfAddress
    def getRawProcesses(self):
        toreturn = []
        for i in pymem.process.list_processes():
            toreturn.append(
                [
                    i.cntThreads,
                    i.cntUsage,
                    i.dwFlags,
                    i.dwSize,
                    i.pcPriClassBase,
                    i.szExeFile,
                    i.th32DefaultHeapID,
                    i.th32ModuleID,
                    i.th32ParentProcessID,
                    i.th32ProcessID,
                ]
            )
        return toreturn
    def SimpleGetProcesses(self):
        toreturn = []
        for i in self.getRawProcesses():
            toreturn.append({"Name": i[5].decode(), "Threads": i[0], "ProcessId": i[9]})
        return toreturn
    def YieldForProgram(self, programName, AutoOpen: bool = False, Limit=1):
        Count = 0
        while True:
            if Count >= Limit:
                return False
            ProcessesList = self.SimpleGetProcesses()
            for i in ProcessesList:
                if i["Name"] == programName:

                    if AutoOpen:
                        self.Pymem.open_process_from_id(i["ProcessId"])
                        self.ProgramName = programName
                        self.Handle = self.Pymem.process_handle
                        self.is64bit = pymem.process.is_64_bit(self.Handle)
                        self.ProcessID = self.Pymem.process_id
                        self.PID = self.ProcessID
                    return True
            time.sleep(1)
            Count += 1
    def ReadPointer(
        self, BaseAddress: int, Offsets_L2R: list, is64Bit: bool = None
    ) -> int:
        x = self.DRP(BaseAddress, is64Bit)
        y = Offsets_L2R
        z = x
        if y == None or len(y) == 0:
            return z
        count = 0
        for i in y:
            try:
                print(self.d2h(x + i))
                print(self.d2h(i))
                z = self.DRP(z + i, is64Bit)
                count += 1
                print(self.d2h(z))
            except:
                print("[X]: 208")
                exit()  

            return z
        return z
    def GetMemoryInfo(self, Address: int, Handle: int = None):
        if Handle:
            return pymem.memory.virtual_query(Handle, Address)
        else:
            return pymem.memory.virtual_query(self.Handle, Address)
    def MemoryInfoToDictionary(self, MemoryInfo):
        return {
            "BaseAddress": MemoryInfo.BaseAddress,
            "AllocationBase": MemoryInfo.AllocationBase,
            "AllocationProtect": MemoryInfo.AllocationProtect,
            "RegionSize": MemoryInfo.RegionSize,
            "State": MemoryInfo.State,
            "Protect": MemoryInfo.Protect,
            "Type": MemoryInfo.Type,
        }
    def SetProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        pymem.ressources.kernel32.VirtualProtectEx(
            self.Pymem.process_handle,
            Address,
            Size,
            ProtectionType,
            ctypes.byref(OldProtect),
        )
        return OldProtect
    def ChangeProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        return self.SetProtection(Address, ProtectionType, Size, OldProtect)

    def GetProtection(self, Address: int):
        return self.GetMemoryInfo(Address).Protect
    def KnowProtection(self, Protection):
        if Protection == 0x10:
            return "PAGE_EXECUTE"
        if Protection == 0x20:
            return "PAGE_EXECUTE_READ"
        if Protection == 0x40:
            return "PAGE_EXECUTE_READWRITE"
        if Protection == 0x80:
            return "PAGE_EXECUTE_WRITECOPY"
        if Protection == 0x01:
            return "PAGE_NOACCESS"
        if Protection == 0x02:
            return "PAGE_READONLY"
        if Protection == 0x04:
            return "PAGE_READWRITE"
        if Protection == 0x08:
            return "PAGE_WRITECOPY"
        if Protection == 0x100:
            return "PAGE_GUARD"
        if Protection == 0x200:
            return "PAGE_NOCACHE"
        if Protection == 0x400:
            return "PAGE_WRITECOMBINE"
        if Protection in ["PAGE_EXECUTE", "execute", "e"]:
            return 0x10
        if Protection in [
            "PAGE_EXECUTE_READ",
            "execute read",
            "read execute",
            "execute_read",
            "read_execute",
            "er",
            "re",
        ]:
            return 0x20
        if Protection in [
            "PAGE_EXECUTE_READWRITE",
            "execute read write",
            "execute write read",
            "write execute read",
            "write read execute",
            "read write execute",
            "read execute write",
            "erw",
            "ewr",
            "wre",
            "wer",
            "rew",
            "rwe",
        ]:
            return 0x40
        if Protection in [
            "PAGE_EXECUTE_WRITECOPY",
            "execute copy write",
            "execute write copy",
            "write execute copy",
            "write copy execute",
            "copy write execute",
            "copy execute write",
            "ecw",
            "ewc",
            "wce",
            "wec",
            "cew",
            "cwe",
        ]:
            return 0x80
        if Protection in ["PAGE_NOACCESS", "noaccess", "na", "n"]:
            return 0x01
        if Protection in ["PAGE_READONLY", "readonly", "ro", "r"]:
            return 0x02
        if Protection in ["PAGE_READWRITE", "read write", "write read", "wr", "rw"]:
            return 0x04
        if Protection in ["PAGE_WRITECOPY", "write copy", "copy write", "wc", "cw"]:
            return 0x08
        if Protection in ["PAGE_GUARD", "pg", "guard", "g"]:
            return 0x100
        if Protection in ["PAGE_NOCACHE", "nc", "nocache"]:
            return 0x200
        if Protection in ["PAGE_WRITECOMBINE", "write combine", "combine write"]:
            return 0x400
        return Protection
    def Suspend(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcess(pid)
        if self.PID:
            kernel32.DebugActiveProcess(self.PID)
    def Resume(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcessStop(pid)
        if self.PID:
            kernel32.DebugActiveProcessStop(self.PID)
InjectorClass = InjectorClass()
def ReadRobloxValue(ExpectedAddress: int, ExpectedLength: int = 1024) -> str:
    StringCount = InjectorClass.Pymem.read_int(ExpectedAddress + 0x10)
    length = (StringCount > 0 and StringCount < 16384) and StringCount or ExpectedLength
    return InjectorClass.Pymem.read_string(ExpectedAddress, length)

def ReadRobloxString(ExpectedAddress: int) -> str:
        try:
            StringCount = InjectorClass.Pymem.read_int(ExpectedAddress + 0x10)
            if StringCount > 15:
                return InjectorClass.Pymem.read_string(InjectorClass.DRP(ExpectedAddress), StringCount)
            return InjectorClass.Pymem.read_string(ExpectedAddress, StringCount)
        except TypeError as e:
            exit()
def GetClassName(Instance: int) -> str:
    ExpectedAddress = InjectorClass.DRP(InjectorClass.DRP(Instance + 0x18) + 8)
    return ReadRobloxString(ExpectedAddress)
def setParent(Instance, Parent, parentOffset, childrenOffset):
    InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(
                    0x1F0FFF,
                    False,
                    InjectorClass.Pymem.process_id,
                )
    PAGE_EXECUTE_READWRITE = 0x40
    ntdll = ctypes.windll.ntdll
    NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
    NtProtectVirtualMemory.restype = ctypes.c_long
    base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
    old_protect = ctypes.c_ulong()
    size = ctypes.c_size_t(0x1000)
    NtProtectVirtualMemory(
        InjectorClass.Pymem.process_handle,
        ctypes.byref(ctypes.c_void_p(base_address)),
        ctypes.byref(size),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect),
    )
    base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
    NtProtectVirtualMemory(
                    InjectorClass.Pymem.process_handle,
                    ctypes.byref(ctypes.c_void_p(base_address)),
                    ctypes.byref(size),
                    old_protect,
                    ctypes.byref(ctypes.c_ulong()),
    )
    InjectorClass.Pymem.write_longlong(Instance + parentOffset, Parent)
    newChildren = InjectorClass.Pymem.allocate(0x400)
    InjectorClass.Pymem.write_longlong(newChildren + 0, newChildren + 0x40)
    ptr = InjectorClass.Pymem.read_longlong(Parent + childrenOffset)
    childrenStart = InjectorClass.Pymem.read_longlong(ptr)
    childrenEnd = InjectorClass.Pymem.read_longlong(ptr + 8)
    if childrenStart == 0 or childrenEnd == 0 or childrenEnd <= childrenStart:
        exit()
    length = childrenEnd - childrenStart
    if length < 0:
        exit()
    b = InjectorClass.Pymem.read_bytes(childrenStart, length)
    InjectorClass.Pymem.write_bytes(newChildren + 0x40, b, len(b))
    e = newChildren + 0x40 + length
    InjectorClass.Pymem.write_longlong(e, Instance)
    InjectorClass.Pymem.write_longlong(e + 8, InjectorClass.Pymem.read_longlong(Instance + 0x10))
    e = e + 0x10
    InjectorClass.Pymem.write_longlong(newChildren + 0x8, e)
    InjectorClass.Pymem.write_longlong(newChildren + 0x10, e)
    
def GetViewRegex(folderPath, latestFile):
    filePath = folderPath + "\\" + latestFile
    regexPattern = re.compile(r"view\((\w+)\)")
    try:
        with open(filePath, "r", encoding="utf-8") as fileStream:
            for line in fileStream:
                match = regexPattern.search(line)
                if match:
                    newAddress = int(match.group(1), 16)
                    return newAddress
    except IOError:
        print(f"Failed to open file: {filePath}")
        return 0

def readQword(process, address, value):
    try:
        value.value = process.read_ulonglong(address)
        return True
    except pymem.exception.MemoryReadError:
       
            exit()
            
def GetMethodModel():
    guiroot_pattern = b"\\x47\\x75\\x69\\x52\\x6F\\x6F\\x74\\x00\\x47\\x75\\x69\\x49\\x74\\x65\\x6D"
    guiroot_address = InjectorClass.AOBSCANALL(guiroot_pattern, xreturn_multiple=False)
    dataModel = InjectorClass.DRP(guiroot_address + 0x38) + 0x198 - 0x8
    if(dataModel):
        return dataModel
    else:
        return None

def GetLatestFile(folderPath, file_filter=None):
    try:
        files = [
            f
            for f in os.listdir(folderPath)
            if os.path.isfile(os.path.join(folderPath, f))
        ]
        if file_filter:
            files = [f for f in files if file_filter in f]
        latest_file = max(
            files, key=lambda f: os.path.getmtime(os.path.join(folderPath, f))
        )
        return latest_file
    except Exception as e:
        print("Error:", e)
        return None

def GetDataModel():
    localAppData = os.environ.get("LOCALAPPDATA")
    if localAppData:
        folderPath = os.path.join(os.getenv("LOCALAPPDATA"), "Roblox", "logs")
        latestFile = GetLatestFile(folderPath, "Player")
        process = pymem.Pymem("RobloxPlayerBeta.exe")
        RenderView = GetViewRegex(folderPath, latestFile)
        if RenderView:
            RandomAssShitlmao = ctypes.c_ulonglong(0)
            readQword(process, RenderView + 0x118, RandomAssShitlmao)
            DataModel = ctypes.c_ulonglong(0)
            if readQword(process, RandomAssShitlmao.value + 0x198, DataModel):
                game = DataModel.value
                return game
            else:
                return None
def ClearDetection():
    for proc in psutil.process_iter():
            if proc.name() == RobloxPlayer[2]:
                proc.terminate()
    for file in os.listdir(f"C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs"):
            try:
                os.remove(f"C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs/" + file)
            except:
                pass
def execute(e):
    if not Injected:
        sendNotif("Not Injected!", 3)
    else:
        ClearDetection()
        ExecuteCode(e)
        
def inject():
    global Injecting, Injected
    if not Injecting or Injected:
        print("[-]: Starting Injection...")
        Injecting = True
        SpoofName = True
        InjectScript = False
        TargetScript = False
        print("[-]: Waiting For Target")
        while True:
          if InjectorClass.YieldForProgram(RobloxPlayer[0], True, 15):
              target = RobloxPlayer[0]
              break
        print("if it takes a while pls clear up the logs folder\n Location:", os.path.join(os.getenv("LOCALAPPDATA"), "Roblox", "logs"))
        try:
            DataModel = GetDataModel()
            print(f"[-]: Found DataModel: {DataModel}")
        except Exception as e:
            print(e)
            print(f"[-]: Failed using: {DataModelMethods[0]}, Trying {DataModelMethods[1]}.")
            try:
               DataModel = GetMethodModel()
            except Exception as e:
               print(f"[-]: Failed To Inject")
               messagebox.showinfo("Synapse X Revive", "Failed to Attach, please re-attach.")
               Injecting = False
               Injected = False
        print("[-]: Beginning Next Stage...")
        global game
        game = toInstance(DataModel)
        players = toInstance(game.FindFirstChild("Players"))
        localPlayer = toInstance(players.GetChildren()[0])
        localName = localPlayer.Name
        workspace = toInstance(game.FindFirstChild("Workspace"))
        playershit = toInstance(workspace.FindFirstChild(localName))
        humanoid = toInstance(playershit.FindFirstChild("Humanoid"))
        print(f"[-]: Found the most retarded person ever: {localName}")
        workspace = toInstance(game.GetChildren()[0])
        character_found = False
        character = toInstance(InjectorClass.Pymem.read_longlong(localPlayer.Self + 0x298))
        if character:
            character_found = True
        if not character_found:
            messagebox.showinfo("Synapse X Revive", "Failed to find character, please re-attach.")
            Injecting = False
            Injected = False
        animateScript = character.findFirstClass("LocalScript")
        if animateScript is None:
            Injected = False
            Injecting = False
            messagebox.showinfo("Synapse X Revive", "Failed to Attach, please re-attach.")
        TargetScript = toInstance(animateScript)
        InjectScript = None
        results = InjectorClass.AOBSCANALL(LightingScript, True)
        print(results)
        if results == []:
           messagebox.showwarning("Synapse X Revive", "Failed to get script! This usually happens when you dont use a teleport game")
           Injected = False
           Injecting = False
        for rn in results:
            result = rn
            bres = InjectorClass.d2h(result)
            aobs = "".join(bres[i - 1: i] for i in range(1, 17))
            aobs = InjectorClass.hex2le(aobs)
            first = False
            res = InjectorClass.AOBSCANALL(aobs, True)
            if res:
                valid = False
                for i in res:
                 result = i
                 if (
                        InjectorClass.Pymem.read_longlong(result - NameOffset + 8)
                    == result - NameOffset
                ):
                    InjectScript = result - NameOffset
                    valid = True
                    break
            if valid:
                  break
        InjectScript = toInstance(InjectScript)
        Injected = True
        Injecting = False
        ClearDetection()
        b = InjectorClass.Pymem.read_bytes(InjectScript.Self + 0x100, 0x150)
        InjectorClass.Pymem.write_bytes(TargetScript.Self + 0x100, b, len(b))
        ClearDetection()
        InjectorClass.Pymem.write_float(humanoid.Address + 0x174, 0.0)
        sendNotif("Attached Successfully!", 3)
        coreGui = toInstance(game.GetChildren()[31])
        TargetScript.SetParent(coreGui.Self)
          

def ExecuteCode(string):
    BridgeService = toInstance(game.findFirstChild("BridgeService"))
    robloxtopythonFuncs = toInstance(BridgeService.FindFirstChild("Functions"))
    StringValue = toInstance(BridgeService.findFirstChild("exe"))
    robloxReadFileReturn = toInstance(robloxtopythonFuncs.FindFirstChild("5"))
    if "setclipboard(" in string:
        setclipboard_pattern = r'setclipboard\("(.*?)", "(.*?)"\)'
        matches = re.findall(setclipboard_pattern, string)
        if matches:
            print(matches[0])
            pyperclip.copy(matches[0])
    if "writefile(" in string:
            writefile_pattern = r'writefile\("(.*?)", "(.*?)"\)'
            matches = re.findall(writefile_pattern, string)
            if matches:
                filename, file_content = matches[0]
                directory = os.path.dirname(filename)
                if not os.path.exists(directory):
                    os.makedirs(directory)
                with open(filename, "w") as file:
                    file.write(file_content)
    
    if "readfile(" in string:
            readfile_pattern = r'readfile\("(.*?)"\)'
            matches = re.findall(readfile_pattern, string)
            if matches:
                filename = matches[0]
                try:
                    with open(filename, "r") as file:
                        file_content = file.read()
                        print(file_content)
                        NewStringPtr = InjectorClass.Pymem.allocate(len(file_content))
                        InjectorClass.Pymem.write_string(NewStringPtr, file_content)
                        InjectorClass.Pymem.write_bytes(
                            robloxReadFileReturn.Self + 0xD0,
                            bytes.fromhex(InjectorClass.hex2le(InjectorClass.d2h(len(file_content)))),
                            8,
                        )
                        InjectorClass.Pymem.write_longlong(robloxReadFileReturn.Self + 0xC0, NewStringPtr)
                        stringAddress = InjectorClass.Pymem.read_longlong(
                            robloxReadFileReturn.Self + 0xC0
                        )
                        length = InjectorClass.Pymem.read_longlong(robloxReadFileReturn.Self + 0xD0)
                        raw = ReadRobloxValue(stringAddress, length)
                        NewStringPtr = InjectorClass.Pymem.allocate(len("readfile()"))
                        InjectorClass.Pymem.write_string(NewStringPtr, string)
                        InjectorClass.Pymem.write_bytes(
                            StringValue.Self + 0xD0,
                            bytes.fromhex(InjectorClass.hex2le(InjectorClass.d2h(len(string)))),
                            8,
                        )
                        InjectorClass.Pymem.write_longlong(StringValue.Self + 0xC0, NewStringPtr)
                        return
                except FileNotFoundError as e:
                    print(e)
    NewStringPtr = InjectorClass.Pymem.allocate(len(string))
    InjectorClass.Pymem.write_string(NewStringPtr, string)
    InjectorClass.Pymem.write_bytes(
            StringValue.Self + 0xD0,
            bytes.fromhex(InjectorClass.hex2le(InjectorClass.d2h(len(string)))),
            8,
        )
    InjectorClass.Pymem.write_longlong(StringValue.Self + 0xC0, NewStringPtr)



new_process_name = "Synapse X"

window = webview.create_window(
        new_process_name, 'index.html', width=750, height=420, frameless=False, on_top=True, resizable=True
    )

window.expose(inject, execute) # each function to carry over to the index.html, it can be used using the pyview api.
webview.start()

