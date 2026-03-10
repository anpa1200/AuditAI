from assessment.scanners.network import NetworkScanner
from assessment.scanners.services import ServicesScanner
from assessment.scanners.os_hardening import OSHardeningScanner
from assessment.scanners.users import UsersScanner
from assessment.scanners.processes import ProcessesScanner
from assessment.scanners.filesystem import FilesystemScanner
from assessment.scanners.kernel import KernelScanner
from assessment.scanners.packages import PackagesScanner
from assessment.scanners.lynis_wrapper import LynisScanner

ALL_SCANNERS = {
    "network": NetworkScanner,
    "services": ServicesScanner,
    "os_hardening": OSHardeningScanner,
    "users": UsersScanner,
    "processes": ProcessesScanner,
    "filesystem": FilesystemScanner,
    "kernel": KernelScanner,
    "packages": PackagesScanner,
    "lynis": LynisScanner,
}
