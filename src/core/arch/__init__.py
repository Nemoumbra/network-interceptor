
from src.consts import WINDOWS, LINUX

if WINDOWS:
    from src.core.arch.windows.wd_interceptor import WinDivertInterceptor
    Interceptor = WinDivertInterceptor

if LINUX:
    from src.core.arch.linux.nfq_interceptor import NFQueueInterceptor
    Interceptor = NFQueueInterceptor
