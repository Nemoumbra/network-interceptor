
from src.network_interceptor.consts import WINDOWS, LINUX

if WINDOWS:
    from src.network_interceptor.core.arch.windows.wd_interceptor import WinDivertInterceptor
    Interceptor = WinDivertInterceptor

if LINUX:
    from src.network_interceptor.core.arch.linux.nfq_interceptor import NFQueueInterceptor
    Interceptor = NFQueueInterceptor
