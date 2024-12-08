
from network_interceptor.consts import WINDOWS, LINUX

if WINDOWS:
    from network_interceptor.core.arch.windows.wd_interceptor import WinDivertInterceptor
    Interceptor = WinDivertInterceptor

if LINUX:
    from network_interceptor.core.arch.linux.nfq_interceptor import NFQueueInterceptor
    Interceptor = NFQueueInterceptor
