#include "textflag.h"

TEXT ·burstBarrier(SB), NOSPLIT, $0-0
	DMB $0xb
	RET
