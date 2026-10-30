#include "textflag.h"

TEXT ·burstBarrier(SB), NOSPLIT, $0-0
	MFENCE
	RET
