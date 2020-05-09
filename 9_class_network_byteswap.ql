
import cpp

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        exists(MacroInvocation m | 
        m.getMacro().getName().regexpMatch("ntoh(l|s|ll)") and 
        this = m.getExpr()
        )
    }
}

from NetworkByteSwap n
select n