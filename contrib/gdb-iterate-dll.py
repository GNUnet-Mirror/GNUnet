from gdb import *

def iterate_dll (head, field, match, pfield):
    """
    Iterates over a DLL data structure

    head: name of the symbol denoting the head of the DLL
    field: the field that should be search for match
    match: the mathing value for field
    pfield: the field whose value is to be printed for matched elements; None to
      print all fields of the matched elemented
    """

    (symbol, _) = lookup_symbol (head)
    if symbol is None:
        print "Can't find symbol: " + head
        return    
    while not symbol:
        symbol_val = symbol.value().derefence
        if match == symbol_val[field]:
            if pfield is None:
                print symbol_val
            else:
                print symbol_val[pfield]
        symbol = symbol_val["next"]

    
