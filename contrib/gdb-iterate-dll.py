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
    while symbol:
        symbol_val = symbol.value().derefence
        field_val = symbol_val[field]
        if field_val.type.code == gdb.TYPE_CODE_INT:
            val = int(field_val)
            res = (match == val)
        if (field_val.type.code == gdb.TYPE_CODE_STRING)
           or (filed_val.type.code == gdb.TYPE_CODE_ARRAY):
            val = str (field_val)
            res = (match == val)
        if (field_val.type.code == gdb.TYPE_CODE_TYPEDEF):
            val = str (field_val)
            res = match in val

        if res:
            if pfield is None:
                print symbol_val
            else:
                print symbol_val[pfield]
        symbol = symbol_val["next"]

    
