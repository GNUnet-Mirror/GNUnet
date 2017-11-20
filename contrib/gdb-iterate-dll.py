from gdb import *

def search_dll (head, field, match, pfield):
    """
    Search in a DLL by iterates over it.

    head: name of the symbol denoting the head of the DLL
    field: the field that should be search for match
    match: the mathing value for field
    pfield: the field whose value is to be printed for matched elements; None to
      print all fields of the matched elemented
    """

    (symbol, _) = lookup_symbol (head)
    if symbol is None:
        print("Can't find symbol: " + head)
        return
    symbol_val = symbol.value()
    while symbol_val:
        symbol_val_def = symbol_val.dereference()
        field_val = symbol_val_def[field]
        if field_val.type.code == gdb.TYPE_CODE_INT:
            val = int(field_val)
            res = (match == val)
        elif (field_val.type.code == gdb.TYPE_CODE_STRING) or (field_val.type.code == gdb.TYPE_CODE_ARRAY):
            val = str (field_val)
            res = (match == val)
        elif (field_val.type.code == gdb.TYPE_CODE_TYPEDEF):
            val = str (field_val)
            res = match in val
        else:
            continue

        if res:
            if pfield is None:
                print symbol_val_def
            else:
                print(symbol_val_def[pfield])
        symbol_val = symbol_val_def["next"]

    
