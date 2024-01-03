# Find all cross references to the function "HashBcsvAttribute"
# (function at address 0x810317a2 in patch eboot.bin) and write 
# call arguments to a JSON file.
# @ps_chap 
# @category Vita/PSAS/BCSV

import os
import json

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# ============================================
#                   GLOBALS
# ============================================

# Maintain a mapping of which functions read which BCSV files.
# Map is in the form of function entry point address -> BCSV file.
FUNC_2_BCSV = {
    0x812728e8: 'gameattributes.bcsv'
}

# Maintain a mapping of where to save hashes for a particular BCSV file
BCSV_2_JSON = {
    'gameattributes.bcsv': 'gameattributes.json'
}

# Encyclopedia name
ENCYCLOPEDIA = 'encyclopedia.json'

# Name of BCSV Hashing Function
HASHING_FUNC = 'HashBcsvAttribute'

# ============================================
#                HELPER FUNCTIONS
# ============================================

def game_attribute_hash(attribute, key):
    """
    Hash BCSV file attribute name as in function 0x810317a2
    (renamed HashBcsvAttribute) from the patch eboot.bin

    :param attribute: the attribute name
    :param key: hashing key
    :return: hashed attribute name
    """

    # Constant used for hashing
    magic = 0x1000193

    # Mask used to ensure returned key is a 32-bit integer
    mask = 0xffffffff

    if attribute == None:
        return 0

    for c in attribute:
        key = ((key ^ ord(c)) * magic) & mask

    return key

def get_string(addr):
    """
    Read a null-terminated string from memory at 
    the specified address.

    :param addr: the address of the string
    :return: null-terminated string at the specified address
    """

    if type(addr) == int:
        addr = toAddr(addr)

    mem = currentProgram.getMemory()
    core_name_str = ''

    while True:
        byte = mem.getByte(addr.add(len(core_name_str)))
        if byte == 0:
            return core_name_str
        core_name_str += chr(byte)

def parse_hash_call_args(addr):
    """
    Decompile and retrieve PCode pertaining to the 
    hashing function call at the specified address. 
    Using the PCode, parse the arguments passed to 
    the function.

    :param addr: address of the function reference
    :return: tuple containing function call arguments
    """

    if type(addr) == int:
        addr = toAddr(addr)

    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()

    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    # Parse call arguments using PCode
    func = getFunctionContaining(addr)
    res = ifc.decompileFunction(func, 60, monitor)
    high_func = res.getHighFunction()
    pcodeops = high_func.getPcodeOps(addr)
    op = pcodeops.next()
    args = op.getInputs()[1:]

    # Process first input (string)
    attribute = None
    if args[0].isUnique():
        attr_def = args[0].getDef()
        attr_addr = toAddr(attr_def.getInput(0).getOffset())
        attribute = get_string(attr_addr)
    
    # Process second input (key/integer)
    key = args[1].getOffset()

    return attribute, key

def build_bcsv_encyclopedia():
    """
    Builds a dictionary containing automatically generated 
    documentation on each column for each BCSV file used by 
    PSASBR.

    :return: bcsv encyclopedia
    """

    # Call arguments
    encyclopedia = {}

    # Find all XRefs to HASHING_FUNC
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    for func in funcs:
        if func.getName() == HASHING_FUNC:
            entry_point = func.getEntryPoint()
            references = getReferencesTo(entry_point)

            # Iterate over all references and create an encyclopedia entry for each
            for xref in references:
                addr = xref.getFromAddress()
                calling_func = fm.getFunctionContaining(addr)
                if calling_func is None:
                    continue

                calling_entry = calling_func.getEntryPoint()
                offset = calling_entry.getOffset()
                if offset in FUNC_2_BCSV:
                    bcsv = FUNC_2_BCSV[offset]
                    if bcsv not in encyclopedia:
                        # Write default info/documentation to encyclopedia entry
                        info = {}
                        info['name'] = os.path.splitext(bcsv)[0]
                        info['namedColumns'] = '0/0'
                        info['documentedColumns'] = '0/0'
                        info['description'] = None
                        info['hashes'] = []
                        encyclopedia[bcsv] = info

                    # Update hash information for attribute being hashed at xref
                    column_info = {}
                    attribute, key = parse_hash_call_args(addr)
                    attr_hash = game_attribute_hash(attribute, key)

                    column_info['hash'] = hex(attr_hash)[:-1]
                    column_info['notes'] = None
                    column_info['name'] = attribute
                    column_info['alias'] = None
                    column_info['knownFunctionality'] = False
                    column_info['datatype'] = None

                    # Update table information to reflect addition of new hash
                    encyclopedia[bcsv]['hashes'].append(column_info)
                    columns = int(encyclopedia[bcsv]['namedColumns'].split('/')[1])
                    named_columns = int(encyclopedia[bcsv]['namedColumns'].split('/')[0])
                    documented_columns = int(encyclopedia[bcsv]['documentedColumns'].split('/')[0])

                    columns += 1
                    named_columns += 1

                    encyclopedia[bcsv]['namedColumns'] = '{}/{}'.format(named_columns, columns)
                    encyclopedia[bcsv]['documentedColumns'] = '{}/{}'.format(documented_columns, columns)

    return encyclopedia

# ============================================
#                     MAIN
# ============================================

def main():
    encyclopedia = build_bcsv_encyclopedia()

    # Write encyclopedia as JSON
    with open(ENCYCLOPEDIA, 'w') as f:
        f.write(json.dumps(encyclopedia, indent=4))

if __name__ == '__main__':
    main()
