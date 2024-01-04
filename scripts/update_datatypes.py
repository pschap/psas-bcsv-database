#! /usr/bin/env python3

import os
import json
import argparse

# ============================================
#                HELPER FUNCTIONS
# ============================================

def parse_args():
    """
    Parse command-line arguments.
    :return: parsed arguments bundle
    """

    parser = argparse.ArgumentParser(prog='update_datatypes.py', description='update bcsv encyclopedia datatypes')

    parser.add_argument('-e', '--encyclopedia', type=str, required=True, help='bcsv encyclopedia')
    parser.add_argument('-b', '--bcsv', type=str, required=True, help='name of bcsv file to retrieve datatypes from')

    args = parser.parse_args()
    return args

def parse_attribute_datatype(dt):
    """
    Parses and returns a string representing
    the datatype of an attribute in a BCSV file.

    :param dt: attribute datatype
    :return: string representation of datatype
    """

    if dt == 1:
        return 'float'
    elif dt == 2:
        return 'int'
    elif dt == 3:
        return 'short'
    elif dt == 4:
        # TODO
        return None

    return None

def update_bcsv_datatypes(bcsv, encyclopedia):
    """
    Read datatypes from a BCSV and update the corresponding
    BCSV encyclopedia entries.

    :param bcsv: the bcsv file
    :param encyclopedia: bcsv encyclopedia
    """

    datatypes = {}

    with open(bcsv, 'rb') as f:
        # Read number of columns in BCSV 
        f.seek(4)
        columns = int.from_bytes(f.read(2), byteorder='little')

        # Read datatypes from BCSV
        f.seek(8)
        for _ in range(columns):
            attr_hash = int.from_bytes(f.read(4), byteorder='little')
            dt_raw = int.from_bytes(f.read(4), byteorder='little')
            dt = parse_attribute_datatype(dt_raw)
            datatypes[hex(attr_hash)] = dt

    # Update encyclopedia entries
    bcsv = os.path.basename(bcsv)
    for attr in encyclopedia[bcsv]['hashes']:
        attr_hash = attr['hash']
        attr['datatype'] = datatypes[attr_hash]

# ============================================
#                     MAIN
# ============================================

def main():
    args = parse_args()
    bcsv = args.bcsv
    encyclopedia_file = args.encyclopedia

    # Check validity of provided BCSV file
    if not os.path.exists(bcsv) or not os.path.isfile(bcsv):
        print('ERROR: Provided BCSV path does not exist. Exiting...')
        return
    elif os.path.splitext(bcsv)[1] != '.bcsv':
        print('ERROR: Provided path is not a BCSV file. Exiting...')
        return

    # Check validity of provided encyclopedia
    if not os.path.exists(encyclopedia_file) or not os.path.isfile(encyclopedia_file):
        print('ERROR: Provided encyclopedia does not exist. Exiting...')
        return
    if not os.path.splitext(encyclopedia_file) != '.json':
        print('ERROR: Provided encyclopedia is not a JSON file. Exiting...')
        return

    # Open encyclopedia
    with open(encyclopedia_file) as f:
        encyclopedia = json.load(f)

    # Update datatypes
    if os.path.basename(bcsv) in encyclopedia:
        update_bcsv_datatypes(bcsv, encyclopedia)

    # Rewrite encyclopedia with updated datatypes
    with open(encyclopedia_file, 'w') as f:
        f.write(json.dumps(encyclopedia, indent=4))

if __name__ == '__main__':
    main()
