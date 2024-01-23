#! /usr/bin/env python3

import os
import csv
import json
import struct
import argparse

# ============================================
#                    GLOBALS
# ============================================

# BCSV Header Bytes
MAGIC = 0x42435653

# ============================================
#                HELPER FUNCTIONS
# ============================================

def parse_args():
    """
    Parse command-line arguments.
    :return: parsed arguments bundle
    """

    parser = argparse.ArgumentParser(prog='bcsv_importer.py', description='import csv file to PSASBR bcsv')

    parser.add_argument('-e', '--encyclopedia', type=str, default='encyclopedia.json', help='bcsv encyclopedia')
    parser.add_argument('-c', '--csv', type=str, required=True, help='csv file to import')
    parser.add_argument('-o', '--output', type=str, required=False, default='imports', help='path to write imported bcsv file')

    args = parser.parse_args()
    return args

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

def val_to_bytes(val, dt):
    """
    Parses an attribute value in a CSV and returns 
    its corresponding little-endian byte representation.

    :param val: attribute value
    :param dt: attribute datatype
    :return: little endian value byte string
    """

    if dt == 'int' or dt == 'short':
        val = int(val)
        return val.to_bytes(4, byteorder='little')
    elif dt == 'float':
        val = float(val)
        return struct.pack('<f', val)

    return b'\xff\xff\xff\xff'

def enumerate_datatype(dt):
    """
    Parses an attribute datatype by returning its corresponding
    enumeration value.

    :param dt: attribute datatype
    :return: datatype enumeration
    """

    if dt == 'float':
        return 1
    if dt == 'int':
        return 2
    
    return -1

def import_csv_to_bcsv(bcsv, csv_file, encyclopedia):
    """
    Reads a CSV file and imports it to a BCSV file.

    :param bcsv: path to write BCSV
    :param csv: csv file to export
    :param encyclopedia: BCSV encyclopedia
    """

    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        i = 0

        header = None
        rows = []
        for line in reader:
            if i == 0:
                header = list(line)
            else:
                rows.append(list(line))

            i += 1

    # Store column hashes / datatypes / attributes values
    basename = os.path.basename(bcsv)
    hashes = encyclopedia[basename]['hashes']
    column_info = []
    for attr in hashes:
        info = {}
        info['hash'] = attr['hash']
        info['datatype'] = attr['datatype']

        if attr['name'] in header:
            idx = header.index(attr['name'])
        else:
            idx = header.index(attr['alias'])
            
        attr_vals = []
        for row in rows:
            attr_vals.append(row[idx])

            info['values'] = attr_vals
            column_info.append(info)

    # Write the BCSV file
    with open(bcsv, 'wb') as f:
        # Write header
        magic = MAGIC.to_bytes(4, byteorder='little')
        f.write(magic)

        columns = len(header).to_bytes(2, byteorder='little')
        rows = len(rows).to_bytes(2, byteorder='little')
        f.write(columns)
        f.write(rows)

        # Write all hashes
        for attr in hashes:
            attr_hash = int(attr['hash'], 16)
            dt = enumerate_datatype(attr['datatype'])

            hash_bytes = attr_hash.to_bytes(4, byteorder='little')
            dt_bytes = dt.to_bytes(4, byteorder='little')
            f.write(hash_bytes)
            f.write(dt_bytes)

        # Write attribute values
        for attr in column_info:
            for val in attr['values']:
                val_bytes = val_to_bytes(val, attr['datatype'])
                f.write(val_bytes)

# ============================================
#                     MAIN
# ============================================

def main():
    args = parse_args()
    csv_file = args.csv
    encyclopedia_file = args.encyclopedia
    output = args.output

    # Check validity of provided CSV file
    if not os.path.exists(csv_file) or not os.path.isfile(csv_file):
        print("ERROR: Provided CSV path does not exist. Exiting...")
        return
    elif os.path.splitext(csv_file)[1] != '.csv':
        print("ERROR: Provided path is not a CSV file. Exiting...")
        return

    # Check validity of provided encyclopedia
    if not os.path.exists(encyclopedia_file) or not os.path.isfile(encyclopedia_file):
        print("ERROR: Provided encyclopedia does not exist. Exiting...")
        return
    if os.path.splitext(encyclopedia_file)[1] != '.json':
        print("ERROR: Provided encyclopedia is not a JSON file. Exiting...")
        return

    # Open encyclopedia
    with open(encyclopedia_file) as f:
        encyclopedia = json.load(f)

    # Create output directory if it does not exist
    if not os.path.exists(output):
        os.makedirs(output)

    # Import CSV to BCSV
    basename = os.path.basename(csv_file)
    filename = os.path.splitext(basename)[0]
    bcsv_file = os.path.join(output, filename + '.bcsv')
    import_csv_to_bcsv(bcsv_file, csv_file, encyclopedia)

if __name__ == '__main__':
    main()
