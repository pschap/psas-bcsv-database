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
    parser.add_argument('-n', '--endianness', type=str, required=False, default='big', choices=['little', 'big'], help='big for PS3, little for PSVita')
    parser.add_argument('-r', '--raw', action='store_true', required=False, help='whether to import values from a raw-exported CSV')

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

def val_to_bytes(val, dt, endianness):
    """
    Parses an attribute value in a CSV and returns 
    its corresponding little-endian byte representation.

    :param val: attribute value
    :param dt: attribute datatype
    :return: little endian value byte string
    """

    if dt == 'int':
        val = int(val)
        return val.to_bytes(4, byteorder=endianness)
    elif dt == 'float':
        val = float(val)
        fmt = '>f' if endianness == 'big' else '<f'
        return struct.pack(fmt, val)
    elif dt == 'magic':
        val = int(val, 16)
        return val.to_bytes(4, byteorder=endianness)

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
    if dt == 'string':
        return 3
    if dt == 'magic':
        return 4
    
    return -1

def import_csv_to_bcsv(bcsv, csv_file, encyclopedia, endianness, raw=False):
    """
    Reads a CSV file and imports it to a BCSV file.

    :param bcsv: path to write BCSV
    :param csv: csv file to export
    :param encyclopedia: BCSV encyclopedia
    """

    with open(csv_file, 'r', encoding='utf-8', newline='') as f:
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
    # Parse from encyclopedia
    hashes = []
    column_info = []
    if not raw:
        basename = os.path.basename(bcsv)
        hashes = encyclopedia[basename]['hashes']
        for attr in hashes:
            info = {}
            info['hash'] = attr['hash']
            info['datatype'] = attr['datatype']

            if attr['name'] in header:
                idx = header.index(attr['name'])
            else:
                idx = header.index(attr['alias'])
                
            info['values'] = []
            for row in rows:
                info['values'].append(row[idx])

            column_info.append(info)
    else:
        # If it's a raw exported CSV we need to parse the hashes and datatypes from the header
        for col in header:
            hash_str, dt_str = col.split(' ')
            hash_str = hash_str.strip()
            dt_str = dt_str.strip('()')

            attr = {}
            attr['hash'] = hash_str
            attr['datatype'] = dt_str

            idx = header.index(col)
            attr['values'] = []
            for row in rows:
                attr['values'].append(row[idx])

            hashes.append(attr)
            column_info.append(attr)

    # Write the BCSV file
    with open(bcsv, 'wb') as f:
        # Write header
        magic = MAGIC.to_bytes(4, byteorder=endianness)
        f.write(magic)

        # Calculate the total BCSV size (excluding string data)
        size = 4 + 2 + 2 + len(hashes)*8 + len(rows)*4*len(hashes)
        written_bytes = 0
        offset = size
        strings = []

        columns = len(header).to_bytes(2, byteorder=endianness)
        rows = len(rows).to_bytes(2, byteorder=endianness)
        f.write(columns)
        f.write(rows)
        written_bytes += 8

        # Write all hashes
        for attr in hashes:
            attr_hash = int(attr['hash'], 16)
            dt = enumerate_datatype(attr['datatype'])

            hash_bytes = attr_hash.to_bytes(4, byteorder=endianness)
            dt_bytes = dt.to_bytes(4, byteorder=endianness)
            f.write(hash_bytes)
            f.write(dt_bytes)
            written_bytes += 8

        # Write attribute values
        for attr in column_info:
            for val in attr['values']:
                if attr['datatype'] != 'string':
                    val_bytes = val_to_bytes(val, attr['datatype'], endianness)
                    f.write(val_bytes)
                    written_bytes += 4
                else:
                    str_offset = offset - written_bytes
                    str_offset = str_offset.to_bytes(4, byteorder=endianness)
                    f.write(str_offset)
                    encoded_val = val.encode('utf-8')
                    strings.append(encoded_val + b'\x00')
                    offset += len(encoded_val) + 1
                    written_bytes += 4

        # Write strings
        for s in strings:
            f.write(s)

        # The PS3 version uses a 1024 byte padding at the end of a BCSV file, maybe used for memory alignment.
        # Did not test omitting it, but we will add it for safety, it seems consistent across all BCSV files.
        # It's not present in the PS Vita version.
        if endianness == 'big':
            f.write(b'\x00' * 1024)

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
    with open(encyclopedia_file, encoding='utf-8') as f:
        encyclopedia = json.load(f)

    # Create output directory if it does not exist
    if not os.path.exists(output):
        os.makedirs(output)

    # Import CSV to BCSV
    basename = os.path.basename(csv_file)
    filename = os.path.splitext(basename)[0]
    bcsv_file = os.path.join(output, filename + '.bcsv')
    import_csv_to_bcsv(bcsv_file, csv_file, encyclopedia, args.endianness, args.raw)

if __name__ == '__main__':
    main()
