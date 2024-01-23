#! /usr/bin/env python3

import os
import csv
import math
import json
import struct
import argparse

# ============================================
#                HELPER FUNCTIONS
# ============================================

def parse_args():
    """
    Parse command-line arguments.
    :return: parsed arguments bundle
    """

    parser = argparse.ArgumentParser(prog='bcsv_exporter.py', description='export PSASBR bcsv files to decoded csv')

    parser.add_argument('-e', '--encyclopedia', type=str, default='encyclopedia.json', help='bcsv encyclopedia')
    parser.add_argument('-b', '--bcsv', type=str, required=True, help='bcsv file to export')
    parser.add_argument('-o', '--output', type=str, required=False, default='exports', help='path to write exported files')

    args = parser.parse_args()
    return args

def magnitude(x):
    """
    Rounds-up a floating point value to the next whole number.
    
    :param x: the floating point value
    """

    return 0 if x == 0 else int(math.floor(math.log10(abs(x)))) + 1

def round_total_digits(x, digits=7):
    """
    Rounds a floating point value to a specified number of digits.

    :param x: the floating point value
    :param digits: number of digits to round to
    :return: rounded floating point value
    """

    return round(x, digits - magnitude(x))

def parse_val(val_bytes, dt):
    """
    Parses bytes corresponding to a attribute value for a 
    BCSV entry using its defined type in the BCSV encyclopedia.

    :param val_bytes: attribute bytes
    :param dt: attribute datatype
    :return: parsed value
    """

    if dt == 'int' or dt == 'short':
        return int.from_bytes(val_bytes, byteorder='little')
    elif dt == 'float':
        return round_total_digits(struct.unpack('<f', val_bytes)[0])

    return None

def export_bcsv_to_csv(bcsv, csv_file, encyclopedia):
    """
    Reads a BCSV file and exports it to a CSV file.

    :param bcsv: BCSV file to export
    :param csv: path to write CSV
    :param encyclopedia: BCSV encyclopedia
    """

    with open(bcsv, 'rb') as f:
        # Read number of rows and columns in BCSV
        f.seek(4)
        columns = int.from_bytes(f.read(2), byteorder='little')
        f.seek(6)
        rows = int.from_bytes(f.read(2), byteorder='little')

        # Initialize CSV header and entries
        header = ['' for _ in range(columns)]
        entries = [['' for _ in range(columns)] for _ in range(rows)]

        # For each hash/column, resolve its offset
        basename = os.path.basename(bcsv)
        hashes = encyclopedia[basename]['hashes']
        offsets = {}
        datatypes = {}

        for i in range(columns):
            f.seek(8*i + 8)
            attr_hash = hex(int.from_bytes(f.read(4), byteorder='little'))
            offsets[i] = 8 + i*rows*4 + columns*8
            for attr in hashes:
                if attr_hash == attr['hash']:
                    name = attr['name']
                    alias = attr['alias']
                    name = name if name is not None else alias
                    header[i] = name 
                    datatypes[i] = attr['datatype']
                    break

        # Read rows
        for i in range(rows):
            for j in range(columns):
                offset = offsets[j]
                dt = datatypes[j]

                f.seek(offset)
                val_bytes = f.read(4)
                val = parse_val(val_bytes, dt)

                entries[i][j] = val

    # Write the CSV
    with open(csv_file, 'w') as f:
        csvwriter = csv.writer(f)
        csvwriter.writerow(header)
        csvwriter.writerows(entries)

# ============================================
#                     MAIN
# ============================================

def main():
    args = parse_args()
    bcsv = args.bcsv
    encyclopedia_file = args.encyclopedia
    output = args.output

    # Check validity of provided BCSV file
    if not os.path.exists(bcsv) or not os.path.isfile(bcsv):
        print("ERROR: Provided BCSV path does not exist. Exiting...")
        return
    elif os.path.splitext(bcsv)[1] != '.bcsv':
        print("ERROR: Provided path is not a BCSV file. Exiting...")
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

    # Export BCSV to CSV
    basename = os.path.basename(bcsv)
    filename = os.path.splitext(basename)[0]
    csv_file = os.path.join(output, filename + '.csv')
    export_bcsv_to_csv(bcsv, csv_file, encyclopedia)

if __name__ == '__main__':
    main()
