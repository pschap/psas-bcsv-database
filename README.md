# PSAS BCSV Database

## Summary
```psas-bcsv-database``` is a collection of scripts and documentation for interpreting and manipulating BCSV files for Playstation All-Stars Battle Royale (PSASBR) for the Playstation Vita.  Specifically, this repository contains:

- Ghidra scripts for finding BCSV columns within the game's ```eboot.bin``` and automatically generating documentation.
- Scripts for exporting/importing BCSV files to/from CSV files.
- Documentation for BCSV attribute hashes and functionality in ```encyclopedia.json```.
- Other utility scripts for automatically managing and adding additional documentation to ```encyclopedia.json```.

## What are BCSV files?
BCSV files are a sort of binary-encoded CSV file/spreadsheet used by PSASBR that are used to store many forms of global data and attributes that are used by the game. Conceptually, you can think of them as just a spreadsheet; each BCSV contains several columns and each following row contains exactly one entry per column. However, instead of directly storing column names within the file, column [hashes](https://en.wikipedia.org/wiki/Hash_function) are used instead to reduce the overall size of each file. Each hash is a unique integer representation of a column name. To retrieve a particular "cell" of a BCSV file, the location of a particular hash in the function is first found. Then, the location of the hash in
this file is used to resolve the location of all values under that particular column.

## Dependencies
To install all required dependencies needed for running the exporter/importer scripts, run:

```bash
pip install -r requirements.txt
```

## Export/Import Scripts
This repository contains scripts to export/import BCSV files to/from CSV files that allow for easy and user-friendly modification of BCSV files. To export a BCSV file to a CSV file, run:

```bash
python3 scripts/bcsv_exporter.py -e encyclopedia.json -b bcsv/<YOUR_BCSV_FILE>
```

Similarly, to import a CSV file back to a BCSV file, run:

```bash
python3 scripts/bcsv_importer.py -e encyclopedia.json -c <YOUR_CSV_FILE>
```

To pack a modified BCSV file back into a PSARC to be used in-game, please see [Cri4key's PSASBR Tool](https://github.com/Cri4Key/PSASBR-Tool).

## Mapping Hashes to Column Names
Unfortunately, it is very difficult to determine specific column names that were used to produce a specific hash. This project aims to match hashes to their corresponding column name as well as document the functionality of each column within each BCSV file. Hashes can best be matched to an appropriate column name by analyzing PSASBR's ```eboot.bin``` using tools such as Ghidra. For example, in the function that reads ```gameattributes.bcsv```, we can see that one of the column names is ```AP_Amount_Light``` and maps to the hash ```0xbb0c224a```:

```C
    hashOffset = HashBcsvAttribute("AP_Amount_Light",0x811c9dc5);
    uVar3 = 0;
    tmpFilePtr = bcsvFilePtr;
    if (*(ushort *)(bcsvFilePtr + 4) != 0) {
      do {
        if (*(uint *)(tmpFilePtr + 8) == hashOffset) goto LAB_81272a2c;
        uVar3 = uVar3 + 1;
        tmpFilePtr = tmpFilePtr + 8;
      } while ((int)uVar3 < (int)(uint)*(ushort *)(bcsvFilePtr + 4));
    }
    uVar3 = 0xffffffff;
LAB_81272a2c:
    pfVar1 = (float *)RetrieveBcsvField((int)bcsvFilePtr,uVar3);
```

Additionally, hashes can be found using dynamic analysis/tools (such as [psas-hooks](https://github.com/pschap/psas-hooks/tree/master)) by printing out hashes as they are being passed to functions.

