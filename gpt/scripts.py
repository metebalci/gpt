import sys
import uuid
import codecs
import argparse
from gpt import MBR, MBR_Partition, GPTHeader
from gpt import encode_mbr, decode_mbr
from gpt import encode_gpt_header, decode_gpt_header
from gpt import encode_gpt_partition_entry_array
from gpt import decode_gpt_partition_entry_array
from gpt import calculate_partition_entry_array_crc32


def tprint(title, formatting, *params):
    s = formatting % params
    print('%s: ' % title, end='')
    print(' ' * (72 - len(s) - len(title)), end='')
    print(s)


def cprint(i, title, formatting, *params):
    tprint('#%d.%s' % (i, title), formatting, *params)


def display_mbr_partition(i, mbr_partition):
    print('<<< MBR Partition #%d >>>' % i)
    if mbr_partition.is_bootable():
        bootable_str = 'Yes'
    else:
        bootable_str = 'No'

    cprint(i, 'BootIndicator', '0x%X', mbr_partition.boot_indicator)
    cprint(i, 'Is Bootable? (syn)', '%s', bootable_str)
    cprint(i, 'StartingCHS', '%d, %d, %d',
           mbr_partition.start_chs[0],
           mbr_partition.start_chs[1],
           mbr_partition.start_chs[2])
    cprint(i, 'OSType', '0x%X',  mbr_partition.os_type)
    cprint(i, 'OSType (syn)', '%s',  mbr_partition.os_type_as_str())
    cprint(i, 'EndingCHS', '%d, %d, %d',
           mbr_partition.end_chs[0],
           mbr_partition.end_chs[1],
           mbr_partition.end_chs[2])
    cprint(i, 'StartingLBA', '%d', mbr_partition.lba_ss[0])
    cprint(i, 'SizeInLBA', '%d',  mbr_partition.lba_ss[1])


def display_mbr(mbr):
    if not mbr.is_valid():
        print('Error: Invalid MBR, signature: 0x%X is not correct.' %
              mbr.signature)
        sys.exit()

    print('<<< MBR >>>')
    print('BootCode: 0x%s' % mbr.bootstrap_code.hex())
    tprint('UniqueMBRDiskSignature', '0x%s', 
            mbr.unique_mbr_disk_signature.hex())
    tprint('Unknown', '0x%s', mbr.unknown.hex())
    print('PartitionRecord: 0x%s' % mbr.partition_record.hex())
    tprint('Signature', '0x%X', mbr.signature)
    for i in range(0, 4):
        display_mbr_partition(i, mbr.partitions[i])


def display_gpt_header(gpt_header):
    if not gpt_header.is_valid():
        print('Error: Invalid GPT Header, signature: 0x%s is not correct.' %
              gpt_header.signature.hex())
        sys.exit()

    calculated_header_crc32 = gpt_header.calculate_header_crc32()
    if gpt_header.header_crc32 != calculated_header_crc32:
        print('Warning: header_crc32 is wrong')

    print('<<< GPT Header >>>')
    tprint('Signature', '0x%s', gpt_header.signature.hex())
    tprint('Revision', '0x%s', gpt_header.revision.hex())
    tprint('HeaderSize', '%d', gpt_header.header_size)
    tprint('HeaderCRC32', '0x%x', gpt_header.header_crc32)
    tprint('HeaderCRC32 (calculated)', '0x%x',
           calculated_header_crc32)
    tprint('Reserved', '0x%s', gpt_header.reserved.hex())
    tprint('MyLBA', '%d', gpt_header.my_lba)
    tprint('AlternateLBA', '%d', gpt_header.alternate_lba)
    tprint('FirstUsableLBA', '%d', gpt_header.first_usable_lba)
    tprint('LastUsableLBA', '%d', gpt_header.last_usable_lba)
    tprint('PartitionEntryLBA', '%d', gpt_header.partition_entry_lba)
    tprint('NumberOfPartitionEntries', '%d',
           gpt_header.number_of_partition_entries)
    tprint('SizeOfPartitionEntry', '%d', gpt_header.size_of_partition_entry)
    tprint('PartitionEntryArrayCRC32', '0x%x',
           gpt_header.partition_entry_array_crc32)


def display_gpt_partition_entry(i, entry):
    print('<<< GPT Partition Entry #%d >>>' % i)
    cprint(i, 'PartitionTypeGUID', '0x%s', entry.partition_type_guid_raw.hex())
    cprint(i, 'PartitionTypeGUID (syn)', '%s', entry.partition_type_guid)
    cprint(i, 'PartitionType (syn)', '%s', entry.partition_type)
    cprint(i, 'UniquePartitionGUID', '0x%s', entry.unique_partition_guid_raw.hex())
    cprint(i, 'UniquePartitionGUID (syn)', '%s', entry.unique_partition_guid)
    cprint(i, 'StartingLBA', '%d', entry.starting_lba)
    cprint(i, 'EndingLBA', '%d', entry.ending_lba)
    cprint(i, 'Attributes', '0x%x', entry.attributes_raw)
    cprint(i, 'Attributes (syn)', '%s', entry.attributes)
    print('#%d.PartitionName: 0x%s' % (i, entry.partition_name_raw.hex()))
    cprint(i, 'PartitionName (syn)', '%s', entry.partition_name)


def display_gpt_partition_entry_array(entries, size, count, showall):
    for i in range(0, count):
        if showall or not entries[i].is_empty():
            display_gpt_partition_entry(i, entries[i])


def print_mbr():
    parser = argparse.ArgumentParser(description='Dumps MBR.')
    parser.add_argument('-f',
                        '--file',
                        help='Use file instead of stdin',
                        dest='file')
    args = parser.parse_args()
    if args.file is None:
        data = sys.stdin.buffer.read()
    else:
        with open(args.file, 'rb') as f:
            data = f.read()

    if len(data) < 512:
        print('Error: Please provide 512 bytes of input')
        sys.exit()

    if len(data) > 512:
        print('Warning: Using only the first 512 bytes of input')

    mbr = decode_mbr(data[0:512])
    display_mbr(mbr)


def print_gpt_header():
    parser = argparse.ArgumentParser(description='Dumps GPT Header.')
    parser.add_argument('-f',
                        '--file',
                        help='Use file instead of stdin',
                        dest='file')
    args = parser.parse_args()
    if args.file is None:
        data = sys.stdin.buffer.read()
    else:
        with open(args.file, 'rb') as f:
            data = f.read()

    if len(data) < 92:
        print('Error: Please provide 92 bytes of input')
        sys.exit()

    if len(data) > 92:
        print('Warning: Using only the first 92 bytes of input')

    gpt_header = decode_gpt_header(data[0:92])
    display_gpt_header(gpt_header)


def print_gpt_partition_entry_array():
    parser = argparse.ArgumentParser(
        description='Dumps GPT Partition Entry Array.')
    parser.add_argument('-f',
                        '--file',
                        help='Use file instead of stdin',
                        dest='file')
    parser.add_argument('-s',
                        '--size',
                        help='Size of a partition entry (default: 128)',
                        type=int,
                        default=128)
    parser.add_argument('-c',
                        '--count',
                        help='Number of partition entries (default: 128)',
                        type=int,
                        default=128,
                        dest='count')
    parser.add_argument('-a',
                        '--all',
                        help='Show all (also unused) partition entries (default: false)',
                        action='store_true',
                        default=False,
                        dest='showall')
    args = parser.parse_args()
    if args.file is None:
        data = sys.stdin.buffer.read()
    else:
        with open(args.file, 'rb') as f:
            data = f.read()

    required = args.size * args.count
    if len(data) < required:
        print('Error: Please provide %d bytes of input' % required)
        sys.exit()

    if len(data) > required:
        print('Warning: Using only the first %d bytes of input' % required)

    gpt_partition_entry_array = decode_gpt_partition_entry_array(
        data,
        args.size,
        args.count)
    display_gpt_partition_entry_array(
            gpt_partition_entry_array,
            args.size,
            args.count,
            args.showall)
    calculated_array_crc32 = calculate_partition_entry_array_crc32(data)
    print('<<< Calculated >>>')
    tprint('PartitionEntryArrayCRC32 (calculated)', '0x%x',
            calculated_array_crc32)
