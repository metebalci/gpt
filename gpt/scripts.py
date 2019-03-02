import sys
import uuid
import codecs
import argparse
from gpt import MBR, MBR_Partition, GPTHeader
from gpt import encode_mbr, decode_mbr
from gpt import encode_gpt_header, decode_gpt_header


# zero terminated string buffer to string
def zts_to_str(buf):
    return buf.split(b'\0', 1)[0]


def decode_guid(guid_as_bytes):
    return uuid.UUID(bytes_le=guid_as_bytes)


'''
def is_gpt_partition_unused(partition_type_guid):
    return PARTITION_TYPE_GUIDS.get(str(partition_type_guid).upper(),
                                    '') == 'Unused Entry'


def decode_gpt_partition_type_guid(partition_type_guid):
    return PARTITION_TYPE_GUIDS.get(str(partition_type_guid).upper(),
                                    'UNKNOWN')
'''


def decode_gpt_partition_entry_attribute(attribute_value):
    r = []
    if (attribute_value & 0x1):
        r.append('Required Partition')
    if (attribute_value & 0x2):
        r.append('No Block IO Protocol')
    if (attribute_value & 0x4):
        r.append('Legacy BIOS Bootable')
    return r


def tprint(title, formatting, *params):
    s = formatting % params
    print('%s:' % title, end='')
    print(' ' * (40 - len(s) - len(title)), end='')
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
    cprint(i, 'Is Bootable? (synth)', '%s', bootable_str)
    cprint(i, 'StartingCHS', '%d, %d, %d',
           mbr_partition.start_chs[0],
           mbr_partition.start_chs[1],
           mbr_partition.start_chs[2])
    cprint(i, 'OSType', '0x%X',  mbr_partition.os_type)
    cprint(i, 'OSType (synth)', '%s',  mbr_partition.os_type_as_str())
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
    print('UniqueMBRDiskSignature: 0x%s' % mbr.unique_mbr_disk_signature.hex())
    print('Unknown: 0x%s' % mbr.unknown.hex())
    print('PartitionRecord: 0x%s' % mbr.partition_record.hex())
    print('Signature: 0x%X' % mbr.signature)
    for i in range(0, 4):
        display_mbr_partition(i, mbr.partitions[i])


def display_gpt_partition_entry_array(data):
    pass


'''
    (partition_type_guid_raw,
     unique_partition_guid_raw,
     starting_lba,
     ending_lba,
     attributes,
     partition_name_raw) = unpack('< 16s 16s Q Q Q 72s',
                                  data)
    partition_type_guid = decode_guid(partition_type_guid_raw)
    if (show_unused or not is_gpt_partition_unused(partition_type_guid)):

        partition_type_guid_decoded = (
            decode_gpt_partition_type_guid(partition_type_guid))

        unique_partition_guid = decode_guid(
            unique_partition_guid_raw)

        partition_name = zts_to_str(partition_name_raw)

        print('<<< GPT Partition Entry #%d >>>' % i)
        print('PartitionTypeGUID: %s' % partition_type_guid_raw.hex())
        print('PartitionTypeGUID (decoded): %s' % partition_type_guid_decoded)
        print('UniquePartitionGUID: %s' % unique_partition_guid_raw.hex())
        print('UniquePartitionGUID (decoded): %s' % unique_partition_guid)
        print('StartingLBA: %d' % starting_lba)
        print('EndingLBA: %d' % ending_lba)
        print('Attributes: 0x%x' % attributes)
        print('Attributes (decoded): %s' %
              decode_gpt_partition_entry_attribute(attributes))
        print('PartitionName: %s' % partition_name.hex())
'''


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


'''
        gpt_header = data[0:92]
        (partition_entry_lba,
         number_of_partition_entries,
         size_of_partition_entry,
         partition_entry_array_crc32) = parse_gpt_header(gpt_header)
        data = data[lbads:]
        partition_entry_array_size = (
            number_of_partition_entries * size_of_partition_entry)
        required_number_of_blocks = (
            math.ceil(partition_entry_array_size / lbads))
        if len(data) < (required_number_of_blocks * lbads):
            print('not enough data to read GPT Partitions')
            print('provide at least %d blocks/%d bytes more input' %
                  (required_number_of_blocks,
                   required_number_of_blocks * lbads))
            sys.exit()
        partition_entry_array = data[0:partition_entry_array_size]
        partition_entry_array_crc32_calculated = binascii.crc32(
            partition_entry_array)
        if (partition_entry_array_crc32 ==
           partition_entry_array_crc32_calculated):
            partition_entry_array_crc32_result = 'matched'
        else:
            partition_entry_array_crc32_result = 'unmatched'

        print('PartitionEntryArrayCRC32 (calculated): %x %s' %
              (partition_entry_array_crc32_calculated,
               partition_entry_array_crc32_result))

        for i in range (0, number_of_partition_entries):
            offset = i * size_of_partition_entry
            partition_record = data[offset:offset + size_of_partition_entry]
            parse_gpt_partition(i, partition_record, show_unused)
'''


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
    args = parser.parse_args()
    if args.file is None:
        data = sys.stdin.buffer.read()
    else:
        with open(args.file, 'rb') as f:
            data = f.read()

    data = sys.stdin.read()
    required = args.size * args.count
    if len(data) < required:
        print('Error: Please provide at least %d bytes of input' % required)
        sys.exit()

    if len(data) > required:
        print('Warning: Using only the first %d bytes of input' % required)

    gpt_partition_entry_array = decode_gpt_partition_entry_array(
        data[0:required],
        args.size,
        args.count)
    display_gpt_partition_entry_array(gpt_partition_entry_array)
