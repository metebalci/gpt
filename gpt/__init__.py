import binascii
from struct import pack, unpack

OS_TYPES = {}
OS_TYPES[0x00] = 'Empty'
OS_TYPES[0xEE] = 'GPT Protective'
OS_TYPES[0xEF] = 'UEFI System Partition'

PARTITION_TYPE_GUIDS = {}
PARTITION_TYPE_GUIDS['00000000-0000-0000-0000-000000000000'] = 'Unused Entry'
PARTITION_TYPE_GUIDS['024DEE41-33E7-11D3-9D69-0008C781F39F'] = 'Legacy MBR'
PARTITION_TYPE_GUIDS['C12A7328-F81F-11D2-BA4B-00A0C93EC93B'] = \
    'EFI System Partition'
PARTITION_TYPE_GUIDS['21686148-6449-6E6F-744E-656564454649'] = \
    'BIOS boot partition'
PARTITION_TYPE_GUIDS['0FC63DAF-8483-4772-8E79-3D69D8477DE4'] = \
    'Linux filesystem data'
PARTITION_TYPE_GUIDS['4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709'] = \
    'Root partition (x86-64)'
PARTITION_TYPE_GUIDS['0657FD6D-A4AB-43C4-84E5-0933C84B4F4F'] = \
    'Swap partition'


class MBR_Partition():
    def __init__(self,
                 boot_indicator,
                 os_type,
                 start_chs,
                 end_chs,
                 lba_ss):
        self.boot_indicator = boot_indicator
        self.os_type = os_type
        self.start_chs = start_chs
        self.end_chs = end_chs
        self.lba_ss = lba_ss

    def os_type_as_str(self):
        return OS_TYPES.get(self.os_type, '?')

    def is_gpt_protective_partition(self):
        return self.os_type == 0xEE

    def is_bootable(self):
        return self.boot_indicator == 0x80


class MBR():
    def __init__(self,
                 bootstrap_code,
                 unique_mbr_disk_signature,
                 unknown,
                 partition_record,
                 partitions,
                 signature):
        self.bootstrap_code = bootstrap_code
        self.unique_mbr_disk_signature = unique_mbr_disk_signature
        self.unknown = unknown
        self.partition_record = partition_record
        self.partitions = partitions
        self.signature = signature

    def is_valid(self):
        return self.signature == 0xAA55


class GPTHeader():
    def __init__(self,
                 signature,
                 revision,
                 header_size,
                 header_crc32,
                 reserved,
                 my_lba,
                 alternate_lba,
                 first_usable_lba,
                 last_usable_lba,
                 disk_guid,
                 partition_entry_lba,
                 number_of_partition_entries,
                 size_of_partition_entry,
                 partition_entry_array_crc32):
        self.signature = signature
        self.revision = revision
        self.header_size = header_size
        self.header_crc32 = header_crc32
        self.reserved = reserved
        self.my_lba = my_lba
        self.alternate_lba = alternate_lba
        self.first_usable_lba = first_usable_lba
        self.last_usable_lba = last_usable_lba
        self.disk_guid = disk_guid
        self.partition_entry_lba = partition_entry_lba
        self.number_of_partition_entries = number_of_partition_entries
        self.size_of_partition_entry = size_of_partition_entry
        self.partition_entry_array_crc32 = partition_entry_array_crc32

    def is_valid(self):
        return self.signature == 'EFI PART'.encode('ascii')

    def calculate_header_crc32(self):
        header_crc32_input = pack('<8s 4s I I 4s Q Q Q Q 16s Q I I I',
                                  self.signature,
                                  self.revision,
                                  self.header_size,
                                  0,  # set to 0 for crc32 calculation
                                  self.reserved,
                                  self.my_lba,
                                  self.alternate_lba,
                                  self.first_usable_lba,
                                  self.last_usable_lba,
                                  self.disk_guid,
                                  self.partition_entry_lba,
                                  self.number_of_partition_entries,
                                  self.size_of_partition_entry,
                                  self.partition_entry_array_crc32)
        return binascii.crc32(header_crc32_input)


class GPTPartitionEntry():
    def __init__(self):
        pass


def encode_mbr(mbr):
    partition_record = bytes()
    for i in range(0, 4):
        partition = input.partitions[i]
        partition_record.append(pack('< B B B B B B B B I I',
                                     partition.boot_indicator,
                                     partition.start_chs[0],
                                     partition.start_chs[1],
                                     partition.start_chs[2],
                                     partition.os_type,
                                     partition.end_chs[0],
                                     partition.end_chs[1],
                                     partition.end_chs[2],
                                     partition.lba_ss[0],
                                     partition.lba_ss[1]))

    output = pack('< 440s 4s 2s 64s H',
                  mbr.bootstrap_code,
                  mbr.unique_mbr_disk_signature,
                  mbr.unknown,
                  partition_record,
                  mbr.signature)
    return output


def decode_mbr(data):
    (bootstrap_code,
     unique_mbr_disk_signature,
     unknown,
     partition_record,
     signature) = unpack('< 440s 4s 2s 64s H', data)
    partitions = []
    for i in range(0, 4):
        offset = i * 16
        (boot_indicator,
         start_head,
         start_sector,
         start_track,
         os_type,
         end_head,
         end_sector,
         end_track,
         starting_lba,
         size_in_lba) = unpack('< B B B B B B B B I I',
                               partition_record[offset:offset + 16])
        partition = MBR_Partition(boot_indicator,
                                  os_type,
                                  (start_head,
                                   start_sector,
                                   start_track),
                                  (end_head,
                                   end_sector,
                                   end_track),
                                  (starting_lba, size_in_lba))
        partitions.append(partition)

    mbr = MBR(bootstrap_code,
              unique_mbr_disk_signature,
              unknown,
              partition_record,
              partitions,
              signature)
    return mbr


def encode_gpt_header(gpt_header):
    pass


def decode_gpt_header(data):
    (signature,
     revision,
     header_size,
     header_crc32,
     reserved,
     my_lba,
     alternate_lba,
     first_usable_lba,
     last_usable_lba,
     disk_guid,
     partition_entry_lba,
     number_of_partition_entries,
     size_of_partition_entry,
     partition_entry_array_crc32) = unpack(
         '< 8s 4s I I 4s Q Q Q Q 16s Q I I I',
         data)
    gpt_header = GPTHeader(signature,
                           revision,
                           header_size,
                           header_crc32,
                           reserved,
                           my_lba,
                           alternate_lba,
                           first_usable_lba,
                           last_usable_lba,
                           disk_guid,
                           partition_entry_lba,
                           number_of_partition_entries,
                           size_of_partition_entry,
                           partition_entry_array_crc32)
    return gpt_header
