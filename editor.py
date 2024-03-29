import sys
from bitsbehumble import *

def print_usage():
    print("Usage:")
    print(f"to add a comment text  : {sys.argv[0]} <pcapngfile> <packetnumber> <comment>")
    print(f'to read a comment      : {sys.argv[0]} <pcapngfile> <packetnumber>')


def get_blocks(pcapng):
    """parses each block in the pcapng file and returns them as hex arrays"""
    enhanced_blocks = []
    all_blocks = []
    # enhanced packet block type to look for in each block
    enhanced_p_block = [  "06000000",  "00000006"]    

    pcapng = hexstring_to_array(pcapng.hex()) # get an array representation of the pcapng file

    i=0
    #parse each block to extract the type , length and content of the block
    while i < len(pcapng):    
        # block type: first 4 bytes
        block_type = hexarr_to_hexstring(pcapng[i:i+4])[2:]
        
        #block length: second 4 bytes
        block_length= hexarr_to_hexstring(pcapng[i+4:i+8])[2:]
        block_length = block_length.replace("00","") # remmove the unnecessary zeros
        block_length = int(block_length,16)  #convert to hex
        
        block = pcapng[i:i+block_length]
        all_blocks.append(block)

        if block_type in enhanced_p_block: 
            enhanced_blocks.append(block)

        i+=block_length

    return enhanced_blocks , all_blocks


def pad(x):
    """pads lengths with zeros until it reaches 4  bytes"""
    #add necessary zeros to form a proper 2 byte hex number for example 0x4 would become 0x04fe
    while len(x) % 4 !=0:
        x=x.zfill(len(x)+1)
    x = hexstring_to_array(x)

    # pad the number with zeros so it's exactly 4 bytes long
    while len(x)!=4:
        x.append("0x00")

    return x


def add_comment(pcap_file,packet_number,comment):
    """this function gets the desired packet block and adds a comment option to the end of it's options list """
    with open(pcap_file,"rb") as f:
        pcapng = f.read()
        f.close()
    
    blocks = get_blocks(pcapng)
    enhanced_blocks = blocks[0]
    all_blocks = blocks[1]
    
    assert packet_number-1 < len(enhanced_blocks), "Invalid packet number"
    
    comment = string_to_hex(comment ,end='big',ret="list") 

    # construct the new option, 3 bytes trailing zeros, 2 bytes option code, 2 bytes option length and then the actual comment
    new_option = ["0x00","0x00","0x00","0x01","0x00",hex(len(comment)),"0x00"] + comment

    # option must be aligned to a 32-bit boundary.
    while len(new_option) %4 !=0: 
        new_option.append("0x00")

    # get the index of this specific enhanced block in all blocks in order to edit it
    block_index = all_blocks.index(enhanced_blocks[packet_number-1])

    # edit the block length
    cur_block = all_blocks[block_index] 
    block_length = hexarr_to_hexstring(cur_block[4:8])[2:]

    block_length = block_length.replace("00","") 
    
    #new block length is the old one + the new option length
    new_length = pad(hex(int(block_length,16) + len(new_option))[2:])

    #overwrite block length
    cur_block[4:8] = new_length
        
    # insert the new option in the existing enhanced_block
    for _byte in new_option: 
        cur_block.insert(-7,_byte) # skip 3 bytes for the opt_endofopt and 4 for the total block length 

    # overwrite the total block length with out new length
    cur_block[-4:] = new_length

    # write to the output file
    with open('output.pcapng',"wb") as new_pcapng:
        for block in all_blocks:
            block = hex_to_bytes(block)
            new_pcapng.write(bytes(block))
        new_pcapng.close()

    print("[+] comment added to output.pcapng in the current working directory")

def read_comment(pcap_file,packet_number):

    with open(pcap_file,"rb") as f:
        pcapng = f.read()
        f.close()

    # get the enhanced blocks as they're the only blocks that can have comments
    blocks = get_blocks(pcapng)[0]
    assert packet_number-1 < len(blocks), "Invalid packet number"

    # get the block that corresponds to the desired packet number
    block = blocks[packet_number-1]
    captured_len = int(hexarr_to_hexstring(block[20:24])[2:].replace("00",""),16)

    #subtracting 4 to remove the block total length that marks the end of a block
    options_field = block[captured_len-4:]

    i=0
    while  i < len(options_field):
        # get each byte in the options and check if it's the start of a comment "01"
        _byte = options_field[i][2:] # remove 0x 
        if _byte ==  "01" and options_field[i+1]=="0x00":
            # found a comment option 0100
            option_length = int(options_field[i+2],16)
            comment = hex_to_string(options_field[ i+4 : i+option_length+4] )
            print(comment)
            i+= option_length +4 # 2 bytes for the option code and 2 for the option length
        else:i+=1
        

def main(argv,argc):
    
    if argc > 3 or argc < 2:
        print_usage()
        sys.exit(2)

    pcap_file  = argv[0]
    packet_number = int(argv[1])
    add_comment(pcap_file,packet_number, argv[2]) if argc == 3 else read_comment(pcap_file,packet_number)    

    
if __name__ == "__main__":
    main(sys.argv[1:],len(sys.argv[1:]))
  
