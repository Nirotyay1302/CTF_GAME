#!/usr/bin/env python3
"""
Create 50 diverse CTF challenges for the CTF game
"""

import os
import sys
from datetime import datetime, timedelta
import secrets
import hashlib

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from CTF_GAME import app, db, fernet
from models import Challenge

def create_50_challenges():
    """Create 50 diverse CTF challenges"""
    
    challenges = [
        # EASY CHALLENGES (1-20)
        {
            'title': 'Welcome to CTF!',
            'description': 'This is your first challenge! The flag format is flag{...}. Can you find the hidden flag in this message? Hint: Look carefully at the first letter of each word: Find Lovely Amazing Goodies {welcome_to_ctf}',
            'flag': 'flag{welcome_to_ctf}',
            'points': 10,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'Base64 Basics',
            'description': 'Decode this Base64 string to find the flag: ZmxhZ3tiYXNlNjRfaXNfZWFzeX0=',
            'flag': 'flag{base64_is_easy}',
            'points': 15,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'Caesar Cipher',
            'description': 'Julius Caesar used this cipher to protect his messages. Can you decode this message with a shift of 13? synt{pnrfne_pvcure_vf_sha}',
            'flag': 'flag{caesar_cipher_is_fun}',
            'points': 20,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'Hidden in Plain Sight',
            'description': 'Sometimes the answer is right in front of you. Inspect this webpage carefully... <!-- flag{inspect_element_ftw} -->',
            'flag': 'flag{inspect_element_ftw}',
            'points': 15,
            'category': 'web',
            'difficulty': 'easy'
        },
        {
            'title': 'Binary Message',
            'description': 'Convert this binary to ASCII: 01100110 01101100 01100001 01100111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01011111 01101001 01110011 01011111 01100011 01101111 01101111 01101100 01111101',
            'flag': 'flag{binary_is_cool}',
            'points': 25,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'Hex Decoder',
            'description': 'Decode this hexadecimal message: 666c61677b6865785f69735f73696d706c657d',
            'flag': 'flag{hex_is_simple}',
            'points': 20,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'Reverse Me',
            'description': 'Sometimes you need to look at things backwards: }ysae_si_esrever{galf',
            'flag': 'flag{reverse_is_easy}',
            'points': 15,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'ASCII Art Flag',
            'description': 'Find the flag hidden in this ASCII art:\n  _____ _               \n |  ___| | __ _  __ _   \n | |_  | |/ _` |/ _` |  \n |  _| | | (_| | (_| |  \n |_|   |_|\\__,_|\\__, |  \n                |___/   \nflag{ascii_art_rocks}',
            'flag': 'flag{ascii_art_rocks}',
            'points': 25,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'URL Decode',
            'description': 'Decode this URL encoded string: flag%7Burl%5Fdecoding%5Fis%5Feasy%7D',
            'flag': 'flag{url_decoding_is_easy}',
            'points': 20,
            'category': 'web',
            'difficulty': 'easy'
        },
        {
            'title': 'Morse Code',
            'description': 'Decode this Morse code message: ..-. .-.. .- --. .---- -... -- --- .-. ... . .---- .. ... .---- ..-. ..- -. .----',
            'flag': 'flag{morse_is_fun}',
            'points': 30,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'Simple Substitution',
            'description': 'Each letter is replaced by the next letter in the alphabet: gmbh{tvctujuvujpo_djqifs}',
            'flag': 'flag{substitution_cipher}',
            'points': 25,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'QR Code',
            'description': 'Scan this QR code (imagine it contains): flag{qr_codes_are_cool}',
            'flag': 'flag{qr_codes_are_cool}',
            'points': 20,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'Keyboard Shift',
            'description': 'This message was typed with fingers shifted one key to the right: gksu{lruniRsf_od_ysrd}',
            'flag': 'flag{keyboard_is_hard}',
            'points': 30,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'Pig Latin',
            'description': 'Decode this Pig Latin message: agflay{igpay_atinlay_away_anguagelay}',
            'flag': 'flag{pig_latin_a_language}',
            'points': 25,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'Atbash Cipher',
            'description': 'The Atbash cipher replaces each letter with its opposite: uozt{zgyzhs_rhkvi}',
            'flag': 'flag{atbash_cipher}',
            'points': 30,
            'category': 'crypto',
            'difficulty': 'easy'
        },
        {
            'title': 'Leetspeak',
            'description': 'Decode this 1337 speak: fl4g{l33t5p34k_15_c00l}',
            'flag': 'flag{leetspeak_is_cool}',
            'points': 20,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'Upside Down',
            'description': 'Turn your screen upside down: ƃɐlɟ{uʍop_ǝpᴉsdn_sᴉ_ɹǝpuoʍ}',
            'flag': 'flag{upside_down_is_wonder}',
            'points': 25,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'Counting',
            'description': 'Count the number of characters in this string and use it as the flag: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" - flag{26}',
            'flag': 'flag{26}',
            'points': 15,
            'category': 'misc',
            'difficulty': 'easy'
        },
        {
            'title': 'Hidden in Image',
            'description': 'The flag is hidden in the filename of this image: flag_hidden_in_filename.jpg contains flag{hidden_in_filename}',
            'flag': 'flag{hidden_in_filename}',
            'points': 20,
            'category': 'forensics',
            'difficulty': 'easy'
        },
        {
            'title': 'Simple Math',
            'description': 'Solve this equation and format as flag: 15 + 27 = ? Answer: flag{42}',
            'flag': 'flag{42}',
            'points': 10,
            'category': 'misc',
            'difficulty': 'easy'
        },
        
        # MEDIUM CHALLENGES (21-35)
        {
            'title': 'Vigenère Cipher',
            'description': 'Decrypt this Vigenère cipher with key "CTF": HMEK{VKIGXGVI_GMTLIV}',
            'flag': 'flag{vigenere_cipher}',
            'points': 40,
            'category': 'crypto',
            'difficulty': 'medium'
        },
        {
            'title': 'SQL Injection',
            'description': 'Find the flag in this vulnerable query. Username: admin\' OR 1=1-- Password: anything. Flag is in users table.',
            'flag': 'flag{sql_injection_works}',
            'points': 50,
            'category': 'web',
            'difficulty': 'medium'
        },
        {
            'title': 'XOR Cipher',
            'description': 'XOR this hex with key 0x42: 24060701420b0a1f0e1b420c1f420a0e1b',
            'flag': 'flag{xor_is_fun}',
            'points': 45,
            'category': 'crypto',
            'difficulty': 'medium'
        },
        {
            'title': 'File Signature',
            'description': 'This file has the wrong extension. The hex signature is: 89504E470D0A1A0A. What type of file is it? flag{png}',
            'flag': 'flag{png}',
            'points': 35,
            'category': 'forensics',
            'difficulty': 'medium'
        },
        {
            'title': 'JWT Token',
            'description': 'Decode this JWT token header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. The flag is the algorithm used.',
            'flag': 'flag{HS256}',
            'points': 40,
            'category': 'web',
            'difficulty': 'medium'
        },
        {
            'title': 'Steganography Text',
            'description': 'The flag is hidden in the first letter of each word: Find Love And Great Success Today Over Various Exciting Races',
            'flag': 'flag{stover}',
            'points': 35,
            'category': 'forensics',
            'difficulty': 'medium'
        },
        {
            'title': 'Hash Collision',
            'description': 'Find a string that has the same MD5 hash as "hello": 5d41402abc4b2a76b9719d911017c592',
            'flag': 'flag{hash_collision}',
            'points': 50,
            'category': 'crypto',
            'difficulty': 'medium'
        },
        {
            'title': 'Buffer Overflow Prep',
            'description': 'This program has a buffer of 64 bytes. What happens if you input 100 A\'s? flag{buffer_overflow}',
            'flag': 'flag{buffer_overflow}',
            'points': 45,
            'category': 'pwn',
            'difficulty': 'medium'
        },
        {
            'title': 'Directory Traversal',
            'description': 'Access the file /etc/passwd using directory traversal: ../../../etc/passwd',
            'flag': 'flag{directory_traversal}',
            'points': 40,
            'category': 'web',
            'difficulty': 'medium'
        },
        {
            'title': 'Reverse Engineering',
            'description': 'This program checks if input equals "secret123". What\'s the flag format?',
            'flag': 'flag{secret123}',
            'points': 45,
            'category': 'reverse',
            'difficulty': 'medium'
        },
        {
            'title': 'Network Packet',
            'description': 'Analyze this HTTP request: GET /flag.txt HTTP/1.1\\nHost: ctf.example.com\\nFlag: flag{packet_analysis}',
            'flag': 'flag{packet_analysis}',
            'points': 40,
            'category': 'forensics',
            'difficulty': 'medium'
        },
        {
            'title': 'Command Injection',
            'description': 'Exploit this command: ping -c 1 [user_input]. Inject: ; cat flag.txt',
            'flag': 'flag{command_injection}',
            'points': 50,
            'category': 'web',
            'difficulty': 'medium'
        },
        {
            'title': 'Polyalphabetic Cipher',
            'description': 'Decrypt using multiple Caesar shifts [1,2,3,4,5]: GMBH{QPMZCKRJGVKE_EKRJGT}',
            'flag': 'flag{polyalphabetic_cipher}',
            'points': 45,
            'category': 'crypto',
            'difficulty': 'medium'
        },
        {
            'title': 'Memory Dump',
            'description': 'Find the flag in this memory dump at offset 0x1000: flag{memory_forensics}',
            'flag': 'flag{memory_forensics}',
            'points': 50,
            'category': 'forensics',
            'difficulty': 'medium'
        },
        {
            'title': 'Assembly Code',
            'description': 'This assembly moves "flag{asm_is_fun}" into register EAX. What\'s the flag?',
            'flag': 'flag{asm_is_fun}',
            'points': 45,
            'category': 'reverse',
            'difficulty': 'medium'
        },
        
        # HARD CHALLENGES (36-50)
        {
            'title': 'RSA Decryption',
            'description': 'Decrypt this RSA message with n=3233, e=17, d=2753: 855',
            'flag': 'flag{rsa_crypto}',
            'points': 75,
            'category': 'crypto',
            'difficulty': 'hard'
        },
        {
            'title': 'Advanced SQL Injection',
            'description': 'Bypass this WAF and extract data: SELECT * FROM users WHERE id = ? (Use UNION injection)',
            'flag': 'flag{advanced_sqli}',
            'points': 80,
            'category': 'web',
            'difficulty': 'hard'
        },
        {
            'title': 'AES Decryption',
            'description': 'Decrypt this AES-128 ECB encrypted hex with key "YELLOW SUBMARINE": 7b5a4215415d544115415d5015455447',
            'flag': 'flag{aes_decrypted}',
            'points': 70,
            'category': 'crypto',
            'difficulty': 'hard'
        },
        {
            'title': 'Return Oriented Programming',
            'description': 'Chain these ROP gadgets to call system("/bin/sh"): pop rdi; ret | pop rsi; ret | syscall',
            'flag': 'flag{rop_chain_master}',
            'points': 90,
            'category': 'pwn',
            'difficulty': 'hard'
        },
        {
            'title': 'Blind SQL Injection',
            'description': 'Extract the admin password using time-based blind SQLi: IF(SUBSTRING(password,1,1)=\'a\',SLEEP(5),0)',
            'flag': 'flag{blind_sqli_master}',
            'points': 85,
            'category': 'web',
            'difficulty': 'hard'
        },
        {
            'title': 'Elliptic Curve Crypto',
            'description': 'Break this weak ECC implementation with curve y²=x³+7 over F_p where p=23',
            'flag': 'flag{ecc_broken}',
            'points': 95,
            'category': 'crypto',
            'difficulty': 'hard'
        },
        {
            'title': 'Kernel Exploitation',
            'description': 'Exploit this kernel module to gain root privileges via /proc/vulnerable',
            'flag': 'flag{kernel_pwned}',
            'points': 100,
            'category': 'pwn',
            'difficulty': 'hard'
        },
        {
            'title': 'Advanced Steganography',
            'description': 'Extract the hidden message using LSB steganography in the blue channel of this PNG',
            'flag': 'flag{lsb_stego_master}',
            'points': 75,
            'category': 'forensics',
            'difficulty': 'hard'
        },
        {
            'title': 'Heap Exploitation',
            'description': 'Exploit this heap overflow to overwrite function pointers and gain code execution',
            'flag': 'flag{heap_overflow_pwn}',
            'points': 90,
            'category': 'pwn',
            'difficulty': 'hard'
        },
        {
            'title': 'Advanced Reverse Engineering',
            'description': 'This binary uses anti-debugging techniques. Bypass them to find the flag.',
            'flag': 'flag{anti_debug_bypassed}',
            'points': 85,
            'category': 'reverse',
            'difficulty': 'hard'
        },
        {
            'title': 'SSRF to RCE',
            'description': 'Chain SSRF with internal service to achieve RCE: http://internal:8080/admin/exec',
            'flag': 'flag{ssrf_to_rce}',
            'points': 80,
            'category': 'web',
            'difficulty': 'hard'
        },
        {
            'title': 'Cryptographic Oracle',
            'description': 'Use this padding oracle to decrypt the ciphertext: CBC mode with PKCS7 padding',
            'flag': 'flag{padding_oracle_attack}',
            'points': 85,
            'category': 'crypto',
            'difficulty': 'hard'
        },
        {
            'title': 'Race Condition',
            'description': 'Exploit the race condition in this multi-threaded application to bypass authentication',
            'flag': 'flag{race_condition_pwn}',
            'points': 75,
            'category': 'pwn',
            'difficulty': 'hard'
        },
        {
            'title': 'Advanced Forensics',
            'description': 'Recover the deleted file from this ext4 filesystem image using journal analysis',
            'flag': 'flag{filesystem_forensics}',
            'points': 80,
            'category': 'forensics',
            'difficulty': 'hard'
        },
        {
            'title': 'Master Challenge',
            'description': 'Combine all your skills: Reverse engineer the binary, exploit the buffer overflow, decrypt the AES payload, and extract the final flag from the network traffic.',
            'flag': 'flag{ctf_master_champion}',
            'points': 150,
            'category': 'misc',
            'difficulty': 'hard'
        }
    ]
    
    print(f"Creating {len(challenges)} CTF challenges...")
    
    created_count = 0
    for challenge_data in challenges:
        # Check if challenge already exists
        existing = Challenge.query.filter_by(title=challenge_data['title']).first()
        if existing:
            print(f"Challenge '{challenge_data['title']}' already exists, skipping...")
            continue
        
        try:
            # Encrypt the flag
            encrypted_flag = fernet.encrypt(challenge_data['flag'].encode())
            
            # Create salt and hash for secure flag validation
            salt = secrets.token_bytes(16)
            flag_hash = hashlib.sha256(salt + challenge_data['flag'].encode()).digest()
            
            # Create challenge
            challenge = Challenge(
                title=challenge_data['title'],
                description=challenge_data['description'],
                flag_encrypted=encrypted_flag,
                flag_salt=salt,
                flag_hash=flag_hash,
                points=challenge_data['points'],
                category=challenge_data['category'],
                difficulty=challenge_data['difficulty'],
                created_at=datetime.utcnow()
            )
            
            db.session.add(challenge)
            created_count += 1
            print(f"Added: {challenge_data['title']} ({challenge_data['points']} pts, {challenge_data['category']}/{challenge_data['difficulty']})")
            
        except Exception as e:
            print(f"Error creating challenge '{challenge_data['title']}': {e}")
            continue
    
    try:
        db.session.commit()
        print(f"\n✅ Successfully created {created_count} challenges!")
        
        # Display summary
        challenges = Challenge.query.all()
        categories = {}
        difficulties = {}
        total_points = 0
        
        for challenge in challenges:
            categories[challenge.category] = categories.get(challenge.category, 0) + 1
            difficulties[challenge.difficulty] = difficulties.get(challenge.difficulty, 0) + 1
            total_points += challenge.points
        
        print("\n📊 Challenge Summary:")
        print("-" * 50)
        print(f"Total Challenges: {len(challenges)}")
        print(f"Total Points Available: {total_points}")
        print(f"Categories: {dict(categories)}")
        print(f"Difficulties: {dict(difficulties)}")
        
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error committing challenges: {e}")
        return False

def main():
    """Main function to create 50 challenges"""
    print("🎯 CTF Challenge Creator - 50 Challenges")
    print("=" * 50)
    
    with app.app_context():
        # Check if database tables exist
        try:
            db.create_all()
            print("✅ Database tables verified/created")
        except Exception as e:
            print(f"❌ Error with database: {e}")
            return
        
        # Check existing challenges
        existing_count = Challenge.query.count()
        print(f"📋 Found {existing_count} existing challenges")
        
        if existing_count > 0:
            response = input("Do you want to add more challenges? (y/n): ").lower()
            if response != 'y':
                print("Exiting...")
                return
        
        # Create 50 challenges
        success = create_50_challenges()
        
        if success:
            print("\n🎉 Challenge creation complete!")
            print("Your CTF game now has a comprehensive set of challenges!")
        else:
            print("\n❌ Challenge creation failed!")

if __name__ == "__main__":
    main()
